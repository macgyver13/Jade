#!/usr/bin/env python3
"""Set up and exercise Jade/Coldcard form-(b) MuSig2 interoperability.

Setup a shared descriptor on Jade (signet uses Jade's ``testnet`` network):

    python3 dev_musig2_interop.py setup \
        --cosigner '[COLD_XFP/48h/1h/0h/3h]tpub...'

Exercise D2/D4 while keeping Jade's RAM-only nonce alive:

    python3 dev_musig2_interop.py sign unsigned.psbt \
        --expect-round1 incomplete --round2-input coldcard-r2.psbt

For D3, first have Coldcard perform round 1 on a fresh PSBT, then use that
PSBT as the input and pass ``--expect-round1 complete``.

The signing command stays connected to Jade while waiting for Coldcard. Do not
disconnect or exit between rounds: that deliberately expires the secnonce.
"""

import argparse
import base64

from test_sp_roundtrip import HARDENED, TEST_MNEMONIC, load_wally


DEFAULT_DEVICE = 'tcp:127.0.0.1:30121'
DEFAULT_ORIGIN = '48h/1h/0h/3h'
NETWORKS = ('mainnet', 'testnet', 'testnet4', 'localtest')


def read_psbt(path):
    data = open(path, 'rb').read()
    if data.startswith(b'psbt\xff'):
        return data
    try:
        decoded = base64.b64decode(data.strip(), validate=True)
    except ValueError as exc:
        raise ValueError(f'{path} is neither a binary nor base64 PSBT') from exc
    if not decoded.startswith(b'psbt\xff'):
        raise ValueError(f'{path} does not contain a PSBT')
    return decoded


def write_bytes(path, data):
    with open(path, 'wb') as output:
        output.write(data)
    print(f'Wrote {path} ({len(data)} bytes)')


def parse_path(path):
    result = []
    for element in path.removeprefix('m/').split('/'):
        hardened = element[-1:] in ('h', 'H', "'")
        value = int(element[:-1] if hardened else element)
        result.append(value | HARDENED if hardened else value)
    return result


def canonical_path(path):
    return '/'.join(f'{value & ~HARDENED}{"h" if value & HARDENED else ""}'
                    for value in parse_path(path))


def descriptor_with_checksum(wally, descriptor):
    parsed = wally.c_void_p()
    assert wally.wally_descriptor_parse(descriptor, None, 0, 0, parsed) == wally.WALLY_OK, \
        'libwally rejected the constructed descriptor'
    ret, checksum = wally.wally_descriptor_get_checksum(parsed, 0)
    wally.wally_descriptor_free(parsed)
    assert ret == wally.WALLY_OK
    if isinstance(checksum, bytes):
        checksum = checksum.decode()
    return f'{descriptor}#{checksum}'


def jade_key_expression(jade, wally, network, origin):
    master = wally.ext_key()
    master_xpub = jade.get_xpub(network, [])
    assert wally.bip32_key_from_base58(master_xpub.encode(), wally.byref(master)) == wally.WALLY_OK
    fingerprint = bytes(master.hash160)[:4].hex()
    path = parse_path(origin)
    account_xpub = jade.get_xpub(network, path)
    return f'[{fingerprint}/{canonical_path(origin)}]{account_xpub}'


def setup(args, jade, wally):
    jade_key = jade_key_expression(jade, wally, args.network, args.origin)
    participants = [jade_key] + args.cosigner
    shared_descriptor = descriptor_with_checksum(
        wally, f'tr(musig({",".join(participants)})/<0;1>/*)')

    print('\nJade participant:')
    print(jade_key)
    print('\nShared descriptor (import/use this exact descriptor on every signer):')
    print(shared_descriptor)
    print('\nConfirm the participant fingerprints and descriptor on Jade.')
    assert jade.register_descriptor(
        args.network, args.name, shared_descriptor, {})
    registered = jade.get_registered_descriptor(args.name)
    assert registered and registered['descriptor'] == shared_descriptor
    assert registered['datavalues'] == {}

    address = jade.get_receive_address(
        args.network, args.branch, args.index, descriptor_name=args.name)
    print(f'\nRegistered as {args.name!r}')
    print(f'Address /{args.branch}/{args.index}: {address}')
    print('Compare this address with Coldcard before funding the signet wallet.')


def parse_psbt(wally, data):
    psbt = wally.POINTER(wally.wally_psbt)()
    assert wally.wally_psbt_from_bytes(data, len(data), 0, wally.byref(psbt)) == wally.WALLY_OK
    return psbt


def sp_output_scripts(wally, psbt):
    scripts = []
    for index in range(psbt.contents.num_outputs):
        ret, info_len = wally.wally_psbt_get_output_sp_v0_info_len(psbt, index)
        if ret == wally.WALLY_OK and info_len:
            ret, script_len = wally.wally_psbt_get_output_script_len(psbt, index)
            assert ret == wally.WALLY_OK
            scripts.append(script_len)
    assert scripts, 'PSBT has no silent-payment outputs'
    return scripts


def snapshot(wally, data):
    psbt = parse_psbt(wally, data)
    inputs = []
    for index in range(psbt.contents.num_inputs):
        item = psbt.contents.inputs[index]
        if item.musig2_pubkeys.num_items:
            ret, tap_sig_len = wally.wally_psbt_get_input_taproot_signature_len(psbt, index)
            assert ret == wally.WALLY_OK
            inputs.append({
                'index': index,
                'shares': item.sp_partial_ecdh_shares.num_items,
                'proofs': item.sp_partial_dleq_proofs.num_items,
                'pubnonces': item.musig2_pubnonces.num_items,
                'partials': item.musig2_partial_sigs.num_items,
                'tap_sig_len': tap_sig_len,
            })
    result = {
        'inputs': inputs,
        'scripts': sp_output_scripts(wally, psbt),
        'modifiable': psbt.contents.tx_modifiable_flags,
    }
    wally.wally_psbt_free(psbt)
    assert inputs, 'PSBT has no MuSig2 inputs'
    return result


def check_round1(before, after, expected):
    assert len(after['inputs']) == len(before['inputs'])
    for old, new in zip(before['inputs'], after['inputs']):
        assert new['index'] == old['index']
        assert new['shares'] > old['shares'], f'input {new["index"]}: no ECDH share added'
        assert new['proofs'] > old['proofs'], f'input {new["index"]}: no DLEQ proof added'
        assert new['pubnonces'] == old['pubnonces'] + 1, \
            f'input {new["index"]}: expected exactly one Jade pubnonce'
        assert new['partials'] == old['partials'], f'input {new["index"]}: signed during round 1'
        assert new['tap_sig_len'] == 0, f'input {new["index"]}: taproot signature present in round 1'
    if expected == 'incomplete':
        assert not any(after['scripts']), 'D2 failed: non-last Jade resolved an output'
        print('D2 PASS: shares/proofs/pubnonces added; no scripts or signatures')
    else:
        assert all(after['scripts']), 'D3 failed: last Jade did not resolve every output'
        assert after['modifiable'] == 0, 'D3 failed: resolved PSBT remains modifiable'
        print('D3 PASS: outputs resolved and fixed; still no signatures')


def check_round2(before, after):
    assert before['scripts'] == after['scripts'], 'D4 failed: output scripts changed in round 2'
    for old, new in zip(before['inputs'], after['inputs']):
        assert new['partials'] == old['partials'] + 1, \
            f'input {new["index"]}: expected exactly one Jade partial signature'
    print('D4 PASS: Jade verified the resolved outputs and added one partial signature per input')


def serialize_psbt(wally, psbt):
    ret, length = wally.wally_psbt_get_length(psbt, 0)
    assert ret == wally.WALLY_OK
    output = (wally.c_ubyte * length)()
    ret, written = wally.wally_psbt_to_bytes(psbt, 0, output, length)
    assert ret == wally.WALLY_OK and written == length
    return bytes(output)


def synthetic_path(wally, psbt_input, aggregate):
    synthetic = wally.POINTER(wally.ext_key)()
    assert wally.wally_musig_pubkey_to_xpub(
        aggregate, len(aggregate), 0x0488B21E, wally.byref(synthetic)) == wally.WALLY_OK
    fingerprint = (wally.c_ubyte * 4)()
    assert wally.bip32_key_get_fingerprint(synthetic, fingerprint, 4) == wally.WALLY_OK
    wally.bip32_key_free(synthetic)

    found = []
    keypaths = wally.byref(psbt_input.taproot_leaf_paths)
    for item_index in range(psbt_input.taproot_leaf_paths.num_items):
        item_fingerprint = (wally.c_ubyte * 4)()
        if wally.wally_map_keypath_get_item_fingerprint(
                keypaths, item_index, item_fingerprint, 4) != wally.WALLY_OK:
            continue
        if bytes(item_fingerprint) != bytes(fingerprint):
            continue
        path = (wally.c_uint32 * 16)()
        ret, written = wally.wally_map_keypath_get_item_path(
            keypaths, item_index, path, len(path))
        if ret == wally.WALLY_OK:
            found.append(list(path[:written]))
    assert len(found) == 1 and len(found[0]) == 2, 'could not identify one synthetic /branch/index path'
    return found[0]


def finalize(args, wally):
    psbt = parse_psbt(wally, read_psbt(args.input))
    for index in range(psbt.contents.num_inputs):
        psbt_input = psbt.contents.inputs[index]
        if not psbt_input.musig2_pubkeys.num_items:
            continue
        assert psbt_input.musig2_pubkeys.num_items == 1
        item = psbt_input.musig2_pubkeys.items[0]
        aggregate = wally.string_at(item.key, item.key_len)
        path_values = synthetic_path(wally, psbt_input, aggregate)
        path = (wally.c_uint32 * len(path_values))(*path_values)
        assert wally.wally_psbt_musig2_agg_then_derive_finalize_input(
            psbt, index, aggregate, len(aggregate), path, len(path_values), 0) == wally.WALLY_OK, \
            f'failed to aggregate input {index}; are all partial signatures present?'

    assert wally.wally_psbt_finalize(psbt, 0) == wally.WALLY_OK
    write_bytes(args.psbt_output, serialize_psbt(wally, psbt))
    tx = wally.POINTER(wally.wally_tx)()
    assert wally.wally_psbt_extract(psbt, 0, wally.byref(tx)) == wally.WALLY_OK
    ret, length = wally.wally_tx_get_length(tx, 1)
    assert ret == wally.WALLY_OK
    raw = (wally.c_ubyte * length)()
    ret, written = wally.wally_tx_to_bytes(tx, 1, raw, length)
    assert ret == wally.WALLY_OK and written == length
    write_bytes(args.tx_output, bytes(raw))
    print(f'Raw transaction hex:\n{bytes(raw).hex()}')
    wally.wally_tx_free(tx)
    wally.wally_psbt_free(psbt)


def sign(args, jade, wally):
    initial = read_psbt(args.input)
    before = snapshot(wally, initial)
    round1 = bytes(jade.sign_psbt(args.network, initial))
    after_round1 = snapshot(wally, round1)
    check_round1(before, after_round1, args.expect_round1)
    write_bytes(args.round1_output, round1)

    if not args.round2_input:
        print('Stopped after round 1. Keep this process/device session alive to perform round 2.')
        return

    print('\nKeep Jade connected. Complete the remaining round-1 and Coldcard round-2 steps.')
    print(f'Save Coldcard\'s round-2 PSBT as: {args.round2_input}')
    input('Press Enter only after that file is ready... ')
    round2_input = read_psbt(args.round2_input)
    before_round2 = snapshot(wally, round2_input)
    assert all(before_round2['scripts']), 'round-2 input does not have every SP output script'
    round2 = bytes(jade.sign_psbt(args.network, round2_input))
    after_round2 = snapshot(wally, round2)
    check_round2(before_round2, after_round2)
    write_bytes(args.output, round2)
    print('Combine/finalize the partial signatures in the coordinator, then broadcast on signet for D9.')


def add_device_args(parser):
    parser.add_argument('--device', default=DEFAULT_DEVICE,
                        help='serial device or emulator TCP address')
    parser.add_argument('--network', default='testnet', choices=NETWORKS,
                        help='use testnet for signet')
    parser.add_argument('--timeout', type=int, default=900)
    parser.add_argument('--mnemonic', help='load a temporary mnemonic (debug/emulator only)')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)

    setup_parser = commands.add_parser('setup', help='construct and register the shared descriptor')
    add_device_args(setup_parser)
    setup_parser.add_argument('--name', default='coldjade')
    setup_parser.add_argument('--origin', default=DEFAULT_ORIGIN,
                              help='Jade account origin path')
    setup_parser.add_argument('--cosigner', action='append', required=True,
                              help='full [fingerprint/origin]tpub Coldcard key expression; repeatable')
    setup_parser.add_argument('--branch', type=int, default=0)
    setup_parser.add_argument('--index', type=int, default=0)

    sign_parser = commands.add_parser('sign', help='run Jade round 1 and round 2 in one connection')
    add_device_args(sign_parser)
    sign_parser.add_argument('input', help='clean or Coldcard-round-1 PSBT')
    sign_parser.add_argument('--expect-round1', choices=('incomplete', 'complete'), required=True)
    sign_parser.add_argument('--round1-output', default='jade-round1.psbt')
    sign_parser.add_argument('--round2-input',
                             help='path where you will save Coldcard round-2 output')
    sign_parser.add_argument('--output', default='jade-round2.psbt')

    finalize_parser = commands.add_parser(
        'finalize', help='aggregate partial signatures and emit a broadcastable transaction')
    finalize_parser.add_argument('input', help='PSBT containing every partial signature')
    finalize_parser.add_argument('--psbt-output', default='finalized.psbt')
    finalize_parser.add_argument('--tx-output', default='signet.tx')

    args = parser.parse_args()
    wally = load_wally()
    if not wally:
        parser.error('build vendored libwally first: cd components/libwally-core/upstream && make')

    if args.command == 'finalize':
        finalize(args, wally)
        return

    from jadepy.jade import JadeAPI
    with JadeAPI.create_serial(device=args.device, timeout=args.timeout) as jade:
        if args.command == 'setup':
            mnemonic = args.mnemonic
            if not mnemonic and args.device.startswith('tcp:'):
                mnemonic = TEST_MNEMONIC
                print('Loading the standard temporary test wallet into the emulator.')
            if mnemonic:
                assert jade.set_mnemonic(
                    mnemonic, temporary_wallet=True)
            setup(args, jade, wally)
        else:
            sign(args, jade, wally)


if __name__ == '__main__':
    main()
