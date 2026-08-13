#!/usr/bin/env python3
"""
Silent payment round trip against a Jade (BIP-352/BIP-375/BIP-392)

Closes the loop between the two silent payment features:
  1. Ask Jade for its BIP-392 silent payment descriptor
  2. Build a PSBT paying the address that descriptor describes
  3. Have Jade resolve and sign it
  4. Verify the signatures and the BIP-375 share it wrote
  5. Scan the extracted transaction as the recipient and find the payment

Nothing here reimplements BIP-352: the recipient side is the secp256k1
silentpayments scanner and the BIP-392 codecs in libwally, driven through the
helpers in the vendored tree's contrib/sp_psbt_roundtrip.py. What the round
trip checks is that Jade's descriptor, its derived output and its BIP-375
share all agree with each other and with a scanner that never saw the PSBT.

With --collaborative it instead runs the BIP-375 two signer flow, where Jade
holds only one of the two eligible inputs: it must contribute its share
without signing, and sign only once the other signer's share completes the
coverage and the outputs are resolved. That needs 'Collaborative' On under
Settings > Wallet > Silent Payments.

Run against the emulator with:
  python test_sp_roundtrip.py --serialport tcp:127.0.0.1:30121
  python test_sp_roundtrip.py --serialport tcp:127.0.0.1:30121 --collaborative

The vendored libwally must be built for the host, ie. run ./configure and
make in components/libwally-core/upstream. Set JADE_WALLY_DIR to use another
build.

TODO: the round trip stops at receiving. Spending the payment back needs the
tweaked spend key b_spend + t_k, which arrives with BIP-376 support.
"""
import argparse
import os
import sys

WALLY_DIR = os.environ.get('JADE_WALLY_DIR',
                           os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                        'components', 'libwally-core', 'upstream'))

HARDENED = 0x80000000
BIP84_PURPOSE = 84 | HARDENED
BIP32_FLAG_KEY_PUBLIC = 0x1
WALLY_PSBT_EXTRACT_NON_FINAL = 0x1
EC_FLAG_ECDSA = 0x1
DLEQ_PROOF_LEN = 64
# TEST_MNEMONIC_SINGLE_SIG from test_jade.py
TEST_MNEMONIC = ('paddle puppy easily actor poet apart screen '
                 'drastic city front predict damp')
INPUT_AMOUNT, SP_AMOUNT, CHANGE_AMOUNT = 100000, 120000, 75000
FUNDING_TXID = bytes([0x5b] * 32)

# Networks Jade knows, and their bip32 coin type
COIN_TYPES = {'mainnet': 0 | HARDENED, 'testnet': 1 | HARDENED,
              'testnet4': 1 | HARDENED, 'localtest': 1 | HARDENED}


def load_wally():
    """Import the vendored libwally ctypes bindings, or None if unavailable.

    util.py finds the library relative to the current directory, so the import
    has to happen from the libwally tree.
    """
    if 'sp_psbt_roundtrip' in sys.modules:
        return sys.modules['sp_psbt_roundtrip']

    library = [os.path.join(WALLY_DIR, 'src', '.libs', 'libwallycore.' + extension)
               for extension in ('so', 'dylib', 'dll')]
    if not any(os.path.isfile(path) for path in library):
        return None

    cwd = os.getcwd()
    sys.path.insert(0, os.path.join(WALLY_DIR, 'contrib'))
    try:
        os.chdir(WALLY_DIR)
        import sp_psbt_roundtrip as sp
        return sp
    except ImportError:
        return None
    finally:
        os.chdir(cwd)
        sys.path.pop(0)


def parse_descriptor(descriptor):
    """Take the spscan key expression out of an sp([origin]spscan1...)#csum."""
    assert descriptor.startswith('sp(') and '#' in descriptor, descriptor
    key = descriptor[len('sp('):descriptor.index('#') - 1]
    return key[key.index(']') + 1:] if ']' in key else key


def get_recipient(jade, sp, network, account):
    """Fetch Jade's silent payment descriptor as a recipient to pay."""
    descriptor = jade.get_silent_payment_descriptor(network, account)
    scan_privkey, spend_pubkey = sp.decode_sp_scan_key(parse_descriptor(descriptor))
    scan_pubkey = sp.pubkey_from_privkey(scan_privkey)
    hrp = 'sp' if network == 'mainnet' else 'tsp'
    return {'descriptor': descriptor,
            'scan_privkey': scan_privkey,
            'scan_pubkey': scan_pubkey,
            'spend_pubkey': spend_pubkey,
            'info': scan_pubkey + spend_pubkey,
            'address': sp.sp_address(scan_pubkey + spend_pubkey, hrp)}


def get_wallet_keys(jade, sp, network, num_inputs):
    """Derive the p2wpkh keys Jade will recognise as its own.

    Everything comes from Jade itself: the master fingerprint from the master
    xpub, the receive keys from the account xpub. The seed is never needed.
    """
    master = sp.ext_key()
    assert sp.bip32_key_from_base58(jade.get_xpub(network, []).encode(),
                                    sp.byref(master)) == sp.WALLY_OK
    fingerprint = bytes(master.hash160)[:4]

    path = [BIP84_PURPOSE, COIN_TYPES[network], 0 | HARDENED]
    account = sp.ext_key()
    assert sp.bip32_key_from_base58(jade.get_xpub(network, path).encode(),
                                    sp.byref(account)) == sp.WALLY_OK

    keys = []
    for branch, index in [(0, i) for i in range(num_inputs)] + [(1, 0)]:
        child = sp.ext_key()
        derivation = (sp.c_uint32 * 2)(branch, index)
        assert sp.bip32_key_from_parent_path(sp.byref(account), derivation, 2,
                                             BIP32_FLAG_KEY_PUBLIC,
                                             sp.byref(child)) == sp.WALLY_OK
        pubkey = bytes(child.pub_key)
        keys.append({'pubkey': pubkey,
                     'script': sp.p2wpkh_script(pubkey),
                     'fingerprint': fingerprint,
                     'path': path + [branch, index]})
    return keys[:-1], keys[-1]


def build_psbt(sp, inputs, change, recipient_info):
    """Build a PSBTv2 spending `inputs` to a silent payment, plus change.

    The silent payment output carries PSBT_OUT_SP_V0_INFO and no script: only
    the signer, which holds the input keys, can say where it goes.
    """
    psbt = sp.pointer(sp.wally_psbt())
    assert sp.wally_psbt_init_alloc(sp.WALLY_PSBT_VERSION_2, len(inputs), 2, 0, 0,
                                    psbt) == sp.WALLY_OK

    for index, key in enumerate(inputs):
        tx_input = sp.pointer(sp.wally_tx_input())
        assert sp.wally_tx_input_init_alloc(FUNDING_TXID, len(FUNDING_TXID), index,
                                            0xffffffff, None, 0, None,
                                            tx_input) == sp.WALLY_OK
        assert sp.wally_psbt_add_tx_input_at(psbt, index, 0, tx_input) == sp.WALLY_OK

        utxo = sp.pointer(sp.wally_tx_output())
        assert sp.wally_tx_output_init_alloc(INPUT_AMOUNT, key['script'], len(key['script']),
                                             utxo) == sp.WALLY_OK
        assert sp.wally_psbt_set_input_witness_utxo(psbt, index, utxo) == sp.WALLY_OK
        assert sp.wally_psbt_set_input_amount(psbt, index, INPUT_AMOUNT) == sp.WALLY_OK
        assert sp.wally_psbt_set_input_sighash(psbt, index, sp.WALLY_SIGHASH_ALL) == sp.WALLY_OK
        add_keypath(sp, psbt, index, key, sp.wally_psbt_add_input_keypath)

    outputs = [(SP_AMOUNT, None), (CHANGE_AMOUNT, change['script'])]
    for index, (amount, script) in enumerate(outputs):
        tx_output = sp.pointer(sp.wally_tx_output())
        assert sp.wally_tx_output_init_alloc(amount, script, len(script) if script else 0,
                                             tx_output) == sp.WALLY_OK
        assert sp.wally_psbt_add_tx_output_at(psbt, index, 0, tx_output) == sp.WALLY_OK
        assert sp.wally_psbt_set_output_amount(psbt, index, amount) == sp.WALLY_OK
    assert sp.wally_psbt_set_output_sp_v0_info(psbt, 0, recipient_info,
                                               len(recipient_info)) == sp.WALLY_OK
    add_keypath(sp, psbt, 1, change, sp.wally_psbt_add_output_keypath)

    buf, buf_len = sp.make_cbuffer('00' * 4096)
    ret, written = sp.wally_psbt_to_bytes(psbt, 0, buf, buf_len)
    assert ret == sp.WALLY_OK
    sp.wally_psbt_free(psbt)
    return bytes(buf[:written])


def add_keypath(sp, psbt, index, key, add_fn):
    """Record the origin of a key, which is how Jade recognises it as its own."""
    path = (sp.c_uint32 * len(key['path']))(*key['path'])
    assert add_fn(psbt, index, key['pubkey'], len(key['pubkey']), key['fingerprint'],
                  len(key['fingerprint']), path, len(key['path'])) == sp.WALLY_OK


def find_global(sp, psbt, field, find_fn, scan_pubkey):
    """Read a BIP-375 global keyed by the recipient's scan pubkey."""
    ret, found = find_fn(psbt, scan_pubkey, len(scan_pubkey))
    if ret != sp.WALLY_OK or not found:
        return None
    item = getattr(psbt.contents, field).items[found - 1]  # 1 based
    return sp.string_at(item.value, item.value_len)


def verify_signed(sp, signed, recipient):
    """Check what Jade wrote, then finalize and verify the signatures."""
    psbt = sp.POINTER(sp.wally_psbt)()
    assert sp.wally_psbt_from_bytes(signed, len(signed), 0, sp.byref(psbt)) == sp.WALLY_OK

    share = find_global(sp, psbt, 'global_sp_ecdh_shares',
                        sp.wally_psbt_find_global_sp_ecdh_share, recipient['scan_pubkey'])
    proof = find_global(sp, psbt, 'global_sp_dleq_proofs',
                        sp.wally_psbt_find_global_sp_dleq_proof, recipient['scan_pubkey'])
    assert share and len(share) == sp.EC_PUBLIC_KEY_LEN, 'no BIP-375 ECDH share'
    assert proof and len(proof) == DLEQ_PROOF_LEN, 'no BIP-375 DLEQ proof'

    # Verify each signature before finalizing, while the sighash is reachable
    unsigned = sp.POINTER(sp.wally_tx)()
    assert sp.wally_psbt_extract(psbt, WALLY_PSBT_EXTRACT_NON_FINAL,
                                 sp.byref(unsigned)) == sp.WALLY_OK
    for index in range(psbt.contents.num_inputs):
        verify_input_signature(sp, psbt, unsigned, index)
    sp.wally_tx_free(unsigned)

    assert sp.wally_psbt_finalize(psbt, 0) == sp.WALLY_OK
    tx = sp.POINTER(sp.wally_tx)()
    assert sp.wally_psbt_extract(psbt, sp.WALLY_PSBT_EXTRACT_OPT_FINAL,
                                 sp.byref(tx)) == sp.WALLY_OK
    outpoint, outpoint_len = sp.make_cbuffer('00' * sp.WALLY_SP_OUTPOINT_LEN)
    assert sp.wally_psbt_get_sp_smallest_outpoint(psbt, outpoint, outpoint_len) == sp.WALLY_OK
    sp.wally_psbt_free(psbt)
    return tx, share, proof, bytes(outpoint)


def verify_input_signature(sp, psbt, tx, index):
    """Verify an input's signature against the sighash Jade should have signed."""
    signatures = psbt.contents.inputs[index].signatures
    assert signatures.num_items == 1, f'input {index} has {signatures.num_items} signatures'
    pubkey = sp.string_at(signatures.items[0].key, signatures.items[0].key_len)
    signature = sp.string_at(signatures.items[0].value, signatures.items[0].value_len)

    script, script_len = sp.make_cbuffer('00' * 256)
    ret, written = sp.wally_psbt_get_input_signing_script(psbt, index, script, script_len)
    assert ret == sp.WALLY_OK
    scriptcode, scriptcode_len = sp.make_cbuffer('00' * 256)
    ret, code_written = sp.wally_psbt_get_input_scriptcode(psbt, index, script, written,
                                                           scriptcode, scriptcode_len)
    assert ret == sp.WALLY_OK

    txhash, _ = sp.make_cbuffer('00' * 32)
    assert sp.wally_psbt_get_input_signature_hash(psbt, index, tx, scriptcode, code_written,
                                                  0, txhash, 32) == sp.WALLY_OK

    # PSBT signatures are DER with a trailing sighash byte
    compact, _ = sp.make_cbuffer('00' * 64)
    assert sp.wally_ec_sig_from_der(signature, len(signature) - 1, compact, 64) == sp.WALLY_OK
    assert sp.wally_ec_sig_verify(pubkey, len(pubkey), txhash, 32, EC_FLAG_ECDSA,
                                  compact, 64) == sp.WALLY_OK, f'input {index} signature invalid'


def scan_as_recipient(sp, tx, recipient, num_inputs, outpoint):
    """Scan the transaction for payments to us, as a watch only wallet would."""
    pubkeys = []
    for index in range(num_inputs):
        pubkey, pubkey_len = sp.make_cbuffer('00' * sp.EC_PUBLIC_KEY_LEN)
        ret, written = sp.wally_tx_get_input_witness(tx, index, 1, pubkey, pubkey_len)
        assert ret == sp.WALLY_OK and written == sp.EC_PUBLIC_KEY_LEN
        pubkeys.append(bytes(pubkey))

    scripts = [sp.string_at(tx.contents.outputs[index].script,
                            tx.contents.outputs[index].script_len)
               for index in range(tx.contents.num_outputs)]

    found = sp.scan_outputs(scripts, recipient['scan_privkey'], recipient['spend_pubkey'],
                            pubkeys, outpoint)
    return found, pubkeys, scripts


def run_roundtrip(jade, network='localtest', account=0, num_inputs=2, verbose=True):
    """Pay Jade's own silent payment address, have it sign, then find the payment."""
    sp = load_wally()
    assert sp, f'no libwally build found under {WALLY_DIR}'

    def log(message):
        if verbose:
            print(message)

    recipient = get_recipient(jade, sp, network, account)
    log(f'Descriptor: {recipient["descriptor"]}')
    log(f'Pay to:     {recipient["address"]}')

    inputs, change = get_wallet_keys(jade, sp, network, num_inputs)
    psbt = build_psbt(sp, inputs, change, recipient['info'])
    log(f'PSBT built with {num_inputs} inputs, a silent payment and change ({len(psbt)} bytes)')

    signed = bytes(jade.sign_psbt(network, psbt))
    tx, share, proof, outpoint = verify_signed(sp, signed, recipient)
    log(f'Jade signed {num_inputs} inputs, and wrote a {len(share)} byte ECDH share '
        f'and a {len(proof)} byte DLEQ proof')

    found, pubkeys, scripts = scan_as_recipient(sp, tx, recipient, num_inputs, outpoint)
    assert list(found) == [0], f'scan found {list(found)}, expected the payment at output 0'
    log(f'Recipient found the payment at output {list(found)[0]}: {scripts[0].hex()}')
    log(f'Spendable with tweak {found[0].hex()}')

    # The proof says the share was made with the keys of these inputs, which is
    # what lets a signer trust a share it did not create itself.
    summed = sp.pubkey_sum(pubkeys)
    assert sp.dleq_verify(proof, summed, recipient['scan_pubkey'], share), 'DLEQ proof invalid'
    log('DLEQ proof verified against the summed input keys')

    sp.wally_tx_free(tx)
    return {'psbt': psbt, 'signed': signed, 'recipient': recipient, 'script': scripts[0]}


FOREIGN_PRIVKEY = bytes([0x77] * 32)
FOREIGN_FINGERPRINT = bytes([0xde, 0xad, 0xbe, 0xef])


def get_foreign_key(sp):
    """A p2wpkh input belonging to another signer, not to Jade.

    The keypath makes it eligible - BIP-352 needs to see that the key is
    compressed - while the foreign fingerprint keeps Jade from claiming it.
    """
    pubkey = sp.pubkey_from_privkey(FOREIGN_PRIVKEY)
    return {'privkey': FOREIGN_PRIVKEY,
            'pubkey': pubkey,
            'script': sp.p2wpkh_script(pubkey),
            'fingerprint': FOREIGN_FINGERPRINT,
            'path': [BIP84_PURPOSE, COIN_TYPES['localtest'], 0 | HARDENED, 0, 0]}


def input_share(sp, psbt, index, scan_pubkey):
    """Read a BIP-375 per-input share, or None if the input carries none."""
    ret, found = sp.wally_psbt_find_input_sp_ecdh_share(psbt, index, scan_pubkey,
                                                        len(scan_pubkey))
    if ret != sp.WALLY_OK or not found:
        return None
    item = psbt.contents.inputs[index].sp_ecdh_shares.items[found - 1]  # 1 based
    return sp.string_at(item.value, item.value_len)


def run_collaborative_roundtrip(jade, network='localtest', account=0, verbose=True):
    """Two signers: Jade contributes shares for its input, then signs last.

    Jade holds one eligible input and another signer holds the other, so
    neither can derive the outputs alone. Jade must add its BIP-375 share
    without signing, and only sign once the other signer's share completes the
    coverage and the outputs are resolved.

    NOTE: requires 'Collaborative' to be On under Settings > Wallet > Silent
    Payments; Jade refuses the psbt outright otherwise.
    """
    sp = load_wally()
    assert sp, f'no libwally build found under {WALLY_DIR}'

    def log(message):
        if verbose:
            print(message)

    recipient = get_recipient(jade, sp, network, account)
    ours, change = get_wallet_keys(jade, sp, network, 1)
    foreign = get_foreign_key(sp)
    log(f'Pay to: {recipient["address"]}')

    # Input 0 is Jade's, input 1 is the other signer's
    psbt_bytes = build_psbt(sp, [ours[0], foreign], change, recipient['info'])
    log(f'PSBT built with 1 Jade input and 1 foreign input ({len(psbt_bytes)} bytes)')

    try:
        contributed = bytes(jade.sign_psbt(network, psbt_bytes))
    except Exception as e:
        if 'Collaborative silent payments are disabled' in str(e):
            print('Enable Settings > Wallet > Silent Payments > Collaborative first')
        raise

    # Jade must have added its share and nothing else: no signature, and no
    # output script, since the outputs cannot be derived until we add ours
    psbt = sp.POINTER(sp.wally_psbt)()
    assert sp.wally_psbt_from_bytes(contributed, len(contributed), 0,
                                    sp.byref(psbt)) == sp.WALLY_OK
    assert psbt.contents.inputs[0].signatures.num_items == 0, 'Jade signed too early'
    share = input_share(sp, psbt, 0, recipient['scan_pubkey'])
    assert share and len(share) == sp.EC_PUBLIC_KEY_LEN, 'Jade wrote no per-input share'
    assert not input_share(sp, psbt, 1, recipient['scan_pubkey']), 'share on a foreign input'
    assert sp.wally_psbt_get_output_script_len(psbt, 0) == (sp.WALLY_OK, 0), \
        'outputs resolved without full coverage'
    ret, status = sp.wally_psbt_get_sp_status(psbt, 0)
    assert (ret, status) == (sp.WALLY_OK, 1), f'status {status}, expected incomplete'
    log(f'Jade contributed a {len(share)} byte share for its input, and did not sign')

    # Jade cannot resolve this yet, and must say so rather than signing
    assert sp.wally_psbt_sp_resolve_shares(psbt, 0) != sp.WALLY_OK

    # The other signer adds its share, which completes the coverage, and
    # resolves the outputs - work that needs no private key at all
    indices = (sp.c_size_t * 1)(1)
    entropy, entropy_len = sp.make_cbuffer('a5' * 32)
    assert sp.wally_psbt_sp_contribute(psbt, indices, 1, foreign['privkey'],
                                       len(foreign['privkey']), entropy, entropy_len,
                                       0) == sp.WALLY_OK
    assert sp.wally_psbt_sp_resolve_shares(psbt, 0) == sp.WALLY_OK
    ret, status = sp.wally_psbt_get_sp_status(psbt, 0)
    assert (ret, status) == (sp.WALLY_OK, 2), f'status {status}, expected complete'
    log('Other signer contributed its share and resolved the outputs')

    buf, buf_len = sp.make_cbuffer('00' * 4096)
    ret, written = sp.wally_psbt_to_bytes(psbt, 0, buf, buf_len)
    assert ret == sp.WALLY_OK
    sp.wally_psbt_free(psbt)

    # Jade is now the final signer: it verifies the resolved outputs against
    # the shares, shows the amounts, and signs the one input it owns
    signed = bytes(jade.sign_psbt(network, bytes(buf[:written])))
    psbt = sp.POINTER(sp.wally_psbt)()
    assert sp.wally_psbt_from_bytes(signed, len(signed), 0, sp.byref(psbt)) == sp.WALLY_OK
    assert psbt.contents.inputs[0].signatures.num_items == 1, 'Jade did not sign its input'
    assert psbt.contents.inputs[1].signatures.num_items == 0, 'Jade signed a foreign input'

    unsigned = sp.POINTER(sp.wally_tx)()
    assert sp.wally_psbt_extract(psbt, WALLY_PSBT_EXTRACT_NON_FINAL,
                                 sp.byref(unsigned)) == sp.WALLY_OK
    verify_input_signature(sp, psbt, unsigned, 0)
    sp.wally_tx_free(unsigned)
    script, script_len = sp.make_cbuffer('00' * 34)
    ret, _ = sp.wally_psbt_get_output_script(psbt, 0, script, script_len)
    assert ret == sp.WALLY_OK
    sp.wally_psbt_free(psbt)
    log(f'Jade signed its input against the resolved payment: {bytes(script).hex()}')
    return {'signed': signed, 'recipient': recipient, 'script': bytes(script)}


def main():
    parser = argparse.ArgumentParser(description='Silent payment round trip against a Jade')
    parser.add_argument('--serialport', default='tcp:127.0.0.1:30121',
                        help='Serial port or emulator address')
    parser.add_argument('--network', default='localtest', choices=sorted(COIN_TYPES))
    parser.add_argument('--timeout', type=int, default=900,
                        help='Serial timeout; the emulator is slow to derive a seed')
    parser.add_argument('--account', type=int, default=0)
    parser.add_argument('--mnemonic', default=TEST_MNEMONIC,
                        help='Temporary wallet to load (debug builds only)')
    parser.add_argument('--collaborative', action='store_true',
                        help='Run the two signer round trip instead; needs '
                             'Settings > Wallet > Silent Payments > Collaborative On')
    args = parser.parse_args()

    if not load_wally():
        parser.error(f'no libwally build found under {WALLY_DIR}; run ./configure && make there')

    from jadepy.jade import JadeAPI
    with JadeAPI.create_serial(device=args.serialport, timeout=args.timeout) as jade:
        jade.set_mnemonic(args.mnemonic, temporary_wallet=True)
        if args.collaborative:
            run_collaborative_roundtrip(jade, args.network, args.account)
        else:
            run_roundtrip(jade, args.network, args.account)
    print('Silent payment round trip complete')


if __name__ == '__main__':
    main()
