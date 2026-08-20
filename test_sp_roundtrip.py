#!/usr/bin/env python3
"""
Silent payment round trip against a Jade (BIP-352/BIP-375/BIP-392)

Closes the loop between the two silent payment features:
  1. Ask Jade for its BIP-392 silent payment descriptor
  2. Build a PSBT paying the address that descriptor describes
  3. Have Jade resolve and sign it
  4. Verify the signatures and the BIP-375 share it wrote
  5. Scan the extracted transaction as the recipient and find the payment
  6. Spend the payment back out, with the tweak the scan found (BIP-376)

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
"""
import argparse
import os
import sys

WALLY_DIR = os.environ.get('JADE_WALLY_DIR',
                           os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                        'components', 'libwally-core', 'upstream'))

HARDENED = 0x80000000
BIP84_PURPOSE = 84 | HARDENED
BIP352_PURPOSE = 352 | HARDENED
SP_SPEND_BRANCH = 0
BIP32_FLAG_KEY_PUBLIC = 0x1
WALLY_PSBT_EXTRACT_NON_FINAL = 0x1
EC_FLAG_ECDSA = 0x1
EC_FLAG_SCHNORR = 0x2
DLEQ_PROOF_LEN = 64
# TEST_MNEMONIC_SINGLE_SIG from test_jade.py
TEST_MNEMONIC = ('paddle puppy easily actor poet apart screen '
                 'drastic city front predict damp')
INPUT_AMOUNT, SP_AMOUNT, CHANGE_AMOUNT = 100000, 120000, 75000
SPEND_AMOUNT = 110000  # Spending the payment back out again
# Errors Jade reports for a silent payment input it will not sign, from
# main/silentpayments.c and the signing loop in main/process/sign_psbt.c
SP_NO_DERIVATION_ERROR = 'Silent payment input missing spend key derivation'
FUNDING_TXID = bytes([0x5b] * 32)

# Networks Jade knows, and their bip32 coin type
COIN_TYPES = {'mainnet': 0 | HARDENED, 'testnet': 1 | HARDENED,
              'testnet4': 1 | HARDENED, 'localtest': 1 | HARDENED}

# Wally network ids, matching the network_t values in main/utils/network.h.
# Jade parses descriptors against these, so key expressions we send it have to
# use the matching bip32 version bytes.
WALLY_NETWORKS = {'mainnet': 0x01, 'testnet': 0x02,
                  'testnet4': 0x02, 'localtest': 0xff}


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


def get_recipient(jade, sp, network, account, fingerprint):
    """Fetch Jade's silent payment descriptor as a recipient to pay."""
    descriptor = jade.get_silent_payment_descriptor(network, account)
    scan_privkey, spend_pubkey = sp.decode_sp_scan_key(parse_descriptor(descriptor))
    scan_pubkey = sp.pubkey_from_privkey(scan_privkey)
    hrp = 'sp' if network == 'mainnet' else 'tsp'
    # BIP-376 names the spend key by its origin, which is where the descriptor
    # says the account is, plus the BIP-352 spend branch
    spend_path = [BIP352_PURPOSE, COIN_TYPES[network], account | HARDENED,
                  SP_SPEND_BRANCH | HARDENED, 0]
    return {'descriptor': descriptor,
            'scan_privkey': scan_privkey,
            'scan_pubkey': scan_pubkey,
            'spend_pubkey': spend_pubkey,
            'spend_key': {'pubkey': spend_pubkey, 'fingerprint': fingerprint,
                          'path': spend_path},
            'info': scan_pubkey + spend_pubkey,
            'address': sp.sp_address(scan_pubkey + spend_pubkey, hrp)}


def get_fingerprint(jade, sp, network):
    """Jade's master key fingerprint, which every key origin starts with."""
    master = sp.ext_key()
    assert sp.bip32_key_from_base58(jade.get_xpub(network, []).encode(),
                                    sp.byref(master)) == sp.WALLY_OK
    return bytes(master.hash160)[:4]


def get_wallet_keys(jade, sp, network, num_inputs, fingerprint):
    """Derive the p2wpkh keys Jade will recognise as its own.

    Everything comes from Jade itself: the master fingerprint from the master
    xpub, the receive keys from the account xpub. The seed is never needed.
    """
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


def build_spend_psbt(sp, recipient, script, txid, tweak, change, spend_keypath=True):
    """Build a PSBTv2 spending a received silent payment (BIP-376).

    The input is a p2tr output with no keypath Jade could recognise: what
    identifies it is the tweak, and the spend key that the tweak applies to.
    """
    psbt = sp.pointer(sp.wally_psbt())
    assert sp.wally_psbt_init_alloc(sp.WALLY_PSBT_VERSION_2, 1, 1, 0, 0, psbt) == sp.WALLY_OK

    tx_input = sp.pointer(sp.wally_tx_input())
    assert sp.wally_tx_input_init_alloc(txid, len(txid), 0, 0xffffffff, None, 0, None,
                                        tx_input) == sp.WALLY_OK
    assert sp.wally_psbt_add_tx_input_at(psbt, 0, 0, tx_input) == sp.WALLY_OK
    utxo = sp.pointer(sp.wally_tx_output())
    assert sp.wally_tx_output_init_alloc(SP_AMOUNT, script, len(script), utxo) == sp.WALLY_OK
    assert sp.wally_psbt_set_input_witness_utxo(psbt, 0, utxo) == sp.WALLY_OK
    assert sp.wally_psbt_set_input_amount(psbt, 0, SP_AMOUNT) == sp.WALLY_OK
    assert sp.wally_psbt_set_input_sp_tweak(psbt, 0, tweak, len(tweak)) == sp.WALLY_OK
    if spend_keypath:
        add_keypath(sp, psbt, 0, recipient['spend_key'],
                    sp.wally_psbt_add_input_sp_spend_keypath)

    tx_output = sp.pointer(sp.wally_tx_output())
    assert sp.wally_tx_output_init_alloc(SPEND_AMOUNT, change['script'], len(change['script']),
                                         tx_output) == sp.WALLY_OK
    assert sp.wally_psbt_add_tx_output_at(psbt, 0, 0, tx_output) == sp.WALLY_OK
    assert sp.wally_psbt_set_output_amount(psbt, 0, SPEND_AMOUNT) == sp.WALLY_OK
    add_keypath(sp, psbt, 0, change, sp.wally_psbt_add_output_keypath)

    buf, buf_len = sp.make_cbuffer('00' * 4096)
    ret, written = sp.wally_psbt_to_bytes(psbt, 0, buf, buf_len)
    assert ret == sp.WALLY_OK
    sp.wally_psbt_free(psbt)
    return bytes(buf[:written])


def verify_spend(sp, signed, output_key):
    """Check that Jade signed the silent payment input as BIP-376 requires."""
    psbt = sp.POINTER(sp.wally_psbt)()
    assert sp.wally_psbt_from_bytes(signed, len(signed), 0, sp.byref(psbt)) == sp.WALLY_OK

    # The signature goes in PSBT_IN_TAP_KEY_SIG, and verifies against the
    # output key directly: BIP-376 applies no further taproot tweak
    sig, sig_len = sp.make_cbuffer('00' * 64)
    ret, written = sp.wally_psbt_get_input_taproot_signature(psbt, 0, sig, sig_len)
    assert (ret, written) == (sp.WALLY_OK, 64), 'silent payment input was not signed'

    unsigned = sp.POINTER(sp.wally_tx)()
    assert sp.wally_psbt_extract(psbt, WALLY_PSBT_EXTRACT_NON_FINAL,
                                 sp.byref(unsigned)) == sp.WALLY_OK
    txhash, _ = sp.make_cbuffer('00' * 32)
    assert sp.wally_psbt_get_input_signature_hash(psbt, 0, unsigned, None, 0, 0,
                                                  txhash, 32) == sp.WALLY_OK
    assert sp.wally_ec_sig_verify(output_key, len(output_key), txhash, 32, EC_FLAG_SCHNORR,
                                  sig, sig_len) == sp.WALLY_OK, 'signature invalid'
    sp.wally_tx_free(unsigned)

    assert sp.wally_psbt_finalize(psbt, 0) == sp.WALLY_OK
    tx = sp.POINTER(sp.wally_tx)()
    assert sp.wally_psbt_extract(psbt, sp.WALLY_PSBT_EXTRACT_OPT_FINAL,
                                 sp.byref(tx)) == sp.WALLY_OK
    sp.wally_tx_free(tx)
    sp.wally_psbt_free(psbt)


def assert_rejected(jade, network, psbt, expected):
    """A PSBT Jade must refuse to sign, for the reason we expect."""
    from jadepy.jade_error import JadeError
    try:
        jade.sign_psbt(network, psbt)
    except JadeError as e:
        assert e.message == expected, f'rejected with "{e.message}", expected "{expected}"'
        return e.message
    assert False, f'Jade signed a psbt it should have rejected: {expected}'


def spend_the_payment(jade, sp, network, recipient, tx, script, tweak, change, log):
    """Spend the silent payment Jade just received, per BIP-376."""
    txid, txid_len = sp.make_cbuffer('00' * 32)
    assert sp.wally_tx_get_txid(tx, txid, txid_len) == sp.WALLY_OK
    txid = bytes(txid)

    # A tweak that does not give the key being spent must not be signed with:
    # it would be a valid signature for a key Jade does not control
    bad = bytes([tweak[0] ^ 1]) + tweak[1:]
    psbt = build_spend_psbt(sp, recipient, script, txid, bad, change)
    log(f'Rejected: {assert_rejected(jade, network, psbt, "Failed to generate signature")}')

    # Without the derivation there is no way to know which key to tweak
    psbt = build_spend_psbt(sp, recipient, script, txid, tweak, change,
                            spend_keypath=False)
    log(f'Rejected: {assert_rejected(jade, network, psbt, SP_NO_DERIVATION_ERROR)}')

    psbt = build_spend_psbt(sp, recipient, script, txid, tweak, change)
    signed = bytes(jade.sign_psbt(network, psbt))
    verify_spend(sp, signed, script[2:])
    log('Jade spent the payment with the scanned tweak')


def run_roundtrip(jade, network='localtest', account=0, num_inputs=2, verbose=True):
    """Pay Jade's own silent payment address, have it sign, then find the payment."""
    sp = load_wally()
    assert sp, f'no libwally build found under {WALLY_DIR}'

    def log(message):
        if verbose:
            print(message)

    fingerprint = get_fingerprint(jade, sp, network)
    recipient = get_recipient(jade, sp, network, account, fingerprint)
    log(f'Descriptor: {recipient["descriptor"]}')
    log(f'Pay to:     {recipient["address"]}')

    inputs, change = get_wallet_keys(jade, sp, network, num_inputs, fingerprint)
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

    # Close the loop: spend the payment back out again (BIP-376)
    spend_the_payment(jade, sp, network, recipient, tx, scripts[0], found[0], change, log)

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

    fingerprint = get_fingerprint(jade, sp, network)
    recipient = get_recipient(jade, sp, network, account, fingerprint)
    ours, change = get_wallet_keys(jade, sp, network, 1, fingerprint)
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

    # Resolving commits to the inputs and outputs, so the transaction can no
    # longer be modifiable - libwally refuses to serialise it until we say so
    assert sp.wally_psbt_set_tx_modifiable_flags(psbt, 0) == sp.WALLY_OK

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



# --- MuSig2 silent payments -------------------------------------------------
# Jade signs a form-(b) MuSig2 input across two rounds, holding its secnonce in
# RAM between them. The other participant is played here, so the whole protocol
# runs without a second device.

MUSIG_ORIGIN = [48 | HARDENED, 1 | HARDENED, 0 | HARDENED, 3 | HARDENED]
MUSIG_BRANCH, MUSIG_INDEX = 0, 0
MUSIG_DESCRIPTOR_NAME = 'spmusig'
COSIGNER_SEED = '22' * 64
BIP32_VER_MAIN_PUBLIC = 0x0488B21E
BIP32_VER_MAIN_PRIVATE = 0x0488ADE4
BIP32_VER_TEST_PUBLIC = 0x043587CF
BIP32_VER_TEST_PRIVATE = 0x04358394
BIP32_FLAG_KEY_PRIVATE = 0x0
SHA256_LEN = 32
MUSIG_AMOUNT, MUSIG_SP_AMOUNT = 100000, 90000
# Errors Jade reports between the two rounds, from main/silentpayments.c
MUSIG_EXPIRED_ERROR = 'Signing session expired'
MUSIG_CHANGED_ERROR = 'Transaction changed between rounds'
MUSIG_UNRESOLVED_ERROR = 'Silent payment outputs do not match the shares'
WALLY_SP_INCOMPLETE, WALLY_SP_COMPLETE = 1, 2


def derive_key(sp, key, path, flags):
    """Derive a child of an ext_key down a full path."""
    values = (sp.c_uint32 * len(path))(*path)
    child = sp.POINTER(sp.ext_key)()
    assert sp.bip32_key_from_parent_path_alloc(key, values, len(path), flags,
                                               sp.byref(child)) == sp.WALLY_OK
    return child


def key_fingerprint(sp, key):
    result = (sp.c_ubyte * 4)()
    assert sp.bip32_key_get_fingerprint(key, result, 4) == sp.WALLY_OK
    return bytes(result)


def bip32_versions(network):
    """The private and public version bytes Jade's xpubs use on `network`."""
    if network == 'mainnet':
        return BIP32_VER_MAIN_PRIVATE, BIP32_VER_MAIN_PUBLIC
    return BIP32_VER_TEST_PRIVATE, BIP32_VER_TEST_PUBLIC


def cosigner_account(sp, network):
    """The other participant, whose keys this test holds."""
    seed, seed_len = sp.make_cbuffer(COSIGNER_SEED)
    master = sp.POINTER(sp.ext_key)()
    version, _ = bip32_versions(network)
    assert sp.bip32_key_from_seed_alloc(seed, seed_len, version, 0,
                                        sp.byref(master)) == sp.WALLY_OK
    return master, derive_key(sp, master, MUSIG_ORIGIN, BIP32_FLAG_KEY_PRIVATE)


def key_expression(sp, xpub, fingerprint):
    origin = '/'.join(f'{value & ~HARDENED}h' for value in MUSIG_ORIGIN)
    return f'[{fingerprint.hex()}/{origin}]{xpub}'


def musig_descriptor(sp, network, expressions):
    """tr(musig(...)/<0;1>/*), the aggregate-then-derive form Jade registers.

    Parsed against the network Jade will use, so a key expression from the
    wrong network fails here rather than as a parse error on the device.
    """
    descriptor = f'tr(musig({",".join(sorted(expressions))})/<0;1>/*)'
    parsed = sp.c_void_p()
    assert sp.wally_descriptor_parse(descriptor.encode(), None,
                                     WALLY_NETWORKS[network], 0,
                                     sp.byref(parsed)) == sp.WALLY_OK
    ret, checksum = sp.wally_descriptor_get_checksum(parsed, 0)
    sp.wally_descriptor_free(parsed)
    assert ret == sp.WALLY_OK
    if isinstance(checksum, bytes):
        checksum = checksum.decode()
    return f'{descriptor}#{checksum}'


def musig_setup(jade, sp, network):
    """Register a two-of-two MuSig2 descriptor with Jade and derive its script.

    Returns everything both signers need: the sorted participant pubkeys, the
    aggregate, the synthetic derivation Jade checks the input against, and the
    scriptPubKey the descriptor produces at MUSIG_BRANCH/MUSIG_INDEX.
    """
    jade_fingerprint = get_fingerprint(jade, sp, network)
    jade_xpub = jade.get_xpub(network, MUSIG_ORIGIN)
    jade_account = sp.ext_key()
    assert sp.bip32_key_from_base58(jade_xpub.encode(),
                                    sp.byref(jade_account)) == sp.WALLY_OK
    jade_pubkey = bytes(jade_account.pub_key)

    cosigner_master, cosigner = cosigner_account(sp, network)
    cosigner_fingerprint = key_fingerprint(sp, cosigner_master)
    cosigner_pubkey = bytes(cosigner.contents.pub_key)
    ret, cosigner_xpub = sp.bip32_key_to_base58(cosigner, BIP32_FLAG_KEY_PUBLIC)
    assert ret == sp.WALLY_OK

    descriptor = musig_descriptor(sp, network, [
        key_expression(sp, jade_xpub, jade_fingerprint),
        key_expression(sp, cosigner_xpub, cosigner_fingerprint)])
    assert jade.register_descriptor(network, MUSIG_DESCRIPTOR_NAME, descriptor, {})

    participants = b''.join(sorted([jade_pubkey, cosigner_pubkey]))
    cache = sp.c_void_p()
    assert sp.wally_musig_pubkey_agg(participants, len(participants), None, 0,
                                     sp.byref(cache)) == sp.WALLY_OK
    buf, buf_len = sp.make_cbuffer('00' * 33)
    assert sp.wally_musig_pubkey_get(cache, buf, buf_len) == sp.WALLY_OK
    aggregate = bytes(buf)
    sp.wally_musig_keyagg_cache_free(cache)

    # The aggregate is derived, not the participants, so the taproot internal
    # key comes from the synthetic xpub the aggregate makes
    synthetic = sp.POINTER(sp.ext_key)()
    _, public_version = bip32_versions(network)
    assert sp.wally_musig_pubkey_to_xpub(aggregate, len(aggregate), public_version,
                                         sp.byref(synthetic)) == sp.WALLY_OK
    internal = derive_key(sp, synthetic, [MUSIG_BRANCH, MUSIG_INDEX], BIP32_FLAG_KEY_PUBLIC)
    internal_key = bytes(internal.contents.pub_key)

    tweaked, tweaked_len = sp.make_cbuffer('00' * 33)
    assert sp.wally_ec_public_key_bip341_tweak(internal_key, len(internal_key), None, 0,
                                               0, tweaked, tweaked_len) == sp.WALLY_OK

    return {'descriptor': descriptor,
            'participants': participants,
            'aggregate': aggregate,
            'internal_key': internal_key[1:],
            'script': b'\x51\x20' + bytes(tweaked)[1:],
            'synthetic_fingerprint': key_fingerprint(sp, synthetic),
            'jade': {'pubkey': jade_pubkey, 'fingerprint': jade_fingerprint},
            'cosigner': {'seckey': bytes(cosigner.contents.priv_key)[1:],
                         'pubkey': cosigner_pubkey}}


def build_musig_psbt(sp, setup, recipient_info, amount=MUSIG_SP_AMOUNT):
    """Build a PSBTv2 spending the MuSig2 output to a silent payment.

    The input carries what Jade needs to bind it to the registered descriptor:
    the participant list, the synthetic derivation of the aggregate, and its own
    key origin.
    """
    psbt = sp.pointer(sp.wally_psbt())
    assert sp.wally_psbt_init_alloc(sp.WALLY_PSBT_VERSION_2, 1, 1, 0, 0,
                                    psbt) == sp.WALLY_OK

    tx_input = sp.pointer(sp.wally_tx_input())
    assert sp.wally_tx_input_init_alloc(FUNDING_TXID, len(FUNDING_TXID), 0, 0xffffffff,
                                        None, 0, None, tx_input) == sp.WALLY_OK
    assert sp.wally_psbt_add_tx_input_at(psbt, 0, 0, tx_input) == sp.WALLY_OK

    utxo = sp.pointer(sp.wally_tx_output())
    assert sp.wally_tx_output_init_alloc(MUSIG_AMOUNT, setup['script'], len(setup['script']),
                                         utxo) == sp.WALLY_OK
    assert sp.wally_psbt_set_input_witness_utxo(psbt, 0, utxo) == sp.WALLY_OK
    assert sp.wally_psbt_set_input_amount(psbt, 0, MUSIG_AMOUNT) == sp.WALLY_OK
    assert sp.wally_psbt_set_input_sighash(psbt, 0, sp.WALLY_SIGHASH_ALL) == sp.WALLY_OK
    assert sp.wally_psbt_set_input_taproot_internal_key(
        psbt, 0, setup['internal_key'], len(setup['internal_key'])) == sp.WALLY_OK
    assert sp.wally_psbt_input_add_musig2_participant_pubkeys(
        psbt.contents.inputs, setup['aggregate'], len(setup['aggregate']),
        setup['participants'], len(setup['participants'])) == sp.WALLY_OK

    add_taproot_keypath(sp, psbt, setup['internal_key'], setup['synthetic_fingerprint'],
                        [MUSIG_BRANCH, MUSIG_INDEX])
    add_taproot_keypath(sp, psbt, setup['jade']['pubkey'][1:], setup['jade']['fingerprint'],
                        MUSIG_ORIGIN)

    tx_output = sp.pointer(sp.wally_tx_output())
    assert sp.wally_tx_output_init_alloc(amount, None, 0, tx_output) == sp.WALLY_OK
    assert sp.wally_psbt_add_tx_output_at(psbt, 0, 0, tx_output) == sp.WALLY_OK
    assert sp.wally_psbt_set_output_amount(psbt, 0, amount) == sp.WALLY_OK
    assert sp.wally_psbt_set_output_sp_v0_info(psbt, 0, recipient_info,
                                               len(recipient_info)) == sp.WALLY_OK
    return serialize_psbt(sp, psbt, free=True)


def add_taproot_keypath(sp, psbt, pubkey, fingerprint, path):
    values = (sp.c_uint32 * len(path))(*path)
    assert sp.wally_psbt_add_input_taproot_keypath(
        psbt, 0, 0, pubkey, len(pubkey), None, 0, fingerprint, len(fingerprint),
        values, len(path)) == sp.WALLY_OK


def serialize_psbt(sp, psbt, free=False):
    buf, buf_len = sp.make_cbuffer('00' * 8192)
    ret, written = sp.wally_psbt_to_bytes(psbt, 0, buf, buf_len)
    assert ret == sp.WALLY_OK
    if free:
        sp.wally_psbt_free(psbt)
    return bytes(buf[:written])


def parse_psbt(sp, data):
    psbt = sp.POINTER(sp.wally_psbt)()
    assert sp.wally_psbt_from_bytes(data, len(data), 0, sp.byref(psbt)) == sp.WALLY_OK
    return psbt


def sp_output_scripts(sp, psbt):
    scripts = []
    for index in range(psbt.contents.num_outputs):
        ret, info_len = sp.wally_psbt_get_output_sp_v0_info_len(psbt, index)
        if ret == sp.WALLY_OK and info_len:
            ret, script_len = sp.wally_psbt_get_output_script_len(psbt, index)
            assert ret == sp.WALLY_OK
            scripts.append(script_len)
    assert scripts, 'PSBT has no silent-payment outputs'
    return scripts


def snapshot(sp, data):
    psbt = parse_psbt(sp, data)
    inputs = []
    for index in range(psbt.contents.num_inputs):
        item = psbt.contents.inputs[index]
        if item.musig2_pubkeys.num_items:
            ret, tap_sig_len = sp.wally_psbt_get_input_taproot_signature_len(psbt, index)
            assert ret == sp.WALLY_OK
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
        'scripts': sp_output_scripts(sp, psbt),
        'modifiable': psbt.contents.tx_modifiable_flags,
    }
    sp.wally_psbt_free(psbt)
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
        assert new['tap_sig_len'] == 0, \
            f'input {new["index"]}: taproot signature present in round 1'
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


def musig_input(sp, setup):
    value = sp.wally_sp_musig_input()
    value.index = 0
    pubkeys, _ = sp.make_cbuffer(setup['participants'].hex())
    value.pub_keys = sp.cast(pubkeys, sp.c_void_p)
    value.pub_keys_len = len(setup['participants'])
    path = (sp.c_uint32 * 2)(MUSIG_BRANCH, MUSIG_INDEX)
    value.path = sp.cast(path, sp.c_void_p)
    value.path_len = 2
    value._buffers = (pubkeys, path)  # keep the ctypes buffers alive
    return value


def session_digest(sp, psbt):
    result, _ = sp.make_cbuffer('00' * SHA256_LEN)
    assert sp.wally_psbt_get_sp_musig_session_digest(psbt, result, SHA256_LEN) == sp.WALLY_OK
    return bytes(result)


def cosigner_round1(sp, setup, data, entropy=b'\x33' * 64):
    """The other participant's round 1: its share, proof and pubnonce."""
    psbt = parse_psbt(sp, data)
    nonce_out = (sp.c_void_p * 1)()
    digest_out, _ = sp.make_cbuffer('00' * SHA256_LEN)
    seckey = setup['cosigner']['seckey']
    ret, status = sp.wally_psbt_sp_musig_round1(
        psbt, sp.byref(musig_input(sp, setup)), 1, seckey, len(seckey), entropy,
        len(entropy), 0, nonce_out, digest_out, SHA256_LEN)
    assert ret == sp.WALLY_OK, ret
    return serialize_psbt(sp, psbt, free=True), nonce_out[0], status


def cosigner_round2(sp, setup, data, secnonce, digest):
    """The other participant's round 2: its partial signature."""
    psbt = parse_psbt(sp, data)
    seckey = setup['cosigner']['seckey']
    nonce = (sp.c_void_p * 1)(secnonce)
    assert sp.wally_psbt_sp_musig_round2(psbt, sp.byref(musig_input(sp, setup)), 1,
                                         seckey, len(seckey), nonce, digest,
                                         len(digest), 0) == sp.WALLY_OK
    return serialize_psbt(sp, psbt, free=True)



def run_musig_roundtrip(jade, network='localtest', verbose=True):
    """Jade signs a MuSig2 silent payment input across both rounds.

    Jade goes first, so round 1 must add its share, proof and pubnonce without
    resolving anything or signing. The cosigner then completes the coverage,
    which resolves the outputs, and Jade signs in round 2.

    Jade holds its secnonce in RAM between the rounds, so this has to run on a
    single connection: reconnecting expires the session by design.
    """
    sp = load_wally()
    assert sp, f'no libwally build found under {WALLY_DIR}'

    def log(message):
        if verbose:
            print(message)

    setup = musig_setup(jade, sp, network)
    log(f'Descriptor: {setup["descriptor"]}')
    recipient = get_recipient(jade, sp, network, 0, get_fingerprint(jade, sp, network))
    psbt_bytes = build_musig_psbt(sp, setup, recipient['info'])

    # Round 1: Jade is not the last signer, so it must not resolve or sign
    before = snapshot(sp, psbt_bytes)
    round1 = bytes(jade.sign_psbt(network, psbt_bytes))
    check_round1(before, snapshot(sp, round1), 'incomplete')

    psbt = parse_psbt(sp, round1)
    digest = session_digest(sp, psbt)
    sp.wally_psbt_free(psbt)

    # The cosigner completes the coverage, which resolves every output
    resolved, cosigner_nonce, status = cosigner_round1(sp, setup, round1)
    assert status == WALLY_SP_COMPLETE, f'cosigner did not complete the shares: {status}'
    psbt = parse_psbt(sp, resolved)
    assert session_digest(sp, psbt) == digest, 'session digest moved across round 1'
    assert psbt.contents.tx_modifiable_flags == 0, 'resolved psbt is still modifiable'
    sp.wally_psbt_free(psbt)
    log('Cosigner resolved the outputs; the session digest is unchanged')

    # Round 2: Jade verifies the resolved outputs and adds one partial signature
    before = snapshot(sp, resolved)
    round2 = bytes(jade.sign_psbt(network, resolved))
    check_round2(before, snapshot(sp, round2))

    final = cosigner_round2(sp, setup, round2, cosigner_nonce, digest)
    verify_musig_signature(sp, setup, final)
    log('Jade and the cosigner produced a valid aggregate signature')

    # The secnonce is spent, so the same round 2 must not be signable again.
    # Signing twice under one nonce would leak the participant key.
    log(f'Rejected: {assert_rejected(jade, network, resolved, MUSIG_EXPIRED_ERROR)}')
    return setup, recipient


def verify_musig_signature(sp, setup, data):
    """Aggregate the partial signatures and check the input finalizes."""
    psbt = parse_psbt(sp, data)
    assert psbt.contents.inputs[0].musig2_partial_sigs.num_items == 2
    path = (sp.c_uint32 * 2)(MUSIG_BRANCH, MUSIG_INDEX)
    assert sp.wally_psbt_musig2_agg_then_derive_finalize_input(
        psbt, 0, setup['aggregate'], len(setup['aggregate']), path, 2, 0) == sp.WALLY_OK
    ret, length = sp.wally_psbt_get_input_taproot_signature_len(psbt, 0)
    assert ret == sp.WALLY_OK and length, 'no aggregate signature produced'
    sp.wally_psbt_free(psbt)


def run_musig_negative_cases(jade, sp, setup, recipient, network='localtest', log=print):
    """What a MuSig2 signing session must refuse between the two rounds.

    Neither case reaches the signing step, so neither spends the secnonce that
    its own round 1 stored.
    """
    # A psbt that is not the one round 1 committed to. The session is found by
    # input and aggregate key, so Jade gets as far as comparing the digests.
    round1 = bytes(jade.sign_psbt(network, build_musig_psbt(sp, setup, recipient['info'])))
    resolved, _, status = cosigner_round1(sp, setup, round1)
    assert status == WALLY_SP_COMPLETE
    mutated = mutate_output_amount(sp, resolved)
    log(f'Rejected: {assert_rejected(jade, network, mutated, MUSIG_CHANGED_ERROR)}')

    # Jade's own round 1 handed straight back: its nonce is there, so this is
    # round 2, but nobody has covered the other input's share
    log(f'Rejected: {assert_rejected(jade, network, round1, MUSIG_UNRESOLVED_ERROR)}')


def mutate_output_amount(sp, data, delta=1):
    """Change what the psbt pays, leaving everything else in place."""
    psbt = parse_psbt(sp, data)
    amount = psbt.contents.outputs[0].amount
    assert sp.wally_psbt_set_output_amount(psbt, 0, amount - delta) == sp.WALLY_OK
    return serialize_psbt(sp, psbt, free=True)


def run_musig_flow(jade, network='localtest', verbose=True):
    """The whole MuSig2 silent payment story: both rounds, then the refusals."""
    sp = load_wally()
    assert sp, f'no libwally build found under {WALLY_DIR}'

    def log(message):
        if verbose:
            print(message)

    setup, recipient = run_musig_roundtrip(jade, network, verbose)
    run_musig_negative_cases(jade, sp, setup, recipient, network, log)


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
    parser.add_argument('--musig', action='store_true',
                        help='Run the MuSig2 two round flow instead; needs '
                             'Settings > Wallet > Silent Payments > Collaborative On')
    args = parser.parse_args()

    if not load_wally():
        parser.error(f'no libwally build found under {WALLY_DIR}; run ./configure && make there')

    from jadepy.jade import JadeAPI
    with JadeAPI.create_serial(device=args.serialport, timeout=args.timeout) as jade:
        jade.set_mnemonic(args.mnemonic, temporary_wallet=True)
        if args.musig:
            run_musig_flow(jade, args.network)
        elif args.collaborative:
            run_collaborative_roundtrip(jade, args.network, args.account)
        else:
            run_roundtrip(jade, args.network, args.account)
    print('Silent payment round trip complete')


if __name__ == '__main__':
    main()
