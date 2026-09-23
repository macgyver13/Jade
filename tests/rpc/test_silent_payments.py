import test_sp_roundtrip

from . import *


def _read_compact_size(data, offset):
    value = data[offset]
    offset += 1
    if value < 0xfd:
        return value, offset
    size = {0xfd: 2, 0xfe: 4, 0xff: 8}[value]
    return int.from_bytes(data[offset:offset + size], 'little'), offset + size


def _write_compact_size(value):
    if value < 0xfd:
        return bytes([value])
    if value <= 0xffff:
        return b'\xfd' + value.to_bytes(2, 'little')
    if value <= 0xffffffff:
        return b'\xfe' + value.to_bytes(4, 'little')
    return b'\xff' + value.to_bytes(8, 'little')


def _read_psbt_map(data, offset):
    fields = []
    while data[offset]:
        key_len, offset = _read_compact_size(data, offset)
        key = data[offset:offset + key_len]
        offset += key_len
        value_len, offset = _read_compact_size(data, offset)
        value = data[offset:offset + value_len]
        offset += value_len
        fields.append((key, value))
    return fields, offset + 1


def _write_psbt_map(fields):
    result = bytearray()
    for key, value in fields:
        result += _write_compact_size(len(key)) + key
        result += _write_compact_size(len(value)) + value
    return bytes(result) + b'\x00'


def _parse_psbt_maps(psbt):
    psbt = bytes(psbt)
    assert psbt[:5] == b'psbt\xff'
    offset = 5
    globals_, offset = _read_psbt_map(psbt, offset)
    globals_by_key = dict(globals_)
    num_inputs = int.from_bytes(globals_by_key[b'\x04'], 'little')
    num_outputs = int.from_bytes(globals_by_key[b'\x05'], 'little')
    inputs, outputs = [], []
    for _ in range(num_inputs):
        fields, offset = _read_psbt_map(psbt, offset)
        inputs.append(fields)
    for _ in range(num_outputs):
        fields, offset = _read_psbt_map(psbt, offset)
        outputs.append(fields)
    assert offset == len(psbt)
    return globals_, inputs, outputs


def _serialize_psbt_maps(globals_, inputs, outputs):
    maps = [globals_, *inputs, *outputs]
    return b'psbt\xff' + b''.join(_write_psbt_map(fields) for fields in maps)


def _duplicate_sp_output(psbt):
    """Add a second silent payment output paying the same address as the first.

    The copy is placed alongside the original so the silent payment outputs are
    outputs 0 and 1. Both share a scan and spend key, which BIP375 orders by
    output index. The copy is paid for out of the change, so the fee is unchanged.
    """
    globals_, inputs, outputs = _parse_psbt_maps(psbt)
    duplicate = list(outputs[0])
    amount = int.from_bytes(dict(duplicate)[b'\x03'], 'little')
    assert dict(outputs[1]).get(b'\x09') is None, 'Second output is not the change'

    change = int.from_bytes(dict(outputs[1])[b'\x03'], 'little') - amount
    outputs[1] = [(key, change.to_bytes(8, 'little') if key == b'\x03' else value)
                  for key, value in outputs[1]]
    outputs.insert(1, duplicate)

    count = _write_compact_size(len(outputs))
    globals_ = [(key, count if key == b'\x05' else value) for key, value in globals_]
    return globals_, inputs, outputs


def _check_silent_payment_psbt(psbt, silent_payment_info):
    globals_, inputs, outputs = _parse_psbt_maps(psbt)
    globals_by_key = dict(globals_)
    scan_key = silent_payment_info[:33]
    assert globals_by_key.get(b'\x06', b'\x00') == b'\x00'
    assert len(globals_by_key[b'\x07' + scan_key]) == 33
    assert len(globals_by_key[b'\x08' + scan_key]) == 64
    # Jade does not set a sighash of its own, so the input's field stays absent
    assert b'\x03' not in dict(inputs[0])
    assert any(key[:1] == b'\x02' for key, _ in inputs[0])
    assert dict(outputs[0])[b'\x09'] == silent_payment_info
    script = dict(outputs[0])[b'\x04']
    assert len(script) == 34 and script[:2] == b'\x51\x20'
    return script, globals_by_key[b'\x08' + scan_key]


# What Jade answers for each psbt_sp_375_* rejection vector, keyed by the id the
# vector carries. The vectors hold no error strings of their own, so the corpus
# says what a case is and this map says what Jade should make of it, and neither
# can drift into the other.
SP_NOT_OURS = "This wallet owns none of the silent payment's eligible inputs"
SP_BAD_PROOFS = 'Silent payment ECDH shares or DLEQ proofs are invalid'
SP_NO_DERIVE = 'Failed to derive silent payment outputs, or a proposed script did not match'
SP_SIGHASH = 'Silent payments require SIGHASH_ALL, or SIGHASH_DEFAULT on a taproot input'

SP_375_REJECTIONS = {
    'foreign_inputs_only': SP_NOT_OURS,
    'ineligible_p2sh': SP_BAD_PROOFS,
    'ineligible_nums_taproot': SP_BAD_PROOFS,
    'sighash_not_all': SP_SIGHASH,
    'segwit_v2_input': 'Silent payments do not support Segwit versions above 1',
    'resolved_output_modifiable': 'Silent payment outputs resolved while the transaction can still change',
    'resolved_without_shares': SP_BAD_PROOFS,
    # A silent payment output with no amount leaves the transaction paying
    # nothing, which the fee confirmation used to assert on rather than refuse
    'output_amount_missing': 'Transaction inputs and outputs must have value',
    'input_utxo_missing': 'Silent payment input utxo missing',
    'origin_script_mismatch_p2wpkh': SP_NOT_OURS,
    'origin_script_mismatch_p2pkh': SP_NOT_OURS,
    'origin_script_mismatch_p2sh_p2wpkh': SP_NOT_OURS,
    'origin_script_mismatch_p2tr': SP_NOT_OURS,
    'foreign_origin': SP_NOT_OURS,
    'invalid_dleq_proof': SP_BAD_PROOFS,
    # A wrong k gives an output script that is not the one BIP375 derives, which
    # wally folds into the same INVALID status as a bad proof, so this is as
    # specific as Jade can be about it
    'wrong_k_assignment': SP_BAD_PROOFS,
    'scan_key_coverage_gap': SP_NOT_OURS,
    # The wallet owns an input here, so ownership is not the complaint: the
    # foreign input's keypath names a key its prevout does not pay to, which
    # leaves the share proven against that key bound to nothing
    'foreign_pubkey_not_bound_to_prevout': SP_BAD_PROOFS,
}


def _find_sp_share(globals_by_key, inputs, scan_key):
    """A share covering a scan key, held globally or on any single input."""
    if b'\x07' + scan_key in globals_by_key:
        return globals_by_key[b'\x07' + scan_key], globals_by_key[b'\x08' + scan_key]
    for fields in inputs:
        by_key = dict(fields)
        if b'\x1d' + scan_key in by_key:
            return by_key[b'\x1d' + scan_key], by_key[b'\x1e' + scan_key]
    return None, None


def _psbt_is_signed(psbt):
    """Whether any input carries a signature, ecdsa or taproot keypath."""
    _globals, inputs, _outputs = _parse_psbt_maps(psbt)
    return any(key[:1] in (b'\x02', b'\x13') for fields in inputs for key, _ in fields)


def _check_sp_375_resolved(psbt, expected_scripts):
    """Jade derived every silent payment output, and proved it did."""
    globals_, inputs, outputs = _parse_psbt_maps(psbt)
    globals_by_key = dict(globals_)
    # BIP375 requires a psbt with resolved outputs to be unmodifiable
    assert globals_by_key.get(b'\x06', b'\x00') == b'\x00', 'resolved psbt is still modifiable'

    for expected in expected_scripts:
        index = expected['output_index']
        output = dict(outputs[index])
        derived = output[b'\x04']
        assert derived == expected['script'], \
            f'output {index}: Jade derived {derived.hex()}, expected {expected["script"].hex()}'
        scan_key = output[b'\x09'][:33]
        share, proof = _find_sp_share(globals_by_key, inputs, scan_key)
        assert share and len(share) == 33, f'output {index}: no ECDH share for its scan key'
        assert proof and len(proof) == 64, f'output {index}: no DLEQ proof for its scan key'


def _check_sp_375_contribution(psbt, expected):
    """Jade owns only some eligible inputs, so it contributes and stops short."""
    _globals, inputs, outputs = _parse_psbt_maps(psbt)
    shared = expected['share_input_indices']
    for index, fields in enumerate(inputs):
        has_share = any(key[:1] == b'\x1d' for key, _ in fields)
        assert has_share == (index in shared), \
            f'input {index}: share {"present" if has_share else "missing"} unexpectedly'
        # Nothing may be signed while an output is still unresolved
        assert not any(key[:1] in (b'\x02', b'\x13') for key, _ in fields), \
            f'input {index}: signed during a contribution'
    for index in expected['unresolved_output_indices']:
        assert b'\x04' not in dict(outputs[index]), f'output {index}: resolved by a contribution'


@pytest.mark.mnemonic(mnemonics.singlesig)
@with_test_cases('tests/rpc/data/sign_psbt/psbt_sp_375_*.json')
def test_sign_psbt_sp_375(jade, mnemonic, test_case):
    """Run one case of the generated BIP375 corpus, keyed to the singlesig mnemonic.

    Rejections are checked against SP_375_REJECTIONS rather than anything in the
    vector, so a case cannot be rejected for the wrong reason and still pass.
    """
    vector_id = test_case['id']
    network, psbt = test_case['input']['network'], test_case['input']['psbt']

    if test_case['validation_result'] == 'valid':
        signed = jade.sign_psbt(network, psbt)
        if 'expected_scripts' in test_case:
            _check_sp_375_resolved(signed, test_case['expected_scripts'])
        else:
            _check_sp_375_contribution(signed, test_case['expected_contribution'])
        return

    assert vector_id in SP_375_REJECTIONS, f'{vector_id}: no expected rejection mapped'
    try:
        signed = jade.sign_psbt(network, psbt)
    except JadeError as err:
        assert err.message == SP_375_REJECTIONS[vector_id], err.message
        return
    # Whether it was signed says how bad an acceptance is: a psbt handed back
    # untouched is a lesser thing than one Jade put a signature on
    state = 'signed' if _psbt_is_signed(signed) else 'returned unsigned'
    assert False, f'{vector_id}: accepted ({state})'


@pytest.mark.mnemonic(mnemonics.singlesig)
def test_silent_payment_roundtrip(jade, mnemonic):
    """Pay Jade's own silent payment address, then scan for the payment.

    Checks the descriptor export and signing against each other, and the
    BIP352 output against an implementation that is not the one Jade uses.
    Skipped unless the vendored libwally has been built for the host.
    """
    if not test_sp_roundtrip.load_wally():
        pytest.skip('No libwally host build')
    test_sp_roundtrip.run_roundtrip(jade, 'localtest', verbose=False)


@pytest.mark.mnemonic(mnemonics.singlesig)
@with_test_cases('tests/rpc/data/sign_psbt/psbt_sp_resolve_sign.json')
def test_silent_payment_sign_psbt(jade, mnemonic, test_case):
    network = test_case['input']['network']
    psbt = test_case['input']['psbt']
    silent_payment_info = test_case['silent_payment_info']

    first = _check_silent_payment_psbt(jade.sign_psbt(network, psbt), silent_payment_info)
    second = _check_silent_payment_psbt(jade.sign_psbt(network, psbt), silent_payment_info)
    assert first[0] == second[0]
    assert first[1] != second[1]

    # A psbt whose outputs another signer has resolved is verified and signed
    # as-is, not derived again. Deriving picks fresh entropy for the proof, as
    # the two differing proofs above show, so a proof that survives unchanged
    # is what shows the final signer path was taken.
    resolved = jade.sign_psbt(network, psbt)
    before = _check_silent_payment_psbt(resolved, silent_payment_info)
    after = _check_silent_payment_psbt(jade.sign_psbt(network, resolved), silent_payment_info)
    assert after == before

    globals_, inputs, outputs = _parse_psbt_maps(psbt)
    inputs[0].append((b'\x03', (2).to_bytes(4, 'little')))
    with pytest.raises(JadeError) as err:
        jade.sign_psbt(network, _serialize_psbt_maps(globals_, inputs, outputs))
    assert err.value.message == SP_SIGHASH

    # Stripping the keypath makes the sole eligible input foreign, leaving
    # Jade with no key to contribute a share with, let alone resolve the
    # outputs. There is nothing it can usefully do with such a psbt.
    globals_, inputs, outputs = _parse_psbt_maps(psbt)
    inputs[0] = [(key, value) for key, value in inputs[0] if key[:1] != b'\x06']
    with pytest.raises(JadeError) as err:
        jade.sign_psbt(network, _serialize_psbt_maps(globals_, inputs, outputs))
    assert err.value.message == SP_NOT_OURS

    # A proposed script on a silent payment output must be the one Jade
    # derives. With a single silent payment output a proposed script makes the
    # psbt claim to be resolved, so a second unresolved output is needed to
    # keep Jade on the deriving path and reach the comparison.
    two_sp = _duplicate_sp_output(psbt)
    outputs = _parse_psbt_maps(jade.sign_psbt(network, _serialize_psbt_maps(*two_sp)))[2]
    derived = [dict(output)[b'\x04'] for output in outputs[:2]]

    # A script on a silent payment output makes it resolved, and BIP375
    # requires resolved outputs to be unmodifiable, so the flags must be
    # cleared or Jade refuses to sign.
    globals_, inputs, outputs = _duplicate_sp_output(psbt)
    globals_ = [(key, b'\x00' if key == b'\x06' else value) for key, value in globals_]
    outputs[0].append((b'\x04', derived[0]))
    signed = _parse_psbt_maps(jade.sign_psbt(network, _serialize_psbt_maps(globals_, inputs, outputs)))[2]
    assert [dict(output)[b'\x04'] for output in signed[:2]] == derived

    globals_, inputs, outputs = _duplicate_sp_output(psbt)
    globals_ = [(key, b'\x00' if key == b'\x06' else value) for key, value in globals_]
    outputs[0].append((b'\x04', derived[0][:-1] + bytes([derived[0][-1] ^ 1])))
    with pytest.raises(JadeError) as err:
        jade.sign_psbt(network, _serialize_psbt_maps(globals_, inputs, outputs))
    assert err.value.message == SP_NO_DERIVE

    # An output script on every silent payment output makes the psbt claim to
    # be resolved, which BIP375 requires ECDH shares to accompany. It has none.
    globals_, inputs, outputs = _parse_psbt_maps(psbt)
    globals_ = [(key, b'\x00' if key == b'\x06' else value) for key, value in globals_]
    outputs[0].append((b'\x04', b'\x51\x20' + bytes(32)))
    with pytest.raises(JadeError) as err:
        jade.sign_psbt(network, _serialize_psbt_maps(globals_, inputs, outputs))
    assert err.value.message == SP_BAD_PROOFS


@pytest.mark.mnemonic(mnemonics.singlesig)
@with_test_cases('tests/rpc/data/sign_psbt/psbt_sp_375_owned_inputs_03.json')
def test_silent_payment_sighash_taproot(jade, mnemonic, test_case):
    """BIP375 allows an explicit sighash only as ALL, or DEFAULT on a taproot input.

    Jade sets no sighash of its own: an absent field stays absent, and an
    explicit one is signed with as given. The signature length shows which.
    """
    network, psbt = test_case['input']['network'], test_case['input']['psbt']

    def sign(sighash):
        globals_, inputs, outputs = _parse_psbt_maps(psbt)
        if sighash is not None:
            inputs[0].append((b'\x03', sighash.to_bytes(4, 'little')))
        signed = _parse_psbt_maps(jade.sign_psbt(network, _serialize_psbt_maps(globals_, inputs, outputs)))
        fields = dict(signed[1][0])
        assert b'\x13' in fields, 'Taproot input not signed'  # PSBT_IN_TAP_KEY_SIG
        return fields

    fields = sign(None)
    assert b'\x03' not in fields
    assert len(fields[b'\x13']) == 64  # SIGHASH_DEFAULT, no sighash byte appended

    fields = sign(wally.WALLY_SIGHASH_DEFAULT)
    assert fields[b'\x03'] == b'\x00\x00\x00\x00'
    assert len(fields[b'\x13']) == 64

    fields = sign(wally.WALLY_SIGHASH_ALL)
    assert fields[b'\x03'] == b'\x01\x00\x00\x00'
    assert len(fields[b'\x13']) == 65 and fields[b'\x13'][-1] == wally.WALLY_SIGHASH_ALL

    for sighash in [wally.WALLY_SIGHASH_NONE, wally.WALLY_SIGHASH_SINGLE]:
        with pytest.raises(JadeError) as err:
            sign(sighash)
        assert err.value.message == SP_SIGHASH


@pytest.mark.mnemonic(mnemonics.singlesig)
@with_test_cases('tests/rpc/data/sign_psbt/psbt_sp_375_owned_inputs_02.json')
def test_silent_payment_sighash_default_segwit(jade, mnemonic, test_case):
    """SIGHASH_DEFAULT is only for taproot, so it is refused on a segwit v0 input."""
    network, psbt = test_case['input']['network'], test_case['input']['psbt']
    globals_, inputs, outputs = _parse_psbt_maps(psbt)
    inputs[0].append((b'\x03', wally.WALLY_SIGHASH_DEFAULT.to_bytes(4, 'little')))
    with pytest.raises(JadeError) as err:
        jade.sign_psbt(network, _serialize_psbt_maps(globals_, inputs, outputs))
    assert err.value.message == SP_SIGHASH
