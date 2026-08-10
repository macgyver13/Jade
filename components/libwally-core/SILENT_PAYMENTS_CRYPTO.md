# Silent payments crypto dependencies

## Sources

- **BIP352 sender module**: already upstream in secp256k1-zkp
  (`src/modules/silentpayments`, added by `0fa38f3d`, present at `469d68d3`).
  It is enabled by default there, so this is not a local addition.
- **BIP374 DLEQ module**: the only local addition, taken from
  `bitcoin-core/secp256k1` PR [#1802](https://github.com/bitcoin-core/secp256k1/pull/1802),
  commit `e820661f8d1284874855998063850579fc03ec41`.

The DLEQ work is carried on the secp256k1 branch `dleq-pr-candidate` as three
reviewable commits:

1. `ecdsa_adaptor: namespace private DLEQ helpers`
2. `dleq: add BIP374 discrete log equality module`
3. `tests: add BIP-374 test vectors`

### Why ecdsa_adaptor is touched

The adaptor module carries a private DLEQ implementation whose six static
helpers are named `secp256k1_dleq_*`. Any BIP374 module necessarily uses the
same names, because #1802 descends from
[#1651](https://github.com/bitcoin-core/secp256k1/pull/1651), which was itself
based on this zkp implementation. Every module's `main_impl.h` is included into
the single `src/secp256k1.c` translation unit, so the two cannot coexist: four
names collide as statics, and `secp256k1_dleq_{prove,verify}` additionally
collide with the BIP374 module's *public* API, which C rejects outright.

The adaptor side is renamed rather than the incoming module, for two reasons.
`prove` and `verify` cannot be fixed on the incoming side at all without
changing the public BIP374 API. And keeping the vendored module byte-identical
to #1802 means re-vendoring stays a clean copy as that PR evolves.

Note the two are different protocols despite the shared ancestry: the adaptor
uses the DLC-spec `SHA256("DLEQ")` challenge tag over a five-point transcript,
BIP374 uses `SHA256("BIP0374/challenge")` over six points plus an optional
message. They cannot be unified, only kept apart.

## Proof API decision

PR #1651 was not used. Its implementation derives a proof from the BIP352
input-hash-tweaked sender scalar and has unresolved auxiliary randomness
handling. BIP375 requires the proof to cover the **untweaked** aggregate
eligible-input scalar.

No combined secp256k1 module is used. Jade composes the BIP352 sender and BIP374
DLEQ APIs in `main/silentpayments.c`. The adapter:

- aggregates eligible input secret keys with BIP352 taproot parity handling;
- creates the BIP375 global ECDH share from the untweaked aggregate;
- draws fresh auxiliary randomness from `get_random()` for every proof, holding
  it on the sensitive stack so it is cleared after use; and
- verifies the generated proof before returning success.

This composition is why `main/` includes `secp256k1*.h` directly, which no other
part of Jade does: libwally has no silent payments API, and several primitives
BIP375 needs are missing from its public surface — there is no EC point multiply
(`wally_ec_public_key_tweak` is `P + t*G`), and `wally_ecdh` returns the SHA256
of the shared point rather than the raw compressed point.

If maintainers decide to keep DLEQ internal to a silent payments module rather
than public, this composition would be replaced by a single combined call. Any
such API must expose the untweaked-aggregate proof, or it will not satisfy
BIP375.

## BIP375 PSBT support

libwally itself carries no silent payments crypto; it gained the BIP375 PSBT
container fields and their accessors. That work is on the libwally branch
`bip375-pr-candidate`, as commits that stand alone against libwally master:

1. `psbt: add BIP375 silent payment fields`
2. `psbt: add per-input and label silent payment accessors`
3. `psbt: test BIP375 silent payment fields`
4. `psbt: test against the BIP375 test vectors`

plus a local-only `build: reference the restructured secp256k1 DLEQ branch`,
which is not part of the upstream candidates.

The "resolved outputs must not be modifiable" rule checks only
`WALLY_PSBT_TXMOD_INPUTS | WALLY_PSBT_TXMOD_OUTPUTS`
(`PSBT_TXMOD_MODIFIABLE_FLAGS` in `src/psbt_io.h`). `WALLY_PSBT_TXMOD_SINGLE`
records that a SIGHASH_SINGLE signature is present, not that the transaction can
be modified, so BIP375 does not require it to be unset.

## What Jade implements

Only the single-signer path: Jade must own every eligible input, and emits a
single BIP375 **global** ECDH share and DLEQ proof covering their sum.

Not implemented, though libwally now exposes the API for both:

- **Collaborative sending** — per-input `PSBT_IN_SP_ECDH_SHARE` /
  `PSBT_IN_SP_DLEQ` for the inputs a signer owns, verifying other signers'
  proofs for the rest, and deferring `PSBT_OUT_SCRIPT` and signing until every
  eligible input has a share.
- **Labelled change detection** — deriving the scan and spend keys from an
  output's `PSBT_OUT_BIP32_DERIVATION` entries, applying
  `PSBT_OUT_SP_V0_LABEL`, and comparing against `PSBT_OUT_SP_V0_INFO`. This
  needs BIP352 receiving key derivation, which Jade does not have. Until then
  silent payment outputs are never flagged as change, so the user confirms
  every one.

## Verification

- **secp256k1**: `./configure --enable-module-silentpayments --enable-module-dleq
  && make check`, or via CMake. BIP352 vectors
  (`run_silentpayments_test_vectors`) and BIP374 vectors
  (`test_dleq_bip374_vectors`) both pass. Note `--enable-experimental` also
  enables `ecdsa_adaptor`, which is what exercises the namespacing.
- **libwally**: `test_psbt`, `test_psbt_limits` and `src/test/test_psbt.py` pass.
  The latter drives the 41 published BIP375 vectors (v1.1.1) through the parser:
  the six structural cases must be rejected, the rest must parse and round trip.
- **Jade**: builds clean for both layouts. The firmware self-check covers the
  BIP352 reference vector and an independent share/proof verification.

Image sizes, both layouts:

- amalgamated ESP32: `0x1130a0` (1,126,560 bytes);
- normal ESP32: `0x112c80` (1,125,504 bytes).

**Not yet verified**: `sp_process_psbt` has never been run end to end against a
real PSBT. `test_jade.py` needs a device or emulator, and the firmware
self-checks are compiled but unflashed.
