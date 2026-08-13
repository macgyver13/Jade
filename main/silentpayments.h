#ifndef SILENTPAYMENTS_H_
#define SILENTPAYMENTS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "jade_assert.h"
#include "utils/address.h"
#include "utils/network.h"
#include "utils/psbt.h"

#include <wally_address.h>

struct wally_psbt;

/** What sp_process_psbt() did, and hence what the caller should do next. */
typedef enum {
    // The psbt has no silent payment outputs, and was not touched
    SP_NONE,
    // The outputs are resolved and may be signed
    SP_SIGN,
    // This wallet owns only some of the eligible inputs, so it can contribute
    // BIP375 shares but cannot resolve the outputs alone. Nothing was changed:
    // the caller confirms the summary with the user, then calls
    // sp_contribute_psbt() to go ahead.
    SP_CONTRIBUTE,
    // We added our BIP375 shares, but the outputs cannot be derived until the
    // remaining signers add theirs. There is nothing to sign yet: SIGHASH_ALL
    // commits to outputs that do not exist. The psbt is returned as it stands.
    SP_SHARES_ONLY,
    // Add aggregate silent-payment shares and a MuSig2 public nonce, without
    // signing even if this contribution resolves the outputs.
    SP_MUSIG_CONTRIBUTE,
    // Aggregate silent-payment outputs and shares have been verified and the
    // held round-1 nonce can now be consumed to add our partial signature.
    SP_MUSIG_SIGN,
} sp_result_t;

// What can be told to the user before a silent payment is resolved. Recipient
// addresses and output amounts are explicit; scripts and change classification
// are not available until every share is present. Non-SP outputs are counted so
// the user can see that outputs other than the listed recipients exist.
#define SP_MAX_SUMMARY_RECIPIENTS 4
typedef struct {
    // The eligible inputs, by whether this wallet holds their keys, and for
    // those it does not, whether another signer's share already covers them
    size_t num_inputs_ours;
    size_t num_inputs_covered;
    size_t num_inputs_uncovered;
    // The recipient addresses, truncated to the first SP_MAX_SUMMARY_RECIPIENTS
    char recipients[SP_MAX_SUMMARY_RECIPIENTS][MAX_ADDRESS_LEN];
    uint64_t recipient_amounts[SP_MAX_SUMMARY_RECIPIENTS];
    size_t num_recipients;
    size_t num_recipients_shown;
    size_t num_change_outputs;
    size_t num_other_outputs;
} sp_summary_t;

/** Resolve, contribute to, or check any PSBT_OUT_SP_V0_INFO outputs in the psbt.
 *
 * A no-op returning SP_NONE if the psbt has no silent payment outputs.
 * Otherwise any BIP375 shares and proofs it already carries must be valid, and:
 *
 * - If another signer has resolved the outputs, they are left alone. We are
 *   the final signer, and need own only the inputs we sign.
 * - If this wallet owns every eligible input, the BIP352 outputs are derived
 *   here, along with one BIP375 global ECDH share and DLEQ proof per recipient
 *   scan key. That share covers the sum of every eligible input.
 * - If this wallet owns only some of the eligible inputs, the psbt is left
 *   untouched and the result is SP_CONTRIBUTE, with 'summary' filled in for
 *   the user to confirm before sp_contribute_psbt() is called.
 *
 * On an SP_SIGN result the inputs signed by this wallet are pinned to
 * SIGHASH_ALL and the psbt's inputs and outputs are marked unmodifiable. An
 * unresolved psbt is left modifiable, as the remaining signers require.
 *
 * NOTE: when another signer resolved the outputs, we verify that each output
 * script is the one BIP352 derives from the shares - which needs no private
 * key of ours, the shares being public and DLEQ proven. So a resolved psbt is
 * checked as thoroughly as one we resolve ourselves.
 */
WARN_UNUSED_RESULT bool sp_process_psbt(
    network_t network_id, struct wally_psbt* psbt, sp_summary_t* summary, sp_result_t* result, const char** errmsg);

/** Contribute this wallet's BIP375 shares to a silent payment it cannot resolve
 * alone, after the user has confirmed the summary sp_process_psbt() returned.
 *
 * Adds a per-input ECDH share and DLEQ proof for each eligible input this
 * wallet owns. Where that completes the coverage the outputs are resolved and
 * the result is SP_SIGN, ie. this signer is also the last one; otherwise it is
 * SP_SHARES_ONLY and the psbt must be passed to the remaining signers.
 *
 * NOTE: only meaningful after an SP_CONTRIBUTE result, and the psbt must not
 * have been modified in between.
 */
WARN_UNUSED_RESULT bool sp_contribute_psbt(
    network_t network_id, struct wally_psbt* psbt, sp_result_t* result, const char** errmsg);

/** Returns true if the input is a BIP376 silent payment spend, ie. it carries
 * a tweak to apply to the silent payment spend key that unlocks it.
 */
bool sp_is_spend_input(const struct wally_psbt* psbt, size_t index);

/** Check that a silent payment input says enough for us to sign it.
 *
 * Only call for an input where `sp_is_spend_input()` is true.
 */
WARN_UNUSED_RESULT bool sp_validate_spend_input(const struct wally_psbt* psbt, size_t index, const char** errmsg);

/** Check that the spend key an iterator matched is a silent payment spend key.
 *
 * The tweak is applied to whichever key the psbt names, so the path it was
 * derived at must be one we would use for silent payments.
 */
WARN_UNUSED_RESULT bool sp_validate_spend_key_path(network_t network_id, const key_iter* iter, const char** errmsg);

/** Consume the stored round-1 nonces and add this device's MuSig2 partial
 * signatures. Only valid after sp_process_psbt() returns SP_MUSIG_SIGN. */
WARN_UNUSED_RESULT bool sp_musig_sign_psbt(
    network_t network_id, struct wally_psbt* psbt, bool* musig_inputs, const char** errmsg);

/** Encode a BIP352 v0 address from a PSBT_OUT_SP_V0_INFO value. */
WARN_UNUSED_RESULT bool sp_encode_address(
    network_t network_id, const uint8_t* sp_v0_info, size_t sp_v0_info_len, char* output, size_t output_len);

/* A BIP392 sp() descriptor: "sp(" + "[" + 8 char fingerprint + the bip352
 * account path + "]" + the 119 character spscan key + ")#" + 8 char checksum.
 */
#define SP_DESCRIPTOR_MAX_LEN 160

/** Build the BIP392 silent payment scan descriptor for the given account.
 *
 * The descriptor is watch-only: it carries the scan private key, which allows
 * incoming payments to be found, and the spend public key, which does not allow
 * them to be spent.
 */
WARN_UNUSED_RESULT bool sp_build_scan_descriptor(
    network_t network_id, uint16_t account_index, char* output, size_t output_len);

#endif /* SILENTPAYMENTS_H_ */
