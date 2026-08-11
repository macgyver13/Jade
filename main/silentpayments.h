#ifndef SILENTPAYMENTS_H_
#define SILENTPAYMENTS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "jade_assert.h"
#include "utils/network.h"

#include <wally_crypto.h>
#include <wally_transaction.h>

struct wally_psbt;

// BIP352 v0 payment info: compressed scan pubkey || compressed spend pubkey
#define SP_V0_INFO_LEN (EC_PUBLIC_KEY_LEN * 2)

/** Derive the BIP352 outputs for any PSBT_OUT_SP_V0_INFO outputs in the psbt.
 *
 * The derived output scripts and the BIP375 global ECDH shares/DLEQ proofs are
 * written into the psbt, and the inputs signed by this wallet are pinned to
 * SIGHASH_ALL. A no-op returning true if the psbt has no silent payment outputs.
 *
 * Only the BIP375 global share is produced, so this wallet must own every
 * eligible input. Collaborative sending, which BIP375 supports via per-input
 * shares and proofs, is not implemented.
 */
WARN_UNUSED_RESULT bool sp_process_psbt(network_t network_id, struct wally_psbt* psbt, const char** errmsg);

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

/* The remainder are internal to sp_process_psbt(), and are exposed only so that
 * selfcheck can unit test them - getting either wrong sends funds to an output
 * the recipient cannot detect. */

// A BIP352 outpoint is the txid followed by the 4-byte little-endian vout
#define SP_OUTPOINT_LEN (WALLY_TXHASH_LEN + 4)

/** Return whether a prevout is eligible to contribute to the BIP352 input hash.
 *
 * The eligible set is exactly P2PKH, P2WPKH, P2SH-P2WPKH and non-NUMS P2TR.
 * The script types are those returned by `wally_scriptpubkey_get_type`.
 */
bool sp_is_eligible_script(size_t script_type, size_t redeem_script_type, const uint8_t* taproot_internal_key,
    size_t taproot_internal_key_len);

/** Serialize the lexicographically smallest outpoint of the psbt's inputs. */
void sp_smallest_outpoint(const struct wally_psbt* psbt, uint8_t output[SP_OUTPOINT_LEN]);

#endif /* SILENTPAYMENTS_H_ */
