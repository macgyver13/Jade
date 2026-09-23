#ifndef SILENTPAYMENTS_H_
#define SILENTPAYMENTS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "jade_assert.h"
#include "utils/network.h"

#include <wally_address.h>

struct wally_psbt;

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

#endif /* SILENTPAYMENTS_H_ */
