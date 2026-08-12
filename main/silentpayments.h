#ifndef SILENTPAYMENTS_H_
#define SILENTPAYMENTS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "jade_assert.h"
#include "utils/network.h"

#include <wally_address.h>

struct wally_psbt;

/** Resolve or check any PSBT_OUT_SP_V0_INFO outputs in the psbt.
 *
 * A no-op returning true if the psbt has no silent payment outputs. Otherwise
 * any BIP375 shares and proofs it already carries must be valid, and then:
 *
 * - If another signer has resolved the outputs, they are left alone. We are
 *   the final signer, and need own only the inputs we sign.
 * - Otherwise the BIP352 outputs are derived here, along with one BIP375
 *   global ECDH share and DLEQ proof per recipient scan key. That share covers
 *   the sum of every eligible input, so this wallet must own all of them.
 *   Contributing per-input shares, which is what BIP375 offers a signer that
 *   owns only some of them, is not implemented.
 *
 * Either way the inputs signed by this wallet are pinned to SIGHASH_ALL and
 * the psbt's inputs and outputs are marked unmodifiable.
 *
 * NOTE: when another signer resolved the outputs, we verify that each output
 * script is the one BIP352 derives from the shares - which needs no private
 * key of ours, the shares being public and DLEQ proven. So a resolved psbt is
 * checked as thoroughly as one we resolve ourselves.
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
