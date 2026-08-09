#ifndef UTILS_BECH32M_H_
#define UTILS_BECH32M_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../jade_assert.h"

/* BIP-352 v0 addresses are 116 (mainnet) or 117 (testnet) characters.
 * Leave room for future payloads while keeping the encoder's stack use bounded. */
#define BECH32M_MAX_ENCODED_LEN 128
#define BECH32M_MAX_BUFFER_LEN (BECH32M_MAX_ENCODED_LEN + 1)

/** Encode a versioned byte payload using Bech32m.
 *
 * The payload is converted from 8-bit bytes to padded 5-bit values and the
 * version is prepended as one 5-bit value. The output is always lowercase and
 * nul-terminated on success. On failure, a non-empty output buffer is cleared.
 */
WARN_UNUSED_RESULT bool bech32m_encode(const char* hrp, uint8_t version, const uint8_t* payload, size_t payload_len,
    char* output, size_t output_len);

#endif /* UTILS_BECH32M_H_ */
