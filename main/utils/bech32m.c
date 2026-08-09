/* Copyright (c) 2017 Pieter Wuille
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#ifndef AMALGAMATED_BUILD
#include "bech32m.h"

#include <string.h>

#define BECH32M_CHECKSUM_CONSTANT 0x2bc830a3u
#define BECH32M_CHECKSUM_LEN 6u
#define BECH32M_HRP_MAX_LEN 83u
/* With a one-character HRP, 74 bytes is the largest payload that can fit. */
#define BECH32M_MAX_PAYLOAD_LEN 74u

static const char BECH32_CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static uint32_t polymod_step(const uint32_t previous)
{
    const uint8_t high = previous >> 25;
    return ((previous & 0x1ffffffu) << 5) ^ (-((high >> 0) & 1u) & 0x3b6a57b2u)
        ^ (-((high >> 1) & 1u) & 0x26508e6du) ^ (-((high >> 2) & 1u) & 0x1ea119fau)
        ^ (-((high >> 3) & 1u) & 0x3d4233ddu) ^ (-((high >> 4) & 1u) & 0x2a1462b3u);
}

static bool convert_to_5_bits(
    const uint8_t* input, const size_t input_len, uint8_t* output, size_t* output_len)
{
    uint32_t accumulator = 0;
    unsigned int bits = 0;
    size_t written = 0;

    for (size_t i = 0; i < input_len; ++i) {
        /* Only the 12 low bits can affect subsequent 5-bit output values. */
        accumulator = ((accumulator << 8) | input[i]) & 0xfffu;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            output[written++] = (accumulator >> bits) & 0x1fu;
        }
    }
    if (bits) {
        output[written++] = (accumulator << (5 - bits)) & 0x1fu;
    }

    *output_len = written;
    return true;
}

bool bech32m_encode(const char* hrp, const uint8_t version, const uint8_t* payload, const size_t payload_len,
    char* output, const size_t output_len)
{
    if (output && output_len) {
        output[0] = '\0';
    }
    if (!hrp || !payload || !output || !output_len || version > 31 || payload_len > BECH32M_MAX_PAYLOAD_LEN) {
        return false;
    }

    size_t hrp_len = 0;
    uint32_t checksum = 1;
    while (hrp[hrp_len]) {
        const unsigned char c = (unsigned char)hrp[hrp_len];
        if (hrp_len == BECH32M_HRP_MAX_LEN || c < 33 || c > 126 || (c >= 'A' && c <= 'Z')) {
            return false;
        }
        checksum = polymod_step(checksum) ^ (c >> 5);
        ++hrp_len;
    }
    if (!hrp_len) {
        return false;
    }

    uint8_t data[BECH32M_MAX_ENCODED_LEN];
    size_t converted_len = 0;
    if (!convert_to_5_bits(payload, payload_len, data + 1, &converted_len)) {
        return false;
    }
    data[0] = version;
    const size_t data_len = converted_len + 1;
    const size_t encoded_len = hrp_len + 1 + data_len + BECH32M_CHECKSUM_LEN;
    if (encoded_len > BECH32M_MAX_ENCODED_LEN || output_len <= encoded_len) {
        return false;
    }

    checksum = polymod_step(checksum);
    for (size_t i = 0; i < hrp_len; ++i) {
        checksum = polymod_step(checksum) ^ (hrp[i] & 0x1f);
        output[i] = hrp[i];
    }

    size_t output_pos = hrp_len;
    output[output_pos++] = '1';
    for (size_t i = 0; i < data_len; ++i) {
        checksum = polymod_step(checksum) ^ data[i];
        output[output_pos++] = BECH32_CHARSET[data[i]];
    }
    for (size_t i = 0; i < BECH32M_CHECKSUM_LEN; ++i) {
        checksum = polymod_step(checksum);
    }
    checksum ^= BECH32M_CHECKSUM_CONSTANT;
    for (size_t i = 0; i < BECH32M_CHECKSUM_LEN; ++i) {
        output[output_pos++] = BECH32_CHARSET[(checksum >> ((5 - i) * 5)) & 0x1fu];
    }
    output[output_pos] = '\0';
    return true;
}
#endif /* AMALGAMATED_BUILD */
