#ifndef AMALGAMATED_BUILD
#include "silentpayments.h"

#include "jade_wally_verify.h"
#include "keychain.h"
#include "random.h"
#include "sensitive.h"
#include "utils/bech32m.h"
#include "utils/malloc_ext.h"
#include "utils/psbt.h"
#include "wallet.h"

#include <secp256k1_dleq.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_silentpayments.h>
#include <wally_address.h>
#include <wally_core.h>
#include <wally_descriptor.h>
#include <wally_psbt.h>
#include <wally_psbt_members.h>
#include <wally_script.h>
#include <wally_transaction.h>

#include <stdlib.h>
#include <string.h>

// A BIP375 DLEQ proof.
// NOTE: namespaced as libwally's psbt.c defines SP_DLEQ_PROOF_LEN, and shares a
// translation unit with this file in the amalgamated build.
#define JADE_SP_DLEQ_PROOF_LEN 64

// The largest redeem script we need to inspect is a segwit witness program
#define SP_MAX_REDEEM_SCRIPT_LEN WALLY_SEGWIT_ADDRESS_PUBKEY_MAX_LEN

// BIP341 unspendable NUMS point 'H', as an x-only pubkey. A taproot input using
// this as its internal key has no key path, so it cannot contribute to BIP352.
static const uint8_t BIP341_NUMS_XONLY[EC_XONLY_PUBLIC_KEY_LEN] = { 0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54,
    0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee,
    0x9a, 0xce, 0x80, 0x3a, 0xc0 };

// A silent payment recipient, and the psbt output index it was read from
typedef struct {
    uint8_t scan_pubkey[EC_PUBLIC_KEY_LEN];
    uint8_t spend_pubkey[EC_PUBLIC_KEY_LEN];
    size_t output_index;
} sp_recipient_t;

// The private key of an input this wallet owns, and whether it is a taproot key
typedef struct {
    uint8_t seckey[EC_PRIVATE_KEY_LEN];
    bool is_taproot;
} sp_input_key_t;

// BIP375 orders recipients by scan pubkey, then spend pubkey, then output index.
// Sorting by scan pubkey first also makes duplicate scan keys adjacent, which is
// what lets us emit one ECDH share and DLEQ proof per unique scan key.
static int sp_recipient_cmp(const void* lhs_ptr, const void* rhs_ptr)
{
    const sp_recipient_t* const lhs = lhs_ptr;
    const sp_recipient_t* const rhs = rhs_ptr;
    int result = memcmp(lhs->scan_pubkey, rhs->scan_pubkey, sizeof(lhs->scan_pubkey));
    if (!result) {
        result = memcmp(lhs->spend_pubkey, rhs->spend_pubkey, sizeof(lhs->spend_pubkey));
    }
    if (!result) {
        result = (lhs->output_index > rhs->output_index) - (lhs->output_index < rhs->output_index);
    }
    return result;
}

// Returns the witness version of a witness program, or -1 if not a witness program.
// NOTE: wally_scriptpubkey_get_type() cannot serve here - it reports witness v2+
// programs as WALLY_SCRIPT_TYPE_UNKNOWN, which would make them merely ineligible.
// BIP352 requires the sender to abort on an input it cannot classify.
static int sp_witness_version(const uint8_t* script, const size_t script_len)
{
    if (!script || script_len < 4 || script_len > 42 || script[1] != script_len - 2 || script[1] < 2
        || script[1] > 40) {
        return -1;
    }
    if (script[0] == 0x00) {
        return 0;
    }
    return script[0] >= 0x51 && script[0] <= 0x60 ? script[0] - 0x50 : -1;
}

bool sp_is_eligible_script(const size_t script_type, const size_t redeem_script_type,
    const uint8_t* taproot_internal_key, const size_t taproot_internal_key_len)
{
    switch (script_type) {
    case WALLY_SCRIPT_TYPE_P2PKH:
    case WALLY_SCRIPT_TYPE_P2WPKH:
        return true;
    case WALLY_SCRIPT_TYPE_P2SH:
        return redeem_script_type == WALLY_SCRIPT_TYPE_P2WPKH;
    case WALLY_SCRIPT_TYPE_P2TR:
        return !taproot_internal_key
            || (taproot_internal_key_len == sizeof(BIP341_NUMS_XONLY)
                && memcmp(taproot_internal_key, BIP341_NUMS_XONLY, sizeof(BIP341_NUMS_XONLY)));
    default:
        return false;
    }
}

void sp_smallest_outpoint(const struct wally_psbt* psbt, uint8_t output[SP_OUTPOINT_LEN])
{
    JADE_ASSERT(psbt);
    JADE_ASSERT(psbt->num_inputs);

    uint8_t candidate[SP_OUTPOINT_LEN];
    for (size_t i = 0; i < psbt->num_inputs; ++i) {
        const struct wally_psbt_input* const input = &psbt->inputs[i];
        memcpy(candidate, input->txhash, WALLY_TXHASH_LEN);
        candidate[32] = (uint8_t)input->index;
        candidate[33] = (uint8_t)(input->index >> 8);
        candidate[34] = (uint8_t)(input->index >> 16);
        candidate[35] = (uint8_t)(input->index >> 24);
        if (!i || memcmp(candidate, output, sizeof(candidate)) < 0) {
            memcpy(output, candidate, sizeof(candidate));
        }
    }
}

bool sp_encode_address(const network_t network_id, const uint8_t* sp_v0_info, const size_t sp_v0_info_len,
    char* output, const size_t output_len)
{
    if (!sp_v0_info || sp_v0_info_len != SP_V0_INFO_LEN || !output) {
        return false;
    }
    const char* const hrp = network_to_type(network_id) == NETWORK_TYPE_MAIN ? "sp" : "tsp";
    return bech32m_encode(hrp, 0, sp_v0_info, sp_v0_info_len, output, output_len);
}

// The BIP352 child paths beneath the account node - m/352'/coin'/account'/x'/0
#define SP_SCAN_KEY_BRANCH 1
#define SP_SPEND_KEY_BRANCH 0
#define SP_KEY_PATH_LEN (SP_EXPORT_PATH_LEN + 2)

// A BIP392 spscan key expression: the scan private key followed by the spend
// public key, bech32m encoded as silent payments v0.
#define SP_SCAN_KEY_LEN (EC_PRIVATE_KEY_LEN + EC_PUBLIC_KEY_LEN)

bool sp_build_scan_descriptor(
    const network_t network_id, const uint16_t account_index, char* output, const size_t output_len)
{
    // Silent payments are bitcoin-only
    JADE_ASSERT(!network_is_liquid(network_id));
    JADE_ASSERT(output);
    JADE_ASSERT(output_len >= SP_DESCRIPTOR_MAX_LEN);

    uint32_t path[SP_KEY_PATH_LEN];
    size_t path_len = 0;
    wallet_get_default_sp_export_path(network_id, account_index, path, SP_EXPORT_PATH_LEN, &path_len);
    JADE_ASSERT(path_len == SP_EXPORT_PATH_LEN);

    // The account path is what the descriptor's key origin refers to
    char pathstr[MAX_PATH_STR_LEN(SP_EXPORT_PATH_LEN)];
    const bool path_only = true;
    if (!wallet_bip32_path_as_str(path, path_len, pathstr, sizeof(pathstr), path_only)) {
        return false;
    }
    // bip380 allows either hardened marker, but bip392 and other signers use 'h'
    for (char* p = pathstr; *p; ++p) {
        if (*p == '\'') {
            *p = 'h';
        }
    }

    uint8_t fingerprint[BIP32_KEY_FINGERPRINT_LEN];
    wallet_get_fingerprint(fingerprint, sizeof(fingerprint));

    uint8_t sp_key[SP_SCAN_KEY_LEN];
    SENSITIVE_PUSH(sp_key, sizeof(sp_key));
    struct ext_key hdkey;
    SENSITIVE_PUSH(&hdkey, sizeof(hdkey));
    bool ret = false;

    path[SP_EXPORT_PATH_LEN] = harden(SP_SCAN_KEY_BRANCH);
    path[SP_EXPORT_PATH_LEN + 1] = 0;
    if (!wallet_get_hdkey(path, SP_KEY_PATH_LEN, BIP32_FLAG_KEY_PRIVATE, &hdkey)) {
        goto cleanup;
    }
    // hdkey.priv_key is the private key prefixed with a zero byte
    memcpy(sp_key, hdkey.priv_key + 1, EC_PRIVATE_KEY_LEN);

    path[SP_EXPORT_PATH_LEN] = harden(SP_SPEND_KEY_BRANCH);
    if (!wallet_get_hdkey(path, SP_KEY_PATH_LEN, BIP32_FLAG_KEY_PRIVATE, &hdkey)) {
        goto cleanup;
    }
    memcpy(sp_key + EC_PRIVATE_KEY_LEN, hdkey.pub_key, EC_PUBLIC_KEY_LEN);

    {
        const char* const hrp = network_to_type(network_id) == NETWORK_TYPE_MAIN ? "spscan" : "tspscan";
        char spscan[BECH32M_MAX_BUFFER_LEN];
        if (!bech32m_encode(hrp, 0, sp_key, sizeof(sp_key), spscan, sizeof(spscan))) {
            goto cleanup;
        }

        char fingerprint_hex[(BIP32_KEY_FINGERPRINT_LEN * 2) + 1];
        for (size_t i = 0; i < sizeof(fingerprint); ++i) {
            const int rc = snprintf(fingerprint_hex + (i * 2), 3, "%02x", fingerprint[i]);
            JADE_ASSERT(rc == 2);
        }

        const int rc = snprintf(output, output_len, "sp([%s/%s]%s)", fingerprint_hex, pathstr, spscan);
        JADE_ASSERT(rc > 0 && rc < output_len);

        // Append the bip380 checksum, as Jade does for other exported descriptors
        struct wally_descriptor* d = NULL;
        if (wally_descriptor_parse(output, NULL, network_id, 0, &d) != WALLY_OK) {
            goto cleanup;
        }
        char* checksum = NULL;
        const int wret = wally_descriptor_get_checksum(d, 0, &checksum);
        JADE_WALLY_VERIFY(wally_descriptor_free(d));
        if (wret != WALLY_OK || !checksum) {
            goto cleanup;
        }
        const size_t descriptor_len = strlen(output);
        JADE_ASSERT(descriptor_len + 1 + strlen(checksum) < output_len);
        output[descriptor_len] = '#';
        strcpy(output + descriptor_len + 1, checksum);
        JADE_WALLY_VERIFY(wally_free_string(checksum));
        ret = true;
    }

cleanup:
    SENSITIVE_POP(&hdkey);
    SENSITIVE_POP(sp_key);
    if (!ret) {
        output[0] = '\0';
    }
    return ret;
}

// Sum the input private keys into the BIP352 'a_sum', negating any taproot key
// whose public key has odd parity. This is the untweaked aggregate that BIP375
// requires the ECDH share and DLEQ proof to be built from.
static bool sp_sum_input_seckeys(const secp256k1_context* ctx, const sp_input_key_t* input_keys,
    const size_t num_input_keys, uint8_t aggregate_seckey[EC_PRIVATE_KEY_LEN])
{
    uint8_t normalized_seckey[EC_PRIVATE_KEY_LEN];
    SENSITIVE_PUSH(normalized_seckey, sizeof(normalized_seckey));
    bool success = false;

    for (size_t i = 0; i < num_input_keys; ++i) {
        memcpy(normalized_seckey, input_keys[i].seckey, sizeof(normalized_seckey));
        if (!secp256k1_ec_seckey_verify(ctx, normalized_seckey)) {
            goto cleanup;
        }
        if (input_keys[i].is_taproot) {
            secp256k1_pubkey pubkey;
            secp256k1_xonly_pubkey xonly_pubkey;
            int parity = 0;
            if (!secp256k1_ec_pubkey_create(ctx, &pubkey, normalized_seckey)
                || !secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly_pubkey, &parity, &pubkey)
                || (parity && !secp256k1_ec_seckey_negate(ctx, normalized_seckey))) {
                goto cleanup;
            }
        }
        if (!i) {
            memcpy(aggregate_seckey, normalized_seckey, EC_PRIVATE_KEY_LEN);
        } else if (!secp256k1_ec_seckey_tweak_add(ctx, aggregate_seckey, normalized_seckey)) {
            goto cleanup;
        }
    }
    success = true;

cleanup:
    SENSITIVE_POP(normalized_seckey);
    return success;
}

// Derive the BIP352 output scripts for the (BIP375-sorted) recipients and write
// them into the psbt, along with one BIP375 global ECDH share and DLEQ proof per
// unique scan pubkey. The caller must wrap `input_keys` in the sensitive stack.
static bool sp_derive_outputs(struct wally_psbt* psbt, const sp_recipient_t* recipients, const size_t num_recipients,
    const uint8_t smallest_outpoint[SP_OUTPOINT_LEN], const sp_input_key_t* input_keys, const size_t num_input_keys,
    const char** errmsg)
{
    JADE_ASSERT(psbt);
    JADE_ASSERT(recipients);
    JADE_ASSERT(num_recipients);
    JADE_ASSERT(input_keys);
    JADE_ASSERT(num_input_keys);
    JADE_ASSERT(errmsg);

    *errmsg = "Failed to derive silent payment outputs";

    const secp256k1_context* const ctx = wally_get_secp_context();

    size_t num_keypairs = 0;
    for (size_t i = 0; i < num_input_keys; ++i) {
        num_keypairs += input_keys[i].is_taproot;
    }
    const size_t num_seckeys = num_input_keys - num_keypairs;

    secp256k1_silentpayments_recipient* const recipient_objs = JADE_CALLOC(num_recipients, sizeof(*recipient_objs));
    const secp256k1_silentpayments_recipient** const recipient_ptrs
        = JADE_CALLOC(num_recipients, sizeof(*recipient_ptrs));
    secp256k1_xonly_pubkey* const output_objs = JADE_CALLOC(num_recipients, sizeof(*output_objs));
    secp256k1_xonly_pubkey** const output_ptrs = JADE_CALLOC(num_recipients, sizeof(*output_ptrs));
    secp256k1_keypair* const keypairs = num_keypairs ? JADE_CALLOC(num_keypairs, sizeof(*keypairs)) : NULL;
    const secp256k1_keypair** const keypair_ptrs
        = num_keypairs ? JADE_CALLOC(num_keypairs, sizeof(*keypair_ptrs)) : NULL;
    const uint8_t** const seckey_ptrs = num_seckeys ? JADE_CALLOC(num_seckeys, sizeof(*seckey_ptrs)) : NULL;
    uint8_t aux_rand[32];
    uint8_t aggregate_seckey[EC_PRIVATE_KEY_LEN];
    bool success = false;

    if (keypairs) {
        SENSITIVE_PUSH(keypairs, num_keypairs * sizeof(*keypairs));
    }
    SENSITIVE_PUSH(aux_rand, sizeof(aux_rand));
    SENSITIVE_PUSH(aggregate_seckey, sizeof(aggregate_seckey));

    // NOTE: sender_create_outputs() may permute recipient_ptrs, but not the
    // recipient_objs storage it points into - so indexing recipient_objs by the
    // caller's (BIP375-sorted) order remains valid below. Setting index = i is
    // what makes secp's internal sort preserve that order for the outputs.
    for (size_t i = 0; i < num_recipients; ++i) {
        if (!secp256k1_ec_pubkey_parse(
                ctx, &recipient_objs[i].scan_pubkey, recipients[i].scan_pubkey, EC_PUBLIC_KEY_LEN)
            || !secp256k1_ec_pubkey_parse(
                ctx, &recipient_objs[i].spend_pubkey, recipients[i].spend_pubkey, EC_PUBLIC_KEY_LEN)) {
            goto cleanup;
        }
        recipient_objs[i].index = i;
        recipient_ptrs[i] = &recipient_objs[i];
        output_ptrs[i] = &output_objs[i];
    }

    size_t keypair_index = 0;
    size_t seckey_index = 0;
    for (size_t i = 0; i < num_input_keys; ++i) {
        if (input_keys[i].is_taproot) {
            if (!secp256k1_keypair_create(ctx, &keypairs[keypair_index], input_keys[i].seckey)) {
                goto cleanup;
            }
            keypair_ptrs[keypair_index] = &keypairs[keypair_index];
            ++keypair_index;
        } else {
            seckey_ptrs[seckey_index++] = input_keys[i].seckey;
        }
    }

    if (!secp256k1_silentpayments_sender_create_outputs(ctx, output_ptrs, recipient_ptrs, num_recipients,
            smallest_outpoint, keypair_ptrs, num_keypairs, seckey_ptrs, num_seckeys)) {
        goto cleanup;
    }
    if (!sp_sum_input_seckeys(ctx, input_keys, num_input_keys, aggregate_seckey)) {
        goto cleanup;
    }
    secp256k1_pubkey aggregate_pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &aggregate_pubkey, aggregate_seckey)) {
        goto cleanup;
    }

    for (size_t i = 0; i < num_recipients; ++i) {
        uint8_t xonly[EC_XONLY_PUBLIC_KEY_LEN];
        uint8_t script[WALLY_SCRIPTPUBKEY_P2TR_LEN];
        size_t script_len = 0;
        if (!secp256k1_xonly_pubkey_serialize(ctx, xonly, &output_objs[i])) {
            goto cleanup;
        }
        // NOTE: x-only keys are used as-is here, ie. not re-tweaked per BIP341
        JADE_WALLY_VERIFY(
            wally_scriptpubkey_p2tr_from_bytes(xonly, sizeof(xonly), 0, script, sizeof(script), &script_len));
        JADE_ASSERT(script_len == sizeof(script));

        // If the psbt already carries a script for this output, it must agree
        const struct wally_psbt_output* const output = &psbt->outputs[recipients[i].output_index];
        if (output->script_len
            && (output->script_len != sizeof(script) || memcmp(output->script, script, sizeof(script)))) {
            *errmsg = "Silent payment output script mismatch";
            goto cleanup;
        }
        JADE_WALLY_VERIFY(wally_psbt_set_output_script(psbt, recipients[i].output_index, script, sizeof(script)));
    }

    for (size_t i = 0; i < num_recipients; ++i) {
        // Duplicate scan keys are adjacent after the BIP375 sort
        if (i && !memcmp(recipients[i].scan_pubkey, recipients[i - 1].scan_pubkey, EC_PUBLIC_KEY_LEN)) {
            continue;
        }
        uint8_t ecdh_share[EC_PUBLIC_KEY_LEN];
        uint8_t dleq_proof[JADE_SP_DLEQ_PROOF_LEN];
        secp256k1_pubkey share_pubkey = recipient_objs[i].scan_pubkey;
        size_t share_len = sizeof(ecdh_share);
        get_random(aux_rand, sizeof(aux_rand));
        if (!secp256k1_ec_pubkey_tweak_mul(ctx, &share_pubkey, aggregate_seckey)
            || !secp256k1_ec_pubkey_serialize(ctx, ecdh_share, &share_len, &share_pubkey, SECP256K1_EC_COMPRESSED)
            || share_len != sizeof(ecdh_share)
            || !secp256k1_dleq_prove(
                ctx, dleq_proof, aggregate_seckey, &recipient_objs[i].scan_pubkey, aux_rand, NULL)
            || !secp256k1_dleq_verify(
                ctx, dleq_proof, &aggregate_pubkey, &recipient_objs[i].scan_pubkey, &share_pubkey, NULL)) {
            goto cleanup;
        }
        JADE_WALLY_VERIFY(wally_psbt_set_global_sp_ecdh_share(
            psbt, recipients[i].scan_pubkey, EC_PUBLIC_KEY_LEN, ecdh_share, sizeof(ecdh_share)));
        JADE_WALLY_VERIFY(wally_psbt_set_global_sp_dleq_proof(
            psbt, recipients[i].scan_pubkey, EC_PUBLIC_KEY_LEN, dleq_proof, sizeof(dleq_proof)));
    }
    success = true;

cleanup:
    SENSITIVE_POP(aggregate_seckey);
    SENSITIVE_POP(aux_rand);
    if (keypairs) {
        SENSITIVE_POP(keypairs);
    }
    free(seckey_ptrs);
    free(keypair_ptrs);
    free(keypairs);
    free(output_ptrs);
    free(output_objs);
    free(recipient_ptrs);
    free(recipient_objs);
    return success;
}

// Read the private key of an input this wallet owns.
// NOTE: we only produce a BIP375 *global* ECDH share, which covers the sum of all
// eligible inputs - so we must own all of them. Failing to own one is fatal here.
// TODO: support collaborative sending, ie. write per-input shares and proofs
// with wally_psbt_input_set_sp_{ecdh_share,dleq_proof}() for the inputs we do
// own, verify other signers' proofs for the rest, and defer PSBT_OUT_SCRIPT
// until every eligible input has a share.
static bool sp_get_input_key(const network_t network_id, const struct wally_psbt* psbt, const size_t index,
    const struct wally_tx_output* utxo, const size_t script_type, key_iter* iter, sp_input_key_t* input_key)
{
    script_variant_t script_variant;
    if (!key_iter_input_begin(psbt, index, iter) || key_iter_get_num_keys(iter) != 1
        || !get_singlesig_variant_from_script_type(script_type, &script_variant)
        || !wallet_verify_singlesig_script_matches(
            network_id, script_variant, &iter->hdkey, utxo->script, utxo->script_len)) {
        return false;
    }
    JADE_ASSERT(iter->hdkey.priv_key[0] == BIP32_FLAG_KEY_PRIVATE);
    memcpy(input_key->seckey, iter->hdkey.priv_key + 1, sizeof(input_key->seckey));
    input_key->is_taproot = script_type == WALLY_SCRIPT_TYPE_P2TR;
    return true;
}

bool sp_process_psbt(const network_t network_id, struct wally_psbt* psbt, const char** errmsg)
{
    JADE_ASSERT(psbt);
    JADE_ASSERT(errmsg);

    size_t num_sp_outputs = 0;
    for (size_t i = 0; i < psbt->num_outputs; ++i) {
        size_t info_len = 0;
        if (wally_psbt_get_output_sp_v0_info_len(psbt, i, &info_len) == WALLY_OK && info_len) {
            ++num_sp_outputs;
        }
    }
    if (!num_sp_outputs) {
        return true;
    }
    if (psbt->version != WALLY_PSBT_VERSION_2) {
        *errmsg = "Silent payments require PSBTv2";
        return false;
    }
    size_t is_elements = 0;
    JADE_WALLY_VERIFY(wally_psbt_is_elements(psbt, &is_elements));
    if (is_elements) {
        *errmsg = "Silent payments are not supported for Liquid";
        return false;
    }

    sp_recipient_t* const recipients = JADE_CALLOC(num_sp_outputs, sizeof(*recipients));
    sp_input_key_t* const input_keys = JADE_CALLOC(psbt->num_inputs, sizeof(*input_keys));
    bool* const owned_inputs = JADE_CALLOC(psbt->num_inputs, sizeof(*owned_inputs));
    key_iter iter;
    SENSITIVE_PUSH(&iter, sizeof(iter));
    SENSITIVE_PUSH(input_keys, psbt->num_inputs * sizeof(*input_keys));

    bool success = false;
    size_t num_input_keys = 0;
    size_t num_recipients = 0;
    uint8_t smallest_outpoint[SP_OUTPOINT_LEN];

    for (size_t i = 0; i < psbt->num_outputs; ++i) {
        uint8_t info[SP_V0_INFO_LEN];
        size_t info_len = 0;
        if (wally_psbt_get_output_sp_v0_info(psbt, i, info, sizeof(info), &info_len) != WALLY_OK || !info_len) {
            continue;
        }
        // Wally validates the length and both pubkeys when parsing the psbt
        JADE_ASSERT(info_len == sizeof(info));
        memcpy(recipients[num_recipients].scan_pubkey, info, EC_PUBLIC_KEY_LEN);
        memcpy(recipients[num_recipients].spend_pubkey, info + EC_PUBLIC_KEY_LEN, EC_PUBLIC_KEY_LEN);
        recipients[num_recipients].output_index = i;
        ++num_recipients;
    }
    JADE_ASSERT(num_recipients == num_sp_outputs);

    for (size_t i = 0; i < psbt->num_inputs; ++i) {
        const struct wally_psbt_input* const input = &psbt->inputs[i];
        const struct wally_tx_output* utxo = NULL;
        if (wally_psbt_get_input_best_utxo(psbt, i, &utxo) != WALLY_OK || !utxo || !utxo->script
            || !utxo->script_len) {
            *errmsg = "Silent payment input utxo missing";
            goto cleanup;
        }
        if (input->sighash && input->sighash != WALLY_SIGHASH_ALL) {
            *errmsg = "Silent payments require SIGHASH_ALL";
            goto cleanup;
        }

        // NOTE: a redeem script larger than the buffer is left unread. It can be
        // neither P2WPKH (22 bytes) nor any witness program (42 bytes max), so the
        // input is simply not eligible - which is not an error, as BIP352 senders
        // may spend ineligible inputs (eg. P2SH-multisig) alongside eligible ones.
        uint8_t redeem_script[SP_MAX_REDEEM_SCRIPT_LEN];
        size_t redeem_script_len = 0;
        size_t field_len = 0;
        if (wally_psbt_get_input_redeem_script_len(psbt, i, &field_len) == WALLY_OK && field_len
            && field_len <= sizeof(redeem_script)) {
            if (wally_psbt_get_input_redeem_script(psbt, i, redeem_script, sizeof(redeem_script), &redeem_script_len)
                != WALLY_OK) {
                *errmsg = "Invalid input redeem script";
                goto cleanup;
            }
        }
        if (sp_witness_version(utxo->script, utxo->script_len) > 1
            || sp_witness_version(redeem_script, redeem_script_len) > 1) {
            *errmsg = "Silent payments do not support Segwit versions above 1";
            goto cleanup;
        }

        uint8_t taproot_internal_key[EC_XONLY_PUBLIC_KEY_LEN];
        size_t taproot_internal_key_len = 0;
        field_len = 0;
        if (wally_psbt_get_input_taproot_internal_key_len(psbt, i, &field_len) == WALLY_OK && field_len) {
            if (field_len != sizeof(taproot_internal_key)
                || wally_psbt_get_input_taproot_internal_key(psbt, i, taproot_internal_key,
                       sizeof(taproot_internal_key), &taproot_internal_key_len)
                    != WALLY_OK) {
                *errmsg = "Invalid taproot internal key";
                goto cleanup;
            }
        }

        size_t script_type = WALLY_SCRIPT_TYPE_UNKNOWN;
        size_t redeem_script_type = WALLY_SCRIPT_TYPE_UNKNOWN;
        if (wally_scriptpubkey_get_type(utxo->script, utxo->script_len, &script_type) != WALLY_OK
            || (redeem_script_len
                && wally_scriptpubkey_get_type(redeem_script, redeem_script_len, &redeem_script_type) != WALLY_OK)) {
            *errmsg = "Invalid input script";
            goto cleanup;
        }
        if (!sp_is_eligible_script(script_type, redeem_script_type,
                taproot_internal_key_len ? taproot_internal_key : NULL, taproot_internal_key_len)) {
            owned_inputs[i] = key_iter_input_begin_public(psbt, i, &iter);
            continue;
        }
        if (!sp_get_input_key(network_id, psbt, i, utxo, script_type, &iter, &input_keys[num_input_keys])) {
            *errmsg = "This silent payment implementation requires ownership of all eligible inputs";
            goto cleanup;
        }
        owned_inputs[i] = true;
        ++num_input_keys;
    }
    if (!num_input_keys) {
        *errmsg = "Silent payment has no eligible inputs";
        goto cleanup;
    }

    sp_smallest_outpoint(psbt, smallest_outpoint);
    qsort(recipients, num_sp_outputs, sizeof(*recipients), sp_recipient_cmp);
    if (!sp_derive_outputs(psbt, recipients, num_sp_outputs, smallest_outpoint, input_keys, num_input_keys, errmsg)) {
        goto cleanup;
    }

    for (size_t i = 0; i < psbt->num_inputs; ++i) {
        if (owned_inputs[i]) {
            JADE_WALLY_VERIFY(wally_psbt_set_input_sighash(psbt, i, WALLY_SIGHASH_ALL));
        }
    }
    // BIP375: the inputs and outputs of a resolved silent payment are fixed
    size_t mod_flags = 0;
    JADE_WALLY_VERIFY(wally_psbt_get_tx_modifiable_flags(psbt, &mod_flags));
    JADE_WALLY_VERIFY(wally_psbt_set_tx_modifiable_flags(
        psbt, mod_flags & ~(WALLY_PSBT_TXMOD_INPUTS | WALLY_PSBT_TXMOD_OUTPUTS)));
    success = true;

cleanup:
    SENSITIVE_POP(input_keys);
    SENSITIVE_POP(&iter);
    free(owned_inputs);
    free(input_keys);
    free(recipients);
    return success;
}
#endif /* AMALGAMATED_BUILD */
