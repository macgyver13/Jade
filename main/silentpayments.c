#ifndef AMALGAMATED_BUILD
#include "silentpayments.h"

#include "jade_wally_verify.h"
#include "keychain.h"
#include "random.h"
#include "sensitive.h"
#include "utils/malloc_ext.h"
#include "utils/psbt.h"
#include "wallet.h"

#include <wally_address.h>
#include <wally_core.h>
#include <wally_descriptor.h>
#include <wally_psbt.h>
#include <wally_psbt_members.h>
#include <wally_silentpayments.h>
#include <wally_script.h>
#include <wally_transaction.h>

#include <stdlib.h>
#include <string.h>

// Entropy for the BIP375 DLEQ proofs, which wally expands per proof
#define SP_DLEQ_ENTROPY_LEN 32

// An all-zero P2TR script, ie. no script was proposed for an output
static const uint8_t ZERO_SCRIPT[WALLY_SCRIPTPUBKEY_P2TR_LEN] = { 0 };

// The largest redeem script we need to inspect is a segwit witness program
#define SP_UNUSED_MAX_REDEEM_SCRIPT_LEN WALLY_SEGWIT_ADDRESS_PUBKEY_MAX_LEN

bool sp_encode_address(const network_t network_id, const uint8_t* sp_v0_info, const size_t sp_v0_info_len,
    char* output, const size_t output_len)
{
    if (!sp_v0_info || sp_v0_info_len != SP_V0_INFO_LEN || !output) {
        return false;
    }
    const char* const hrp = network_to_type(network_id) == NETWORK_TYPE_MAIN ? "sp" : "tsp";
    char* address = NULL;
    if (wally_sp_address_from_bytes(sp_v0_info, sp_v0_info_len, hrp, 0, &address) != WALLY_OK) {
        return false;
    }
    const bool ret = strlen(address) < output_len;
    if (ret) {
        strcpy(output, address);
    } else {
        output[0] = '\0';
    }
    JADE_WALLY_VERIFY(wally_free_string(address));
    return ret;
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
        char* spscan = NULL;
        if (wally_descriptor_sp_key_from_bytes(sp_key, sizeof(sp_key), hrp, &spscan) != WALLY_OK) {
            goto cleanup;
        }

        char fingerprint_hex[(BIP32_KEY_FINGERPRINT_LEN * 2) + 1];
        for (size_t i = 0; i < sizeof(fingerprint); ++i) {
            const int rc = snprintf(fingerprint_hex + (i * 2), 3, "%02x", fingerprint[i]);
            JADE_ASSERT(rc == 2);
        }

        const int rc = snprintf(output, output_len, "sp([%s/%s]%s)", fingerprint_hex, pathstr, spscan);
        // The key expression carries the scan private key; wally_free_string wipes it
        JADE_WALLY_VERIFY(wally_free_string(spscan));
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

// Read the private key of an input this wallet owns.
// NOTE: we only produce a BIP375 *global* ECDH share, which covers the sum of all
// eligible inputs - so we must own all of them. Failing to own one is fatal here.
// TODO: support collaborative sending, ie. write per-input shares and proofs
// with wally_psbt_input_set_sp_{ecdh_share,dleq_proof}() for the inputs we do
// own, verify other signers' proofs for the rest, and defer PSBT_OUT_SCRIPT
// until every eligible input has a share.
static bool sp_get_input_key(
    const network_t network_id, const struct wally_psbt* psbt, const size_t index, key_iter* iter, uint8_t* seckey)
{
    const struct wally_tx_output* utxo = NULL;
    size_t script_type = WALLY_SCRIPT_TYPE_UNKNOWN;
    script_variant_t script_variant;
    if (wally_psbt_get_input_best_utxo(psbt, index, &utxo) != WALLY_OK || !utxo
        || wally_scriptpubkey_get_type(utxo->script, utxo->script_len, &script_type) != WALLY_OK) {
        return false;
    }
    if (!key_iter_input_begin(psbt, index, iter) || key_iter_get_num_keys(iter) != 1
        || !get_singlesig_variant_from_script_type(script_type, &script_variant)
        || !wallet_verify_singlesig_script_matches(
            network_id, script_variant, &iter->hdkey, utxo->script, utxo->script_len)) {
        return false;
    }
    JADE_ASSERT(iter->hdkey.priv_key[0] == BIP32_FLAG_KEY_PRIVATE);
    memcpy(seckey, iter->hdkey.priv_key + 1, EC_PRIVATE_KEY_LEN);
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

    // Any script already present must match what we derive, so keep a copy
    uint8_t* const claimed_scripts = JADE_CALLOC(psbt->num_outputs, WALLY_SCRIPTPUBKEY_P2TR_LEN);
    uint8_t* const seckeys = JADE_CALLOC(psbt->num_inputs, EC_PRIVATE_KEY_LEN);
    bool* const owned_inputs = JADE_CALLOC(psbt->num_inputs, sizeof(*owned_inputs));
    key_iter iter;
    SENSITIVE_PUSH(&iter, sizeof(iter));
    SENSITIVE_PUSH(seckeys, psbt->num_inputs * EC_PRIVATE_KEY_LEN);

    bool success = false;
    size_t num_seckeys = 0;
    uint8_t entropy[SP_DLEQ_ENTROPY_LEN];

    for (size_t i = 0; i < psbt->num_outputs; ++i) {
        size_t script_len = 0;
        if (wally_psbt_get_output_script_len(psbt, i, &script_len) == WALLY_OK
            && script_len == WALLY_SCRIPTPUBKEY_P2TR_LEN) {
            size_t written = 0;
            JADE_WALLY_VERIFY(wally_psbt_get_output_script(psbt, i,
                claimed_scripts + (i * WALLY_SCRIPTPUBKEY_P2TR_LEN), WALLY_SCRIPTPUBKEY_P2TR_LEN, &written));
        }
    }

    for (size_t i = 0; i < psbt->num_inputs; ++i) {
        const struct wally_psbt_input* const input = &psbt->inputs[i];
        if (input->sighash && input->sighash != WALLY_SIGHASH_ALL) {
            *errmsg = "Silent payments require SIGHASH_ALL";
            goto cleanup;
        }

        size_t is_eligible = 0;
        const int wret = wally_psbt_get_input_sp_eligible(psbt, i, &is_eligible);
        if (wret == WALLY_ERROR) {
            // An input wally cannot classify, eg. an unknown witness version
            *errmsg = "Silent payments do not support Segwit versions above 1";
            goto cleanup;
        }
        if (wret != WALLY_OK) {
            *errmsg = "Silent payment input utxo missing";
            goto cleanup;
        }
        if (!is_eligible) {
            owned_inputs[i] = key_iter_input_begin_public(psbt, i, &iter);
            continue;
        }
        if (!sp_get_input_key(network_id, psbt, i, &iter, seckeys + (num_seckeys * EC_PRIVATE_KEY_LEN))) {
            *errmsg = "This silent payment implementation requires ownership of all eligible inputs";
            goto cleanup;
        }
        owned_inputs[i] = true;
        ++num_seckeys;
    }
    if (!num_seckeys) {
        *errmsg = "Silent payment has no eligible inputs";
        goto cleanup;
    }

    get_random(entropy, sizeof(entropy));
    if (wally_psbt_sp_resolve(psbt, seckeys, num_seckeys * EC_PRIVATE_KEY_LEN, entropy, sizeof(entropy), 0)
        != WALLY_OK) {
        *errmsg = "Failed to derive silent payment outputs";
        goto cleanup;
    }

    // The sender may have proposed the outputs; if so ours must agree
    for (size_t i = 0; i < psbt->num_outputs; ++i) {
        const uint8_t* const claimed = claimed_scripts + (i * WALLY_SCRIPTPUBKEY_P2TR_LEN);
        uint8_t derived[WALLY_SCRIPTPUBKEY_P2TR_LEN];
        size_t written = 0;
        if (!memcmp(claimed, ZERO_SCRIPT, sizeof(derived))) {
            continue; // No script was proposed for this output
        }
        if (wally_psbt_get_output_script(psbt, i, derived, sizeof(derived), &written) != WALLY_OK
            || written != sizeof(derived) || memcmp(claimed, derived, sizeof(derived))) {
            *errmsg = "Silent payment output script mismatch";
            goto cleanup;
        }
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
    SENSITIVE_POP(seckeys);
    SENSITIVE_POP(&iter);
    free(owned_inputs);
    free(seckeys);
    free(claimed_scripts);
    return success;
}
#endif /* AMALGAMATED_BUILD */
