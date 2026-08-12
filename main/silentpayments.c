#ifndef AMALGAMATED_BUILD
#include "silentpayments.h"

#include "jade_wally_verify.h"
#include "random.h"
#include "sensitive.h"
#include "utils/malloc_ext.h"
#include "utils/psbt.h"
#include "wallet.h"

#include <wally_address.h>
#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_psbt.h>
#include <wally_psbt_members.h>
#include <wally_silentpayments.h>
#include <wally_script.h>
#include <wally_transaction.h>

#include <stdlib.h>
#include <string.h>

// Entropy for the BIP375 DLEQ proofs, which wally expands per proof
#define SP_DLEQ_ENTROPY_LEN 32

bool sp_encode_address(const network_t network_id, const uint8_t* sp_v0_info, const size_t sp_v0_info_len,
    char* output, const size_t output_len)
{
    if (!sp_v0_info || sp_v0_info_len != WALLY_SP_V0_INFO_LEN || !output) {
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
    if (script_variant == P2TR) {
        // BIP352 uses the key of the taproot output key, so tweak per BIP341
        // as the signing path does. Silent payments are bitcoin-only, hence
        // no EC_FLAG_ELEMENTS here.
        return wally_ec_private_key_bip341_tweak(
                   iter->hdkey.priv_key + 1, EC_PRIVATE_KEY_LEN, NULL, 0, 0, seckey, EC_PRIVATE_KEY_LEN)
            == WALLY_OK;
    }
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

    uint8_t* const seckeys = JADE_CALLOC(psbt->num_inputs, EC_PRIVATE_KEY_LEN);
    bool* const owned_inputs = JADE_CALLOC(psbt->num_inputs, sizeof(*owned_inputs));
    key_iter iter;
    // The entropy is DLEQ nonce material, so it is wiped like the keys
    uint8_t entropy[SP_DLEQ_ENTROPY_LEN];
    SENSITIVE_PUSH(&iter, sizeof(iter));
    SENSITIVE_PUSH(seckeys, psbt->num_inputs * EC_PRIVATE_KEY_LEN);
    SENSITIVE_PUSH(entropy, sizeof(entropy));

    bool success = false;
    size_t num_seckeys = 0;

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

    // A sender may propose the output scripts; wally rejects any that
    // differ from what it derives, and leaves the psbt untouched if so
    get_random(entropy, sizeof(entropy));
    if (wally_psbt_sp_resolve(psbt, seckeys, num_seckeys * EC_PRIVATE_KEY_LEN, entropy, sizeof(entropy), 0)
        != WALLY_OK) {
        *errmsg = "Failed to derive silent payment outputs";
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
    SENSITIVE_POP(entropy);
    SENSITIVE_POP(seckeys);
    SENSITIVE_POP(&iter);
    free(owned_inputs);
    free(seckeys);
    return success;
}
#endif /* AMALGAMATED_BUILD */
