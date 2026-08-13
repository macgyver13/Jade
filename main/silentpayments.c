#ifndef AMALGAMATED_BUILD
#include "silentpayments.h"

#include "descriptor.h"
#include "jade_wally_verify.h"
#include "keychain.h"
#include "musig_session.h"
#include "random.h"
#include "sensitive.h"
#include "storage.h"
#include "utils/malloc_ext.h"
#include "utils/psbt.h"
#include "wallet.h"

#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_core.h>
#include <wally_descriptor.h>
#include <wally_map.h>
#include <wally_musig.h>
#include <wally_psbt.h>
#include <wally_psbt_members.h>
#include <wally_silentpayments.h>
#include <wally_script.h>
#include <wally_transaction.h>

#include <stdlib.h>
#include <string.h>

// Entropy for the BIP375 DLEQ proofs, which wally expands per proof
#define SP_DLEQ_ENTROPY_LEN 32
#define SP_MUSIG_PATH_LEN 2

typedef struct {
    struct wally_sp_musig_input wally;
    uint8_t agg_pubkey[EC_PUBLIC_KEY_LEN];
    uint32_t path[SP_MUSIG_PATH_LEN];
    uint8_t seckey[EC_PRIVATE_KEY_LEN];
    uint8_t participant[EC_PUBLIC_KEY_LEN];
} sp_musig_input_t;

static bool sp_musig_descriptor_matches(const network_t network_id, const uint32_t branch, const uint32_t index,
    const uint8_t* script, const size_t script_len)
{
    char names[MAX_DESCRIPTOR_REGISTRATIONS][NVS_KEY_NAME_MAX_SIZE];
    size_t num_descriptors = 0;
    if (!storage_get_all_descriptor_registration_names(
            names, sizeof(names) / sizeof(names[0]), &num_descriptors)) {
        return false;
    }
    for (size_t i = 0; i < num_descriptors; ++i) {
        descriptor_data_t descriptor;
        const char* errmsg = NULL;
        uint8_t trial_script[WALLY_SCRIPTPUBKEY_P2WSH_LEN];
        size_t trial_script_len = 0;
        if (descriptor_load_from_storage(names[i], &descriptor, &errmsg)
            && wallet_build_descriptor_script(network_id, names[i], &descriptor, branch, index, trial_script,
                sizeof(trial_script), &trial_script_len, &errmsg)
            && trial_script_len == script_len && !memcmp(trial_script, script, script_len)) {
            return true;
        }
    }
    return false;
}

static bool sp_musig_change_output_matches(const network_t network_id, const struct wally_psbt_output* output)
{
    if (output->musig2_pubkeys.num_items != 1 || !output->script_len) {
        return false;
    }
    const struct wally_map_item* const participants = &output->musig2_pubkeys.items[0];
    if (!participants->key || participants->key_len != EC_PUBLIC_KEY_LEN
        || participants->value_len < 2 * EC_PUBLIC_KEY_LEN
        || participants->value_len % EC_PUBLIC_KEY_LEN) {
        return false;
    }

    struct wally_musig_keyagg_cache* cache = NULL;
    struct ext_key* synthetic = NULL;
    struct ext_key derived;
    uint8_t aggregate[EC_PUBLIC_KEY_LEN];
    uint8_t fingerprint[BIP32_KEY_FINGERPRINT_LEN];
    uint32_t path[SP_MUSIG_PATH_LEN];
    const struct wally_map_item* internal_key
        = wally_map_get_integer(&output->psbt_fields, PSBT_OUT_TAP_INTERNAL_KEY);
    size_t found = 0;
    bool matched = false;

    if (!internal_key || internal_key->value_len != EC_XONLY_PUBLIC_KEY_LEN
        || wally_musig_pubkey_agg(participants->value, participants->value_len, NULL, 0, &cache) != WALLY_OK
        || wally_musig_pubkey_get(cache, aggregate, sizeof(aggregate)) != WALLY_OK
        || memcmp(aggregate, participants->key, sizeof(aggregate))
        || wally_musig_pubkey_to_xpub(aggregate, sizeof(aggregate), BIP32_VER_MAIN_PUBLIC, &synthetic) != WALLY_OK
        || bip32_key_get_fingerprint(synthetic, fingerprint, sizeof(fingerprint)) != WALLY_OK) {
        goto cleanup;
    }

    for (size_t i = 0; i < output->taproot_leaf_paths.num_items; ++i) {
        uint8_t item_fingerprint[BIP32_KEY_FINGERPRINT_LEN];
        size_t path_len = 0;
        const struct wally_map_item* const item = &output->taproot_leaf_paths.items[i];
        if (item->key_len == EC_XONLY_PUBLIC_KEY_LEN
            && !memcmp(item->key, internal_key->value, EC_XONLY_PUBLIC_KEY_LEN)
            && wally_map_keypath_get_item_fingerprint(
                   &output->taproot_leaf_paths, i, item_fingerprint, sizeof(item_fingerprint))
                == WALLY_OK
            && !memcmp(item_fingerprint, fingerprint, sizeof(fingerprint))
            && wally_map_keypath_get_item_path(
                   &output->taproot_leaf_paths, i, path, SP_MUSIG_PATH_LEN, &path_len)
                == WALLY_OK
            && path_len == SP_MUSIG_PATH_LEN && path[0] < BIP32_INITIAL_HARDENED_CHILD
            && path[1] < BIP32_INITIAL_HARDENED_CHILD) {
            ++found;
        }
    }
    if (found != 1
        || bip32_key_from_parent_path(synthetic, path, SP_MUSIG_PATH_LEN, BIP32_FLAG_KEY_PUBLIC, &derived)
            != WALLY_OK
        || memcmp(derived.pub_key + 1, internal_key->value, EC_XONLY_PUBLIC_KEY_LEN)) {
        goto cleanup;
    }

    /* The supplied path is a verified hint: descriptor derivation must still
     * reproduce the final script. For registered multipath wallets, item 1 is
     * the change role; path[0] is the concrete branch value supplied by the
     * coordinator and committed by the synthetic derivation above. */
    matched = path[0] == 1
        && sp_musig_descriptor_matches(network_id, path[0], path[1], output->script, output->script_len);

cleanup:
    JADE_WALLY_VERIFY(wally_musig_keyagg_cache_free(cache));
    if (synthetic) {
        JADE_WALLY_VERIFY(bip32_key_free(synthetic));
    }
    JADE_WALLY_VERIFY(wally_bzero(&derived, sizeof(derived)));
    return matched;
}

// Classify and bind one form-(b) MuSig input to a registered descriptor. The
// PSBT supplies the participant list and synthetic path, but neither is trusted
// until the registered descriptor reproduces the spent script.
static bool sp_get_musig_input(const network_t network_id, const struct wally_psbt* psbt, const size_t index,
    const bool verify_descriptor, sp_musig_input_t* output, const char** errmsg)
{
    const struct wally_psbt_input* input = &psbt->inputs[index];
    const struct wally_tx_output* utxo = NULL;
    struct wally_musig_keyagg_cache* cache = NULL;
    struct ext_key* synthetic = NULL;
    struct ext_key participant_key;
    uint8_t synthetic_fingerprint[BIP32_KEY_FINGERPRINT_LEN];
    size_t found = 0;
    bool success = false;

    if (input->musig2_pubkeys.num_items != 1 || !input->musig2_pubkeys.items[0].key
        || input->musig2_pubkeys.items[0].key_len != EC_PUBLIC_KEY_LEN
        || input->musig2_pubkeys.items[0].value_len < 2 * EC_PUBLIC_KEY_LEN
        || input->musig2_pubkeys.items[0].value_len % EC_PUBLIC_KEY_LEN) {
        *errmsg = "Invalid MuSig2 participant list";
        return false;
    }
    const struct wally_map_item* const item = &input->musig2_pubkeys.items[0];
    memcpy(output->agg_pubkey, item->key, sizeof(output->agg_pubkey));
    output->wally.index = index;
    output->wally.pub_keys = item->value;
    output->wally.pub_keys_len = item->value_len;
    output->wally.path = output->path;
    output->wally.path_len = SP_MUSIG_PATH_LEN;

    uint8_t aggregate[EC_PUBLIC_KEY_LEN];
    if (wally_musig_pubkey_agg(item->value, item->value_len, NULL, 0, &cache) != WALLY_OK
        || wally_musig_pubkey_get(cache, aggregate, sizeof(aggregate)) != WALLY_OK
        || memcmp(aggregate, output->agg_pubkey, sizeof(aggregate))
        || wally_musig_pubkey_to_xpub(
               aggregate, sizeof(aggregate), BIP32_VER_MAIN_PUBLIC, &synthetic)
            != WALLY_OK
        || bip32_key_get_fingerprint(synthetic, synthetic_fingerprint, sizeof(synthetic_fingerprint)) != WALLY_OK) {
        *errmsg = "MuSig2 aggregate does not match its participants";
        goto cleanup;
    }

    for (size_t i = 0; i < input->taproot_leaf_paths.num_items; ++i) {
        uint8_t fingerprint[BIP32_KEY_FINGERPRINT_LEN];
        size_t path_len = 0;
        if (wally_map_keypath_get_item_fingerprint(
                &input->taproot_leaf_paths, i, fingerprint, sizeof(fingerprint))
                == WALLY_OK
            && !memcmp(fingerprint, synthetic_fingerprint, sizeof(fingerprint))
            && wally_map_keypath_get_item_path(
                   &input->taproot_leaf_paths, i, output->path, SP_MUSIG_PATH_LEN, &path_len)
                == WALLY_OK
            && path_len == SP_MUSIG_PATH_LEN && output->path[0] < BIP32_INITIAL_HARDENED_CHILD
            && output->path[1] < BIP32_INITIAL_HARDENED_CHILD) {
            ++found;
        }
    }
    if (found != 1 || wally_psbt_get_input_best_utxo(psbt, index, &utxo) != WALLY_OK || !utxo
        || (verify_descriptor
            && !sp_musig_descriptor_matches(
                network_id, output->path[0], output->path[1], utxo->script, utxo->script_len))) {
        *errmsg = "MuSig2 input does not match a registered descriptor";
        goto cleanup;
    }

    found = 0;
    if (wally_map_keypath_get_bip32_key_from(
            &input->taproot_leaf_paths, 0, &keychain_get()->xpriv, &participant_key, &found)
            != WALLY_OK
        || !found || participant_key.priv_key[0] != BIP32_FLAG_KEY_PRIVATE) {
        *errmsg = "This wallet is not a MuSig2 participant";
        goto cleanup;
    }
    for (size_t i = 0; i < item->value_len; i += EC_PUBLIC_KEY_LEN) {
        if (!memcmp(participant_key.pub_key, item->value + i, EC_PUBLIC_KEY_LEN)) {
            memcpy(output->participant, participant_key.pub_key, sizeof(output->participant));
            memcpy(output->seckey, participant_key.priv_key + 1, sizeof(output->seckey));
            success = true;
            break;
        }
    }
    if (!success) {
        *errmsg = "Wallet key is not in the MuSig2 participant list";
    }

cleanup:
    JADE_WALLY_VERIFY(wally_musig_keyagg_cache_free(cache));
    if (synthetic) {
        JADE_WALLY_VERIFY(bip32_key_free(synthetic));
    }
    JADE_WALLY_VERIFY(wally_bzero(&participant_key, sizeof(participant_key)));
    return success;
}

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

bool sp_is_spend_input(const struct wally_psbt* psbt, const size_t index)
{
    size_t tweak_len = 0;
    return wally_psbt_get_input_sp_tweak_len(psbt, index, &tweak_len) == WALLY_OK && tweak_len;
}

bool sp_validate_spend_input(const struct wally_psbt* psbt, const size_t index, const char** errmsg)
{
    JADE_ASSERT(psbt);
    JADE_ASSERT(errmsg);
    JADE_ASSERT(sp_is_spend_input(psbt, index));

    // BIP376 only recommends the derivation field, and allows it to name no
    // path at all. Without one we cannot tell which of our silent payment
    // accounts the tweak applies to, so refuse rather than sign blindly.
    size_t num_keypaths = 0;
    JADE_WALLY_VERIFY(wally_psbt_get_input_sp_spend_keypaths_size(psbt, index, &num_keypaths));
    if (!num_keypaths) {
        *errmsg = "Silent payment input missing spend key derivation";
        return false;
    }
    return true;
}

bool sp_validate_spend_key_path(const network_t network_id, const key_iter* iter, const char** errmsg)
{
    JADE_ASSERT(iter);
    JADE_ASSERT(errmsg);

    uint32_t path[SP_KEY_PATH_LEN];
    size_t path_len = 0;
    if (!key_iter_get_path(iter, path, SP_KEY_PATH_LEN, &path_len)
        || !wallet_is_expected_sp_spend_path(network_id, path, path_len)) {
        *errmsg = "Unexpected silent payment spend key path";
        return false;
    }
    return true;
}

// Read the private key of an input this wallet owns.
// NOTE: we only produce a BIP375 *global* ECDH share, which covers the sum of all
// eligible inputs - so we must own all of them. Failing to own one is fatal here.
// TODO: support collaborative sending, ie. write per-input shares and proofs
// with wally_psbt_input_set_sp_{ecdh_share,dleq_proof}() for the inputs we do
// own, verify other signers' proofs for the rest, and defer PSBT_OUT_SCRIPT
// until every eligible input has a share.
// Read the private key of an input this wallet owns. Returning false is not
// necessarily fatal: a signer that owns only some of the eligible inputs can
// still contribute a per-input share for each one it does own. An input that
// is ours but cannot be signed says so through errmsg, and that is fatal.
static bool sp_get_input_key(const network_t network_id, const struct wally_psbt* psbt, const size_t index,
    key_iter* iter, uint8_t* seckey, const char** errmsg)
{
    const struct wally_tx_output* utxo = NULL;
    size_t script_type = WALLY_SCRIPT_TYPE_UNKNOWN;
    script_variant_t script_variant;
    if (wally_psbt_get_input_best_utxo(psbt, index, &utxo) != WALLY_OK || !utxo
        || wally_scriptpubkey_get_type(utxo->script, utxo->script_len, &script_type) != WALLY_OK) {
        return false;
    }
    if (sp_is_spend_input(psbt, index)) {
        // A silent payment we received, being spent to make another one. Its
        // key comes from no path we can check a script against, so wally
        // verifies it against the output being spent instead.
        if (!sp_validate_spend_input(psbt, index, errmsg)) {
            return false;
        }
        return key_iter_input_begin(psbt, index, iter) && key_iter_get_num_keys(iter) == 1
            && sp_validate_spend_key_path(network_id, iter, errmsg)
            && wally_psbt_get_input_sp_spend_key(psbt, index, &iter->hdkey, seckey, EC_PRIVATE_KEY_LEN) == WALLY_OK;
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

// Count the psbt's silent payment outputs
static size_t sp_num_outputs(const struct wally_psbt* psbt)
{
    size_t num_sp_outputs = 0;
    for (size_t i = 0; i < psbt->num_outputs; ++i) {
        size_t info_len = 0;
        if (wally_psbt_get_output_sp_v0_info_len(psbt, i, &info_len) == WALLY_OK && info_len) {
            ++num_sp_outputs;
        }
    }
    return num_sp_outputs;
}

// Check the psbt's shares and proofs, whoever wrote them, and that its inputs
// can be signed at all. Returns false with *errmsg set if not.
static bool sp_check_psbt(const struct wally_psbt* psbt, size_t* sp_status, const char** errmsg)
{
    for (size_t i = 0; i < psbt->num_inputs; ++i) {
        const struct wally_psbt_input* const input = &psbt->inputs[i];
        if (input->sighash && input->sighash != WALLY_SIGHASH_ALL) {
            *errmsg = "Silent payments require SIGHASH_ALL";
            return false;
        }
    }

    const int status_ret = wally_psbt_get_sp_status(psbt, 0, sp_status);
    if (status_ret == WALLY_ERROR) {
        // An input wally cannot classify, eg. an unknown witness version
        *errmsg = "Silent payments do not support Segwit versions above 1";
        return false;
    }
    if (status_ret != WALLY_OK || *sp_status == WALLY_SP_INVALID) {
        *errmsg = "Silent payment ECDH shares or DLEQ proofs are invalid";
        return false;
    }
    return true;
}

// Whether an eligible input we do not own already carries a share for every
// recipient scan key, ie. whether another signer has covered it for us. The
// shares present are known valid, sp_check_psbt() having verified them.
static bool sp_input_is_covered(const struct wally_psbt* psbt, const size_t index)
{
    for (size_t i = 0; i < psbt->num_outputs; ++i) {
        uint8_t sp_info[WALLY_SP_V0_INFO_LEN];
        size_t written = 0, found = 0;
        if (wally_psbt_get_output_sp_v0_info(psbt, i, sp_info, sizeof(sp_info), &written) != WALLY_OK || !written) {
            continue;
        }
        // The scan key is the first half of the output's sp v0 info. A global
        // share for it covers every eligible input at once; failing that, this
        // input must carry its own. Every scan key must be covered, not just
        // some, or the outputs still cannot be derived.
        if (wally_psbt_find_global_sp_ecdh_share(psbt, sp_info, EC_PUBLIC_KEY_LEN, &found) == WALLY_OK && found) {
            continue;
        }
        if (wally_psbt_find_input_sp_ecdh_share(psbt, index, sp_info, EC_PUBLIC_KEY_LEN, &found) != WALLY_OK
            || !found) {
            return false;
        }
    }
    return true;
}

// Classify the eligible inputs by whether we hold their keys, collecting the
// keys of those we do. 'owned_inputs' marks every input we can sign, eligible
// or not, and 'indices' the eligible ones we own, in input order.
static bool sp_classify_inputs(const network_t network_id, const struct wally_psbt* psbt, const bool resolved,
    key_iter* iter, uint8_t* seckeys, size_t* indices, bool* owned_inputs, sp_summary_t* summary, const char** errmsg)
{
    for (size_t i = 0; i < psbt->num_inputs; ++i) {
        size_t is_eligible = 0;
        if (wally_psbt_get_input_sp_eligible(psbt, i, &is_eligible) != WALLY_OK) {
            // WALLY_ERROR is impossible here, having been ruled out already
            *errmsg = "Silent payment input utxo missing";
            return false;
        }
        if (!is_eligible || resolved) {
            // Nothing to contribute: we only need to know whether we can sign
            // it. A resolved psbt needs no key of ours but the signing key.
            owned_inputs[i] = key_iter_input_begin_public(psbt, i, iter);
            continue;
        }
        // A silent payment input can say specifically why it cannot be signed.
        // That is fatal however many of the others we could contribute for.
        const char* sp_errmsg = NULL;
        if (sp_get_input_key(
                network_id, psbt, i, iter, seckeys + (summary->num_inputs_ours * EC_PRIVATE_KEY_LEN), &sp_errmsg)) {
            indices[summary->num_inputs_ours] = i;
            ++summary->num_inputs_ours;
            owned_inputs[i] = true;
        } else if (sp_errmsg) {
            *errmsg = sp_errmsg;
            return false;
        } else if (sp_input_is_covered(psbt, i)) {
            ++summary->num_inputs_covered;
        } else {
            ++summary->num_inputs_uncovered;
        }
    }
    return true;
}

// Fill in the recipients of the payment, which the psbt names whether or not
// the outputs have been derived from them yet
static bool sp_summarise_recipients(
    const network_t network_id, const struct wally_psbt* psbt, sp_summary_t* summary, const char** errmsg)
{
    for (size_t i = 0; i < psbt->num_outputs; ++i) {
        uint8_t sp_info[WALLY_SP_V0_INFO_LEN];
        size_t written = 0;
        if (wally_psbt_get_output_sp_v0_info(psbt, i, sp_info, sizeof(sp_info), &written) != WALLY_OK || !written) {
            if (sp_musig_change_output_matches(network_id, &psbt->outputs[i])) {
                ++summary->num_change_outputs;
            } else {
                ++summary->num_other_outputs;
            }
            continue;
        }
        ++summary->num_recipients;
        if (summary->num_recipients_shown == SP_MAX_SUMMARY_RECIPIENTS) {
            continue; // Too many to show; the count still tells the user so
        }
        char* const address = summary->recipients[summary->num_recipients_shown];
        if (!sp_encode_address(network_id, sp_info, written, address, MAX_ADDRESS_LEN)) {
            *errmsg = "Failed to encode Silent Payment address";
            return false;
        }
        if (wally_psbt_get_output_amount(psbt, i,
                &summary->recipient_amounts[summary->num_recipients_shown])
            != WALLY_OK) {
            *errmsg = "Silent Payment output amount missing";
            return false;
        }
        ++summary->num_recipients_shown;
    }
    return true;
}

static bool sp_has_musig_inputs(const struct wally_psbt* psbt)
{
    for (size_t i = 0; i < psbt->num_inputs; ++i) {
        if (psbt->inputs[i].musig2_pubkeys.num_items) {
            return true;
        }
    }
    return false;
}

static bool sp_collect_musig_inputs(const network_t network_id, const struct wally_psbt* psbt,
    const bool verify_descriptor, sp_musig_input_t* musig_inputs, const size_t musig_inputs_len, size_t* written,
    const char** errmsg)
{
    *written = 0;
    for (size_t i = 0; i < psbt->num_inputs; ++i) {
        const struct wally_psbt_input* input = &psbt->inputs[i];
        if (!input->musig2_pubkeys.num_items) {
            continue;
        }
        size_t is_eligible = 0;
        if (*written == musig_inputs_len || wally_psbt_get_input_sp_eligible(psbt, i, &is_eligible) != WALLY_OK
            || !is_eligible) {
            *errmsg = "All MuSig2 inputs must be silent-payment eligible";
            return false;
        }
        if (!sp_get_musig_input(network_id, psbt, i, verify_descriptor, &musig_inputs[*written], errmsg)) {
            return false;
        }
        ++*written;
    }
    return *written != 0;
}

static bool sp_musig_participant_has_nonce(
    const struct wally_psbt_input* input, const uint8_t* participant)
{
    for (size_t i = 0; i < input->musig2_pubnonces.num_items; ++i) {
        const struct wally_map_item* const nonce = &input->musig2_pubnonces.items[i];
        if (nonce->key_len == 2 * EC_PUBLIC_KEY_LEN
            && !memcmp(nonce->key, participant, EC_PUBLIC_KEY_LEN)) {
            return true;
        }
    }
    return false;
}

static bool sp_process_musig_psbt(const network_t network_id, const struct wally_psbt* psbt,
    sp_summary_t* summary, sp_result_t* result, const char** errmsg)
{
    sp_musig_input_t* const inputs = JADE_CALLOC(psbt->num_inputs, sizeof(*inputs));
    SENSITIVE_PUSH(inputs, psbt->num_inputs * sizeof(*inputs));
    size_t num_inputs = 0;
    bool success = false;

    if (!(storage_get_qr_flags() & SP_COLLABORATIVE)) {
        *errmsg = "Collaborative silent payments are disabled - enable in Settings";
        goto cleanup;
    }
    if (!sp_collect_musig_inputs(network_id, psbt, true, inputs, psbt->num_inputs, &num_inputs, errmsg)
        || !sp_summarise_recipients(network_id, psbt, summary, errmsg)) {
        goto cleanup;
    }
    summary->num_inputs_ours = num_inputs;
    key_iter iter;
    uint8_t ordinary_seckey[EC_PRIVATE_KEY_LEN];
    SENSITIVE_PUSH(&iter, sizeof(iter));
    SENSITIVE_PUSH(ordinary_seckey, sizeof(ordinary_seckey));
    for (size_t i = 0; i < psbt->num_inputs; ++i) {
        size_t is_eligible = 0;
        if (psbt->inputs[i].musig2_pubkeys.num_items
            || wally_psbt_get_input_sp_eligible(psbt, i, &is_eligible) != WALLY_OK || !is_eligible) {
            continue;
        }
        // sp_process_psbt() has already rejected any input of ours that cannot
        // be signed, so a failure here only means the input is not ours
        const char* sp_errmsg = NULL;
        if (sp_get_input_key(network_id, psbt, i, &iter, ordinary_seckey, &sp_errmsg)) {
            ++summary->num_inputs_ours;
        } else if (sp_input_is_covered(psbt, i)) {
            ++summary->num_inputs_covered;
        } else {
            ++summary->num_inputs_uncovered;
        }
    }
    SENSITIVE_POP(ordinary_seckey);
    SENSITIVE_POP(&iter);

    size_t num_with_our_nonce = 0;
    bool all_nonces_present = true;
    for (size_t i = 0; i < num_inputs; ++i) {
        const struct wally_psbt_input* const input = &psbt->inputs[inputs[i].wally.index];
        if (sp_musig_participant_has_nonce(input, inputs[i].participant)) {
            ++num_with_our_nonce;
        }
        for (size_t j = 0; j < inputs[i].wally.pub_keys_len; j += EC_PUBLIC_KEY_LEN) {
            all_nonces_present
                &= sp_musig_participant_has_nonce(input, inputs[i].wally.pub_keys + j);
        }
    }
    if (!num_with_our_nonce) {
        *result = SP_MUSIG_CONTRIBUTE;
        success = true;
        goto cleanup;
    }
    if (num_with_our_nonce != num_inputs || !all_nonces_present) {
        *errmsg = "Silent payment outputs do not match the shares";
        goto cleanup;
    }

    uint8_t stored_digest[SHA256_LEN], digest[SHA256_LEN];
    if (!musig_session_get_digest(inputs[0].wally.index, inputs[0].agg_pubkey, stored_digest)) {
        *errmsg = "Signing session expired";
        goto cleanup;
    }
    for (size_t i = 1; i < num_inputs; ++i) {
        uint8_t other_digest[SHA256_LEN];
        if (!musig_session_get_digest(inputs[i].wally.index, inputs[i].agg_pubkey, other_digest)) {
            *errmsg = "Signing session expired";
            goto cleanup;
        }
        if (memcmp(stored_digest, other_digest, sizeof(stored_digest))) {
            *errmsg = "Transaction changed between rounds";
            goto cleanup;
        }
    }
    if (wally_psbt_get_sp_musig_session_digest(psbt, digest, sizeof(digest)) != WALLY_OK
        || memcmp(stored_digest, digest, sizeof(digest))) {
        *errmsg = "Transaction changed between rounds";
        goto cleanup;
    }
    struct wally_sp_musig_input* const values = JADE_CALLOC(num_inputs, sizeof(*values));
    for (size_t i = 0; i < num_inputs; ++i) {
        values[i] = inputs[i].wally;
    }
    size_t status = WALLY_SP_INVALID;
    const int status_ret = wally_psbt_get_sp_musig_status(psbt, values, num_inputs, 0, &status);
    free(values);
    if (status_ret != WALLY_OK || status != WALLY_SP_COMPLETE) {
        *errmsg = "Silent payment outputs do not match the shares";
        goto cleanup;
    }
    *result = SP_MUSIG_SIGN;
    success = true;

cleanup:
    SENSITIVE_POP(inputs);
    free(inputs);
    return success;
}

// Pin the inputs we sign to SIGHASH_ALL and fix the psbt's inputs and outputs,
// as BIP375 requires of a resolved silent payment
static void sp_finalise_resolved(struct wally_psbt* psbt, const bool* owned_inputs)
{
    for (size_t i = 0; i < psbt->num_inputs; ++i) {
        if (owned_inputs[i]) {
            JADE_WALLY_VERIFY(wally_psbt_set_input_sighash(psbt, i, WALLY_SIGHASH_ALL));
        }
    }
    size_t mod_flags = 0;
    JADE_WALLY_VERIFY(wally_psbt_get_tx_modifiable_flags(psbt, &mod_flags));
    JADE_WALLY_VERIFY(wally_psbt_set_tx_modifiable_flags(
        psbt, mod_flags & ~(WALLY_PSBT_TXMOD_INPUTS | WALLY_PSBT_TXMOD_OUTPUTS)));
}

bool sp_process_psbt(const network_t network_id, struct wally_psbt* psbt, sp_summary_t* summary, sp_result_t* result,
    const char** errmsg)
{
    JADE_ASSERT(psbt);
    JADE_ASSERT(summary);
    JADE_ASSERT(result);
    JADE_ASSERT(errmsg);

    memset(summary, 0, sizeof(*summary));
    *result = SP_NONE;

    if (!sp_num_outputs(psbt)) {
        return true;
    }

    if (sp_has_musig_inputs(psbt)) {
        return sp_process_musig_psbt(network_id, psbt, summary, result, errmsg);
    }

    size_t sp_status = WALLY_SP_INVALID;
    if (!sp_check_psbt(psbt, &sp_status, errmsg)) {
        return false;
    }

    // Another signer may have resolved the outputs already, in which case we
    // sign what they produced rather than deriving it ourselves. That needs no
    // private key but our own, so we need not own every eligible input: a
    // complete status means every output script is the one BIP352 derives from
    // the shares, which the DLEQ proofs bind to the inputs being spent.
    const bool resolved = sp_status == WALLY_SP_COMPLETE;

    uint8_t* const seckeys = JADE_CALLOC(psbt->num_inputs, EC_PRIVATE_KEY_LEN);
    size_t* const indices = JADE_CALLOC(psbt->num_inputs, sizeof(*indices));
    bool* const owned_inputs = JADE_CALLOC(psbt->num_inputs, sizeof(*owned_inputs));
    key_iter iter;
    uint8_t entropy[SP_DLEQ_ENTROPY_LEN];
    SENSITIVE_PUSH(&iter, sizeof(iter));
    SENSITIVE_PUSH(seckeys, psbt->num_inputs * EC_PRIVATE_KEY_LEN);
    SENSITIVE_PUSH(entropy, sizeof(entropy));

    bool success = false;

    if (!sp_classify_inputs(network_id, psbt, resolved, &iter, seckeys, indices, owned_inputs, summary, errmsg)) {
        goto cleanup;
    }

    if (!resolved) {
        if (!summary->num_inputs_ours) {
            *errmsg = summary->num_inputs_covered || summary->num_inputs_uncovered
                ? "This wallet owns none of the silent payment's eligible inputs"
                : "Silent payment has no eligible inputs";
            goto cleanup;
        }
        if (summary->num_inputs_covered || summary->num_inputs_uncovered) {
            // We own only some of the eligible inputs, so we cannot derive the
            // outputs alone. Report what we would contribute and leave the psbt
            // untouched: the user confirms before anything is written.
            if (!(storage_get_qr_flags() & SP_COLLABORATIVE)) {
                *errmsg = "Collaborative silent payments are disabled - enable in Settings";
                goto cleanup;
            }
            if (!sp_summarise_recipients(network_id, psbt, summary, errmsg)) {
                goto cleanup;
            }
            *result = SP_CONTRIBUTE;
            success = true;
            goto cleanup;
        }

        // We own every eligible input, so one global share covers them all.
        // A sender may propose the output scripts; wally rejects any that
        // differ from what it derives, and leaves the psbt untouched if so
        get_random(entropy, sizeof(entropy));
        if (wally_psbt_sp_resolve(
                psbt, seckeys, summary->num_inputs_ours * EC_PRIVATE_KEY_LEN, entropy, sizeof(entropy), 0)
            != WALLY_OK) {
            *errmsg = "Failed to derive silent payment outputs, or a proposed script did not match";
            goto cleanup;
        }
    }

    sp_finalise_resolved(psbt, owned_inputs);
    *result = SP_SIGN;
    success = true;

cleanup:
    SENSITIVE_POP(entropy);
    SENSITIVE_POP(seckeys);
    SENSITIVE_POP(&iter);
    free(owned_inputs);
    free(indices);
    free(seckeys);
    return success;
}

bool sp_contribute_psbt(
    const network_t network_id, struct wally_psbt* psbt, sp_result_t* result, const char** errmsg)
{
    JADE_ASSERT(psbt);
    JADE_ASSERT(result);
    JADE_ASSERT(errmsg);

    *result = SP_NONE;

    // Both checks are only reachable if the psbt changed since sp_process_psbt()
    if (!sp_num_outputs(psbt)) {
        *errmsg = "Not a silent payment";
        return false;
    }

    if (sp_has_musig_inputs(psbt)) {
        sp_musig_input_t* const inputs = JADE_CALLOC(psbt->num_inputs, sizeof(*inputs));
        struct wally_sp_musig_input* const values = JADE_CALLOC(psbt->num_inputs, sizeof(*values));
        struct wally_musig_secnonce** const secnonces = JADE_CALLOC(psbt->num_inputs, sizeof(*secnonces));
        uint8_t* const seckeys = JADE_CALLOC(psbt->num_inputs, EC_PRIVATE_KEY_LEN);
        uint8_t* const ordinary_seckeys = JADE_CALLOC(psbt->num_inputs, EC_PRIVATE_KEY_LEN);
        size_t* const ordinary_indices = JADE_CALLOC(psbt->num_inputs, sizeof(*ordinary_indices));
        uint8_t* const entropy = JADE_CALLOC(psbt->num_inputs + 1, SHA256_LEN);
        uint8_t ordinary_entropy[SP_DLEQ_ENTROPY_LEN];
        uint8_t digest[SHA256_LEN];
        struct wally_psbt* staged = NULL;
        size_t num_inputs = 0, num_ordinary_inputs = 0, status = WALLY_SP_INVALID;
        bool success = false;
        key_iter iter;
        SENSITIVE_PUSH(&iter, sizeof(iter));
        SENSITIVE_PUSH(inputs, psbt->num_inputs * sizeof(*inputs));
        SENSITIVE_PUSH(seckeys, psbt->num_inputs * EC_PRIVATE_KEY_LEN);
        SENSITIVE_PUSH(ordinary_seckeys, psbt->num_inputs * EC_PRIVATE_KEY_LEN);
        SENSITIVE_PUSH(entropy, (psbt->num_inputs + 1) * SHA256_LEN);
        SENSITIVE_PUSH(ordinary_entropy, sizeof(ordinary_entropy));

        if (!sp_collect_musig_inputs(network_id, psbt, false, inputs, psbt->num_inputs, &num_inputs, errmsg)) {
            goto musig_cleanup;
        }
        for (size_t i = 0; i < num_inputs; ++i) {
            values[i] = inputs[i].wally;
            memcpy(seckeys + i * EC_PRIVATE_KEY_LEN, inputs[i].seckey, EC_PRIVATE_KEY_LEN);
            uint8_t old_digest[SHA256_LEN];
            if (musig_session_get_digest(inputs[i].wally.index, inputs[i].agg_pubkey, old_digest)) {
                musig_session_clear_digest(old_digest);
            }
        }
        // As above: an input of ours that cannot be signed is already refused
        const char* sp_errmsg = NULL;
        for (size_t i = 0; i < psbt->num_inputs; ++i) {
            size_t is_eligible = 0;
            if (!psbt->inputs[i].musig2_pubkeys.num_items
                && wally_psbt_get_input_sp_eligible(psbt, i, &is_eligible) == WALLY_OK && is_eligible
                && sp_get_input_key(network_id, psbt, i, &iter,
                    ordinary_seckeys + num_ordinary_inputs * EC_PRIVATE_KEY_LEN, &sp_errmsg)) {
                ordinary_indices[num_ordinary_inputs++] = i;
            }
        }
        if (wally_psbt_clone_alloc(psbt, 0, &staged) != WALLY_OK) {
            *errmsg = "Failed to prepare MuSig2 silent payment round";
            goto musig_cleanup;
        }
        if (num_ordinary_inputs) {
            get_random(ordinary_entropy, sizeof(ordinary_entropy));
            if (wally_psbt_sp_contribute(staged, ordinary_indices, num_ordinary_inputs, ordinary_seckeys,
                    num_ordinary_inputs * EC_PRIVATE_KEY_LEN, ordinary_entropy, sizeof(ordinary_entropy), 0)
                != WALLY_OK) {
                *errmsg = "Failed to add ordinary silent payment shares";
                goto musig_cleanup;
            }
        }
        get_random(entropy, (num_inputs + 1) * SHA256_LEN);
        if (wally_psbt_sp_musig_round1(staged, values, num_inputs, seckeys,
                num_inputs * EC_PRIVATE_KEY_LEN, entropy, (num_inputs + 1) * SHA256_LEN, 0, secnonces, digest,
                sizeof(digest), &status)
            != WALLY_OK) {
            *errmsg = "Failed to add MuSig2 silent payment shares";
            goto musig_cleanup;
        }
        for (size_t i = 0; i < num_inputs; ++i) {
            if (!musig_session_store(
                    digest, inputs[i].wally.index, inputs[i].agg_pubkey, secnonces[i], errmsg)) {
                musig_session_clear_digest(digest);
                goto musig_cleanup;
            }
            secnonces[i] = NULL;
        }
        {
            struct wally_psbt old = *psbt;
            *psbt = *staged;
            *staged = old;
        }
        *result = SP_SHARES_ONLY;
        success = true;

musig_cleanup:
        for (size_t i = 0; i < num_inputs; ++i) {
            JADE_WALLY_VERIFY(wally_musig_secnonce_free(secnonces[i]));
        }
        JADE_WALLY_VERIFY(wally_psbt_free(staged));
        SENSITIVE_POP(ordinary_entropy);
        SENSITIVE_POP(entropy);
        SENSITIVE_POP(ordinary_seckeys);
        SENSITIVE_POP(seckeys);
        SENSITIVE_POP(inputs);
        SENSITIVE_POP(&iter);
        free(entropy);
        free(ordinary_indices);
        free(ordinary_seckeys);
        free(seckeys);
        free(secnonces);
        free(values);
        free(inputs);
        return success;
    }
    size_t sp_status = WALLY_SP_INVALID;
    if (!sp_check_psbt(psbt, &sp_status, errmsg)) {
        return false;
    }

    uint8_t* const seckeys = JADE_CALLOC(psbt->num_inputs, EC_PRIVATE_KEY_LEN);
    size_t* const indices = JADE_CALLOC(psbt->num_inputs, sizeof(*indices));
    bool* const owned_inputs = JADE_CALLOC(psbt->num_inputs, sizeof(*owned_inputs));
    key_iter iter;
    uint8_t entropy[SP_DLEQ_ENTROPY_LEN];
    SENSITIVE_PUSH(&iter, sizeof(iter));
    SENSITIVE_PUSH(seckeys, psbt->num_inputs * EC_PRIVATE_KEY_LEN);
    SENSITIVE_PUSH(entropy, sizeof(entropy));

    sp_summary_t summary = { 0 };
    bool success = false;

    if (!sp_classify_inputs(network_id, psbt, false, &iter, seckeys, indices, owned_inputs, &summary, errmsg)) {
        goto cleanup;
    }
    if (!summary.num_inputs_ours) {
        *errmsg = "This wallet owns none of the silent payment's eligible inputs";
        goto cleanup;
    }

    get_random(entropy, sizeof(entropy));
    if (wally_psbt_sp_contribute(psbt, indices, summary.num_inputs_ours, seckeys,
            summary.num_inputs_ours * EC_PRIVATE_KEY_LEN, entropy, sizeof(entropy), 0)
        != WALLY_OK) {
        *errmsg = "Failed to add silent payment shares";
        goto cleanup;
    }

    // Our shares may have been the last ones missing, in which case we can
    // derive the outputs and go on to sign in this same pass. Resolving fails
    // where the coverage is still incomplete, which is not an error here.
    if (wally_psbt_sp_resolve_shares(psbt, 0) == WALLY_OK) {
        sp_finalise_resolved(psbt, owned_inputs);
        *result = SP_SIGN;
    } else {
        // Still waiting on another signer. The psbt keeps its modifiable flags
        // and its inputs are left unsigned: SIGHASH_ALL commits to outputs
        // which do not exist yet.
        *result = SP_SHARES_ONLY;
    }
    success = true;

cleanup:
    SENSITIVE_POP(entropy);
    SENSITIVE_POP(seckeys);
    SENSITIVE_POP(&iter);
    free(owned_inputs);
    free(indices);
    free(seckeys);
    return success;
}

bool sp_musig_sign_psbt(
    const network_t network_id, struct wally_psbt* psbt, bool* musig_inputs, const char** errmsg)
{
    JADE_ASSERT(psbt);
    JADE_ASSERT(musig_inputs);
    JADE_INIT_OUT_PPTR(errmsg);

    sp_musig_input_t* const inputs = JADE_CALLOC(psbt->num_inputs, sizeof(*inputs));
    struct wally_sp_musig_input* const values = JADE_CALLOC(psbt->num_inputs, sizeof(*values));
    struct wally_musig_secnonce** const secnonces = JADE_CALLOC(psbt->num_inputs, sizeof(*secnonces));
    uint8_t* const seckeys = JADE_CALLOC(psbt->num_inputs, EC_PRIVATE_KEY_LEN);
    uint8_t digest[SHA256_LEN];
    size_t num_inputs = 0;
    bool success = false, have_digest = false;
    SENSITIVE_PUSH(inputs, psbt->num_inputs * sizeof(*inputs));
    SENSITIVE_PUSH(seckeys, psbt->num_inputs * EC_PRIVATE_KEY_LEN);

    if (!sp_collect_musig_inputs(network_id, psbt, false, inputs, psbt->num_inputs, &num_inputs, errmsg)
        || !musig_session_get_digest(inputs[0].wally.index, inputs[0].agg_pubkey, digest)) {
        if (!*errmsg) {
            *errmsg = "Signing session expired";
        }
        goto cleanup;
    }
    have_digest = true;
    for (size_t i = 0; i < num_inputs; ++i) {
        values[i] = inputs[i].wally;
        memcpy(seckeys + i * EC_PRIVATE_KEY_LEN, inputs[i].seckey, EC_PRIVATE_KEY_LEN);
        if (!musig_session_take(digest, inputs[i].wally.index, inputs[i].agg_pubkey, &secnonces[i])) {
            *errmsg = "Signing session expired";
            goto cleanup;
        }
    }
    // Once taken, every nonce in this session is considered spent on every
    // path, including a libwally validation or signing failure.
    musig_session_clear_digest(digest);
    if (wally_psbt_sp_musig_round2(psbt, values, num_inputs, seckeys, num_inputs * EC_PRIVATE_KEY_LEN, secnonces,
            digest, sizeof(digest), 0)
        != WALLY_OK) {
        *errmsg = "Failed to sign MuSig2 silent payment inputs";
        goto cleanup;
    }
    for (size_t i = 0; i < num_inputs; ++i) {
        musig_inputs[inputs[i].wally.index] = true;
    }
    success = true;

cleanup:
    if (have_digest) {
        musig_session_clear_digest(digest);
    }
    for (size_t i = 0; i < num_inputs; ++i) {
        JADE_WALLY_VERIFY(wally_musig_secnonce_free(secnonces[i]));
    }
    SENSITIVE_POP(seckeys);
    SENSITIVE_POP(inputs);
    free(seckeys);
    free(secnonces);
    free(values);
    free(inputs);
    return success;
}
#endif /* AMALGAMATED_BUILD */
