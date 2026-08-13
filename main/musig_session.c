#ifndef AMALGAMATED_BUILD
#include "musig_session.h"

#include "jade_wally_verify.h"

#include <string.h>
#include <wally_crypto.h>
#include <wally_musig.h>

#define MUSIG_MAX_NONCE_SLOTS 8

typedef struct {
    bool in_use;
    uint32_t stored_at; // Store order, to find the oldest session when full
    uint8_t session_digest[SHA256_LEN];
    size_t input_index;
    uint8_t agg_pubkey[EC_PUBLIC_KEY_LEN];
    struct wally_musig_secnonce* secnonce;
} musig_slot_t;

static musig_slot_t slots[MUSIG_MAX_NONCE_SLOTS];
static uint32_t store_count;

static bool slot_identity_matches(const musig_slot_t* slot, size_t input_index, const uint8_t* agg_pubkey)
{
    return slot->in_use && slot->input_index == input_index
        && !memcmp(slot->agg_pubkey, agg_pubkey, sizeof(slot->agg_pubkey));
}

static bool slot_matches(
    const musig_slot_t* slot, const uint8_t* session_digest, size_t input_index, const uint8_t* agg_pubkey)
{
    return slot_identity_matches(slot, input_index, agg_pubkey)
        && !memcmp(slot->session_digest, session_digest, sizeof(slot->session_digest));
}

static void slot_clear(musig_slot_t* slot)
{
    if (slot->secnonce) {
        JADE_WALLY_VERIFY(wally_musig_secnonce_free(slot->secnonce));
    }
    JADE_WALLY_VERIFY(wally_bzero(slot, sizeof(*slot)));
}

bool musig_session_store(const uint8_t* session_digest, size_t input_index, const uint8_t* agg_pubkey,
    struct wally_musig_secnonce* secnonce, const char** errmsg)
{
    JADE_ASSERT(session_digest);
    JADE_ASSERT(agg_pubkey);
    JADE_ASSERT(secnonce);
    JADE_INIT_OUT_PPTR(errmsg);

    musig_slot_t* available = NULL;
    musig_slot_t* oldest = NULL;
    for (size_t i = 0; i < MUSIG_MAX_NONCE_SLOTS; ++i) {
        if (slot_matches(&slots[i], session_digest, input_index, agg_pubkey)) {
            *errmsg = "Nonce already stored for input";
            return false;
        }
        if (!slots[i].in_use) {
            if (!available) {
                available = &slots[i];
            }
        } else if (memcmp(slots[i].session_digest, session_digest, sizeof(slots[i].session_digest))
            && (!oldest || slots[i].stored_at < oldest->stored_at)) {
            oldest = &slots[i];
        }
    }

    if (!available && oldest) {
        // Drop the oldest other session whole. That can only make it expire,
        // never let one of its nonces be used twice.
        uint8_t oldest_digest[SHA256_LEN];
        memcpy(oldest_digest, oldest->session_digest, sizeof(oldest_digest));
        musig_session_clear_digest(oldest_digest);
        available = oldest;
    }
    if (!available) {
        *errmsg = "Too many inputs to co-sign";
        return false;
    }

    available->in_use = true;
    available->stored_at = store_count++;
    memcpy(available->session_digest, session_digest, sizeof(available->session_digest));
    available->input_index = input_index;
    memcpy(available->agg_pubkey, agg_pubkey, sizeof(available->agg_pubkey));
    available->secnonce = secnonce;
    return true;
}

bool musig_session_take(const uint8_t* session_digest, size_t input_index, const uint8_t* agg_pubkey,
    struct wally_musig_secnonce** secnonce_out)
{
    JADE_ASSERT(session_digest);
    JADE_ASSERT(agg_pubkey);
    JADE_INIT_OUT_PPTR(secnonce_out);

    for (size_t i = 0; i < MUSIG_MAX_NONCE_SLOTS; ++i) {
        if (slot_matches(&slots[i], session_digest, input_index, agg_pubkey)) {
            *secnonce_out = slots[i].secnonce;
            slots[i].secnonce = NULL;
            JADE_WALLY_VERIFY(wally_bzero(&slots[i], sizeof(slots[i])));
            return true;
        }
    }
    return false;
}

bool musig_session_has(const uint8_t* session_digest, size_t input_index, const uint8_t* agg_pubkey)
{
    JADE_ASSERT(session_digest);
    JADE_ASSERT(agg_pubkey);

    for (size_t i = 0; i < MUSIG_MAX_NONCE_SLOTS; ++i) {
        if (slot_matches(&slots[i], session_digest, input_index, agg_pubkey)) {
            return true;
        }
    }
    return false;
}

bool musig_session_has_identity(size_t input_index, const uint8_t* agg_pubkey)
{
    JADE_ASSERT(agg_pubkey);

    for (size_t i = 0; i < MUSIG_MAX_NONCE_SLOTS; ++i) {
        if (slot_identity_matches(&slots[i], input_index, agg_pubkey)) {
            return true;
        }
    }
    return false;
}

void musig_session_clear(void)
{
    for (size_t i = 0; i < MUSIG_MAX_NONCE_SLOTS; ++i) {
        slot_clear(&slots[i]);
    }
}

void musig_session_clear_digest(const uint8_t* session_digest)
{
    JADE_ASSERT(session_digest);

    for (size_t i = 0; i < MUSIG_MAX_NONCE_SLOTS; ++i) {
        if (slots[i].in_use && !memcmp(slots[i].session_digest, session_digest, sizeof(slots[i].session_digest))) {
            slot_clear(&slots[i]);
        }
    }
}
#endif // AMALGAMATED_BUILD
