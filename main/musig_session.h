#ifndef MUSIG_SESSION_H_
#define MUSIG_SESSION_H_

#include "jade_assert.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct wally_musig_secnonce;

/* Stores a secnonce under the Stage C 32-byte session digest. Ownership is
 * transferred only on success. When every slot is in use, the oldest session
 * with a different digest is dropped to make room. */
WARN_UNUSED_RESULT bool musig_session_store(const uint8_t* session_digest, size_t input_index,
    const uint8_t* agg_pubkey, struct wally_musig_secnonce* secnonce, const char** errmsg);

/* Removes a slot and transfers ownership of its secnonce to the caller. */
WARN_UNUSED_RESULT bool musig_session_take(const uint8_t* session_digest, size_t input_index,
    const uint8_t* agg_pubkey, struct wally_musig_secnonce** secnonce_out);

/* Returns whether a matching, unconsumed secnonce is held. */
bool musig_session_has(const uint8_t* session_digest, size_t input_index, const uint8_t* agg_pubkey);

/* Returns whether a secnonce is held for this input under any session digest. */
bool musig_session_has_identity(size_t input_index, const uint8_t* agg_pubkey);

void musig_session_clear(void);
void musig_session_clear_digest(const uint8_t* session_digest);

#endif /* MUSIG_SESSION_H_ */
