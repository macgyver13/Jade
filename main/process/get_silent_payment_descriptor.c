#ifndef AMALGAMATED_BUILD
#include "../jade_assert.h"
#include "../keychain.h"
#include "../process.h"
#include "../silentpayments.h"
#include "../utils/cbor_rpc.h"
#include "../utils/network.h"

#include "process_utils.h"

// Must match the account index limit offered by the qr export options
#define SP_ACCOUNT_INDEX_MAX 65536

void get_silent_payment_descriptor_process(void* process_ptr)
{
    JADE_LOGI("Starting: %d", xPortGetFreeHeapSize());
    jade_process_t* process = process_ptr;

    ASSERT_CURRENT_MESSAGE(process, "get_silent_payment_descriptor");
    ASSERT_KEYCHAIN_UNLOCKED_BY_MESSAGE_SOURCE(process);
    GET_MSG_PARAMS(process);
    CHECK_NETWORK_CONSISTENT(process);

    if (network_is_liquid(network_id)) {
        jade_process_reject_message(
            process, CBOR_RPC_BAD_PARAMETERS, "Silent payments are not supported on liquid networks");
        goto cleanup;
    }

    // account is optional, but must be valid if present
    uint32_t account_index = 0;
    if (rpc_has_field_data("account", &params)) {
        if (!rpc_get_uint32("account", &params, &account_index) || account_index >= SP_ACCOUNT_INDEX_MAX) {
            jade_process_reject_message(
                process, CBOR_RPC_BAD_PARAMETERS, "Failed to extract valid account index from parameters");
            goto cleanup;
        }
    }

    char descriptor[SP_DESCRIPTOR_MAX_LEN];
    if (!sp_build_scan_descriptor(network_id, (uint16_t)account_index, descriptor, sizeof(descriptor))) {
        jade_process_reject_message(
            process, CBOR_RPC_INTERNAL_ERROR, "Cannot build silent payment descriptor for account");
        goto cleanup;
    }

    uint8_t buf[256];
    jade_process_reply_to_message_result(&process->ctx, buf, sizeof(buf), descriptor, cbor_result_string_cb);

    JADE_LOGI("Success");

cleanup:
    return;
}
#endif // AMALGAMATED_BUILD
