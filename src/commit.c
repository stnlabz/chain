#include <stdio.h>
#include <string.h>
#include <windows.h>

#include "audit.h"
#include "commit.h"
#include "sha256.h"
#include "transaction.h"

#define AUTHORITATIVE_INDEX \
    "C:\\stn-labz\\policies\\policy.index.json"

#define AUTHORITATIVE_AUDIT \
    "C:\\stn-labz\\policies\\policy.index.json.chainlog"

#define PREPARED_INDEX \
    "C:\\stn-labz\\policies\\.chain\\policy.index.json.prepared"

#define PREPARED_AUDIT \
    "C:\\stn-labz\\policies\\.chain\\policy.index.json.chainlog.prepared"

static int file_exists(
    const char *path)
{
    DWORD attributes;

    if (path == NULL) {
        return 0;
    }

    attributes =
        GetFileAttributesA(path);

    if (attributes ==
        INVALID_FILE_ATTRIBUTES) {

        return 0;
    }

    if (attributes &
        FILE_ATTRIBUTE_DIRECTORY) {

        return 0;
    }

    return 1;
}

static int copy_string(
    char *destination,
    size_t destination_size,
    const char *source)
{
    if (destination == NULL ||
        destination_size == 0 ||
        source == NULL) {

        return 0;
    }

    if (strlen(source) >=
        destination_size) {

        return 0;
    }

    return
        strcpy_s(
            destination,
            destination_size,
            source) == 0;
}

static const char *path_basename(
    const char *path)
{
    const char *backslash;
    const char *slash;
    const char *base;

    if (path == NULL ||
        *path == '\0') {

        return NULL;
    }

    backslash =
        strrchr(path, '\\');

    slash =
        strrchr(path, '/');

    base = path;

    if (backslash != NULL &&
        backslash + 1 > base) {

        base = backslash + 1;
    }

    if (slash != NULL &&
        slash + 1 > base) {

        base = slash + 1;
    }

    if (*base == '\0') {
        return NULL;
    }

    return base;
}

static int same_file_hash(
    const char *first,
    const char *second)
{
    unsigned char first_hash[
        SHA256_DIGEST_SIZE
    ];

    unsigned char second_hash[
        SHA256_DIGEST_SIZE
    ];

    if (!file_exists(first) ||
        !file_exists(second)) {

        return 0;
    }

    if (!sha256_file(
        first,
        first_hash)) {

        return 0;
    }

    if (!sha256_file(
        second,
        second_hash)) {

        return 0;
    }

    return memcmp(
        first_hash,
        second_hash,
        SHA256_DIGEST_SIZE) == 0;
}

static int prepare_copy(
    const char *source,
    const char *destination)
{
    DeleteFileA(destination);

    if (!CopyFileA(
        source,
        destination,
        FALSE)) {

        return 0;
    }

    if (!same_file_hash(
        source,
        destination)) {

        DeleteFileA(destination);

        return 0;
    }

    return 1;
}

static int install_prepared(
    const char *prepared,
    const char *destination,
    int allow_replace)
{
    char temporary[
        COMMIT_PATH_SIZE
    ];

    int written;

    if (!file_exists(prepared)) {
        return 0;
    }

    if (!allow_replace &&
        file_exists(destination)) {

        return 0;
    }

    written = snprintf(
        temporary,
        sizeof(temporary),
        "%s.commit.tmp",
        destination
    );

    if (written <= 0 ||
        written >=
        (int)sizeof(temporary)) {

        return 0;
    }

    DeleteFileA(temporary);

    if (!CopyFileA(
        prepared,
        temporary,
        FALSE)) {

        return 0;
    }

    if (!same_file_hash(
        prepared,
        temporary)) {

        DeleteFileA(temporary);

        return 0;
    }

    if (!MoveFileExA(
        temporary,
        destination,
        (allow_replace
            ? MOVEFILE_REPLACE_EXISTING
            : 0) |
        MOVEFILE_WRITE_THROUGH)) {

        DeleteFileA(temporary);

        return 0;
    }

    return same_file_hash(
        prepared,
        destination
    );
}

static int build_plan(
    const char *document_path,
    const char *index_path,
    commit_plan *plan)
{
    const char *document_name;

    int written;

    if (document_path == NULL ||
        index_path == NULL ||
        plan == NULL) {

        return 0;
    }

    memset(
        plan,
        0,
        sizeof(*plan)
    );

    document_name =
        path_basename(document_path);

    if (document_name == NULL) {
        return 0;
    }

    if (!copy_string(
            plan->source_document,
            sizeof(plan->source_document),
            document_path) ||

        !copy_string(
            plan->source_index,
            sizeof(plan->source_index),
            index_path)) {

        return 0;
    }

    written = snprintf(
        plan->source_audit,
        sizeof(plan->source_audit),
        "%s.chainlog",
        index_path
    );

    if (written <= 0 ||
        written >=
        (int)sizeof(plan->source_audit)) {

        return 0;
    }

    written = snprintf(
        plan->prepared_document,
        sizeof(plan->prepared_document),
        "%s\\%s.prepared",
        CHAIN_TRANSACTION_ROOT,
        document_name
    );

    if (written <= 0 ||
        written >=
        (int)sizeof(
            plan->prepared_document)) {

        return 0;
    }

    if (!copy_string(
            plan->prepared_index,
            sizeof(plan->prepared_index),
            PREPARED_INDEX) ||

        !copy_string(
            plan->prepared_audit,
            sizeof(plan->prepared_audit),
            PREPARED_AUDIT)) {

        return 0;
    }

    written = snprintf(
        plan->authoritative_document,
        sizeof(plan->authoritative_document),
        "%s\\%s",
        CHAIN_POLICY_ROOT,
        document_name
    );

    if (written <= 0 ||
        written >=
        (int)sizeof(
            plan->authoritative_document)) {

        return 0;
    }

    if (!copy_string(
            plan->authoritative_index,
            sizeof(plan->authoritative_index),
            AUTHORITATIVE_INDEX) ||

        !copy_string(
            plan->authoritative_audit,
            sizeof(plan->authoritative_audit),
            AUTHORITATIVE_AUDIT)) {

        return 0;
    }

    return 1;
}

commit_result commit_prepare(
    const char *document_path,
    const char *index_path,
    commit_plan *plan)
{
    if (!build_plan(
            document_path,
            index_path,
            plan)) {

        return COMMIT_ERR_PATH;
    }

    if (!file_exists(
            plan->source_document) ||
        !file_exists(
            plan->source_index) ||
        !file_exists(
            plan->source_audit)) {

        return
            COMMIT_ERR_SOURCE_MISSING;
    }

    /*
     * Revision documents are immutable once
     * committed to the authoritative store.
     */
    if (file_exists(
            plan->authoritative_document)) {

        return
            COMMIT_ERR_DOCUMENT_EXISTS;
    }

    if (!prepare_copy(
            plan->source_document,
            plan->prepared_document)) {

        return COMMIT_ERR_PREPARE;
    }

    if (!prepare_copy(
            plan->source_index,
            plan->prepared_index)) {

        DeleteFileA(
            plan->prepared_document
        );

        return COMMIT_ERR_PREPARE;
    }

    if (!prepare_copy(
            plan->source_audit,
            plan->prepared_audit)) {

        DeleteFileA(
            plan->prepared_document
        );

        DeleteFileA(
            plan->prepared_index
        );

        return COMMIT_ERR_PREPARE;
    }

    if (!same_file_hash(
            plan->source_document,
            plan->prepared_document) ||

        !same_file_hash(
            plan->source_index,
            plan->prepared_index) ||

        !same_file_hash(
            plan->source_audit,
            plan->prepared_audit)) {

        return
            COMMIT_ERR_PREPARE_VERIFY;
    }

    return COMMIT_OK;
}

static commit_result verify_authoritative_index(
    const commit_plan *plan)
{
    if (!same_file_hash(
            plan->prepared_index,
            plan->authoritative_index)) {

        return COMMIT_ERR_INDEX_VERIFY;
    }

    return COMMIT_OK;
}

static commit_result verify_authoritative_document(
    const commit_plan *plan)
{
    if (!same_file_hash(
            plan->prepared_document,
            plan->authoritative_document)) {

        return COMMIT_ERR_DOCUMENT_VERIFY;
    }

    return COMMIT_OK;
}

static commit_result verify_authoritative_audit(
    const commit_plan *plan)
{
    if (!same_file_hash(
            plan->prepared_audit,
            plan->authoritative_audit)) {

        return COMMIT_ERR_AUDIT_VERIFY;
    }

    if (audit_verify(
            plan->authoritative_index) !=
        AUDIT_OK) {

        return COMMIT_ERR_AUDIT_VERIFY;
    }

    return COMMIT_OK;
}

static commit_result final_verify(
    const commit_plan *plan)
{
    commit_result result;

    result =
        verify_authoritative_index(plan);

    if (result != COMMIT_OK) {
        return result;
    }

    result =
        verify_authoritative_document(plan);

    if (result != COMMIT_OK) {
        return result;
    }

    result =
        verify_authoritative_audit(plan);

    if (result != COMMIT_OK) {
        return result;
    }

    return COMMIT_OK;
}

commit_result commit_apply(
    const commit_plan *plan)
{
    transaction_result tx_result;
    commit_result verify_result;

    if (plan == NULL) {
        return COMMIT_ERR_ARGUMENT;
    }

    /*
     * INDEX
     */
    if (!install_prepared(
            plan->prepared_index,
            plan->authoritative_index,
            1)) {

        return COMMIT_ERR_INDEX_COMMIT;
    }

    tx_result =
        transaction_set_stage(
            TRANSACTION_STAGE_INDEX_COMMITTED
        );

    if (tx_result !=
        TRANSACTION_OK) {

        return
            COMMIT_ERR_TRANSACTION_STAGE;
    }

    /*
     * DOCUMENT
     */
    if (!install_prepared(
            plan->prepared_document,
            plan->authoritative_document,
            0)) {

        return
            COMMIT_ERR_DOCUMENT_COMMIT;
    }

    tx_result =
        transaction_set_stage(
            TRANSACTION_STAGE_DOCUMENT_COMMITTED
        );

    if (tx_result !=
        TRANSACTION_OK) {

        return
            COMMIT_ERR_TRANSACTION_STAGE;
    }

    /*
     * AUDIT
     */
    if (!install_prepared(
            plan->prepared_audit,
            plan->authoritative_audit,
            1)) {

        return
            COMMIT_ERR_AUDIT_COMMIT;
    }

    tx_result =
        transaction_set_stage(
            TRANSACTION_STAGE_AUDIT_COMMITTED
        );

    if (tx_result !=
        TRANSACTION_OK) {

        return
            COMMIT_ERR_TRANSACTION_STAGE;
    }

    verify_result =
        final_verify(plan);

    if (verify_result !=
        COMMIT_OK) {

        return verify_result;
    }

    tx_result =
        transaction_set_stage(
            TRANSACTION_STAGE_VERIFIED
        );

    if (tx_result !=
        TRANSACTION_OK) {

        return
            COMMIT_ERR_TRANSACTION_STAGE;
    }

    return COMMIT_OK;
}

commit_result commit_recover(
    const transaction_status *status)
{
    commit_plan plan;

    commit_result result;
    transaction_result tx_result;

    if (status == NULL) {
        return COMMIT_ERR_ARGUMENT;
    }

    if (status->stage ==
        TRANSACTION_STAGE_NONE) {

        return COMMIT_OK;
    }

    if (!build_plan(
            status->document_path,
            status->index_path,
            &plan)) {

        return COMMIT_ERR_PATH;
    }

    /*
     * Recovery relies on prepared artifacts.
     * They are the intended committed state.
     */
    if (!file_exists(
            plan.prepared_document) ||
        !file_exists(
            plan.prepared_index) ||
        !file_exists(
            plan.prepared_audit)) {

        return
            COMMIT_ERR_RECOVERY_EVIDENCE;
    }

    /*
     * --------------------------------------------------------
     * PREPARED
     *
     * No authoritative stage recorded.
     * Caller may abandon instead of forwarding.
     * --------------------------------------------------------
     */
    if (status->stage ==
        TRANSACTION_STAGE_PREPARED) {

        return COMMIT_OK;
    }

    /*
     * --------------------------------------------------------
     * INDEX_COMMITTED
     *
     * Prove the authoritative index actually
     * matches the prepared intended state.
     * --------------------------------------------------------
     */
    if (status->stage ==
        TRANSACTION_STAGE_INDEX_COMMITTED) {

        result =
            verify_authoritative_index(
                &plan
            );

        if (result !=
            COMMIT_OK) {

            return
                COMMIT_ERR_RECOVERY_EVIDENCE;
        }

        /*
         * The document must not already exist
         * unless it exactly matches prepared state.
         *
         * If it exists and matches, recovery can
         * safely recognize that the actual write
         * completed before stage persistence.
         */
        if (file_exists(
                plan.authoritative_document)) {

            if (!same_file_hash(
                    plan.prepared_document,
                    plan.authoritative_document)) {

                return
                    COMMIT_ERR_RECOVERY_EVIDENCE;
            }
        }
        else {

            if (!install_prepared(
                    plan.prepared_document,
                    plan.authoritative_document,
                    0)) {

                return
                    COMMIT_ERR_DOCUMENT_COMMIT;
            }
        }

        tx_result =
            transaction_set_stage(
                TRANSACTION_STAGE_DOCUMENT_COMMITTED
            );

        if (tx_result !=
            TRANSACTION_OK) {

            return
                COMMIT_ERR_TRANSACTION_STAGE;
        }

        /*
         * Continue forward.
         */
        if (!install_prepared(
                plan.prepared_audit,
                plan.authoritative_audit,
                1)) {

            return
                COMMIT_ERR_AUDIT_COMMIT;
        }

        tx_result =
            transaction_set_stage(
                TRANSACTION_STAGE_AUDIT_COMMITTED
            );

        if (tx_result !=
            TRANSACTION_OK) {

            return
                COMMIT_ERR_TRANSACTION_STAGE;
        }

        result =
            final_verify(
                &plan
            );

        if (result !=
            COMMIT_OK) {

            return result;
        }

        tx_result =
            transaction_set_stage(
                TRANSACTION_STAGE_VERIFIED
            );

        if (tx_result !=
            TRANSACTION_OK) {

            return
                COMMIT_ERR_TRANSACTION_STAGE;
        }

        return COMMIT_OK;
    }

    /*
     * --------------------------------------------------------
     * DOCUMENT_COMMITTED
     *
     * Both earlier artifacts must match the
     * prepared state before audit is resumed.
     * --------------------------------------------------------
     */
    if (status->stage ==
        TRANSACTION_STAGE_DOCUMENT_COMMITTED) {

        result =
            verify_authoritative_index(
                &plan
            );

        if (result !=
            COMMIT_OK) {

            return
                COMMIT_ERR_RECOVERY_EVIDENCE;
        }

        result =
            verify_authoritative_document(
                &plan
            );

        if (result !=
            COMMIT_OK) {

            return
                COMMIT_ERR_RECOVERY_EVIDENCE;
        }

        if (!install_prepared(
                plan.prepared_audit,
                plan.authoritative_audit,
                1)) {

            return
                COMMIT_ERR_AUDIT_COMMIT;
        }

        tx_result =
            transaction_set_stage(
                TRANSACTION_STAGE_AUDIT_COMMITTED
            );

        if (tx_result !=
            TRANSACTION_OK) {

            return
                COMMIT_ERR_TRANSACTION_STAGE;
        }

        result =
            final_verify(
                &plan
            );

        if (result !=
            COMMIT_OK) {

            return result;
        }

        tx_result =
            transaction_set_stage(
                TRANSACTION_STAGE_VERIFIED
            );

        if (tx_result !=
            TRANSACTION_OK) {

            return
                COMMIT_ERR_TRANSACTION_STAGE;
        }

        return COMMIT_OK;
    }

    /*
     * --------------------------------------------------------
     * AUDIT_COMMITTED
     *
     * No more artifact writes are needed.
     * Prove authoritative state and advance.
     * --------------------------------------------------------
     */
    if (status->stage ==
        TRANSACTION_STAGE_AUDIT_COMMITTED) {

        result =
            final_verify(
                &plan
            );

        if (result !=
            COMMIT_OK) {

            return
                COMMIT_ERR_RECOVERY_EVIDENCE;
        }

        tx_result =
            transaction_set_stage(
                TRANSACTION_STAGE_VERIFIED
            );

        if (tx_result !=
            TRANSACTION_OK) {

            return
                COMMIT_ERR_TRANSACTION_STAGE;
        }

        return COMMIT_OK;
    }

    /*
     * VERIFIED requires no forward artifact work.
     */
    if (status->stage ==
        TRANSACTION_STAGE_VERIFIED) {

        result =
            final_verify(
                &plan
            );

        if (result !=
            COMMIT_OK) {

            return
                COMMIT_ERR_RECOVERY_EVIDENCE;
        }

        return COMMIT_OK;
    }

    return COMMIT_ERR_RECOVERY_STAGE;
}

commit_result commit_cleanup_prepared(
    const commit_plan *plan)
{
    int failure = 0;

    if (plan == NULL) {
        return COMMIT_ERR_ARGUMENT;
    }

    if (file_exists(
            plan->prepared_document) &&
        !DeleteFileA(
            plan->prepared_document)) {

        failure = 1;
    }

    if (file_exists(
            plan->prepared_index) &&
        !DeleteFileA(
            plan->prepared_index)) {

        failure = 1;
    }

    if (file_exists(
            plan->prepared_audit) &&
        !DeleteFileA(
            plan->prepared_audit)) {

        failure = 1;
    }

    return failure
        ? COMMIT_ERR_CLEANUP
        : COMMIT_OK;
}

commit_result commit_cleanup_transaction_artifacts(void)
{
    WIN32_FIND_DATAA find_data;
    HANDLE find_handle;

    char pattern[
        COMMIT_PATH_SIZE
    ];

    char path[
        COMMIT_PATH_SIZE
    ];

    int failure = 0;

    if (snprintf(
            pattern,
            sizeof(pattern),
            "%s\\*.prepared",
            CHAIN_TRANSACTION_ROOT) <= 0) {

        return COMMIT_ERR_CLEANUP;
    }

    find_handle =
        FindFirstFileA(
            pattern,
            &find_data
        );

    if (find_handle ==
        INVALID_HANDLE_VALUE) {

        if (GetLastError() ==
            ERROR_FILE_NOT_FOUND) {

            return COMMIT_OK;
        }

        return COMMIT_ERR_CLEANUP;
    }

    do {

        if (find_data.dwFileAttributes &
            FILE_ATTRIBUTE_DIRECTORY) {

            continue;
        }

        if (snprintf(
                path,
                sizeof(path),
                "%s\\%s",
                CHAIN_TRANSACTION_ROOT,
                find_data.cFileName) <= 0) {

            failure = 1;
            continue;
        }

        if (!DeleteFileA(path)) {
            failure = 1;
        }

    } while (FindNextFileA(
        find_handle,
        &find_data));

    FindClose(find_handle);

    return failure
        ? COMMIT_ERR_CLEANUP
        : COMMIT_OK;
}

const char *commit_result_string(
    commit_result result)
{
    switch (result) {

        case COMMIT_OK:
            return "PASS";

        case COMMIT_ERR_ARGUMENT:
            return "FAIL_COMMIT_ARGUMENT";

        case COMMIT_ERR_PATH:
            return "FAIL_COMMIT_PATH";

        case COMMIT_ERR_SOURCE_MISSING:
            return "FAIL_COMMIT_SOURCE_MISSING";

        case COMMIT_ERR_PREPARE:
            return "FAIL_COMMIT_PREPARE";

        case COMMIT_ERR_PREPARE_VERIFY:
            return "FAIL_COMMIT_PREPARE_VERIFY";

        case COMMIT_ERR_DOCUMENT_EXISTS:
            return "FAIL_COMMIT_DOCUMENT_EXISTS";

        case COMMIT_ERR_INDEX_COMMIT:
            return "FAIL_COMMIT_INDEX";

        case COMMIT_ERR_DOCUMENT_COMMIT:
            return "FAIL_COMMIT_DOCUMENT";

        case COMMIT_ERR_AUDIT_COMMIT:
            return "FAIL_COMMIT_AUDIT";

        case COMMIT_ERR_INDEX_VERIFY:
            return "FAIL_COMMIT_INDEX_VERIFY";

        case COMMIT_ERR_DOCUMENT_VERIFY:
            return "FAIL_COMMIT_DOCUMENT_VERIFY";

        case COMMIT_ERR_AUDIT_VERIFY:
            return "FAIL_COMMIT_AUDIT_VERIFY";

        case COMMIT_ERR_FINAL_VERIFY:
            return "FAIL_COMMIT_FINAL_VERIFY";

        case COMMIT_ERR_TRANSACTION_STAGE:
            return "FAIL_COMMIT_TRANSACTION_STAGE";

        case COMMIT_ERR_RECOVERY_EVIDENCE:
            return "FAIL_COMMIT_RECOVERY_EVIDENCE";

        case COMMIT_ERR_RECOVERY_STAGE:
            return "FAIL_COMMIT_RECOVERY_STAGE";

        case COMMIT_ERR_CLEANUP:
            return "FAIL_COMMIT_CLEANUP";

        default:
            return "FAIL_COMMIT_UNKNOWN";
    }
}