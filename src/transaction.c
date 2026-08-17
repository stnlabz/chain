#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "transaction.h"

#define TRANSACTION_LINE_SIZE 2048

static int directory_exists(
    const char *path)
{
    DWORD attributes;

    attributes =
        GetFileAttributesA(path);

    if (attributes ==
        INVALID_FILE_ATTRIBUTES) {

        return 0;
    }

    return
        (attributes &
         FILE_ATTRIBUTE_DIRECTORY)
        ? 1
        : 0;
}

static int file_exists(
    const char *path)
{
    DWORD attributes;

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

static int ensure_directory(
    const char *path)
{
    if (directory_exists(path)) {
        return 1;
    }

    if (CreateDirectoryA(
        path,
        NULL)) {

        return 1;
    }

    if (GetLastError() ==
        ERROR_ALREADY_EXISTS) {

        return directory_exists(path);
    }

    return 0;
}

static int ensure_transaction_directories(void)
{
    if (!ensure_directory(
        "C:\\stn-labz")) {

        return 0;
    }

    if (!ensure_directory(
        CHAIN_POLICY_ROOT)) {

        return 0;
    }

    if (!ensure_directory(
        CHAIN_TRANSACTION_ROOT)) {

        return 0;
    }

    return 1;
}

static transaction_stage parse_stage(
    const char *value)
{
    if (value == NULL) {
        return TRANSACTION_STAGE_NONE;
    }

    if (strcmp(
        value,
        "PREPARED") == 0) {

        return
            TRANSACTION_STAGE_PREPARED;
    }

    if (strcmp(
        value,
        "INDEX_COMMITTED") == 0) {

        return
            TRANSACTION_STAGE_INDEX_COMMITTED;
    }

    if (strcmp(
        value,
        "DOCUMENT_COMMITTED") == 0) {

        return
            TRANSACTION_STAGE_DOCUMENT_COMMITTED;
    }

    if (strcmp(
        value,
        "AUDIT_COMMITTED") == 0) {

        return
            TRANSACTION_STAGE_AUDIT_COMMITTED;
    }

    if (strcmp(
        value,
        "VERIFIED") == 0) {

        return
            TRANSACTION_STAGE_VERIFIED;
    }

    return TRANSACTION_STAGE_NONE;
}

const char *transaction_stage_string(
    transaction_stage stage)
{
    switch (stage) {

        case TRANSACTION_STAGE_PREPARED:
            return "PREPARED";

        case TRANSACTION_STAGE_INDEX_COMMITTED:
            return "INDEX_COMMITTED";

        case TRANSACTION_STAGE_DOCUMENT_COMMITTED:
            return "DOCUMENT_COMMITTED";

        case TRANSACTION_STAGE_AUDIT_COMMITTED:
            return "AUDIT_COMMITTED";

        case TRANSACTION_STAGE_VERIFIED:
            return "VERIFIED";

        case TRANSACTION_STAGE_NONE:
        default:
            return "NONE";
    }
}

static int copy_value(
    char *destination,
    size_t destination_size,
    const char *value)
{
    if (destination == NULL ||
        destination_size == 0 ||
        value == NULL) {

        return 0;
    }

    if (strlen(value) >=
        destination_size) {

        return 0;
    }

    return
        strcpy_s(
            destination,
            destination_size,
            value) == 0;
}

static void strip_line_end(
    char *line)
{
    size_t length;

    if (line == NULL) {
        return;
    }

    length = strlen(line);

    while (length > 0) {

        if (line[length - 1] != '\r' &&
            line[length - 1] != '\n') {

            break;
        }

        line[length - 1] = '\0';
        --length;
    }
}

static transaction_result write_status(
    const transaction_status *status)
{
    FILE *fp = NULL;

    char temp_path[
        TRANSACTION_PATH_SIZE
    ];

    int written;

    if (status == NULL) {
        return TRANSACTION_ERR_ARGUMENT;
    }

    written = snprintf(
        temp_path,
        sizeof(temp_path),
        "%s.tmp",
        CHAIN_TRANSACTION_STATE
    );

    if (written <= 0 ||
        written >=
        (int)sizeof(temp_path)) {

        return
            TRANSACTION_ERR_STATE_WRITE;
    }

    DeleteFileA(temp_path);

    if (fopen_s(
        &fp,
        temp_path,
        "wb") != 0 ||
        fp == NULL) {

        return
            TRANSACTION_ERR_STATE_CREATE;
    }

    if (fprintf(
        fp,
        "version=%d\r\n"
        "state=%s\r\n"
        "operation=%s\r\n"
        "document=%s\r\n"
        "index=%s\r\n"
        "policy_root=%s\r\n",
        status->version,
        transaction_stage_string(
            status->stage
        ),
        status->operation,
        status->document_path,
        status->index_path,
        status->policy_root) < 0) {

        fclose(fp);
        DeleteFileA(temp_path);

        return
            TRANSACTION_ERR_STATE_WRITE;
    }

    if (fflush(fp) != 0) {

        fclose(fp);
        DeleteFileA(temp_path);

        return
            TRANSACTION_ERR_STATE_WRITE;
    }

    if (fclose(fp) != 0) {

        DeleteFileA(temp_path);

        return
            TRANSACTION_ERR_STATE_WRITE;
    }

    if (!MoveFileExA(
        temp_path,
        CHAIN_TRANSACTION_STATE,
        MOVEFILE_REPLACE_EXISTING |
        MOVEFILE_WRITE_THROUGH)) {

        DeleteFileA(temp_path);

        return
            TRANSACTION_ERR_STATE_WRITE;
    }

    return TRANSACTION_OK;
}

int transaction_exists(void)
{
    return file_exists(
        CHAIN_TRANSACTION_STATE
    );
}

transaction_result transaction_get_status(
    transaction_status *status)
{
    FILE *fp = NULL;

    char line[
        TRANSACTION_LINE_SIZE
    ];

    int found_version = 0;
    int found_state = 0;
    int found_operation = 0;
    int found_document = 0;
    int found_index = 0;
    int found_policy_root = 0;

    if (status == NULL) {
        return TRANSACTION_ERR_ARGUMENT;
    }

    memset(
        status,
        0,
        sizeof(*status)
    );

    if (!ensure_transaction_directories()) {

        return
            TRANSACTION_ERR_DIRECTORY;
    }

    if (!file_exists(
        CHAIN_TRANSACTION_STATE)) {

        status->stage =
            TRANSACTION_STAGE_NONE;

        return TRANSACTION_OK;
    }

    if (fopen_s(
        &fp,
        CHAIN_TRANSACTION_STATE,
        "rb") != 0 ||
        fp == NULL) {

        return
            TRANSACTION_ERR_STATE_OPEN;
    }

    while (fgets(
        line,
        sizeof(line),
        fp) != NULL) {

        char *separator;
        char *key;
        char *value;

        strip_line_end(line);

        separator = strchr(
            line,
            '='
        );

        if (separator == NULL) {

            fclose(fp);

            return
                TRANSACTION_ERR_STATE_MALFORMED;
        }

        *separator = '\0';

        key = line;
        value = separator + 1;

        if (strcmp(
            key,
            "version") == 0) {

            char *end = NULL;
            long version;

            if (found_version) {

                fclose(fp);

                return
                    TRANSACTION_ERR_STATE_MALFORMED;
            }

            version = strtol(
                value,
                &end,
                10
            );

            if (end == value ||
                *end != '\0' ||
                version != 2) {

                fclose(fp);

                return
                    TRANSACTION_ERR_STATE_MALFORMED;
            }

            status->version =
                (int)version;

            found_version = 1;
        }
        else if (strcmp(
            key,
            "state") == 0) {

            transaction_stage stage;

            if (found_state) {

                fclose(fp);

                return
                    TRANSACTION_ERR_STATE_MALFORMED;
            }

            stage = parse_stage(
                value
            );

            if (stage ==
                TRANSACTION_STAGE_NONE) {

                fclose(fp);

                return
                    TRANSACTION_ERR_STATE_UNKNOWN;
            }

            status->stage = stage;

            found_state = 1;
        }
        else if (strcmp(
            key,
            "operation") == 0) {

            if (found_operation ||
                !copy_value(
                    status->operation,
                    sizeof(status->operation),
                    value)) {

                fclose(fp);

                return
                    TRANSACTION_ERR_STATE_MALFORMED;
            }

            found_operation = 1;
        }
        else if (strcmp(
            key,
            "document") == 0) {

            if (found_document ||
                !copy_value(
                    status->document_path,
                    sizeof(status->document_path),
                    value)) {

                fclose(fp);

                return
                    TRANSACTION_ERR_STATE_MALFORMED;
            }

            found_document = 1;
        }
        else if (strcmp(
            key,
            "index") == 0) {

            if (found_index ||
                !copy_value(
                    status->index_path,
                    sizeof(status->index_path),
                    value)) {

                fclose(fp);

                return
                    TRANSACTION_ERR_STATE_MALFORMED;
            }

            found_index = 1;
        }
        else if (strcmp(
            key,
            "policy_root") == 0) {

            if (found_policy_root ||
                !copy_value(
                    status->policy_root,
                    sizeof(status->policy_root),
                    value)) {

                fclose(fp);

                return
                    TRANSACTION_ERR_STATE_MALFORMED;
            }

            found_policy_root = 1;
        }
        else {

            fclose(fp);

            return
                TRANSACTION_ERR_STATE_MALFORMED;
        }
    }

    if (ferror(fp)) {

        fclose(fp);

        return
            TRANSACTION_ERR_STATE_READ;
    }

    fclose(fp);

    if (!found_version ||
        !found_state ||
        !found_operation ||
        !found_document ||
        !found_index ||
        !found_policy_root) {

        return
            TRANSACTION_ERR_STATE_MALFORMED;
    }

    if (strcmp(
        status->policy_root,
        CHAIN_POLICY_ROOT) != 0) {

        return
            TRANSACTION_ERR_STATE_MALFORMED;
    }

    return TRANSACTION_OK;
}

transaction_result transaction_check_clear(void)
{
    transaction_status status;
    transaction_result result;

    result = transaction_get_status(
        &status
    );

    if (result != TRANSACTION_OK) {
        return result;
    }

    if (status.stage !=
        TRANSACTION_STAGE_NONE) {

        return
            TRANSACTION_ERR_RECOVERY_REQUIRED;
    }

    return TRANSACTION_OK;
}

transaction_result transaction_begin(
    const char *document_path,
    const char *index_path,
    const char *operation)
{
    transaction_status status;
    transaction_result result;

    if (document_path == NULL ||
        index_path == NULL ||
        operation == NULL) {

        return TRANSACTION_ERR_ARGUMENT;
    }

    result =
        transaction_check_clear();

    if (result != TRANSACTION_OK) {
        return result;
    }

    memset(
        &status,
        0,
        sizeof(status)
    );

    status.version = 2;

    status.stage =
        TRANSACTION_STAGE_PREPARED;

    if (!copy_value(
            status.operation,
            sizeof(status.operation),
            operation) ||

        !copy_value(
            status.document_path,
            sizeof(status.document_path),
            document_path) ||

        !copy_value(
            status.index_path,
            sizeof(status.index_path),
            index_path) ||

        !copy_value(
            status.policy_root,
            sizeof(status.policy_root),
            CHAIN_POLICY_ROOT)) {

        return TRANSACTION_ERR_ARGUMENT;
    }

    return write_status(
        &status
    );
}

transaction_result transaction_set_stage(
    transaction_stage stage)
{
    transaction_status status;
    transaction_result result;

    if (stage ==
        TRANSACTION_STAGE_NONE) {

        return TRANSACTION_ERR_ARGUMENT;
    }

    result = transaction_get_status(
        &status
    );

    if (result != TRANSACTION_OK) {
        return result;
    }

    if (status.stage ==
        TRANSACTION_STAGE_NONE) {

        return
            TRANSACTION_ERR_STATE_MALFORMED;
    }

    if (stage <=
        status.stage) {

        return
            TRANSACTION_ERR_STATE_UNKNOWN;
    }

    status.stage = stage;

    return write_status(
        &status
    );
}

transaction_result transaction_complete(void)
{
    transaction_status status;
    transaction_result result;

    if (!file_exists(
        CHAIN_TRANSACTION_STATE)) {

        return TRANSACTION_OK;
    }

    result = transaction_get_status(
        &status
    );

    if (result != TRANSACTION_OK) {
        return result;
    }

    if (status.stage !=
        TRANSACTION_STAGE_VERIFIED) {

        return
            TRANSACTION_ERR_RECOVERY_REQUIRED;
    }

    if (!DeleteFileA(
        CHAIN_TRANSACTION_STATE)) {

        return
            TRANSACTION_ERR_STATE_REMOVE;
    }

    return TRANSACTION_OK;
}

transaction_result transaction_abandon_prepared(void)
{
    transaction_status status;
    transaction_result result;

    result = transaction_get_status(
        &status
    );

    if (result != TRANSACTION_OK) {
        return result;
    }

    if (status.stage ==
        TRANSACTION_STAGE_NONE) {

        return TRANSACTION_OK;
    }

    /*
     * Only PREPARED may be safely abandoned.
     *
     * Once an authoritative artifact was
     * committed, deleting recovery evidence
     * is prohibited.
     */
    if (status.stage !=
        TRANSACTION_STAGE_PREPARED) {

        return
            TRANSACTION_ERR_RECOVERY_REQUIRED;
    }

    if (!DeleteFileA(
        CHAIN_TRANSACTION_STATE)) {

        return
            TRANSACTION_ERR_STATE_REMOVE;
    }

    return TRANSACTION_OK;
}

const char *transaction_result_string(
    transaction_result result)
{
    switch (result) {

        case TRANSACTION_OK:
            return "PASS";

        case TRANSACTION_ERR_ARGUMENT:
            return
                "FAIL_TRANSACTION_ARGUMENT";

        case TRANSACTION_ERR_DIRECTORY:
            return
                "FAIL_TRANSACTION_DIRECTORY";

        case TRANSACTION_ERR_RECOVERY_REQUIRED:
            return
                "FAIL_RECOVERY_REQUIRED";

        case TRANSACTION_ERR_STATE_CREATE:
            return
                "FAIL_TRANSACTION_STATE_CREATE";

        case TRANSACTION_ERR_STATE_OPEN:
            return
                "FAIL_TRANSACTION_STATE_OPEN";

        case TRANSACTION_ERR_STATE_READ:
            return
                "FAIL_TRANSACTION_STATE_READ";

        case TRANSACTION_ERR_STATE_WRITE:
            return
                "FAIL_TRANSACTION_STATE_WRITE";

        case TRANSACTION_ERR_STATE_REMOVE:
            return
                "FAIL_TRANSACTION_STATE_REMOVE";

        case TRANSACTION_ERR_STATE_MALFORMED:
            return
                "FAIL_TRANSACTION_STATE_MALFORMED";

        case TRANSACTION_ERR_STATE_UNKNOWN:
            return
                "FAIL_TRANSACTION_STATE_UNKNOWN";

        default:
            return
                "FAIL_TRANSACTION_UNKNOWN";
    }
}