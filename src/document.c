#include <stdio.h>
#include <string.h>

#include "document.h"

#define ROOT_PREFIX      "Root Document ID:"
#define REVISION_PREFIX  "Revision ID:"
#define PREVIOUS_PREFIX  "Previous Revision:"
#define TITLE_PREFIX     "# "
#define STATUS_PREFIX    "**Status:**"

static int copy_value(
    const char* value,
    char* destination,
    size_t destination_size)
{
    size_t length;

    if (value == NULL ||
        destination == NULL ||
        destination_size == 0) {

        return 0;
    }

    while (*value == ' ' ||
        *value == '\t') {

        ++value;
    }

    length = strcspn(
        value,
        "\r\n"
    );

    while (length > 0 &&
        (value[length - 1] == ' ' ||
            value[length - 1] == '\t')) {

        --length;
    }

    if (length == 0 ||
        length >= destination_size) {

        return 0;
    }

    memcpy(
        destination,
        value,
        length
    );

    destination[length] = '\0';

    return 1;
}

static int copy_prefixed_value(
    const char* line,
    const char* prefix,
    char* destination,
    size_t destination_size)
{
    size_t prefix_length;

    if (line == NULL ||
        prefix == NULL ||
        destination == NULL) {

        return 0;
    }

    prefix_length = strlen(prefix);

    if (strncmp(
        line,
        prefix,
        prefix_length) != 0) {

        return 0;
    }

    return copy_value(
        line + prefix_length,
        destination,
        destination_size
    );
}

document_result document_read_identity(
    const char* path,
    document_identity* identity)
{
    FILE* fp = NULL;

    char line[1024];

    int root_count = 0;
    int revision_count = 0;
    int previous_count = 0;
    int title_count = 0;
    int status_count = 0;

    int root_malformed = 0;
    int revision_malformed = 0;
    int previous_malformed = 0;
    int title_malformed = 0;
    int status_malformed = 0;

    if (path == NULL ||
        identity == NULL) {

        return DOCUMENT_ERR_ARGUMENT;
    }

    memset(
        identity,
        0,
        sizeof(*identity)
    );

    if (fopen_s(
        &fp,
        path,
        "rb") != 0 ||
        fp == NULL) {

        return DOCUMENT_ERR_OPEN;
    }

    while (fgets(
        line,
        sizeof(line),
        fp) != NULL) {

        if (strncmp(
            line,
            ROOT_PREFIX,
            strlen(ROOT_PREFIX)) == 0) {

            ++root_count;

            if (!copy_prefixed_value(
                line,
                ROOT_PREFIX,
                identity->root_document_id,
                sizeof(identity->root_document_id))) {

                root_malformed = 1;
            }

            continue;
        }

        if (strncmp(
            line,
            REVISION_PREFIX,
            strlen(REVISION_PREFIX)) == 0) {

            ++revision_count;

            if (!copy_prefixed_value(
                line,
                REVISION_PREFIX,
                identity->revision_id,
                sizeof(identity->revision_id))) {

                revision_malformed = 1;
            }

            continue;
        }

        if (strncmp(
            line,
            PREVIOUS_PREFIX,
            strlen(PREVIOUS_PREFIX)) == 0) {

            ++previous_count;

            if (!copy_prefixed_value(
                line,
                PREVIOUS_PREFIX,
                identity->previous_revision,
                sizeof(identity->previous_revision))) {

                previous_malformed = 1;
            }

            continue;
        }

        if (strncmp(
            line,
            TITLE_PREFIX,
            strlen(TITLE_PREFIX)) == 0) {

            ++title_count;

            if (!copy_prefixed_value(
                line,
                TITLE_PREFIX,
                identity->title,
                sizeof(identity->title))) {

                title_malformed = 1;
            }

            continue;
        }

        if (strncmp(
            line,
            STATUS_PREFIX,
            strlen(STATUS_PREFIX)) == 0) {

            ++status_count;

            if (!copy_prefixed_value(
                line,
                STATUS_PREFIX,
                identity->status,
                sizeof(identity->status))) {

                status_malformed = 1;
            }

            continue;
        }
    }

    if (ferror(fp)) {
        fclose(fp);
        return DOCUMENT_ERR_READ;
    }

    fclose(fp);

    /*
     * Root Document ID
     */
    if (root_count == 0) {
        return DOCUMENT_ERR_ROOT_MISSING;
    }

    if (root_count > 1) {
        return DOCUMENT_ERR_ROOT_DUPLICATE;
    }

    if (root_malformed) {
        return DOCUMENT_ERR_ROOT_MALFORMED;
    }

    /*
     * Revision ID
     */
    if (revision_count == 0) {
        return DOCUMENT_ERR_REVISION_MISSING;
    }

    if (revision_count > 1) {
        return DOCUMENT_ERR_REVISION_DUPLICATE;
    }

    if (revision_malformed) {
        return DOCUMENT_ERR_REVISION_MALFORMED;
    }

    /*
     * Previous Revision
     */
    if (previous_count == 0) {
        return DOCUMENT_ERR_PREVIOUS_MISSING;
    }

    if (previous_count > 1) {
        return DOCUMENT_ERR_PREVIOUS_DUPLICATE;
    }

    if (previous_malformed) {
        return DOCUMENT_ERR_PREVIOUS_MALFORMED;
    }

    /*
     * Title
     */
    if (title_count == 0) {
        return DOCUMENT_ERR_TITLE_MISSING;
    }

    if (title_count > 1) {
        return DOCUMENT_ERR_TITLE_DUPLICATE;
    }

    if (title_malformed) {
        return DOCUMENT_ERR_TITLE_MALFORMED;
    }

    /*
     * Status
     */
    if (status_count == 0) {
        return DOCUMENT_ERR_STATUS_MISSING;
    }

    if (status_count > 1) {
        return DOCUMENT_ERR_STATUS_DUPLICATE;
    }

    if (status_malformed) {
        return DOCUMENT_ERR_STATUS_MALFORMED;
    }

    return DOCUMENT_OK;
}

int document_is_initial_revision(
    const document_identity* identity)
{
    char expected_revision[
        DOCUMENT_REVISION_ID_SIZE
    ];

    int written;

    if (identity == NULL) {
        return 0;
    }

    written = snprintf(
        expected_revision,
        sizeof(expected_revision),
        "%s.R0",
        identity->root_document_id
    );

    if (written <= 0 ||
        (size_t)written >=
        sizeof(expected_revision)) {

        return 0;
    }

    if (strcmp(
        identity->revision_id,
        expected_revision) != 0) {

        return 0;
    }

    if (strcmp(
        identity->previous_revision,
        "NONE") != 0) {

        return 0;
    }

    return 1;
}

const char* document_result_string(
    document_result result)
{
    switch (result) {

    case DOCUMENT_OK:
        return "PASS";

    case DOCUMENT_ERR_ARGUMENT:
        return "FAIL_DOCUMENT_ARGUMENT";

    case DOCUMENT_ERR_OPEN:
        return "FAIL_DOCUMENT_OPEN";

    case DOCUMENT_ERR_READ:
        return "FAIL_DOCUMENT_READ";

    case DOCUMENT_ERR_ROOT_MISSING:
        return "FAIL_ROOT_MISSING";

    case DOCUMENT_ERR_ROOT_DUPLICATE:
        return "FAIL_ROOT_DUPLICATE";

    case DOCUMENT_ERR_ROOT_MALFORMED:
        return "FAIL_ROOT_MALFORMED";

    case DOCUMENT_ERR_REVISION_MISSING:
        return "FAIL_REVISION_MISSING";

    case DOCUMENT_ERR_REVISION_DUPLICATE:
        return "FAIL_REVISION_DUPLICATE";

    case DOCUMENT_ERR_REVISION_MALFORMED:
        return "FAIL_REVISION_MALFORMED";

    case DOCUMENT_ERR_PREVIOUS_MISSING:
        return "FAIL_PREVIOUS_MISSING";

    case DOCUMENT_ERR_PREVIOUS_DUPLICATE:
        return "FAIL_PREVIOUS_DUPLICATE";

    case DOCUMENT_ERR_PREVIOUS_MALFORMED:
        return "FAIL_PREVIOUS_MALFORMED";

    case DOCUMENT_ERR_TITLE_MISSING:
        return "FAIL_TITLE_MISSING";

    case DOCUMENT_ERR_TITLE_DUPLICATE:
        return "FAIL_TITLE_DUPLICATE";

    case DOCUMENT_ERR_TITLE_MALFORMED:
        return "FAIL_TITLE_MALFORMED";

    case DOCUMENT_ERR_STATUS_MISSING:
        return "FAIL_STATUS_MISSING";

    case DOCUMENT_ERR_STATUS_DUPLICATE:
        return "FAIL_STATUS_DUPLICATE";

    case DOCUMENT_ERR_STATUS_MALFORMED:
        return "FAIL_STATUS_MALFORMED";

    default:
        return "FAIL_DOCUMENT_UNKNOWN";
    }
}