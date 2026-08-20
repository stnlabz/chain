#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>

#include "audit.h"

#define AUDIT_PATH_SIZE 1024
#define AUDIT_LINE_SIZE 2048

#define ZERO_HASH \
    "0000000000000000000000000000000000000000000000000000000000000000"

static int make_audit_path(
    const char *index_path,
    char path[AUDIT_PATH_SIZE])
{
    int written;

    if (index_path == NULL ||
        path == NULL) {

        return 0;
    }

    written = snprintf(
        path,
        AUDIT_PATH_SIZE,
        "%s.chainlog",
        index_path
    );

    if (written <= 0 ||
        written >= AUDIT_PATH_SIZE) {

        return 0;
    }

    return 1;
}

static int hash_canonical_record(
    const char *timestamp,
    const char *operation,
    const char *root,
    const char *revision,
    const char *previous_revision,
    const char *document_sha256,
    const char *previous_record_sha256,
    char output[SHA256_HEX_SIZE])
{
    char canonical[AUDIT_LINE_SIZE];

    unsigned char digest[
        SHA256_DIGEST_SIZE
    ];

    int written;

    if (timestamp == NULL ||
        operation == NULL ||
        root == NULL ||
        revision == NULL ||
        previous_revision == NULL ||
        document_sha256 == NULL ||
        previous_record_sha256 == NULL ||
        output == NULL) {

        return 0;
    }

    /*
     * This exact byte representation is the
     * canonical audit-record representation.
     */
    written = snprintf(
        canonical,
        sizeof(canonical),
        "%s|%s|%s|%s|%s|%s|%s",
        timestamp,
        operation,
        root,
        revision,
        previous_revision,
        document_sha256,
        previous_record_sha256
    );

    if (written <= 0 ||
        written >=
        (int)sizeof(canonical)) {

        return 0;
    }

    if (!sha256_buffer(
        (const unsigned char *)canonical,
        (size_t)written,
        digest)) {

        return 0;
    }

    sha256_to_hex(
        digest,
        output
    );

    return 1;
}

static int get_timestamp(
    char *buffer,
    size_t size)
{
    SYSTEMTIME st;

    int written;

    if (buffer == NULL ||
        size == 0) {

        return 0;
    }

    GetSystemTime(&st);

    written = snprintf(
        buffer,
        size,
        "%04u-%02u-%02uT%02u:%02u:%02uZ",
        st.wYear,
        st.wMonth,
        st.wDay,
        st.wHour,
        st.wMinute,
        st.wSecond
    );

    if (written <= 0 ||
        written >= (int)size) {

        return 0;
    }

    return 1;
}

static int parse_line(
    char *line,
    char **timestamp,
    char **operation,
    char **root,
    char **revision,
    char **previous_revision,
    char **document_sha256,
    char **previous_record_sha256,
    char **record_sha256)
{
    char *context = NULL;
    char *token;

    char **fields[8];

    size_t i;

    fields[0] = timestamp;
    fields[1] = operation;
    fields[2] = root;
    fields[3] = revision;
    fields[4] = previous_revision;
    fields[5] = document_sha256;
    fields[6] = previous_record_sha256;
    fields[7] = record_sha256;

    token = strtok_s(
        line,
        "|\r\n",
        &context
    );

    for (i = 0; i < 8; ++i) {

        if (token == NULL) {
            return 0;
        }

        *fields[i] = token;

        token = strtok_s(
            NULL,
            "|\r\n",
            &context
        );
    }

    /*
     * Exactly eight fields.
     */
    if (token != NULL) {
        return 0;
    }

    return 1;
}

audit_result audit_verify(
    const char *index_path)
{
    char audit_path[
        AUDIT_PATH_SIZE
    ];

    FILE *fp = NULL;

    char line[
        AUDIT_LINE_SIZE
    ];

    char expected_previous[
        SHA256_HEX_SIZE
    ];

    if (!make_audit_path(
        index_path,
        audit_path)) {

        return AUDIT_ERR_ARGUMENT;
    }

    /*
     * No audit file yet is valid:
     * the first successful operation will
     * create the initial record.
     */
    if (fopen_s(
        &fp,
        audit_path,
        "rb") != 0 ||
        fp == NULL) {

        return AUDIT_OK;
    }

    strcpy_s(
        expected_previous,
        sizeof(expected_previous),
        ZERO_HASH
    );

    while (fgets(
        line,
        sizeof(line),
        fp) != NULL) {

        char *scan =
            line;

        char *timestamp;
        char *operation;
        char *root;
        char *revision;
        char *previous_revision;
        char *document_sha256;
        char *previous_record_sha256;
        char *record_sha256;

        char calculated[
            SHA256_HEX_SIZE
        ];

        /*
         * Empty lines are not audit records. Older Chain builds could
         * leave a trailing blank line during interrupted work; ignoring
         * whitespace-only lines prevents that presentation artifact from
         * becoming a permanent global registration failure.
         */
        while (
            *scan == ' ' ||
            *scan == '\t' ||
            *scan == '\r' ||
            *scan == '\n'
            )
        {
            ++scan;
        }

        if (*scan == '\0')
        {
            continue;
        }

        if (!parse_line(
            line,
            &timestamp,
            &operation,
            &root,
            &revision,
            &previous_revision,
            &document_sha256,
            &previous_record_sha256,
            &record_sha256)) {

            fclose(fp);

            return AUDIT_ERR_MALFORMED;
        }

        if (
            timestamp[0] == '\0' ||
            operation[0] == '\0' ||
            root[0] == '\0' ||
            revision[0] == '\0' ||
            previous_revision[0] == '\0' ||
            strlen(document_sha256) != 64 ||
            strlen(previous_record_sha256) != 64 ||
            strlen(record_sha256) != 64
            )
        {
            fclose(fp);

            return AUDIT_ERR_MALFORMED;
        }

        if (strcmp(
            previous_record_sha256,
            expected_previous) != 0) {

            fclose(fp);

            return AUDIT_ERR_CHAIN_BROKEN;
        }

        if (!hash_canonical_record(
            timestamp,
            operation,
            root,
            revision,
            previous_revision,
            document_sha256,
            previous_record_sha256,
            calculated)) {

            fclose(fp);

            return AUDIT_ERR_HASH;
        }

        if (strcmp(
            calculated,
            record_sha256) != 0) {

            fclose(fp);

            return AUDIT_ERR_CHAIN_BROKEN;
        }

        strcpy_s(
            expected_previous,
            sizeof(expected_previous),
            record_sha256
        );
    }

    if (ferror(fp)) {

        fclose(fp);

        return AUDIT_ERR_READ;
    }

    fclose(fp);

    return AUDIT_OK;
}

static audit_result get_last_record_hash(
    const char *audit_path,
    char output[SHA256_HEX_SIZE])
{
    FILE *fp = NULL;

    char line[
        AUDIT_LINE_SIZE
    ];

    char last_hash[
        SHA256_HEX_SIZE
    ];

    strcpy_s(
        last_hash,
        sizeof(last_hash),
        ZERO_HASH
    );

    if (fopen_s(
        &fp,
        audit_path,
        "rb") != 0 ||
        fp == NULL) {

        strcpy_s(
            output,
            SHA256_HEX_SIZE,
            ZERO_HASH
        );

        return AUDIT_OK;
    }

    while (fgets(
        line,
        sizeof(line),
        fp) != NULL) {

        char *scan =
            line;

        char *timestamp;
        char *operation;
        char *root;
        char *revision;
        char *previous_revision;
        char *document_sha256;
        char *previous_record_sha256;
        char *record_sha256;

        while (
            *scan == ' ' ||
            *scan == '\t' ||
            *scan == '\r' ||
            *scan == '\n'
            )
        {
            ++scan;
        }

        if (*scan == '\0')
        {
            continue;
        }

        if (!parse_line(
            line,
            &timestamp,
            &operation,
            &root,
            &revision,
            &previous_revision,
            &document_sha256,
            &previous_record_sha256,
            &record_sha256)) {

            fclose(fp);

            return AUDIT_ERR_MALFORMED;
        }

        strcpy_s(
            last_hash,
            sizeof(last_hash),
            record_sha256
        );
    }

    if (ferror(fp)) {

        fclose(fp);

        return AUDIT_ERR_READ;
    }

    fclose(fp);

    strcpy_s(
        output,
        SHA256_HEX_SIZE,
        last_hash
    );

    return AUDIT_OK;
}

audit_result audit_append(
    const char *index_path,
    const document_identity *identity,
    const char sha256[SHA256_HEX_SIZE],
    const char *operation)
{
    char audit_path[
        AUDIT_PATH_SIZE
    ];

    char timestamp[32];

    char previous_record_hash[
        SHA256_HEX_SIZE
    ];

    char record_hash[
        SHA256_HEX_SIZE
    ];

    FILE *fp = NULL;

    audit_result result;

    if (index_path == NULL ||
        identity == NULL ||
        sha256 == NULL ||
        operation == NULL) {

        return AUDIT_ERR_ARGUMENT;
    }

    /*
     * Never append onto a broken audit chain.
     */
    result = audit_verify(
        index_path
    );

    if (result != AUDIT_OK) {
        return result;
    }

    if (!make_audit_path(
        index_path,
        audit_path)) {

        return AUDIT_ERR_ARGUMENT;
    }

    result = get_last_record_hash(
        audit_path,
        previous_record_hash
    );

    if (result != AUDIT_OK) {
        return result;
    }

    if (!get_timestamp(
        timestamp,
        sizeof(timestamp))) {

        return AUDIT_ERR_WRITE;
    }

    if (!hash_canonical_record(
        timestamp,
        operation,
        identity->root_document_id,
        identity->revision_id,
        identity->previous_revision,
        sha256,
        previous_record_hash,
        record_hash)) {

        return AUDIT_ERR_HASH;
    }

    if (fopen_s(
        &fp,
        audit_path,
        "ab") != 0 ||
        fp == NULL) {

        return AUDIT_ERR_OPEN;
    }

    if (fprintf(
        fp,
        "%s|%s|%s|%s|%s|%s|%s|%s\r\n",
        timestamp,
        operation,
        identity->root_document_id,
        identity->revision_id,
        identity->previous_revision,
        sha256,
        previous_record_hash,
        record_hash) < 0) {

        fclose(fp);

        return AUDIT_ERR_WRITE;
    }

    if (fflush(fp) != 0) {

        fclose(fp);

        return AUDIT_ERR_WRITE;
    }

    if (fclose(fp) != 0) {

        return AUDIT_ERR_WRITE;
    }

    /*
     * Prove our own append did not break
     * the audit chain.
     */
    return audit_verify(
        index_path
    );
}

const char *audit_result_string(
    audit_result result)
{
    switch (result) {

        case AUDIT_OK:
            return "PASS";

        case AUDIT_ERR_ARGUMENT:
            return "FAIL_AUDIT_ARGUMENT";

        case AUDIT_ERR_OPEN:
            return "FAIL_AUDIT_OPEN";

        case AUDIT_ERR_READ:
            return "FAIL_AUDIT_READ";

        case AUDIT_ERR_WRITE:
            return "FAIL_AUDIT_WRITE";

        case AUDIT_ERR_MALFORMED:
            return "FAIL_AUDIT_MALFORMED";

        case AUDIT_ERR_CHAIN_BROKEN:
            return "FAIL_AUDIT_CHAIN_BROKEN";

        case AUDIT_ERR_HASH:
            return "FAIL_AUDIT_HASH";

        default:
            return "FAIL_AUDIT_UNKNOWN";
    }
}