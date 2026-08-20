#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <windows.h>

#include "index.h"

#define INDEX_MAX_SIZE (1024U * 1024U)

static int file_exists(
    const char* path)
{
    DWORD attributes;

    attributes = GetFileAttributesA(path);

    if (attributes == INVALID_FILE_ATTRIBUTES) {
        return 0;
    }

    if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
        return 0;
    }

    return 1;
}

static int json_string_safe(
    const char* value)
{
    const unsigned char* p;

    if (value == NULL ||
        *value == '\0') {

        return 0;
    }

    p = (const unsigned char*)value;

    while (*p != '\0') {

        if (*p == '"' ||
            *p == '\\' ||
            *p < 0x20) {

            return 0;
        }

        ++p;
    }

    return 1;
}

static char* read_file(
    const char* path,
    size_t* out_size)
{
    FILE* fp = NULL;
    char* data = NULL;

    long size;
    size_t read_count;

    if (path == NULL ||
        out_size == NULL) {

        return NULL;
    }

    *out_size = 0;

    if (fopen_s(
        &fp,
        path,
        "rb") != 0 ||
        fp == NULL) {

        return NULL;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }

    size = ftell(fp);

    if (size < 0 ||
        (unsigned long)size > INDEX_MAX_SIZE) {

        fclose(fp);
        return NULL;
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return NULL;
    }

    data = (char*)malloc(
        (size_t)size + 1
    );

    if (data == NULL) {
        fclose(fp);
        return NULL;
    }

    read_count = fread(
        data,
        1,
        (size_t)size,
        fp
    );

    fclose(fp);

    if (read_count !=
        (size_t)size) {

        free(data);
        return NULL;
    }

    data[size] = '\0';
    *out_size = (size_t)size;

    return data;
}

static int contains_exact_field(
    const char* data,
    const char* field,
    const char* value)
{
    char pattern[512];
    int written;

    if (data == NULL ||
        field == NULL ||
        value == NULL) {

        return 0;
    }

    written = snprintf(
        pattern,
        sizeof(pattern),
        "\"%s\": \"%s\"",
        field,
        value
    );

    if (written <= 0 ||
        written >=
        (int)sizeof(pattern)) {

        return 0;
    }

    return strstr(
        data,
        pattern
    ) != NULL;
}

static int extract_string_field(
    const char* object,
    const char* field,
    char* destination,
    size_t destination_size)
{
    char pattern[128];

    const char* start;
    const char* end;

    size_t length;

    int written;

    if (object == NULL ||
        field == NULL ||
        destination == NULL ||
        destination_size == 0) {

        return 0;
    }

    written = snprintf(
        pattern,
        sizeof(pattern),
        "\"%s\": \"",
        field
    );

    if (written <= 0 ||
        written >=
        (int)sizeof(pattern)) {

        return 0;
    }

    start = strstr(
        object,
        pattern
    );

    if (start == NULL) {
        return 0;
    }

    start += strlen(pattern);

    end = strchr(
        start,
        '"'
    );

    if (end == NULL) {
        return 0;
    }

    length =
        (size_t)(end - start);

    if (length == 0 ||
        length >= destination_size) {

        return 0;
    }

    memcpy(
        destination,
        start,
        length
    );

    destination[length] = '\0';

    return 1;
}

static int status_is_approved(
    const char* status)
{
    static const char approved[] =
        "APPROVED";

    size_t i;

    if (status == NULL) {
        return 0;
    }

    if (strlen(status) !=
        strlen(approved)) {

        return 0;
    }

    for (i = 0;
        i < strlen(approved);
        ++i) {

        if (toupper(
            (unsigned char)status[i]) !=
            approved[i]) {

            return 0;
        }
    }

    return 1;
}

static int parse_revision_number(
    const char* root_document_id,
    const char* revision_id,
    unsigned long* revision_number)
{
    char prefix[INDEX_REVISION_SIZE];

    const char* number_text;
    char* end;

    unsigned long value;

    int written;

    if (root_document_id == NULL ||
        revision_id == NULL ||
        revision_number == NULL) {

        return 0;
    }

    written = snprintf(
        prefix,
        sizeof(prefix),
        "%s.R",
        root_document_id
    );

    if (written <= 0 ||
        written >=
        (int)sizeof(prefix)) {

        return 0;
    }

    if (strncmp(
        revision_id,
        prefix,
        strlen(prefix)) != 0) {

        return 0;
    }

    number_text =
        revision_id +
        strlen(prefix);

    if (*number_text == '\0') {
        return 0;
    }

    {
        const char* p =
            number_text;

        while (*p != '\0') {

            if (!isdigit(
                (unsigned char)*p)) {

                return 0;
            }

            ++p;
        }
    }

    value = strtoul(
        number_text,
        &end,
        10
    );

    if (*end != '\0') {
        return 0;
    }

    /*
     * R0 is not a valid revision.
     *
     * The root document is represented by
     * Revision ID: NONE.
     */
    if (value == 0 ||
        value == ULONG_MAX) {

        return 0;
    }

    *revision_number = value;

    return 1;
}

index_state index_get_state(
    const char* path)
{
    if (path == NULL) {
        return INDEX_ERROR;
    }

    if (!file_exists(path)) {
        return INDEX_MISSING;
    }

    return INDEX_EXISTS;
}

int index_create_initial(
    const char* path,
    const document_identity* identity,
    const char sha256[SHA256_HEX_SIZE])
{
    FILE* fp = NULL;
    char temp_path[MAX_PATH];
    int written;

    if (path == NULL ||
        identity == NULL ||
        sha256 == NULL) {

        return 0;
    }

    if (file_exists(path)) {
        return 0;
    }

    /*
     * A new index begins with a root document.
     *
     * Root document:
     * Revision ID: NONE
     * Previous Revision: NONE
     */
    if (document_classify_identity(
        identity) !=
        DOCUMENT_IDENTITY_ROOT) {

        return 0;
    }

    if (strlen(sha256) != 64) {
        return 0;
    }

    if (!json_string_safe(
        identity->root_document_id) ||
        !json_string_safe(
            identity->revision_id) ||
        !json_string_safe(
            identity->title) ||
        !json_string_safe(
            identity->status) ||
        !json_string_safe(
            identity->previous_revision)) {

        return 0;
    }

    written = snprintf(
        temp_path,
        sizeof(temp_path),
        "%s.chain.tmp",
        path
    );

    if (written <= 0 ||
        written >=
        (int)sizeof(temp_path)) {

        return 0;
    }

    if (file_exists(temp_path)) {
        DeleteFileA(temp_path);
    }

    if (fopen_s(
        &fp,
        temp_path,
        "wb") != 0 ||
        fp == NULL) {

        return 0;
    }

    if (fprintf(
        fp,
        "[\r\n"
        "  {\r\n"
        "    \"root_document_id\": \"%s\",\r\n"
        "    \"revision_id\": \"%s\",\r\n"
        "    \"title\": \"%s\",\r\n"
        "    \"status\": \"%s\",\r\n"
        "    \"previous_revision\": \"%s\",\r\n"
        "    \"sha256\": \"%s\"\r\n"
        "  }\r\n"
        "]\r\n",
        identity->root_document_id,
        identity->revision_id,
        identity->title,
        identity->status,
        identity->previous_revision,
        sha256) < 0) {

        fclose(fp);
        DeleteFileA(temp_path);
        return 0;
    }

    if (fflush(fp) != 0) {
        fclose(fp);
        DeleteFileA(temp_path);
        return 0;
    }

    if (fclose(fp) != 0) {
        DeleteFileA(temp_path);
        return 0;
    }

    if (file_exists(path)) {
        DeleteFileA(temp_path);
        return 0;
    }

    if (!MoveFileExA(
        temp_path,
        path,
        MOVEFILE_WRITE_THROUGH)) {

        DeleteFileA(temp_path);
        return 0;
    }

    return 1;
}

int index_verify_initial(
    const char* path,
    const document_identity* identity,
    const char sha256[SHA256_HEX_SIZE])
{
    char* data;
    size_t size;
    int result;

    if (path == NULL ||
        identity == NULL ||
        sha256 == NULL) {

        return 0;
    }

    data = read_file(
        path,
        &size
    );

    if (data == NULL) {
        return 0;
    }

    (void)size;

    result =
        contains_exact_field(
            data,
            "root_document_id",
            identity->root_document_id) &&

        contains_exact_field(
            data,
            "revision_id",
            identity->revision_id) &&

        contains_exact_field(
            data,
            "title",
            identity->title) &&

        contains_exact_field(
            data,
            "status",
            identity->status) &&

        contains_exact_field(
            data,
            "previous_revision",
            identity->previous_revision) &&

        contains_exact_field(
            data,
            "sha256",
            sha256);

    free(data);

    return result;
}

index_match_result index_find_revision(
    const char* path,
    const char* root_document_id,
    const char* revision_id)
{
    char* data;
    size_t size;

    size_t i;

    int depth = 0;
    int in_string = 0;
    int escaped = 0;

    size_t object_start = 0;

    int match_count = 0;

    if (path == NULL ||
        root_document_id == NULL ||
        revision_id == NULL) {

        return INDEX_MATCH_ERROR;
    }

    data = read_file(
        path,
        &size
    );

    if (data == NULL) {
        return INDEX_MATCH_ERROR;
    }

    for (i = 0; i < size; ++i) {

        char c = data[i];

        if (in_string) {

            if (escaped) {
                escaped = 0;
                continue;
            }

            if (c == '\\') {
                escaped = 1;
                continue;
            }

            if (c == '"') {
                in_string = 0;
            }

            continue;
        }

        if (c == '"') {
            in_string = 1;
            continue;
        }

        if (c == '{') {

            if (depth == 0) {
                object_start = i;
            }

            ++depth;
            continue;
        }

        if (c == '}') {

            if (depth <= 0) {
                free(data);
                return INDEX_MATCH_ERROR;
            }

            --depth;

            if (depth == 0) {

                size_t object_length =
                    i - object_start + 1;

                char* object =
                    (char*)malloc(
                        object_length + 1
                    );

                if (object == NULL) {
                    free(data);
                    return INDEX_MATCH_ERROR;
                }

                memcpy(
                    object,
                    data + object_start,
                    object_length
                );

                object[object_length] = '\0';

                if (
                    contains_exact_field(
                        object,
                        "root_document_id",
                        root_document_id) &&

                    contains_exact_field(
                        object,
                        "revision_id",
                        revision_id)) {

                    ++match_count;
                }

                free(object);
            }
        }
    }

    if (depth != 0 ||
        in_string) {

        free(data);
        return INDEX_MATCH_ERROR;
    }

    free(data);

    if (match_count == 0) {
        return INDEX_MATCH_NONE;
    }

    if (match_count == 1) {
        return INDEX_MATCH_ONE;
    }

    return INDEX_MATCH_DUPLICATE;
}

index_match_result index_find_root(
    const char* path,
    const char* root_document_id)
{
    char* data;
    size_t size;

    size_t i;

    int depth = 0;
    int in_string = 0;
    int escaped = 0;

    size_t object_start = 0;

    int match_count = 0;

    if (path == NULL ||
        root_document_id == NULL) {

        return INDEX_MATCH_ERROR;
    }

    data = read_file(
        path,
        &size
    );

    if (data == NULL) {
        return INDEX_MATCH_ERROR;
    }

    for (i = 0; i < size; ++i) {

        char c = data[i];

        if (in_string) {

            if (escaped) {
                escaped = 0;
                continue;
            }

            if (c == '\\') {
                escaped = 1;
                continue;
            }

            if (c == '"') {
                in_string = 0;
            }

            continue;
        }

        if (c == '"') {
            in_string = 1;
            continue;
        }

        if (c == '{') {

            if (depth == 0) {
                object_start = i;
            }

            ++depth;
            continue;
        }

        if (c == '}') {

            if (depth <= 0) {
                free(data);
                return INDEX_MATCH_ERROR;
            }

            --depth;

            if (depth == 0) {

                size_t object_length =
                    i - object_start + 1;

                char* object =
                    (char*)malloc(
                        object_length + 1
                    );

                if (object == NULL) {
                    free(data);
                    return INDEX_MATCH_ERROR;
                }

                memcpy(
                    object,
                    data + object_start,
                    object_length
                );

                object[object_length] = '\0';

                if (contains_exact_field(
                    object,
                    "root_document_id",
                    root_document_id)) {

                    ++match_count;
                }

                free(object);
            }
        }
    }

    if (depth != 0 ||
        in_string) {

        free(data);
        return INDEX_MATCH_ERROR;
    }

    free(data);

    if (match_count == 0) {
        return INDEX_MATCH_NONE;
    }

    return INDEX_MATCH_ONE;
}

index_resolve_result index_resolve_latest_approved(
    const char* path,
    const char* root_document_id,
    index_revision_resolution* resolution)
{
    char* data;
    size_t size;

    size_t i;

    int depth = 0;
    int in_string = 0;
    int escaped = 0;

    size_t object_start = 0;

    int found = 0;

    if (path == NULL ||
        root_document_id == NULL ||
        resolution == NULL) {

        return INDEX_RESOLVE_ERROR;
    }

    memset(
        resolution,
        0,
        sizeof(*resolution)
    );

    data = read_file(
        path,
        &size
    );

    if (data == NULL) {
        return INDEX_RESOLVE_ERROR;
    }

    for (i = 0; i < size; ++i) {

        char c = data[i];

        if (in_string) {

            if (escaped) {
                escaped = 0;
                continue;
            }

            if (c == '\\') {
                escaped = 1;
                continue;
            }

            if (c == '"') {
                in_string = 0;
            }

            continue;
        }

        if (c == '"') {
            in_string = 1;
            continue;
        }

        if (c == '{') {

            if (depth == 0) {
                object_start = i;
            }

            ++depth;
            continue;
        }

        if (c == '}') {

            if (depth <= 0) {
                free(data);
                return INDEX_RESOLVE_ERROR;
            }

            --depth;

            if (depth == 0) {

                size_t object_length =
                    i - object_start + 1;

                char* object;

                object = (char*)malloc(
                    object_length + 1
                );

                if (object == NULL) {
                    free(data);
                    return INDEX_RESOLVE_ERROR;
                }

                memcpy(
                    object,
                    data + object_start,
                    object_length
                );

                object[object_length] = '\0';

                if (contains_exact_field(
                    object,
                    "root_document_id",
                    root_document_id)) {

                    char revision_id[
                        INDEX_REVISION_SIZE
                    ];

                    char status[
                        INDEX_STATUS_SIZE
                    ];

                    unsigned long revision_number = 0;

                    if (!extract_string_field(
                        object,
                        "revision_id",
                        revision_id,
                        sizeof(revision_id)) ||

                        !extract_string_field(
                            object,
                            "status",
                            status,
                            sizeof(status))) {

                        free(object);
                        free(data);

                        return INDEX_RESOLVE_ERROR;
                    }

                    /*
                     * Root document:
                     *
                     * Revision ID: NONE
                     *
                     * The root is the baseline document and
                     * therefore uses revision number 0 only
                     * internally for resolution ordering.
                     *
                     * This does NOT create or imply R0.
                     */
                    if (strcmp(
                        revision_id,
                        "NONE") == 0) {

                        revision_number = 0;
                    }
                    else if (!parse_revision_number(
                        root_document_id,
                        revision_id,
                        &revision_number)) {

                        free(object);
                        free(data);

                        return INDEX_RESOLVE_ERROR;
                    }

                    if (status_is_approved(
                        status)) {

                        if (!found ||
                            revision_number >
                            resolution->revision_number) {

                            strcpy_s(
                                resolution->revision_id,
                                sizeof(
                                    resolution
                                    ->revision_id),
                                revision_id
                            );

                            strcpy_s(
                                resolution->status,
                                sizeof(
                                    resolution
                                    ->status),
                                status
                            );

                            resolution
                                ->revision_number =
                                revision_number;

                            found = 1;
                        }
                    }
                }

                free(object);
            }
        }
    }

    if (depth != 0 ||
        in_string) {

        free(data);
        return INDEX_RESOLVE_ERROR;
    }

    free(data);

    if (!found) {
        return INDEX_RESOLVE_NONE;
    }

    return INDEX_RESOLVE_FOUND;
}

int index_append_revision(
    const char* path,
    const document_identity* identity,
    const char sha256[SHA256_HEX_SIZE])
{
    char* data = NULL;
    FILE* fp = NULL;

    char temp_path[MAX_PATH];

    size_t size;
    size_t end;

    int written;

    if (path == NULL ||
        identity == NULL ||
        sha256 == NULL) {

        return 0;
    }

    if (!file_exists(path)) {
        return 0;
    }

    /*
     * Only a valid root document or valid revision
     * may be appended to the index.
     */
    if (document_classify_identity(
        identity) ==
        DOCUMENT_IDENTITY_INVALID) {

        return 0;
    }

    if (strlen(sha256) != 64) {
        return 0;
    }

    if (!json_string_safe(
        identity->root_document_id) ||
        !json_string_safe(
            identity->revision_id) ||
        !json_string_safe(
            identity->title) ||
        !json_string_safe(
            identity->status) ||
        !json_string_safe(
            identity->previous_revision)) {

        return 0;
    }

    data = read_file(
        path,
        &size
    );

    if (data == NULL) {
        return 0;
    }

    end = size;

    while (end > 0 &&
        (data[end - 1] == ' ' ||
            data[end - 1] == '\t' ||
            data[end - 1] == '\r' ||
            data[end - 1] == '\n')) {

        --end;
    }

    if (end == 0 ||
        data[end - 1] != ']') {

        free(data);
        return 0;
    }

    --end;

    while (end > 0 &&
        (data[end - 1] == ' ' ||
            data[end - 1] == '\t' ||
            data[end - 1] == '\r' ||
            data[end - 1] == '\n')) {

        --end;
    }

    if (end == 0) {
        free(data);
        return 0;
    }

    written = snprintf(
        temp_path,
        sizeof(temp_path),
        "%s.chain.tmp",
        path
    );

    if (written <= 0 ||
        written >=
        (int)sizeof(temp_path)) {

        free(data);
        return 0;
    }

    if (file_exists(temp_path)) {
        DeleteFileA(temp_path);
    }

    if (fopen_s(
        &fp,
        temp_path,
        "wb") != 0 ||
        fp == NULL) {

        free(data);
        return 0;
    }

    if (fwrite(
        data,
        1,
        end,
        fp) != end) {

        fclose(fp);
        DeleteFileA(temp_path);
        free(data);
        return 0;
    }

    free(data);
    data = NULL;

    if (fprintf(
        fp,
        ",\r\n"
        "  {\r\n"
        "    \"root_document_id\": \"%s\",\r\n"
        "    \"revision_id\": \"%s\",\r\n"
        "    \"title\": \"%s\",\r\n"
        "    \"status\": \"%s\",\r\n"
        "    \"previous_revision\": \"%s\",\r\n"
        "    \"sha256\": \"%s\"\r\n"
        "  }\r\n"
        "]\r\n",
        identity->root_document_id,
        identity->revision_id,
        identity->title,
        identity->status,
        identity->previous_revision,
        sha256) < 0) {

        fclose(fp);
        DeleteFileA(temp_path);
        return 0;
    }

    if (fflush(fp) != 0) {
        fclose(fp);
        DeleteFileA(temp_path);
        return 0;
    }

    if (fclose(fp) != 0) {
        DeleteFileA(temp_path);
        return 0;
    }

    if (!MoveFileExA(
        temp_path,
        path,
        MOVEFILE_REPLACE_EXISTING |
        MOVEFILE_WRITE_THROUGH)) {

        DeleteFileA(temp_path);
        return 0;
    }

    return 1;
}