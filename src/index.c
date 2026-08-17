#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

    if (value == NULL || *value == '\0') {
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

    if (path == NULL || out_size == NULL) {
        return NULL;
    }

    *out_size = 0;

    if (fopen_s(&fp, path, "rb") != 0 ||
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

    data = (char*)malloc((size_t)size + 1);

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

    if (read_count != (size_t)size) {
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
        written >= (int)sizeof(pattern)) {

        return 0;
    }

    return strstr(data, pattern) != NULL;
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

    if (!document_is_initial_revision(identity)) {
        return 0;
    }

    if (strlen(sha256) != 64) {
        return 0;
    }

    if (!json_string_safe(identity->root_document_id) ||
        !json_string_safe(identity->revision_id) ||
        !json_string_safe(identity->title) ||
        !json_string_safe(identity->status) ||
        !json_string_safe(identity->previous_revision)) {

        return 0;
    }

    written = snprintf(
        temp_path,
        sizeof(temp_path),
        "%s.chain.tmp",
        path
    );

    if (written <= 0 ||
        written >= (int)sizeof(temp_path)) {

        return 0;
    }

    if (file_exists(temp_path)) {
        DeleteFileA(temp_path);
    }

    if (fopen_s(&fp, temp_path, "wb") != 0 ||
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

    data = read_file(path, &size);

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

    data = read_file(path, &size);

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

    if (depth != 0 || in_string) {
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

    if (strlen(sha256) != 64) {
        return 0;
    }

    if (!json_string_safe(identity->root_document_id) ||
        !json_string_safe(identity->revision_id) ||
        !json_string_safe(identity->title) ||
        !json_string_safe(identity->status) ||
        !json_string_safe(identity->previous_revision)) {

        return 0;
    }

    data = read_file(path, &size);

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
        written >= (int)sizeof(temp_path)) {

        free(data);
        return 0;
    }

    if (file_exists(temp_path)) {
        DeleteFileA(temp_path);
    }

    if (fopen_s(&fp, temp_path, "wb") != 0 ||
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