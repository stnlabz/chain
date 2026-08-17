#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <bcrypt.h>

#include "sha256.h"

#pragma comment(lib, "bcrypt.lib")

#define READ_BUFFER_SIZE 4096

#define SHA256_PREFIX "sha256:"
#define CANONICAL_SHA256_LINE "sha256: <authoritative hash>"

int sha256_buffer(
    const unsigned char* data,
    size_t length,
    unsigned char digest[SHA256_DIGEST_SIZE])
{
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;

    NTSTATUS status;

    if (data == NULL || digest == NULL) {
        return 0;
    }

    /*
     * BCryptHashData takes ULONG length.
     * Reject buffers that cannot be represented
     * safely rather than truncating size_t.
     */
    if (length > ULONG_MAX) {
        return 0;
    }

    status = BCryptOpenAlgorithmProvider(
        &algorithm,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        0
    );

    if (!BCRYPT_SUCCESS(status)) {
        return 0;
    }

    status = BCryptCreateHash(
        algorithm,
        &hash,
        NULL,
        0,
        NULL,
        0,
        0
    );

    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(
            algorithm,
            0
        );

        return 0;
    }

    status = BCryptHashData(
        hash,
        (PUCHAR)data,
        (ULONG)length,
        0
    );

    if (!BCRYPT_SUCCESS(status)) {

        BCryptDestroyHash(hash);

        BCryptCloseAlgorithmProvider(
            algorithm,
            0
        );

        return 0;
    }

    status = BCryptFinishHash(
        hash,
        digest,
        SHA256_DIGEST_SIZE,
        0
    );

    BCryptDestroyHash(hash);

    BCryptCloseAlgorithmProvider(
        algorithm,
        0
    );

    return BCRYPT_SUCCESS(status)
        ? 1
        : 0;
}

int sha256_file(
    const char* path,
    unsigned char digest[SHA256_DIGEST_SIZE])
{
    FILE* fp = NULL;

    unsigned char buffer[READ_BUFFER_SIZE];

    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;

    NTSTATUS status;

    size_t count;

    if (path == NULL || digest == NULL) {
        return 0;
    }

    if (fopen_s(
        &fp,
        path,
        "rb") != 0 ||
        fp == NULL) {

        return 0;
    }

    status = BCryptOpenAlgorithmProvider(
        &algorithm,
        BCRYPT_SHA256_ALGORITHM,
        NULL,
        0
    );

    if (!BCRYPT_SUCCESS(status)) {
        fclose(fp);
        return 0;
    }

    status = BCryptCreateHash(
        algorithm,
        &hash,
        NULL,
        0,
        NULL,
        0,
        0
    );

    if (!BCRYPT_SUCCESS(status)) {

        BCryptCloseAlgorithmProvider(
            algorithm,
            0
        );

        fclose(fp);

        return 0;
    }

    while ((count = fread(
        buffer,
        1,
        sizeof(buffer),
        fp)) > 0) {

        status = BCryptHashData(
            hash,
            buffer,
            (ULONG)count,
            0
        );

        if (!BCRYPT_SUCCESS(status)) {

            BCryptDestroyHash(hash);

            BCryptCloseAlgorithmProvider(
                algorithm,
                0
            );

            fclose(fp);

            return 0;
        }
    }

    if (ferror(fp)) {

        BCryptDestroyHash(hash);

        BCryptCloseAlgorithmProvider(
            algorithm,
            0
        );

        fclose(fp);

        return 0;
    }

    status = BCryptFinishHash(
        hash,
        digest,
        SHA256_DIGEST_SIZE,
        0
    );

    BCryptDestroyHash(hash);

    BCryptCloseAlgorithmProvider(
        algorithm,
        0
    );

    fclose(fp);

    return BCRYPT_SUCCESS(status)
        ? 1
        : 0;
}

int sha256_canonical_file(
    const char* path,
    unsigned char digest[SHA256_DIGEST_SIZE])
{
    FILE* fp = NULL;

    unsigned char* input = NULL;
    unsigned char* canonical = NULL;

    long file_size;

    size_t bytes_read;
    size_t i = 0;
    size_t output_index = 0;

    int sha256_fields = 0;

    const size_t prefix_length =
        strlen(SHA256_PREFIX);

    const size_t canonical_line_length =
        strlen(CANONICAL_SHA256_LINE);

    if (path == NULL || digest == NULL) {
        return 0;
    }

    if (fopen_s(
        &fp,
        path,
        "rb") != 0 ||
        fp == NULL) {

        return 0;
    }

    if (fseek(
        fp,
        0,
        SEEK_END) != 0) {

        fclose(fp);
        return 0;
    }

    file_size = ftell(fp);

    if (file_size < 0) {
        fclose(fp);
        return 0;
    }

    if (fseek(
        fp,
        0,
        SEEK_SET) != 0) {

        fclose(fp);
        return 0;
    }

    input = (unsigned char*)malloc(
        (size_t)file_size + 1
    );

    if (input == NULL) {
        fclose(fp);
        return 0;
    }

    bytes_read = fread(
        input,
        1,
        (size_t)file_size,
        fp
    );

    fclose(fp);
    fp = NULL;

    if (bytes_read !=
        (size_t)file_size) {

        free(input);
        return 0;
    }

    canonical = (unsigned char*)malloc(
        (size_t)file_size +
        canonical_line_length +
        1
    );

    if (canonical == NULL) {
        free(input);
        return 0;
    }

    while (i < (size_t)file_size) {

        size_t line_start = i;
        size_t line_end;

        while (
            i < (size_t)file_size &&
            input[i] != '\r' &&
            input[i] != '\n') {

            ++i;
        }

        line_end = i;

        if (
            (line_end - line_start) >=
            prefix_length &&

            memcmp(
                input + line_start,
                SHA256_PREFIX,
                prefix_length
            ) == 0) {

            ++sha256_fields;

            memcpy(
                canonical + output_index,
                CANONICAL_SHA256_LINE,
                canonical_line_length
            );

            output_index +=
                canonical_line_length;
        }
        else {

            size_t line_length =
                line_end - line_start;

            memcpy(
                canonical + output_index,
                input + line_start,
                line_length
            );

            output_index +=
                line_length;
        }

        /*
         * Preserve original line endings exactly.
         */
        if (
            i < (size_t)file_size &&
            input[i] == '\r') {

            canonical[output_index++] =
                input[i++];

            if (
                i < (size_t)file_size &&
                input[i] == '\n') {

                canonical[output_index++] =
                    input[i++];
            }
        }
        else if (
            i < (size_t)file_size &&
            input[i] == '\n') {

            canonical[output_index++] =
                input[i++];
        }
    }

    free(input);

    if (sha256_fields != 1) {
        free(canonical);
        return 0;
    }

    if (!sha256_buffer(
        canonical,
        output_index,
        digest)) {

        free(canonical);
        return 0;
    }

    free(canonical);

    return 1;
}

int sha256_stamp_file(
    const char* path,
    const char hex[SHA256_HEX_SIZE])
{
    FILE* input_fp = NULL;
    FILE* output_fp = NULL;

    char* temp_path = NULL;

    unsigned char* input = NULL;

    long file_size;
    size_t bytes_read;

    size_t i = 0;

    int sha256_fields = 0;

    const size_t prefix_length =
        strlen(SHA256_PREFIX);

    size_t path_length;

    if (path == NULL || hex == NULL) {
        return 0;
    }

    /*
     * SHA-256 hex digest must contain exactly
     * 64 hexadecimal characters.
     */
    if (strlen(hex) != 64) {
        return 0;
    }

    if (fopen_s(
        &input_fp,
        path,
        "rb") != 0 ||
        input_fp == NULL) {

        return 0;
    }

    if (fseek(
        input_fp,
        0,
        SEEK_END) != 0) {

        fclose(input_fp);
        return 0;
    }

    file_size = ftell(input_fp);

    if (file_size < 0) {
        fclose(input_fp);
        return 0;
    }

    if (fseek(
        input_fp,
        0,
        SEEK_SET) != 0) {

        fclose(input_fp);
        return 0;
    }

    input = (unsigned char*)malloc(
        (size_t)file_size + 1
    );

    if (input == NULL) {
        fclose(input_fp);
        return 0;
    }

    bytes_read = fread(
        input,
        1,
        (size_t)file_size,
        input_fp
    );

    fclose(input_fp);
    input_fp = NULL;

    if (bytes_read !=
        (size_t)file_size) {

        free(input);
        return 0;
    }

    path_length = strlen(path);

    temp_path = (char*)malloc(
        path_length +
        strlen(".chain.tmp") +
        1
    );

    if (temp_path == NULL) {
        free(input);
        return 0;
    }

    strcpy_s(
        temp_path,
        path_length +
        strlen(".chain.tmp") +
        1,
        path
    );

    strcat_s(
        temp_path,
        path_length +
        strlen(".chain.tmp") +
        1,
        ".chain.tmp"
    );

    if (fopen_s(
        &output_fp,
        temp_path,
        "wb") != 0 ||
        output_fp == NULL) {

        free(temp_path);
        free(input);

        return 0;
    }

    while (i < (size_t)file_size) {

        size_t line_start = i;
        size_t line_end;

        while (
            i < (size_t)file_size &&
            input[i] != '\r' &&
            input[i] != '\n') {

            ++i;
        }

        line_end = i;

        if (
            (line_end - line_start) >=
            prefix_length &&

            memcmp(
                input + line_start,
                SHA256_PREFIX,
                prefix_length
            ) == 0) {

            ++sha256_fields;

            if (fprintf(
                output_fp,
                "sha256: %s",
                hex) < 0) {

                fclose(output_fp);
                DeleteFileA(temp_path);

                free(temp_path);
                free(input);

                return 0;
            }
        }
        else {

            size_t line_length =
                line_end - line_start;

            if (line_length > 0) {

                if (fwrite(
                    input + line_start,
                    1,
                    line_length,
                    output_fp) !=
                    line_length) {

                    fclose(output_fp);
                    DeleteFileA(temp_path);

                    free(temp_path);
                    free(input);

                    return 0;
                }
            }
        }

        /*
         * Preserve original line endings exactly.
         */
        if (
            i < (size_t)file_size &&
            input[i] == '\r') {

            if (fputc(
                input[i++],
                output_fp) == EOF) {

                fclose(output_fp);
                DeleteFileA(temp_path);

                free(temp_path);
                free(input);

                return 0;
            }

            if (
                i < (size_t)file_size &&
                input[i] == '\n') {

                if (fputc(
                    input[i++],
                    output_fp) == EOF) {

                    fclose(output_fp);
                    DeleteFileA(temp_path);

                    free(temp_path);
                    free(input);

                    return 0;
                }
            }
        }
        else if (
            i < (size_t)file_size &&
            input[i] == '\n') {

            if (fputc(
                input[i++],
                output_fp) == EOF) {

                fclose(output_fp);
                DeleteFileA(temp_path);

                free(temp_path);
                free(input);

                return 0;
            }
        }
    }

    free(input);
    input = NULL;

    if (sha256_fields != 1) {

        fclose(output_fp);
        DeleteFileA(temp_path);

        free(temp_path);

        return 0;
    }

    if (fflush(output_fp) != 0) {

        fclose(output_fp);
        DeleteFileA(temp_path);

        free(temp_path);

        return 0;
    }

    if (fclose(output_fp) != 0) {

        DeleteFileA(temp_path);

        free(temp_path);

        return 0;
    }

    output_fp = NULL;

    /*
     * Replace the original only after the complete
     * temporary artifact has been successfully written.
     */
    if (!MoveFileExA(
        temp_path,
        path,
        MOVEFILE_REPLACE_EXISTING |
        MOVEFILE_WRITE_THROUGH)) {

        DeleteFileA(temp_path);

        free(temp_path);

        return 0;
    }

    free(temp_path);

    return 1;
}

void sha256_to_hex(
    const unsigned char digest[SHA256_DIGEST_SIZE],
    char hex[SHA256_HEX_SIZE])
{
    static const char digits[] =
        "0123456789abcdef";

    size_t i;

    for (
        i = 0;
        i < SHA256_DIGEST_SIZE;
        ++i) {

        hex[i * 2] =
            digits[
                (digest[i] >> 4) &
                    0x0F
            ];

        hex[i * 2 + 1] =
            digits[
                digest[i] &
                    0x0F
            ];
    }

    hex[64] = '\0';
}