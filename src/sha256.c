#include <stdio.h>
#include <windows.h>
#include <bcrypt.h>

#include "sha256.h"

#pragma comment(lib, "bcrypt.lib")

int sha256_file(
    const char *path,
    unsigned char digest[SHA256_DIGEST_SIZE])
{
    FILE *fp = NULL;
    unsigned char buffer[4096];

    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;

    NTSTATUS status;
    size_t count;

    if (path == NULL || digest == NULL) {
        return 0;
    }

    if (fopen_s(&fp, path, "rb") != 0 || fp == NULL) {
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
        BCryptCloseAlgorithmProvider(algorithm, 0);
        fclose(fp);
        return 0;
    }

    while ((count = fread(buffer, 1, sizeof(buffer), fp)) > 0) {

        status = BCryptHashData(
            hash,
            buffer,
            (ULONG)count,
            0
        );

        if (!BCRYPT_SUCCESS(status)) {
            BCryptDestroyHash(hash);
            BCryptCloseAlgorithmProvider(algorithm, 0);
            fclose(fp);
            return 0;
        }
    }

    if (ferror(fp)) {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(algorithm, 0);
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
    BCryptCloseAlgorithmProvider(algorithm, 0);
    fclose(fp);

    return BCRYPT_SUCCESS(status) ? 1 : 0;
}

void sha256_to_hex(
    const unsigned char digest[SHA256_DIGEST_SIZE],
    char hex[SHA256_HEX_SIZE])
{
    static const char digits[] = "0123456789abcdef";

    size_t i;

    for (i = 0; i < SHA256_DIGEST_SIZE; ++i) {
        hex[i * 2]     = digits[(digest[i] >> 4) & 0x0F];
        hex[i * 2 + 1] = digits[digest[i] & 0x0F];
    }

    hex[64] = '\0';
}