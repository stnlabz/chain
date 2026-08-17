#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>

#define SHA256_DIGEST_SIZE 32
#define SHA256_HEX_SIZE    65

int sha256_buffer(
    const unsigned char *data,
    size_t length,
    unsigned char digest[SHA256_DIGEST_SIZE]
);

int sha256_file(
    const char *path,
    unsigned char digest[SHA256_DIGEST_SIZE]
);

int sha256_canonical_file(
    const char *path,
    unsigned char digest[SHA256_DIGEST_SIZE]
);

int sha256_stamp_file(
    const char *path,
    const char hex[SHA256_HEX_SIZE]
);

void sha256_to_hex(
    const unsigned char digest[SHA256_DIGEST_SIZE],
    char hex[SHA256_HEX_SIZE]
);

#endif