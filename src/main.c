#include <stdio.h>

#include "sha256.h"

int main(int argc, char **argv)
{
    unsigned char digest[SHA256_DIGEST_SIZE];
    char hex[SHA256_HEX_SIZE];

    if (argc != 2) {
        fprintf(stderr, "Usage: chain <document>\n");
        return 1;
    }

    if (!sha256_file(argv[1], digest)) {
        fprintf(stderr, "CHAIN: FAIL\n");
        return 1;
    }

    sha256_to_hex(digest, hex);

    printf("SHA-256: %s\n", hex);
    printf("CHAIN: PASS\n");

    return 0;
}