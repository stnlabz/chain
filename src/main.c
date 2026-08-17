#include <stdio.h>
#include <string.h>

#include "sha256.h"

int main(int argc, char** argv)
{
    unsigned char canonical_digest[
        SHA256_DIGEST_SIZE
    ];

    unsigned char verification_digest[
        SHA256_DIGEST_SIZE
    ];

    unsigned char raw_digest[
        SHA256_DIGEST_SIZE
    ];

    char canonical_hex[
        SHA256_HEX_SIZE
    ];

    char verification_hex[
        SHA256_HEX_SIZE
    ];

    char raw_hex[
        SHA256_HEX_SIZE
    ];

    if (argc != 2) {

        fprintf(
            stderr,
            "Usage: chain <document>\n"
        );

        return 1;
    }

    /*
     * Establish authoritative SHA-256 from
     * canonical document representation.
     */
    if (!sha256_canonical_file(
        argv[1],
        canonical_digest)) {

        fprintf(
            stderr,
            "CHAIN: FAIL_CANONICAL_HASH\n"
        );

        return 1;
    }

    sha256_to_hex(
        canonical_digest,
        canonical_hex
    );

    /*
     * Stamp authoritative SHA-256 into
     * the human-readable document metadata.
     */
    if (!sha256_stamp_file(
        argv[1],
        canonical_hex)) {

        fprintf(
            stderr,
            "CHAIN: FAIL_DOCUMENT_UPDATE\n"
        );

        return 1;
    }

    /*
     * Re-read the modified document and
     * independently calculate canonical SHA-256.
     */
    if (!sha256_canonical_file(
        argv[1],
        verification_digest)) {

        fprintf(
            stderr,
            "CHAIN: FAIL_POST_WRITE_HASH\n"
        );

        return 1;
    }

    sha256_to_hex(
        verification_digest,
        verification_hex
    );

    /*
     * The canonical digest after modification
     * must be identical to the digest established
     * before modification.
     */
    if (memcmp(
        canonical_digest,
        verification_digest,
        SHA256_DIGEST_SIZE) != 0) {

        fprintf(
            stderr,
            "CHAIN: FAIL_POST_WRITE_VERIFY\n"
        );

        return 1;
    }

    /*
     * Calculate final raw artifact digest
     * for diagnostic evidence.
     */
    if (!sha256_file(
        argv[1],
        raw_digest)) {

        fprintf(
            stderr,
            "CHAIN: FAIL_FINAL_RAW_HASH\n"
        );

        return 1;
    }

    sha256_to_hex(
        raw_digest,
        raw_hex
    );

    printf(
        "AUTHORITATIVE SHA-256: %s\n",
        canonical_hex
    );

    printf(
        "RAW ARTIFACT SHA-256:  %s\n",
        raw_hex
    );

    printf(
        "DOCUMENT: UPDATED\n"
    );

    printf(
        "VERIFY:   PASS\n"
    );

    printf(
        "CHAIN:    PASS\n"
    );

    return 0;
}