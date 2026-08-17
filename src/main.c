#include <stdio.h>
#include <string.h>

#include "document.h"
#include "index.h"
#include "sha256.h"

int main(int argc, char** argv)
{
    document_identity identity;

    document_result document_status;

    index_state state;
    index_match_result match;

    unsigned char canonical_digest[
        SHA256_DIGEST_SIZE
    ];

    unsigned char verification_digest[
        SHA256_DIGEST_SIZE
    ];

    char canonical_hex[
        SHA256_HEX_SIZE
    ];

    if (argc != 3) {

        fprintf(
            stderr,
            "Usage: chain <document> <index>\n"
        );

        return 1;
    }

    /*
     * Read and deterministically validate
     * controlled-document metadata.
     */
    document_status = document_read_identity(
        argv[1],
        &identity
    );

    if (document_status != DOCUMENT_OK) {

        fprintf(
            stderr,
            "CHAIN: %s\n",
            document_result_string(
                document_status
            )
        );

        return 1;
    }

    /*
     * Calculate authoritative digest from
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

    state = index_get_state(
        argv[2]
    );

    if (state == INDEX_ERROR) {

        fprintf(
            stderr,
            "CHAIN: FAIL_INDEX_STATE\n"
        );

        return 1;
    }

    /*
     * INITIAL CHAIN
     */
    if (state == INDEX_MISSING) {

        if (!document_is_initial_revision(
            &identity)) {

            fprintf(
                stderr,
                "CHAIN: FAIL_MISSING_PREDECESSOR_CHAIN\n"
            );

            return 1;
        }

        if (!index_create_initial(
            argv[2],
            &identity,
            canonical_hex)) {

            fprintf(
                stderr,
                "CHAIN: FAIL_INDEX_CREATE\n"
            );

            return 1;
        }

        if (!sha256_stamp_file(
            argv[1],
            canonical_hex)) {

            fprintf(
                stderr,
                "CHAIN: FAIL_DOCUMENT_UPDATE\n"
            );

            return 1;
        }

        if (!sha256_canonical_file(
            argv[1],
            verification_digest)) {

            fprintf(
                stderr,
                "CHAIN: FAIL_POST_WRITE_HASH\n"
            );

            return 1;
        }

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

        if (!index_verify_initial(
            argv[2],
            &identity,
            canonical_hex)) {

            fprintf(
                stderr,
                "CHAIN: FAIL_FINAL_INDEX_VERIFY\n"
            );

            return 1;
        }

        printf(
            "ROOT:       %s\n"
            "REVISION:   %s\n"
            "PREVIOUS:   %s\n"
            "SHA-256:    %s\n"
            "INDEX:      CREATED\n"
            "DOCUMENT:   UPDATED\n"
            "VERIFY:     PASS\n"
            "CHAIN:      PASS\n",

            identity.root_document_id,
            identity.revision_id,
            identity.previous_revision,
            canonical_hex
        );

        return 0;
    }

    /*
     * EXISTING CHAIN
     *
     * Reject already-registered revision.
     */
    match = index_find_revision(
        argv[2],
        identity.root_document_id,
        identity.revision_id
    );

    if (match == INDEX_MATCH_ERROR) {

        fprintf(
            stderr,
            "CHAIN: FAIL_INDEX_PARSE\n"
        );

        return 1;
    }

    if (match == INDEX_MATCH_DUPLICATE) {

        fprintf(
            stderr,
            "CHAIN: FAIL_REVISION_DUPLICATE\n"
        );

        return 1;
    }

    if (match == INDEX_MATCH_ONE) {

        fprintf(
            stderr,
            "CHAIN: FAIL_REVISION_ALREADY_EXISTS\n"
        );

        return 1;
    }

    /*
     * R0 cannot be appended to an
     * already-established chain.
     */
    if (document_is_initial_revision(
        &identity)) {

        fprintf(
            stderr,
            "CHAIN: FAIL_INITIAL_REVISION_ALREADY_CHAINED\n"
        );

        return 1;
    }

    /*
     * Required predecessor must exist
     * exactly once under the same root.
     */
    match = index_find_revision(
        argv[2],
        identity.root_document_id,
        identity.previous_revision
    );

    if (match == INDEX_MATCH_ERROR) {

        fprintf(
            stderr,
            "CHAIN: FAIL_PREDECESSOR_LOOKUP\n"
        );

        return 1;
    }

    if (match == INDEX_MATCH_NONE) {

        fprintf(
            stderr,
            "CHAIN: FAIL_PREDECESSOR_NOT_FOUND\n"
        );

        return 1;
    }

    if (match == INDEX_MATCH_DUPLICATE) {

        fprintf(
            stderr,
            "CHAIN: FAIL_PREDECESSOR_DUPLICATE\n"
        );

        return 1;
    }

    /*
     * Append new revision after lineage
     * has been deterministically proven.
     */
    if (!index_append_revision(
        argv[2],
        &identity,
        canonical_hex)) {

        fprintf(
            stderr,
            "CHAIN: FAIL_INDEX_APPEND\n"
        );

        return 1;
    }

    /*
     * Verify newly registered revision
     * exists exactly once.
     */
    match = index_find_revision(
        argv[2],
        identity.root_document_id,
        identity.revision_id
    );

    if (match != INDEX_MATCH_ONE) {

        fprintf(
            stderr,
            "CHAIN: FAIL_NEW_REVISION_VERIFY\n"
        );

        return 1;
    }

    /*
     * Stamp controlled document only after
     * authoritative index registration.
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
     * Re-read and independently validate
     * canonical document digest.
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

    printf(
        "ROOT:       %s\n"
        "REVISION:   %s\n"
        "PREVIOUS:   %s\n"
        "SHA-256:    %s\n"
        "LINEAGE:    VERIFIED\n"
        "INDEX:      UPDATED\n"
        "DOCUMENT:   UPDATED\n"
        "VERIFY:     PASS\n"
        "CHAIN:      PASS\n",

        identity.root_document_id,
        identity.revision_id,
        identity.previous_revision,
        canonical_hex
    );

    return 0;
}