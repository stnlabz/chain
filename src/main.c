#include <stdio.h>
#include <string.h>

#include "audit.h"
#include "document.h"
#include "index.h"
#include "reference.h"
#include "sha256.h"

static void print_help(void)
{
    printf(
        "STN-LABZ chain\n"
        "Trust Chain Authoring and Validation Utility\n"
        "\n"
        "USAGE\n"
        "\n"
        "  chain <document> <index>\n"
        "      Register a controlled document revision.\n"
        "\n"
        "  chain --check-references <document> <index>\n"
        "      Resolve and verify controlled references.\n"
        "      No files are modified.\n"
        "\n"
        "  chain --update-references <document> <index>\n"
        "      Resolve root-only references to the latest\n"
        "      APPROVED tracked revision, update the document,\n"
        "      then register the resulting controlled revision.\n"
        "\n"
        "  chain --verify-audit <index>\n"
        "      Verify the hash-linked chain operation record.\n"
        "\n"
        "  chain --help\n"
        "  chain -h\n"
        "  chain help\n"
        "      Display this help information.\n"
        "\n"
        "DOCUMENT REQUIREMENTS\n"
        "\n"
        "    Root Document ID: YYYYMMDD.#\n"
        "    Revision ID: YYYYMMDD.#.R#\n"
        "    Previous Revision: YYYYMMDD.#.R# | NONE\n"
        "    sha256: <hash>\n"
        "    **Status:** <status>\n"
        "\n"
        "REFERENCE RULES\n"
        "\n"
        "  Root-only reference:\n"
        "\n"
        "    - 20260729.6 — Engineering Documentation\n"
        "\n"
        "  Resolves to the latest APPROVED tracked revision.\n"
        "\n"
        "  Explicit revision reference:\n"
        "\n"
        "    - 20260729.6.R0 — Engineering Documentation\n"
        "\n"
        "  Verifies exactly the named revision.\n"
        "\n"
        "AUDIT RECORD\n"
        "\n"
        "  Successful modifying operations append evidence to:\n"
        "\n"
        "    <index>.chainlog\n"
        "\n"
        "  Each record contains the hash of the previous record.\n"
        "  Audit evidence does not independently establish\n"
        "  organizational authority.\n"
        "\n"
    );
}

static int verify_audit_command(
    const char* index_path)
{
    audit_result result;

    result = audit_verify(
        index_path
    );

    if (result != AUDIT_OK) {

        printf(
            "AUDIT:  %s\n"
            "CHAIN:  FAIL\n",
            audit_result_string(result)
        );

        return 1;
    }

    printf(
        "AUDIT:  PASS\n"
        "CHAIN:  PASS\n"
    );

    return 0;
}

static int append_audit_evidence(
    const char* index_path,
    const document_identity* identity,
    const char canonical_hex[SHA256_HEX_SIZE],
    const char* operation)
{
    audit_result result;

    result = audit_append(
        index_path,
        identity,
        canonical_hex,
        operation
    );

    if (result != AUDIT_OK) {

        fprintf(
            stderr,
            "AUDIT: %s\n",
            audit_result_string(result)
        );

        fprintf(
            stderr,
            "CHAIN: FAIL_AUDIT\n"
        );

        return 0;
    }

    printf(
        "AUDIT:      PASS\n"
    );

    return 1;
}

static int check_references(
    const char* document_path,
    const char* index_path)
{
    reference_list references;
    reference_result result;

    size_t i;
    int failures = 0;

    result = reference_read_document(
        document_path,
        &references
    );

    if (result != REFERENCE_OK) {

        fprintf(
            stderr,
            "CHAIN: %s\n",
            reference_result_string(result)
        );

        return 1;
    }

    if (index_get_state(index_path) !=
        INDEX_EXISTS) {

        fprintf(
            stderr,
            "CHAIN: FAIL_INDEX_MISSING\n"
        );

        return 1;
    }

    for (i = 0;
        i < references.count;
        ++i) {

        const document_reference* reference =
            &references.items[i];

        if (reference->explicit_revision) {

            index_match_result match;

            match = index_find_revision(
                index_path,
                reference->root_document_id,
                reference->revision_id
            );

            if (match == INDEX_MATCH_ONE) {

                printf(
                    "REFERENCE: %-24s VERIFIED\n",
                    reference->revision_id
                );
            }
            else {

                printf(
                    "REFERENCE: %-24s FAIL\n",
                    reference->revision_id
                );

                ++failures;
            }
        }
        else {

            index_revision_resolution resolution;
            index_resolve_result resolved;

            resolved =
                index_resolve_latest_approved(
                    index_path,
                    reference->root_document_id,
                    &resolution
                );

            if (resolved ==
                INDEX_RESOLVE_FOUND) {

                printf(
                    "REFERENCE: %-24s RESOLVED\n",
                    reference->root_document_id
                );

                printf(
                    "  REVISION: %-22s\n",
                    resolution.revision_id
                );

                printf(
                    "  STATUS:   %s\n",
                    resolution.status
                );
            }
            else {

                printf(
                    "REFERENCE: %-24s FAIL\n",
                    reference->root_document_id
                );

                ++failures;
            }
        }
    }

    printf(
        "REFERENCES:  %zu CHECKED\n",
        references.count
    );

    if (failures != 0) {

        printf(
            "VERIFY:      FAIL\n"
            "CHAIN:       FAIL\n"
        );

        return 1;
    }

    printf(
        "VERIFY:      PASS\n"
        "CHAIN:       PASS\n"
    );

    return 0;
}

static int verify_and_stamp_document(
    const char* document_path,
    const char canonical_hex[SHA256_HEX_SIZE],
    const unsigned char canonical_digest[SHA256_DIGEST_SIZE])
{
    unsigned char verification_digest[
        SHA256_DIGEST_SIZE
    ];

    if (!sha256_stamp_file(
        document_path,
        canonical_hex)) {

        fprintf(
            stderr,
            "CHAIN: FAIL_DOCUMENT_UPDATE\n"
        );

        return 0;
    }

    if (!sha256_canonical_file(
        document_path,
        verification_digest)) {

        fprintf(
            stderr,
            "CHAIN: FAIL_POST_WRITE_HASH\n"
        );

        return 0;
    }

    if (memcmp(
        canonical_digest,
        verification_digest,
        SHA256_DIGEST_SIZE) != 0) {

        fprintf(
            stderr,
            "CHAIN: FAIL_POST_WRITE_VERIFY\n"
        );

        return 0;
    }

    return 1;
}

static int register_document(
    const char* document_path,
    const char* index_path,
    const char* operation)
{
    document_identity identity;

    document_result document_status;

    index_state state;
    index_match_result match;
    index_match_result root_match;

    unsigned char canonical_digest[
        SHA256_DIGEST_SIZE
    ];

    char canonical_hex[
        SHA256_HEX_SIZE
    ];

    /*
     * Verify existing audit evidence before
     * performing another modifying operation.
     *
     * No audit file yet is valid for the
     * first audited operation.
     */
    {
        audit_result audit_status;

        audit_status = audit_verify(
            index_path
        );

        if (audit_status != AUDIT_OK) {

            fprintf(
                stderr,
                "AUDIT: %s\n",
                audit_result_string(
                    audit_status
                )
            );

            fprintf(
                stderr,
                "CHAIN: FAIL_AUDIT_PRECHECK\n"
            );

            return 1;
        }
    }

    document_status =
        document_read_identity(
            document_path,
            &identity
        );

    if (document_status !=
        DOCUMENT_OK) {

        fprintf(
            stderr,
            "CHAIN: %s\n",
            document_result_string(
                document_status
            )
        );

        return 1;
    }

    if (!sha256_canonical_file(
        document_path,
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
        index_path
    );

    if (state == INDEX_ERROR) {

        fprintf(
            stderr,
            "CHAIN: FAIL_INDEX_STATE\n"
        );

        return 1;
    }

    /*
     * --------------------------------------------------------
     * First global index record.
     * --------------------------------------------------------
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
            index_path,
            &identity,
            canonical_hex)) {

            fprintf(
                stderr,
                "CHAIN: FAIL_INDEX_CREATE\n"
            );

            return 1;
        }

        if (!verify_and_stamp_document(
            document_path,
            canonical_hex,
            canonical_digest)) {

            return 1;
        }

        if (!index_verify_initial(
            index_path,
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
            "ROOT CHAIN: CREATED\n"
            "INDEX:      CREATED\n"
            "DOCUMENT:   UPDATED\n"
            "VERIFY:     PASS\n",

            identity.root_document_id,
            identity.revision_id,
            identity.previous_revision,
            canonical_hex
        );

        if (!append_audit_evidence(
            index_path,
            &identity,
            canonical_hex,
            operation)) {

            return 1;
        }

        printf(
            "CHAIN:      PASS\n"
        );

        return 0;
    }

    /*
     * Determine whether this root already exists.
     */
    root_match = index_find_root(
        index_path,
        identity.root_document_id
    );

    if (root_match ==
        INDEX_MATCH_ERROR) {

        fprintf(
            stderr,
            "CHAIN: FAIL_ROOT_LOOKUP\n"
        );

        return 1;
    }

    /*
     * --------------------------------------------------------
     * New root in an existing global index.
     * --------------------------------------------------------
     */
    if (root_match ==
        INDEX_MATCH_NONE) {

        if (!document_is_initial_revision(
            &identity)) {

            fprintf(
                stderr,
                "CHAIN: FAIL_MISSING_PREDECESSOR_CHAIN\n"
            );

            return 1;
        }

        if (!index_append_revision(
            index_path,
            &identity,
            canonical_hex)) {

            fprintf(
                stderr,
                "CHAIN: FAIL_ROOT_CHAIN_APPEND\n"
            );

            return 1;
        }

        match = index_find_revision(
            index_path,
            identity.root_document_id,
            identity.revision_id
        );

        if (match !=
            INDEX_MATCH_ONE) {

            fprintf(
                stderr,
                "CHAIN: FAIL_NEW_ROOT_VERIFY\n"
            );

            return 1;
        }

        if (!verify_and_stamp_document(
            document_path,
            canonical_hex,
            canonical_digest)) {

            return 1;
        }

        printf(
            "ROOT:       %s\n"
            "REVISION:   %s\n"
            "PREVIOUS:   %s\n"
            "SHA-256:    %s\n"
            "ROOT CHAIN: CREATED\n"
            "INDEX:      UPDATED\n"
            "DOCUMENT:   UPDATED\n"
            "VERIFY:     PASS\n",

            identity.root_document_id,
            identity.revision_id,
            identity.previous_revision,
            canonical_hex
        );

        if (!append_audit_evidence(
            index_path,
            &identity,
            canonical_hex,
            operation)) {

            return 1;
        }

        printf(
            "CHAIN:      PASS\n"
        );

        return 0;
    }

    /*
     * --------------------------------------------------------
     * Existing root.
     * --------------------------------------------------------
     */
    match = index_find_revision(
        index_path,
        identity.root_document_id,
        identity.revision_id
    );

    if (match ==
        INDEX_MATCH_ERROR) {

        fprintf(
            stderr,
            "CHAIN: FAIL_INDEX_PARSE\n"
        );

        return 1;
    }

    if (match ==
        INDEX_MATCH_DUPLICATE) {

        fprintf(
            stderr,
            "CHAIN: FAIL_REVISION_DUPLICATE\n"
        );

        return 1;
    }

    if (match ==
        INDEX_MATCH_ONE) {

        fprintf(
            stderr,
            "CHAIN: FAIL_REVISION_ALREADY_EXISTS\n"
        );

        return 1;
    }

    if (document_is_initial_revision(
        &identity)) {

        fprintf(
            stderr,
            "CHAIN: FAIL_INITIAL_REVISION_ALREADY_CHAINED\n"
        );

        return 1;
    }

    /*
     * Required predecessor must already exist.
     */
    match = index_find_revision(
        index_path,
        identity.root_document_id,
        identity.previous_revision
    );

    if (match ==
        INDEX_MATCH_ERROR) {

        fprintf(
            stderr,
            "CHAIN: FAIL_PREDECESSOR_LOOKUP\n"
        );

        return 1;
    }

    if (match ==
        INDEX_MATCH_NONE) {

        fprintf(
            stderr,
            "CHAIN: FAIL_PREDECESSOR_NOT_FOUND\n"
        );

        return 1;
    }

    if (match ==
        INDEX_MATCH_DUPLICATE) {

        fprintf(
            stderr,
            "CHAIN: FAIL_PREDECESSOR_DUPLICATE\n"
        );

        return 1;
    }

    /*
     * Append revision only after lineage is proven.
     */
    if (!index_append_revision(
        index_path,
        &identity,
        canonical_hex)) {

        fprintf(
            stderr,
            "CHAIN: FAIL_INDEX_APPEND\n"
        );

        return 1;
    }

    match = index_find_revision(
        index_path,
        identity.root_document_id,
        identity.revision_id
    );

    if (match !=
        INDEX_MATCH_ONE) {

        fprintf(
            stderr,
            "CHAIN: FAIL_NEW_REVISION_VERIFY\n"
        );

        return 1;
    }

    if (!verify_and_stamp_document(
        document_path,
        canonical_hex,
        canonical_digest)) {

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
        "VERIFY:     PASS\n",

        identity.root_document_id,
        identity.revision_id,
        identity.previous_revision,
        canonical_hex
    );

    if (!append_audit_evidence(
        index_path,
        &identity,
        canonical_hex,
        operation)) {

        return 1;
    }

    printf(
        "CHAIN:      PASS\n"
    );

    return 0;
}

static int update_references(
    const char* document_path,
    const char* index_path)
{
    document_identity identity;

    document_result document_status;

    index_match_result match;
    index_match_result root_match;

    reference_update_summary summary;
    reference_result result;

    document_status =
        document_read_identity(
            document_path,
            &identity
        );

    if (document_status !=
        DOCUMENT_OK) {

        fprintf(
            stderr,
            "CHAIN: %s\n",
            document_result_string(
                document_status
            )
        );

        return 1;
    }

    if (index_get_state(index_path) !=
        INDEX_EXISTS) {

        fprintf(
            stderr,
            "CHAIN: FAIL_INDEX_MISSING\n"
        );

        return 1;
    }

    /*
     * Audit history must already be valid before
     * reference rewriting can begin.
     */
    {
        audit_result audit_status;

        audit_status = audit_verify(
            index_path
        );

        if (audit_status !=
            AUDIT_OK) {

            fprintf(
                stderr,
                "AUDIT: %s\n",
                audit_result_string(
                    audit_status
                )
            );

            fprintf(
                stderr,
                "CHAIN: FAIL_AUDIT_PRECHECK\n"
            );

            return 1;
        }
    }

    root_match = index_find_root(
        index_path,
        identity.root_document_id
    );

    if (root_match ==
        INDEX_MATCH_ERROR) {

        fprintf(
            stderr,
            "CHAIN: FAIL_ROOT_LOOKUP\n"
        );

        return 1;
    }

    if (root_match ==
        INDEX_MATCH_ONE) {

        match = index_find_revision(
            index_path,
            identity.root_document_id,
            identity.revision_id
        );

        if (match !=
            INDEX_MATCH_NONE) {

            fprintf(
                stderr,
                "CHAIN: FAIL_REVISION_ALREADY_EXISTS\n"
            );

            return 1;
        }

        match = index_find_revision(
            index_path,
            identity.root_document_id,
            identity.previous_revision
        );

        if (match !=
            INDEX_MATCH_ONE) {

            fprintf(
                stderr,
                "CHAIN: FAIL_PREDECESSOR_NOT_FOUND\n"
            );

            return 1;
        }
    }
    else {

        if (!document_is_initial_revision(
            &identity)) {

            fprintf(
                stderr,
                "CHAIN: FAIL_MISSING_PREDECESSOR_CHAIN\n"
            );

            return 1;
        }
    }

    result = reference_update_document(
        document_path,
        index_path,
        &summary
    );

    if (result !=
        REFERENCE_OK) {

        fprintf(
            stderr,
            "CHAIN: %s\n",
            reference_result_string(
                result
            )
        );

        return 1;
    }

    printf(
        "REFERENCES:  %zu CHECKED\n",
        summary.checked
    );

    printf(
        "UPDATED:     %zu\n",
        summary.updated
    );

    printf(
        "EXPLICIT:    %zu VERIFIED\n",
        summary.explicit_verified
    );

    /*
     * The normal registration path performs
     * hashing, lineage, index registration,
     * stamping, verification and audit append.
     */
    return register_document(
        document_path,
        index_path,
        "UPDATE_REFERENCES"
    );
}

int main(int argc, char** argv)
{
    if (argc == 1) {

        print_help();
        return 0;
    }

    if (argc == 2 &&
        (
            strcmp(
                argv[1],
                "--help") == 0 ||

            strcmp(
                argv[1],
                "-h") == 0 ||

            strcmp(
                argv[1],
                "help") == 0
            )) {

        print_help();
        return 0;
    }

    /*
     * Audit validation.
     */
    if (argc == 3 &&
        strcmp(
            argv[1],
            "--verify-audit") == 0) {

        return verify_audit_command(
            argv[2]
        );
    }

    /*
     * Read-only reference verification.
     */
    if (argc == 4 &&
        strcmp(
            argv[1],
            "--check-references") == 0) {

        return check_references(
            argv[2],
            argv[3]
        );
    }

    /*
     * Controlled reference update.
     */
    if (argc == 4 &&
        strcmp(
            argv[1],
            "--update-references") == 0) {

        return update_references(
            argv[2],
            argv[3]
        );
    }

    /*
     * Normal registration.
     */
    if (argc == 3) {

        return register_document(
            argv[1],
            argv[2],
            "REGISTER"
        );
    }

    fprintf(
        stderr,
        "CHAIN: FAIL_ARGUMENTS\n"
        "\n"
        "Run:\n"
        "  chain --help\n"
        "\n"
    );

    return 1;
}