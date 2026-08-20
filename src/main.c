#include <stdio.h>
#include <string.h>

#include "audit.h"
#include "commit.h"
#include "document.h"
#include "index.h"
#include "reference.h"
#include "sha256.h"
#include "transaction.h"

static void print_help(void)
{
    printf(
        "STN-LABZ chain\n"
        "Trust Chain Authoring and Validation Utility\n"
        "\n"
        "USAGE\n"
        "\n"
        "  chain <document> <index>\n"
        "      Process a controlled document or revision and commit\n"
        "      verified authoritative artifacts to C:\\stn-labz\\policies.\n"
        "\n"
        "  chain --check-references <document> <index>\n"
        "      Resolve and verify controlled references.\n"
        "      Read-only.\n"
        "\n"
        "  chain --update-references <document> <index>\n"
        "      Resolve root references, update the controlled document,\n"
        "      process it, and commit authoritative artifacts.\n"
        "\n"
        "  chain --verify-audit <index>\n"
        "      Verify the working hash-linked audit record.\n"
        "\n"
        "  chain --transaction-status\n"
        "      Display transaction/recovery status.\n"
        "\n"
        "  chain --recover\n"
        "      Recover an incomplete transaction when recorded\n"
        "      evidence supports deterministic forward recovery.\n"
        "\n"
        "      PREPARED may be safely abandoned.\n"
        "      INDEX_COMMITTED resumes document and audit commit.\n"
        "      DOCUMENT_COMMITTED resumes audit commit.\n"
        "      AUDIT_COMMITTED performs final verification.\n"
        "      VERIFIED performs cleanup and completion.\n"
        "\n"
        "      Recovery fails closed when evidence does not match.\n"
        "\n"
        "  chain --help\n"
        "  chain -h\n"
        "  chain help\n"
        "\n"
        "DOCUMENT IDENTITY\n"
        "\n"
        "  Root document:\n"
        "      Revision ID: NONE\n"
        "      Previous Revision: NONE\n"
        "\n"
        "  First revision:\n"
        "      Revision ID: <ROOT>.R1\n"
        "      Previous Revision: NONE\n"
        "\n"
        "  Subsequent revision:\n"
        "      Revision ID: <ROOT>.R2+\n"
        "      Previous Revision: immediately preceding revision\n"
        "\n"
        "AUTHORITATIVE STORE\n"
        "\n"
        "  C:\\stn-labz\\policies\n"
        "\n"
        "TRANSACTION WORKSPACE\n"
        "\n"
        "  C:\\stn-labz\\policies\\.chain\n"
        "\n"
    );
}

static int transaction_status_command(void)
{
    transaction_status status;
    transaction_result result;

    result =
        transaction_get_status(
            &status
        );

    if (result !=
        TRANSACTION_OK) {

        printf(
            "TRANSACTION: %s\n"
            "CHAIN:       FAIL\n",
            transaction_result_string(
                result
            )
        );

        return 1;
    }

    if (status.stage ==
        TRANSACTION_STAGE_NONE) {

        printf(
            "TRANSACTION: CLEAR\n"
            "CHAIN:       PASS\n"
        );

        return 0;
    }

    printf(
        "TRANSACTION: RECOVERY REQUIRED\n"
        "VERSION:     %d\n"
        "STATE:       %s\n"
        "OPERATION:   %s\n"
        "DOCUMENT:    %s\n"
        "INDEX:       %s\n"
        "POLICY ROOT: %s\n"
        "CHAIN:       FAIL\n",
        status.version,
        transaction_stage_string(
            status.stage
        ),
        status.operation,
        status.document_path,
        status.index_path,
        status.policy_root
    );

    return 1;
}

static int recover_command(void)
{
    transaction_status status;

    transaction_result tx_result;

    commit_result commit_status;
    commit_result cleanup_status;

    tx_result =
        transaction_get_status(
            &status
        );

    if (tx_result !=
        TRANSACTION_OK) {

        printf(
            "RECOVERY: %s\n"
            "CHAIN:    FAIL\n",
            transaction_result_string(
                tx_result
            )
        );

        return 1;
    }

    if (status.stage ==
        TRANSACTION_STAGE_NONE) {

        printf(
            "RECOVERY:    NOT REQUIRED\n"
            "TRANSACTION: CLEAR\n"
            "CHAIN:       PASS\n"
        );

        return 0;
    }

    if (status.stage ==
        TRANSACTION_STAGE_PREPARED) {

        cleanup_status =
            commit_cleanup_transaction_artifacts();

        if (cleanup_status !=
            COMMIT_OK) {

            printf(
                "RECOVERY: %s\n"
                "CHAIN:    FAIL\n",
                commit_result_string(
                    cleanup_status
                )
            );

            return 1;
        }

        tx_result =
            transaction_abandon_prepared();

        if (tx_result !=
            TRANSACTION_OK) {

            printf(
                "RECOVERY: %s\n"
                "CHAIN:    FAIL\n",
                transaction_result_string(
                    tx_result
                )
            );

            return 1;
        }

        printf(
            "RECOVERY:    PREPARED TRANSACTION ABANDONED\n"
            "TRANSACTION: CLEAR\n"
            "CHAIN:       PASS\n"
        );

        return 0;
    }

    commit_status =
        commit_recover(
            &status
        );

    if (commit_status !=
        COMMIT_OK) {

        printf(
            "RECOVERY:    %s\n"
            "STATE:       %s\n"
            "TRANSACTION: PRESERVED\n"
            "CHAIN:       FAIL\n",
            commit_result_string(
                commit_status
            ),
            transaction_stage_string(
                status.stage
            )
        );

        return 1;
    }

    tx_result =
        transaction_get_status(
            &status
        );

    if (tx_result !=
        TRANSACTION_OK) {

        printf(
            "RECOVERY: %s\n"
            "CHAIN:    FAIL\n",
            transaction_result_string(
                tx_result
            )
        );

        return 1;
    }

    if (status.stage !=
        TRANSACTION_STAGE_VERIFIED) {

        printf(
            "RECOVERY:    FAIL_RECOVERY_NOT_VERIFIED\n"
            "STATE:       %s\n"
            "TRANSACTION: PRESERVED\n"
            "CHAIN:       FAIL\n",
            transaction_stage_string(
                status.stage
            )
        );

        return 1;
    }

    cleanup_status =
        commit_cleanup_transaction_artifacts();

    if (cleanup_status !=
        COMMIT_OK) {

        printf(
            "RECOVERY:    %s\n"
            "STATE:       VERIFIED\n"
            "TRANSACTION: PRESERVED\n"
            "CHAIN:       FAIL\n",
            commit_result_string(
                cleanup_status
            )
        );

        return 1;
    }

    tx_result =
        transaction_complete();

    if (tx_result !=
        TRANSACTION_OK) {

        printf(
            "RECOVERY: %s\n"
            "CHAIN:    FAIL\n",
            transaction_result_string(
                tx_result
            )
        );

        return 1;
    }

    printf(
        "RECOVERY:    FORWARD RECOVERY COMPLETE\n"
        "TRANSACTION: CLEAR\n"
        "CHAIN:       PASS\n"
    );

    return 0;
}

static int verify_audit_command(
    const char* index_path)
{
    audit_result result;

    result =
        audit_verify(index_path);

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

static int check_references(
    const char* document_path,
    const char* index_path)
{
    reference_list references;
    reference_result result;

    size_t i;
    int failures = 0;

    result =
        reference_read_document(
            document_path,
            &references
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

    if (index_get_state(
        index_path) !=
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

            match =
                index_find_revision(
                    index_path,
                    reference->root_document_id,
                    reference->revision_id
                );

            if (match ==
                INDEX_MATCH_ONE) {

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

static int preflight_registration(
    const char* document_path,
    const char* index_path)
{
    document_identity identity;
    document_identity_type identity_type;

    document_result document_status;

    unsigned char digest[
        SHA256_DIGEST_SIZE
    ];

    index_state state;

    index_match_result root_match;
    index_match_result match;

    audit_result audit_status;

    audit_status =
        audit_verify(index_path);

    if (audit_status !=
        AUDIT_OK) {

        fprintf(
            stderr,
            "AUDIT: %s\n"
            "CHAIN: FAIL_AUDIT_PRECHECK\n",
            audit_result_string(
                audit_status
            )
        );

        return 1;
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

    identity_type =
        document_classify_identity(
            &identity
        );

    if (identity_type ==
        DOCUMENT_IDENTITY_INVALID) {

        fprintf(
            stderr,
            "CHAIN: FAIL_DOCUMENT_IDENTITY\n"
        );

        return 1;
    }

    if (!sha256_canonical_file(
        document_path,
        digest)) {

        fprintf(
            stderr,
            "CHAIN: FAIL_CANONICAL_HASH\n"
        );

        return 1;
    }

    state =
        index_get_state(
            index_path
        );

    if (state ==
        INDEX_ERROR) {

        fprintf(
            stderr,
            "CHAIN: FAIL_INDEX_STATE\n"
        );

        return 1;
    }

    /*
     * An empty global index may only begin with
     * a root document.
     */
    if (state ==
        INDEX_MISSING) {

        if (identity_type !=
            DOCUMENT_IDENTITY_ROOT) {

            fprintf(
                stderr,
                "CHAIN: FAIL_ROOT_DOCUMENT_REQUIRED\n"
            );

            return 1;
        }

        return 0;
    }

    root_match =
        index_find_root(
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
     * A new document lineage must begin with
     * its root document.
     */
    if (root_match ==
        INDEX_MATCH_NONE) {

        if (identity_type !=
            DOCUMENT_IDENTITY_ROOT) {

            fprintf(
                stderr,
                "CHAIN: FAIL_ROOT_DOCUMENT_NOT_FOUND\n"
            );

            return 1;
        }

        return 0;
    }

    /*
     * The root exists.
     *
     * A second root artifact for the same Root
     * Document ID is not permitted.
     */
    if (identity_type ==
        DOCUMENT_IDENTITY_ROOT) {

        fprintf(
            stderr,
            "CHAIN: FAIL_ROOT_ALREADY_EXISTS\n"
        );

        return 1;
    }

    /*
     * Proposed revision must not already exist.
     */
    match =
        index_find_revision(
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

    /*
     * R1 is the first revision.
     *
     * The root document already exists, and
     * R1 correctly has Previous Revision: NONE.
     * No revision predecessor lookup is required.
     */
    if (identity_type ==
        DOCUMENT_IDENTITY_FIRST_REVISION) {

        return 0;
    }

    /*
     * R2+ requires its immediately preceding
     * revision to exist exactly once.
     */
    match =
        index_find_revision(
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

    return 0;
}

static int process_working_revision(
    const char* document_path,
    const char* index_path,
    const char* operation,
    document_identity* final_identity,
    char final_sha256[SHA256_HEX_SIZE])
{
    document_identity identity;

    unsigned char canonical_digest[
        SHA256_DIGEST_SIZE
    ];

    unsigned char verification_digest[
        SHA256_DIGEST_SIZE
    ];

    char canonical_hex[
        SHA256_HEX_SIZE
    ];

    index_state state;

    index_match_result root_match;
    index_match_result match;

    audit_result audit_status;

    if (document_read_identity(
        document_path,
        &identity) !=
        DOCUMENT_OK) {

        return 1;
    }

    if (document_classify_identity(
        &identity) ==
        DOCUMENT_IDENTITY_INVALID) {

        return 1;
    }

    if (!sha256_canonical_file(
        document_path,
        canonical_digest)) {

        return 1;
    }

    sha256_to_hex(
        canonical_digest,
        canonical_hex
    );

    state =
        index_get_state(
            index_path
        );

    if (state ==
        INDEX_MISSING) {

        if (!index_create_initial(
            index_path,
            &identity,
            canonical_hex)) {

            return 1;
        }
    }
    else {

        root_match =
            index_find_root(
                index_path,
                identity.root_document_id
            );

        if (root_match ==
            INDEX_MATCH_ERROR) {

            return 1;
        }

        /*
         * index_append_revision() appends either:
         *
         * a new root document inside an existing index
         * or
         * a revision of an existing root document.
         */
        if (!index_append_revision(
            index_path,
            &identity,
            canonical_hex)) {

            return 1;
        }
    }

    match =
        index_find_revision(
            index_path,
            identity.root_document_id,
            identity.revision_id
        );

    if (match !=
        INDEX_MATCH_ONE) {

        return 1;
    }

    if (!sha256_stamp_file(
        document_path,
        canonical_hex)) {

        return 1;
    }

    if (!sha256_canonical_file(
        document_path,
        verification_digest)) {

        return 1;
    }

    if (memcmp(
        canonical_digest,
        verification_digest,
        SHA256_DIGEST_SIZE) != 0) {

        return 1;
    }

    audit_status =
        audit_append(
            index_path,
            &identity,
            canonical_hex,
            operation
        );

    if (audit_status !=
        AUDIT_OK) {

        return 1;
    }

    if (audit_verify(
        index_path) !=
        AUDIT_OK) {

        return 1;
    }

    if (final_identity != NULL) {

        *final_identity =
            identity;
    }

    if (final_sha256 != NULL) {

        strcpy_s(
            final_sha256,
            SHA256_HEX_SIZE,
            canonical_hex
        );
    }

    return 0;
}

static int finish_authoritative_commit(
    const char* document_path,
    const char* index_path,
    const char* operation)
{
    commit_plan plan;

    commit_result commit_status;

    transaction_result tx_status;

    document_identity identity;

    char canonical_hex[
        SHA256_HEX_SIZE
    ];

    if (process_working_revision(
        document_path,
        index_path,
        operation,
        &identity,
        canonical_hex) != 0) {

        fprintf(
            stderr,
            "WORKING:     FAIL\n"
            "TRANSACTION: INCOMPLETE\n"
            "CHAIN:       RECOVERY_REQUIRED\n"
        );

        return 1;
    }

    commit_status =
        commit_prepare(
            document_path,
            index_path,
            &plan
        );

    if (commit_status !=
        COMMIT_OK) {

        fprintf(
            stderr,
            "COMMIT:      %s\n"
            "TRANSACTION: INCOMPLETE\n"
            "CHAIN:       RECOVERY_REQUIRED\n",
            commit_result_string(
                commit_status
            )
        );

        return 1;
    }

    commit_status =
        commit_apply(
            &plan
        );

    if (commit_status !=
        COMMIT_OK) {

        fprintf(
            stderr,
            "COMMIT:      %s\n"
            "TRANSACTION: INCOMPLETE\n"
            "CHAIN:       RECOVERY_REQUIRED\n",
            commit_result_string(
                commit_status
            )
        );

        return 1;
    }

    commit_status =
        commit_cleanup_prepared(
            &plan
        );

    if (commit_status !=
        COMMIT_OK) {

        fprintf(
            stderr,
            "COMMIT:      %s\n"
            "TRANSACTION: RECOVERY_REQUIRED\n"
            "CHAIN:       FAIL\n",
            commit_result_string(
                commit_status
            )
        );

        return 1;
    }

    tx_status =
        transaction_complete();

    if (tx_status !=
        TRANSACTION_OK) {

        fprintf(
            stderr,
            "TRANSACTION: %s\n"
            "CHAIN:       FAIL\n",
            transaction_result_string(
                tx_status
            )
        );

        return 1;
    }

    printf(
        "ROOT:          %s\n"
        "REVISION:      %s\n"
        "PREVIOUS:      %s\n"
        "SHA-256:       %s\n"
        "WORKING:       VERIFIED\n"
        "AUTH INDEX:    COMMITTED\n"
        "AUTH DOCUMENT: COMMITTED\n"
        "AUTH AUDIT:    COMMITTED\n"
        "VERIFY:        PASS\n"
        "CHAIN:         PASS\n"
        "TRANSACTION:   PASS\n",
        identity.root_document_id,
        identity.revision_id,
        identity.previous_revision,
        canonical_hex
    );

    return 0;
}

static int run_registration(
    const char* document_path,
    const char* index_path)
{
    transaction_result tx_status;

    tx_status =
        transaction_check_clear();

    if (tx_status !=
        TRANSACTION_OK) {

        fprintf(
            stderr,
            "TRANSACTION: %s\n"
            "CHAIN: FAIL_TRANSACTION_PRECHECK\n",
            transaction_result_string(
                tx_status
            )
        );

        return 1;
    }

    if (preflight_registration(
        document_path,
        index_path) != 0) {

        return 1;
    }

    tx_status =
        transaction_begin(
            document_path,
            index_path,
            "REGISTER"
        );

    if (tx_status !=
        TRANSACTION_OK) {

        fprintf(
            stderr,
            "TRANSACTION: %s\n",
            transaction_result_string(
                tx_status
            )
        );

        return 1;
    }

    return
        finish_authoritative_commit(
            document_path,
            index_path,
            "REGISTER"
        );
}

static int run_reference_update(
    const char* document_path,
    const char* index_path)
{
    reference_update_summary summary;

    reference_result reference_status;

    transaction_result tx_status;

    tx_status =
        transaction_check_clear();

    if (tx_status !=
        TRANSACTION_OK) {

        fprintf(
            stderr,
            "TRANSACTION: %s\n"
            "CHAIN: FAIL_TRANSACTION_PRECHECK\n",
            transaction_result_string(
                tx_status
            )
        );

        return 1;
    }

    if (preflight_registration(
        document_path,
        index_path) != 0) {

        return 1;
    }

    if (check_references(
        document_path,
        index_path) != 0) {

        return 1;
    }

    tx_status =
        transaction_begin(
            document_path,
            index_path,
            "UPDATE_REFERENCES"
        );

    if (tx_status !=
        TRANSACTION_OK) {

        fprintf(
            stderr,
            "TRANSACTION: %s\n",
            transaction_result_string(
                tx_status
            )
        );

        return 1;
    }

    reference_status =
        reference_update_document(
            document_path,
            index_path,
            &summary
        );

    if (reference_status !=
        REFERENCE_OK) {

        fprintf(
            stderr,
            "CHAIN: %s\n"
            "TRANSACTION: INCOMPLETE\n"
            "CHAIN: RECOVERY_REQUIRED\n",
            reference_result_string(
                reference_status
            )
        );

        return 1;
    }

    printf(
        "REFERENCES:  %zu CHECKED\n"
        "UPDATED:     %zu\n"
        "EXPLICIT:    %zu VERIFIED\n",
        summary.checked,
        summary.updated,
        summary.explicit_verified
    );

    return
        finish_authoritative_commit(
            document_path,
            index_path,
            "UPDATE_REFERENCES"
        );
}

int main(
    int argc,
    char** argv)
{
    if (argc == 1) {

        print_help();
        return 0;
    }

    if (argc == 2) {

        if (strcmp(
            argv[1],
            "--help") == 0 ||
            strcmp(
                argv[1],
                "-h") == 0 ||
            strcmp(
                argv[1],
                "help") == 0) {

            print_help();
            return 0;
        }

        if (strcmp(
            argv[1],
            "--transaction-status") == 0) {

            return
                transaction_status_command();
        }

        if (strcmp(
            argv[1],
            "--recover") == 0) {

            return
                recover_command();
        }
    }

    if (argc == 3 &&
        strcmp(
            argv[1],
            "--verify-audit") == 0) {

        return
            verify_audit_command(
                argv[2]
            );
    }

    if (argc == 4 &&
        strcmp(
            argv[1],
            "--check-references") == 0) {

        return
            check_references(
                argv[2],
                argv[3]
            );
    }

    if (argc == 4 &&
        strcmp(
            argv[1],
            "--update-references") == 0) {

        return
            run_reference_update(
                argv[2],
                argv[3]
            );
    }

    if (argc == 3) {

        return
            run_registration(
                argv[1],
                argv[2]
            );
    }

    fprintf(
        stderr,
        "CHAIN: FAIL_ARGUMENTS\n"
        "Run: chain --help\n"
    );

    return 1;
}