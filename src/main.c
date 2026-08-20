/*
 * STN-LABZ
 * chain
 *
 * src/main.c
 *
 * Deterministic controlled-document Trust Chain authoring and validation.
 *
 * Retool focus:
 * - validate before mutation
 * - root document = Revision ID: NONE
 * - first revision = .R1
 * - no routine transaction/recovery requirement
 * - working document, index, and audit updates are rollback protected
 * - no duplicate "authoritative copy" commit stage
 *
 * Legacy transaction commands remain available only to clear/recover
 * transaction state left by older builds.
 */

#define WIN32_LEAN_AND_MEAN

#include <stdio.h>
#include <string.h>
#include <windows.h>

#include "audit.h"
#include "commit.h"
#include "document.h"
#include "index.h"
#include "reference.h"
#include "sha256.h"
#include "transaction.h"


#define CHAIN_PATH_SIZE 1024


typedef struct
{
    char document_path[CHAIN_PATH_SIZE];
    char index_path[CHAIN_PATH_SIZE];
    char audit_path[CHAIN_PATH_SIZE];

    char document_backup[CHAIN_PATH_SIZE];
    char index_backup[CHAIN_PATH_SIZE];
    char audit_backup[CHAIN_PATH_SIZE];

    int index_existed;
    int audit_existed;
    int active;

} working_snapshot;


/*
 * ------------------------------------------------
 * HELP
 * ------------------------------------------------
 */

static void
print_help(void)
{
    printf(
        "STN-LABZ chain\n"
        "Trust Chain Authoring and Validation Utility\n"
        "\n"
        "USAGE\n"
        "\n"
        "  chain <document> <index>\n"
        "      Validate and register a controlled document or revision.\n"
        "      On PASS, Chain stamps the canonical SHA-256 into the\n"
        "      supplied document, updates the supplied index, and appends\n"
        "      audit evidence.\n"
        "\n"
        "  chain --check-references <document> <index>\n"
        "      Resolve and verify controlled references.\n"
        "      Read-only.\n"
        "\n"
        "  chain --update-references <document> <index>\n"
        "      Resolve root references, update the controlled document,\n"
        "      then validate and register it.\n"
        "\n"
        "  chain --verify-audit <index>\n"
        "      Verify the hash-linked audit record associated with index.\n"
        "\n"
        "  chain --transaction-status\n"
        "      Display legacy transaction/recovery state.\n"
        "\n"
        "  chain --recover\n"
        "      Recover or clear transaction state left by an older build.\n"
        "      Normal registration does not create transaction state.\n"
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
    );
}


/*
 * ------------------------------------------------
 * BASIC FILE HELPERS
 * ------------------------------------------------
 */

static int
file_exists(
    const char *path
)
{
    DWORD attributes;

    if (
        path == NULL ||
        path[0] == '\0'
        )
    {
        return 0;
    }

    attributes =
        GetFileAttributesA(
            path
        );

    if (
        attributes ==
        INVALID_FILE_ATTRIBUTES
        )
    {
        return 0;
    }

    return
        (
            attributes &
            FILE_ATTRIBUTE_DIRECTORY
        ) == 0;
}


static int
same_file_hash(
    const char *first,
    const char *second
)
{
    unsigned char first_hash[
        SHA256_DIGEST_SIZE
    ];

    unsigned char second_hash[
        SHA256_DIGEST_SIZE
    ];

    if (
        !file_exists(first) ||
        !file_exists(second)
        )
    {
        return 0;
    }

    if (
        !sha256_file(
            first,
            first_hash
        ) ||
        !sha256_file(
            second,
            second_hash
        )
        )
    {
        return 0;
    }

    return
        memcmp(
            first_hash,
            second_hash,
            SHA256_DIGEST_SIZE
        ) == 0;
}


static int
make_related_path(
    const char *base,
    const char *suffix,
    char *output,
    size_t output_size
)
{
    int written;

    if (
        base == NULL ||
        suffix == NULL ||
        output == NULL ||
        output_size == 0
        )
    {
        return 0;
    }

    written =
        snprintf(
            output,
            output_size,
            "%s%s",
            base,
            suffix
        );

    return
        written > 0 &&
        written < (int)output_size;
}


static int
backup_file(
    const char *source,
    const char *backup
)
{
    DeleteFileA(
        backup
    );

    if (
        !CopyFileA(
            source,
            backup,
            FALSE
        )
        )
    {
        return 0;
    }

    if (
        !same_file_hash(
            source,
            backup
        )
        )
    {
        DeleteFileA(
            backup
        );

        return 0;
    }

    return 1;
}


static int
restore_backup(
    const char *backup,
    const char *destination
)
{
    if (
        !file_exists(
            backup
        )
        )
    {
        return 0;
    }

    if (
        !MoveFileExA(
            backup,
            destination,
            MOVEFILE_REPLACE_EXISTING |
            MOVEFILE_WRITE_THROUGH
        )
        )
    {
        return 0;
    }

    return 1;
}


/*
 * ------------------------------------------------
 * WORKING SNAPSHOT
 * ------------------------------------------------
 *
 * Chain modifies three supplied artifacts during registration:
 *
 * - document
 * - index
 * - <index>.chainlog
 *
 * Snapshotting those artifacts before mutation allows a failure to
 * restore the exact pre-operation state instead of leaving a partially
 * registered document that later appears to be a duplicate.
 */

static int
working_snapshot_begin(
    const char *document_path,
    const char *index_path,
    working_snapshot *snapshot
)
{
    int written;

    if (
        document_path == NULL ||
        index_path == NULL ||
        snapshot == NULL
        )
    {
        return 0;
    }

    memset(
        snapshot,
        0,
        sizeof(*snapshot)
    );

    if (
        strlen(document_path) >=
            sizeof(snapshot->document_path) ||
        strlen(index_path) >=
            sizeof(snapshot->index_path)
        )
    {
        return 0;
    }

    strcpy_s(
        snapshot->document_path,
        sizeof(snapshot->document_path),
        document_path
    );

    strcpy_s(
        snapshot->index_path,
        sizeof(snapshot->index_path),
        index_path
    );

    written =
        snprintf(
            snapshot->audit_path,
            sizeof(snapshot->audit_path),
            "%s.chainlog",
            index_path
        );

    if (
        written <= 0 ||
        written >=
            (int)sizeof(snapshot->audit_path)
        )
    {
        return 0;
    }

    if (
        !make_related_path(
            document_path,
            ".chain.rollback",
            snapshot->document_backup,
            sizeof(snapshot->document_backup)
        ) ||
        !make_related_path(
            index_path,
            ".chain.rollback",
            snapshot->index_backup,
            sizeof(snapshot->index_backup)
        ) ||
        !make_related_path(
            snapshot->audit_path,
            ".rollback",
            snapshot->audit_backup,
            sizeof(snapshot->audit_backup)
        )
        )
    {
        return 0;
    }

    if (
        !file_exists(
            document_path
        )
        )
    {
        return 0;
    }

    snapshot->index_existed =
        file_exists(
            index_path
        );

    snapshot->audit_existed =
        file_exists(
            snapshot->audit_path
        );

    if (
        !backup_file(
            document_path,
            snapshot->document_backup
        )
        )
    {
        return 0;
    }

    if (
        snapshot->index_existed &&
        !backup_file(
            index_path,
            snapshot->index_backup
        )
        )
    {
        DeleteFileA(
            snapshot->document_backup
        );

        return 0;
    }

    if (
        snapshot->audit_existed &&
        !backup_file(
            snapshot->audit_path,
            snapshot->audit_backup
        )
        )
    {
        DeleteFileA(
            snapshot->document_backup
        );

        DeleteFileA(
            snapshot->index_backup
        );

        return 0;
    }

    snapshot->active =
        1;

    return 1;
}


static int
working_snapshot_rollback(
    working_snapshot *snapshot
)
{
    int ok =
        1;

    if (
        snapshot == NULL ||
        !snapshot->active
        )
    {
        return 0;
    }

    if (
        !restore_backup(
            snapshot->document_backup,
            snapshot->document_path
        )
        )
    {
        ok =
            0;
    }

    if (
        snapshot->index_existed
        )
    {
        if (
            !restore_backup(
                snapshot->index_backup,
                snapshot->index_path
            )
            )
        {
            ok =
                0;
        }
    }
    else
    {
        DeleteFileA(
            snapshot->index_path
        );

        DeleteFileA(
            snapshot->index_backup
        );
    }

    if (
        snapshot->audit_existed
        )
    {
        if (
            !restore_backup(
                snapshot->audit_backup,
                snapshot->audit_path
            )
            )
        {
            ok =
                0;
        }
    }
    else
    {
        DeleteFileA(
            snapshot->audit_path
        );

        DeleteFileA(
            snapshot->audit_backup
        );
    }

    snapshot->active =
        0;

    return ok;
}


static int
working_snapshot_commit(
    working_snapshot *snapshot
)
{
    if (
        snapshot == NULL ||
        !snapshot->active
        )
    {
        return 0;
    }

    if (
        file_exists(
            snapshot->document_backup
        ) &&
        !DeleteFileA(
            snapshot->document_backup
        )
        )
    {
        return 0;
    }

    if (
        file_exists(
            snapshot->index_backup
        ) &&
        !DeleteFileA(
            snapshot->index_backup
        )
        )
    {
        return 0;
    }

    if (
        file_exists(
            snapshot->audit_backup
        ) &&
        !DeleteFileA(
            snapshot->audit_backup
        )
        )
    {
        return 0;
    }

    snapshot->active =
        0;

    return 1;
}


/*
 * ------------------------------------------------
 * LEGACY TRANSACTION STATUS
 * ------------------------------------------------
 */

static int
transaction_status_command(void)
{
    transaction_status status;
    transaction_result result;

    result =
        transaction_get_status(
            &status
        );

    if (
        result !=
        TRANSACTION_OK
        )
    {
        printf(
            "TRANSACTION: %s\n"
            "CHAIN:       FAIL\n",
            transaction_result_string(
                result
            )
        );

        return 1;
    }

    if (
        status.stage ==
        TRANSACTION_STAGE_NONE
        )
    {
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


/*
 * ------------------------------------------------
 * LEGACY RECOVERY
 * ------------------------------------------------
 *
 * Retained so installations that contain transaction state produced by
 * an older Chain build can still be recovered or cleared.
 */

static int
recover_command(void)
{
    transaction_status status;

    transaction_result tx_result;

    commit_result commit_status;
    commit_result cleanup_status;

    tx_result =
        transaction_get_status(
            &status
        );

    if (
        tx_result !=
        TRANSACTION_OK
        )
    {
        printf(
            "RECOVERY: %s\n"
            "CHAIN:    FAIL\n",
            transaction_result_string(
                tx_result
            )
        );

        return 1;
    }

    if (
        status.stage ==
        TRANSACTION_STAGE_NONE
        )
    {
        printf(
            "RECOVERY:    NOT REQUIRED\n"
            "TRANSACTION: CLEAR\n"
            "CHAIN:       PASS\n"
        );

        return 0;
    }

    if (
        status.stage ==
        TRANSACTION_STAGE_PREPARED
        )
    {
        cleanup_status =
            commit_cleanup_transaction_artifacts();

        if (
            cleanup_status !=
            COMMIT_OK
            )
        {
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

        if (
            tx_result !=
            TRANSACTION_OK
            )
        {
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

    if (
        commit_status !=
        COMMIT_OK
        )
    {
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

    if (
        tx_result !=
        TRANSACTION_OK
        )
    {
        printf(
            "RECOVERY: %s\n"
            "CHAIN:    FAIL\n",
            transaction_result_string(
                tx_result
            )
        );

        return 1;
    }

    if (
        status.stage !=
        TRANSACTION_STAGE_VERIFIED
        )
    {
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

    if (
        cleanup_status !=
        COMMIT_OK
        )
    {
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

    if (
        tx_result !=
        TRANSACTION_OK
        )
    {
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


/*
 * ------------------------------------------------
 * AUDIT VERIFICATION COMMAND
 * ------------------------------------------------
 */

static int
verify_audit_command(
    const char *index_path
)
{
    audit_result result;

    result =
        audit_verify(
            index_path
        );

    if (
        result !=
        AUDIT_OK
        )
    {
        printf(
            "AUDIT:  %s\n"
            "CHAIN:  FAIL\n",
            audit_result_string(
                result
            )
        );

        return 1;
    }

    printf(
        "AUDIT:  PASS\n"
        "CHAIN:  PASS\n"
    );

    return 0;
}


/*
 * ------------------------------------------------
 * REFERENCE CHECK
 * ------------------------------------------------
 */

static int
check_references(
    const char *document_path,
    const char *index_path
)
{
    reference_list references;
    reference_result result;

    size_t i;
    int failures =
        0;

    result =
        reference_read_document(
            document_path,
            &references
        );

    if (
        result !=
        REFERENCE_OK
        )
    {
        fprintf(
            stderr,
            "CHAIN: %s\n",
            reference_result_string(
                result
            )
        );

        return 1;
    }

    if (
        index_get_state(
            index_path
        ) !=
        INDEX_EXISTS
        )
    {
        fprintf(
            stderr,
            "CHAIN: FAIL_INDEX_MISSING\n"
        );

        return 1;
    }

    for (
        i = 0;
        i < references.count;
        ++i
        )
    {
        const document_reference *reference =
            &references.items[i];

        if (
            reference->explicit_revision
            )
        {
            index_match_result match;

            match =
                index_find_revision(
                    index_path,
                    reference->root_document_id,
                    reference->revision_id
                );

            if (
                match ==
                INDEX_MATCH_ONE
                )
            {
                printf(
                    "REFERENCE: %-24s VERIFIED\n",
                    reference->revision_id
                );
            }
            else
            {
                printf(
                    "REFERENCE: %-24s FAIL\n",
                    reference->revision_id
                );

                ++failures;
            }
        }
        else
        {
            index_revision_resolution resolution;
            index_resolve_result resolved;

            resolved =
                index_resolve_latest_approved(
                    index_path,
                    reference->root_document_id,
                    &resolution
                );

            if (
                resolved ==
                INDEX_RESOLVE_FOUND
                )
            {
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
            else
            {
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

    if (
        failures != 0
        )
    {
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


/*
 * ------------------------------------------------
 * REGISTRATION PREFLIGHT
 * ------------------------------------------------
 *
 * This is read-only. No index, audit, document, or transaction state is
 * changed here.
 */

static int
preflight_registration(
    const char *document_path,
    const char *index_path
)
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

    document_status =
        document_read_identity(
            document_path,
            &identity
        );

    if (
        document_status !=
        DOCUMENT_OK
        )
    {
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

    if (
        identity_type ==
        DOCUMENT_IDENTITY_INVALID
        )
    {
        fprintf(
            stderr,
            "CHAIN: FAIL_DOCUMENT_IDENTITY\n"
        );

        return 1;
    }

    if (
        !sha256_canonical_file(
            document_path,
            digest
        )
        )
    {
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

    if (
        state ==
        INDEX_ERROR
        )
    {
        fprintf(
            stderr,
            "CHAIN: FAIL_INDEX_STATE\n"
        );

        return 1;
    }

    if (
        state ==
        INDEX_MISSING
        )
    {
        if (
            identity_type !=
            DOCUMENT_IDENTITY_ROOT
            )
        {
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

    if (
        root_match ==
        INDEX_MATCH_ERROR
        )
    {
        fprintf(
            stderr,
            "CHAIN: FAIL_ROOT_LOOKUP\n"
        );

        return 1;
    }

    if (
        root_match ==
        INDEX_MATCH_NONE
        )
    {
        if (
            identity_type !=
            DOCUMENT_IDENTITY_ROOT
            )
        {
            fprintf(
                stderr,
                "CHAIN: FAIL_ROOT_DOCUMENT_NOT_FOUND\n"
            );

            return 1;
        }

        return 0;
    }

    if (
        identity_type ==
        DOCUMENT_IDENTITY_ROOT
        )
    {
        fprintf(
            stderr,
            "CHAIN: FAIL_ROOT_ALREADY_EXISTS\n"
        );

        return 1;
    }

    match =
        index_find_revision(
            index_path,
            identity.root_document_id,
            identity.revision_id
        );

    if (
        match ==
        INDEX_MATCH_ERROR
        )
    {
        fprintf(
            stderr,
            "CHAIN: FAIL_INDEX_PARSE\n"
        );

        return 1;
    }

    if (
        match ==
        INDEX_MATCH_DUPLICATE
        )
    {
        fprintf(
            stderr,
            "CHAIN: FAIL_REVISION_DUPLICATE\n"
        );

        return 1;
    }

    if (
        match ==
        INDEX_MATCH_ONE
        )
    {
        fprintf(
            stderr,
            "CHAIN: FAIL_REVISION_ALREADY_EXISTS\n"
        );

        return 1;
    }

    if (
        identity_type ==
        DOCUMENT_IDENTITY_FIRST_REVISION
        )
    {
        return 0;
    }

    match =
        index_find_revision(
            index_path,
            identity.root_document_id,
            identity.previous_revision
        );

    if (
        match ==
        INDEX_MATCH_ERROR
        )
    {
        fprintf(
            stderr,
            "CHAIN: FAIL_PREDECESSOR_LOOKUP\n"
        );

        return 1;
    }

    if (
        match ==
        INDEX_MATCH_NONE
        )
    {
        fprintf(
            stderr,
            "CHAIN: FAIL_PREDECESSOR_NOT_FOUND\n"
        );

        return 1;
    }

    if (
        match ==
        INDEX_MATCH_DUPLICATE
        )
    {
        fprintf(
            stderr,
            "CHAIN: FAIL_PREDECESSOR_DUPLICATE\n"
        );

        return 1;
    }

    return 0;
}


/*
 * ------------------------------------------------
 * WORKING REGISTRATION
 * ------------------------------------------------
 *
 * Mutations occur only after preflight and only while a rollback
 * snapshot exists.
 */

static int
process_working_revision(
    const char *document_path,
    const char *index_path,
    const char *operation,
    document_identity *final_identity,
    char final_sha256[
        SHA256_HEX_SIZE
    ]
)
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

    index_match_result match;

    audit_result audit_status;

    if (
        document_read_identity(
            document_path,
            &identity
        ) !=
        DOCUMENT_OK
        )
    {
        fprintf(
            stderr,
            "CHAIN: FAIL_DOCUMENT_METADATA\n"
        );

        return 1;
    }

    if (
        document_classify_identity(
            &identity
        ) ==
        DOCUMENT_IDENTITY_INVALID
        )
    {
        fprintf(
            stderr,
            "CHAIN: FAIL_DOCUMENT_IDENTITY\n"
        );

        return 1;
    }

    if (
        !sha256_canonical_file(
            document_path,
            canonical_digest
        )
        )
    {
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

    state =
        index_get_state(
            index_path
        );

    if (
        state ==
        INDEX_MISSING
        )
    {
        if (
            !index_create_initial(
                index_path,
                &identity,
                canonical_hex
            )
            )
        {
            fprintf(
                stderr,
                "CHAIN: FAIL_INDEX_CREATE\n"
            );

            return 1;
        }
    }
    else
    {
        if (
            state !=
            INDEX_EXISTS
            )
        {
            fprintf(
                stderr,
                "CHAIN: FAIL_INDEX_STATE\n"
            );

            return 1;
        }

        if (
            !index_append_revision(
                index_path,
                &identity,
                canonical_hex
            )
            )
        {
            fprintf(
                stderr,
                "CHAIN: FAIL_INDEX_APPEND\n"
            );

            return 1;
        }
    }

    match =
        index_find_revision(
            index_path,
            identity.root_document_id,
            identity.revision_id
        );

    if (
        match !=
        INDEX_MATCH_ONE
        )
    {
        fprintf(
            stderr,
            "CHAIN: FAIL_INDEX_VERIFY\n"
        );

        return 1;
    }

    if (
        !sha256_stamp_file(
            document_path,
            canonical_hex
        )
        )
    {
        fprintf(
            stderr,
            "CHAIN: FAIL_DOCUMENT_STAMP\n"
        );

        return 1;
    }

    if (
        !sha256_canonical_file(
            document_path,
            verification_digest
        )
        )
    {
        fprintf(
            stderr,
            "CHAIN: FAIL_CANONICAL_VERIFY\n"
        );

        return 1;
    }

    if (
        memcmp(
            canonical_digest,
            verification_digest,
            SHA256_DIGEST_SIZE
        ) != 0
        )
    {
        fprintf(
            stderr,
            "CHAIN: FAIL_CANONICAL_CHANGED\n"
        );

        return 1;
    }

    audit_status =
        audit_append(
            index_path,
            &identity,
            canonical_hex,
            operation
        );

    if (
        audit_status !=
        AUDIT_OK
        )
    {
        fprintf(
            stderr,
            "CHAIN: %s\n",
            audit_result_string(
                audit_status
            )
        );

        return 1;
    }

    audit_status =
        audit_verify(
            index_path
        );

    if (
        audit_status !=
        AUDIT_OK
        )
    {
        fprintf(
            stderr,
            "CHAIN: %s\n",
            audit_result_string(
                audit_status
            )
        );

        return 1;
    }

    if (
        final_identity != NULL
        )
    {
        *final_identity =
            identity;
    }

    if (
        final_sha256 != NULL
        )
    {
        strcpy_s(
            final_sha256,
            SHA256_HEX_SIZE,
            canonical_hex
        );
    }

    return 0;
}


/*
 * ------------------------------------------------
 * SNAPSHOT-PROTECTED REGISTRATION
 * ------------------------------------------------
 */

static int
finish_registration(
    const char *document_path,
    const char *index_path,
    const char *operation,
    working_snapshot *existing_snapshot
)
{
    working_snapshot local_snapshot;
    working_snapshot *snapshot;

    document_identity identity;

    char canonical_hex[
        SHA256_HEX_SIZE
    ];

    int owns_snapshot =
        0;

    if (
        existing_snapshot != NULL
        )
    {
        snapshot =
            existing_snapshot;
    }
    else
    {
        snapshot =
            &local_snapshot;

        if (
            !working_snapshot_begin(
                document_path,
                index_path,
                snapshot
            )
            )
        {
            fprintf(
                stderr,
                "CHAIN: FAIL_SNAPSHOT_CREATE\n"
            );

            return 1;
        }

        owns_snapshot =
            1;
    }

    if (
        process_working_revision(
            document_path,
            index_path,
            operation,
            &identity,
            canonical_hex
        ) != 0
        )
    {
        if (
            !working_snapshot_rollback(
                snapshot
            )
            )
        {
            fprintf(
                stderr,
                "ROLLBACK: FAIL\n"
                "CHAIN:    FAIL_ROLLBACK\n"
            );

            return 1;
        }

        fprintf(
            stderr,
            "ROLLBACK: PASS\n"
            "CHAIN:    FAIL\n"
        );

        return 1;
    }

    if (
        !working_snapshot_commit(
            snapshot
        )
        )
    {
        /*
         * Registration itself is valid at this point. Failure to delete
         * rollback files must not be reported as a false registration
         * failure. Keep the files as conservative recovery evidence.
         */
        fprintf(
            stderr,
            "CLEANUP:      ROLLBACK_FILES_RETAINED\n"
        );
    }

    printf(
        "ROOT:          %s\n"
        "REVISION:      %s\n"
        "PREVIOUS:      %s\n"
        "SHA-256:       %s\n"
        "INDEX:         UPDATED\n"
        "DOCUMENT:      STAMPED\n"
        "AUDIT:         VERIFIED\n"
        "VERIFY:        PASS\n"
        "CHAIN:         PASS\n",
        identity.root_document_id,
        identity.revision_id,
        identity.previous_revision,
        canonical_hex
    );

    (void)owns_snapshot;

    return 0;
}


/*
 * ------------------------------------------------
 * REGISTER
 * ------------------------------------------------
 */

static int
run_registration(
    const char *document_path,
    const char *index_path
)
{
    /*
     * New registration does not create persistent transaction state.
     * A stale transaction produced by an older Chain build is reported
     * explicitly so the operator can clear it once with --recover.
     */

    if (
        transaction_exists()
        )
    {
        transaction_status status;
        transaction_result tx_status;

        tx_status =
            transaction_get_status(
                &status
            );

        if (
            tx_status !=
            TRANSACTION_OK
            )
        {
            fprintf(
                stderr,
                "TRANSACTION: %s\n"
                "CHAIN:       FAIL_TRANSACTION_STATE\n",
                transaction_result_string(
                    tx_status
                )
            );

            return 1;
        }

        if (
            status.stage !=
            TRANSACTION_STAGE_NONE
            )
        {
            fprintf(
                stderr,
                "TRANSACTION: RECOVERY REQUIRED\n"
                "CHAIN:       FAIL_TRANSACTION_PRECHECK\n"
            );

            return 1;
        }
    }

    if (
        preflight_registration(
            document_path,
            index_path
        ) != 0
        )
    {
        return 1;
    }

    return
        finish_registration(
            document_path,
            index_path,
            "REGISTER",
            NULL
        );
}


/*
 * ------------------------------------------------
 * UPDATE REFERENCES
 * ------------------------------------------------
 */

static int
run_reference_update(
    const char *document_path,
    const char *index_path
)
{
    reference_update_summary summary;
    reference_result reference_status;

    working_snapshot snapshot;

    if (
        transaction_exists()
        )
    {
        transaction_status status;
        transaction_result tx_status;

        tx_status =
            transaction_get_status(
                &status
            );

        if (
            tx_status !=
            TRANSACTION_OK
            )
        {
            fprintf(
                stderr,
                "TRANSACTION: %s\n"
                "CHAIN:       FAIL_TRANSACTION_STATE\n",
                transaction_result_string(
                    tx_status
                )
            );

            return 1;
        }

        if (
            status.stage !=
            TRANSACTION_STAGE_NONE
            )
        {
            fprintf(
                stderr,
                "TRANSACTION: RECOVERY REQUIRED\n"
                "CHAIN:       FAIL_TRANSACTION_PRECHECK\n"
            );

            return 1;
        }
    }

    if (
        preflight_registration(
            document_path,
            index_path
        ) != 0
        )
    {
        return 1;
    }

    if (
        check_references(
            document_path,
            index_path
        ) != 0
        )
    {
        return 1;
    }

    if (
        !working_snapshot_begin(
            document_path,
            index_path,
            &snapshot
        )
        )
    {
        fprintf(
            stderr,
            "CHAIN: FAIL_SNAPSHOT_CREATE\n"
        );

        return 1;
    }

    reference_status =
        reference_update_document(
            document_path,
            index_path,
            &summary
        );

    if (
        reference_status !=
        REFERENCE_OK
        )
    {
        if (
            !working_snapshot_rollback(
                &snapshot
            )
            )
        {
            fprintf(
                stderr,
                "CHAIN: FAIL_ROLLBACK\n"
            );

            return 1;
        }

        fprintf(
            stderr,
            "CHAIN: %s\n",
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
        finish_registration(
            document_path,
            index_path,
            "UPDATE_REFERENCES",
            &snapshot
        );
}


/*
 * ------------------------------------------------
 * MAIN
 * ------------------------------------------------
 */

int
main(
    int argc,
    char **argv
)
{
    if (
        argc == 1
        )
    {
        print_help();

        return 0;
    }

    if (
        argc == 2
        )
    {
        if (
            strcmp(
                argv[1],
                "--help"
            ) == 0 ||
            strcmp(
                argv[1],
                "-h"
            ) == 0 ||
            strcmp(
                argv[1],
                "help"
            ) == 0
            )
        {
            print_help();

            return 0;
        }

        if (
            strcmp(
                argv[1],
                "--transaction-status"
            ) == 0
            )
        {
            return
                transaction_status_command();
        }

        if (
            strcmp(
                argv[1],
                "--recover"
            ) == 0
            )
        {
            return
                recover_command();
        }
    }

    if (
        argc == 3 &&
        strcmp(
            argv[1],
            "--verify-audit"
        ) == 0
        )
    {
        return
            verify_audit_command(
                argv[2]
            );
    }

    if (
        argc == 4 &&
        strcmp(
            argv[1],
            "--check-references"
        ) == 0
        )
    {
        return
            check_references(
                argv[2],
                argv[3]
            );
    }

    if (
        argc == 4 &&
        strcmp(
            argv[1],
            "--update-references"
        ) == 0
        )
    {
        return
            run_reference_update(
                argv[2],
                argv[3]
            );
    }

    if (
        argc == 3
        )
    {
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
