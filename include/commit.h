#ifndef COMMIT_H
#define COMMIT_H

#include <stddef.h>

#include "transaction.h"

#define COMMIT_PATH_SIZE 1024

typedef enum {
    COMMIT_OK = 0,

    COMMIT_ERR_ARGUMENT,
    COMMIT_ERR_PATH,
    COMMIT_ERR_SOURCE_MISSING,
    COMMIT_ERR_PREPARE,
    COMMIT_ERR_PREPARE_VERIFY,
    COMMIT_ERR_DOCUMENT_EXISTS,
    COMMIT_ERR_INDEX_COMMIT,
    COMMIT_ERR_DOCUMENT_COMMIT,
    COMMIT_ERR_AUDIT_COMMIT,
    COMMIT_ERR_INDEX_VERIFY,
    COMMIT_ERR_DOCUMENT_VERIFY,
    COMMIT_ERR_AUDIT_VERIFY,
    COMMIT_ERR_FINAL_VERIFY,
    COMMIT_ERR_TRANSACTION_STAGE,
    COMMIT_ERR_RECOVERY_EVIDENCE,
    COMMIT_ERR_RECOVERY_STAGE,
    COMMIT_ERR_CLEANUP

} commit_result;

typedef struct {
    char source_document[
        COMMIT_PATH_SIZE
    ];

    char source_index[
        COMMIT_PATH_SIZE
    ];

    char source_audit[
        COMMIT_PATH_SIZE
    ];

    char prepared_document[
        COMMIT_PATH_SIZE
    ];

    char prepared_index[
        COMMIT_PATH_SIZE
    ];

    char prepared_audit[
        COMMIT_PATH_SIZE
    ];

    char authoritative_document[
        COMMIT_PATH_SIZE
    ];

    char authoritative_index[
        COMMIT_PATH_SIZE
    ];

    char authoritative_audit[
        COMMIT_PATH_SIZE
    ];

} commit_plan;

commit_result commit_prepare(
    const char *document_path,
    const char *index_path,
    commit_plan *plan
);

commit_result commit_apply(
    const commit_plan *plan
);

commit_result commit_recover(
    const transaction_status *status
);

commit_result commit_cleanup_prepared(
    const commit_plan *plan
);

commit_result commit_cleanup_transaction_artifacts(void);

const char *commit_result_string(
    commit_result result
);

#endif