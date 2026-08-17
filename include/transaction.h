#ifndef TRANSACTION_H
#define TRANSACTION_H

#include <stddef.h>

#define CHAIN_POLICY_ROOT \
    "C:\\stn-labz\\policies"

#define CHAIN_TRANSACTION_ROOT \
    "C:\\stn-labz\\policies\\.chain"

#define CHAIN_TRANSACTION_STATE \
    "C:\\stn-labz\\policies\\.chain\\transaction.state"

#define TRANSACTION_PATH_SIZE      1024
#define TRANSACTION_OPERATION_SIZE 64

typedef enum {
    TRANSACTION_OK = 0,

    TRANSACTION_ERR_ARGUMENT,
    TRANSACTION_ERR_DIRECTORY,
    TRANSACTION_ERR_RECOVERY_REQUIRED,
    TRANSACTION_ERR_STATE_CREATE,
    TRANSACTION_ERR_STATE_OPEN,
    TRANSACTION_ERR_STATE_READ,
    TRANSACTION_ERR_STATE_WRITE,
    TRANSACTION_ERR_STATE_REMOVE,
    TRANSACTION_ERR_STATE_MALFORMED,
    TRANSACTION_ERR_STATE_UNKNOWN

} transaction_result;

typedef enum {
    TRANSACTION_STAGE_NONE = 0,
    TRANSACTION_STAGE_PREPARED,
    TRANSACTION_STAGE_INDEX_COMMITTED,
    TRANSACTION_STAGE_DOCUMENT_COMMITTED,
    TRANSACTION_STAGE_AUDIT_COMMITTED,
    TRANSACTION_STAGE_VERIFIED
} transaction_stage;

typedef struct {
    int version;

    transaction_stage stage;

    char operation[
        TRANSACTION_OPERATION_SIZE
    ];

    char document_path[
        TRANSACTION_PATH_SIZE
    ];

    char index_path[
        TRANSACTION_PATH_SIZE
    ];

    char policy_root[
        TRANSACTION_PATH_SIZE
    ];

} transaction_status;

transaction_result transaction_check_clear(void);

transaction_result transaction_begin(
    const char *document_path,
    const char *index_path,
    const char *operation
);

transaction_result transaction_set_stage(
    transaction_stage stage
);

transaction_result transaction_get_status(
    transaction_status *status
);

transaction_result transaction_complete(void);

transaction_result transaction_abandon_prepared(void);

int transaction_exists(void);

const char *transaction_stage_string(
    transaction_stage stage
);

const char *transaction_result_string(
    transaction_result result
);

#endif