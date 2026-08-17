#ifndef AUDIT_H
#define AUDIT_H

#include "document.h"
#include "sha256.h"

#define AUDIT_HASH_SIZE SHA256_HEX_SIZE

typedef enum {
    AUDIT_OK = 0,
    AUDIT_ERR_ARGUMENT,
    AUDIT_ERR_OPEN,
    AUDIT_ERR_READ,
    AUDIT_ERR_WRITE,
    AUDIT_ERR_MALFORMED,
    AUDIT_ERR_CHAIN_BROKEN,
    AUDIT_ERR_HASH
} audit_result;

audit_result audit_verify(
    const char *index_path
);

audit_result audit_append(
    const char *index_path,
    const document_identity *identity,
    const char sha256[SHA256_HEX_SIZE],
    const char *operation
);

const char *audit_result_string(
    audit_result result
);

#endif