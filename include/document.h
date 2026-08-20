#ifndef DOCUMENT_H
#define DOCUMENT_H

#include <stddef.h>

#define DOCUMENT_ROOT_ID_SIZE       64
#define DOCUMENT_REVISION_ID_SIZE   96
#define DOCUMENT_PREVIOUS_SIZE      96
#define DOCUMENT_TITLE_SIZE         256
#define DOCUMENT_STATUS_SIZE        64

typedef struct {
    char root_document_id[DOCUMENT_ROOT_ID_SIZE];
    char revision_id[DOCUMENT_REVISION_ID_SIZE];
    char previous_revision[DOCUMENT_PREVIOUS_SIZE];
    char title[DOCUMENT_TITLE_SIZE];
    char status[DOCUMENT_STATUS_SIZE];
} document_identity;

typedef enum {
    DOCUMENT_OK = 0,

    DOCUMENT_ERR_ARGUMENT,
    DOCUMENT_ERR_OPEN,
    DOCUMENT_ERR_READ,

    DOCUMENT_ERR_ROOT_MISSING,
    DOCUMENT_ERR_ROOT_DUPLICATE,
    DOCUMENT_ERR_ROOT_MALFORMED,

    DOCUMENT_ERR_REVISION_MISSING,
    DOCUMENT_ERR_REVISION_DUPLICATE,
    DOCUMENT_ERR_REVISION_MALFORMED,

    DOCUMENT_ERR_PREVIOUS_MISSING,
    DOCUMENT_ERR_PREVIOUS_DUPLICATE,
    DOCUMENT_ERR_PREVIOUS_MALFORMED,

    DOCUMENT_ERR_TITLE_MISSING,
    DOCUMENT_ERR_TITLE_DUPLICATE,
    DOCUMENT_ERR_TITLE_MALFORMED,

    DOCUMENT_ERR_STATUS_MISSING,
    DOCUMENT_ERR_STATUS_DUPLICATE,
    DOCUMENT_ERR_STATUS_MALFORMED

} document_result;

typedef enum {
    DOCUMENT_IDENTITY_INVALID = 0,
    DOCUMENT_IDENTITY_ROOT,
    DOCUMENT_IDENTITY_FIRST_REVISION,
    DOCUMENT_IDENTITY_REVISION
} document_identity_type;

document_result document_read_identity(
    const char* path,
    document_identity* identity
);

document_identity_type document_classify_identity(
    const document_identity* identity
);

const char* document_result_string(
    document_result result
);

#endif