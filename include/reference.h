#ifndef REFERENCE_H
#define REFERENCE_H

#include <stddef.h>

#define REFERENCE_ROOT_SIZE      64
#define REFERENCE_REVISION_SIZE  96
#define REFERENCE_MAX_COUNT      256

typedef struct {
    char root_document_id[REFERENCE_ROOT_SIZE];
    char revision_id[REFERENCE_REVISION_SIZE];
    int explicit_revision;
} document_reference;

typedef struct {
    document_reference items[REFERENCE_MAX_COUNT];
    size_t count;
} reference_list;

typedef enum {
    REFERENCE_OK = 0,
    REFERENCE_ERR_ARGUMENT,
    REFERENCE_ERR_OPEN,
    REFERENCE_ERR_READ,
    REFERENCE_ERR_WRITE,
    REFERENCE_ERR_REPLACE,
    REFERENCE_ERR_TOO_MANY,
    REFERENCE_ERR_DUPLICATE,
    REFERENCE_ERR_MALFORMED,
    REFERENCE_ERR_NOT_FOUND,
    REFERENCE_ERR_NO_APPROVED_REVISION,
    REFERENCE_ERR_EXPLICIT_REVISION
} reference_result;

typedef struct {
    size_t checked;
    size_t updated;
    size_t explicit_verified;
} reference_update_summary;

reference_result reference_read_document(
    const char* path,
    reference_list* references
);

reference_result reference_update_document(
    const char* path,
    const char* index_path,
    reference_update_summary* summary
);

const char* reference_result_string(
    reference_result result
);

#endif