#ifndef INDEX_H
#define INDEX_H

#include <stddef.h>

#include "document.h"
#include "sha256.h"

#define INDEX_REVISION_SIZE 96
#define INDEX_STATUS_SIZE   64

typedef enum {
    INDEX_ERROR = -1,
    INDEX_MISSING = 0,
    INDEX_EXISTS = 1
} index_state;

typedef enum {
    INDEX_MATCH_ERROR = -1,
    INDEX_MATCH_NONE = 0,
    INDEX_MATCH_ONE = 1,
    INDEX_MATCH_DUPLICATE = 2
} index_match_result;

typedef enum {
    INDEX_RESOLVE_ERROR = -1,
    INDEX_RESOLVE_NONE = 0,
    INDEX_RESOLVE_FOUND = 1
} index_resolve_result;

typedef struct {
    char revision_id[INDEX_REVISION_SIZE];
    char status[INDEX_STATUS_SIZE];
    unsigned long revision_number;
} index_revision_resolution;

index_state index_get_state(
    const char* path
);

int index_create_initial(
    const char* path,
    const document_identity* identity,
    const char sha256[SHA256_HEX_SIZE]
);

int index_verify_initial(
    const char* path,
    const document_identity* identity,
    const char sha256[SHA256_HEX_SIZE]
);

index_match_result index_find_revision(
    const char* path,
    const char* root_document_id,
    const char* revision_id
);

index_match_result index_find_root(
    const char* path,
    const char* root_document_id
);

index_resolve_result index_resolve_latest_approved(
    const char* path,
    const char* root_document_id,
    index_revision_resolution* resolution
);

int index_append_revision(
    const char* path,
    const document_identity* identity,
    const char sha256[SHA256_HEX_SIZE]
);

#endif