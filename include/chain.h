#ifndef CHAIN_H
#define CHAIN_H

typedef enum {
    CHAIN_OK = 0,
    CHAIN_ERR_ARGUMENTS,
    CHAIN_ERR_FILE_OPEN,
    CHAIN_ERR_FILE_READ,
    CHAIN_ERR_HASH_INIT,
    CHAIN_ERR_HASH_UPDATE,
    CHAIN_ERR_HASH_FINAL
} chain_result;

#endif