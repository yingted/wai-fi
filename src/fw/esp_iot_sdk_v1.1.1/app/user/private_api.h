#ifndef __PRIVATE_API_H__
#define __PRIVATE_API_H__

#include "os_type.h"

void *aes_encrypt_init(const uint8 *key, size_t len);
 
void aes_encrypt(void *ctx, const uint8 *plain, uint8 *crypt);
 
void aes_encrypt_deinit(void *ctx);

#endif

