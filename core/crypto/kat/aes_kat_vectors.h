// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_KAT_VECTORS_H_
#define AES_KAT_VECTORS_H_

#include <stddef.h>
#include <stdint.h>

/* AES-GCM 256 bits test vectors for self tests */
extern const uint8_t AES_GCM_KAT_VECTORS_256_KEY[];
extern const size_t AES_GCM_KAT_VECTORS_256_KEY_LEN;

extern const uint8_t AES_GCM_KAT_VECTORS_IV[];
extern const size_t AES_GCM_KAT_VECTORS_IV_LEN;

extern const uint8_t AES_GCM_KAT_VECTORS_PLAINTEXT[];
#define AES_GCM_KAT_VECTORS_PLAINTEXT_LEN 16

extern const uint8_t AES_GCM_KAT_VECTORS_CIPHERTEXT[];
#define AES_GCM_KAT_VECTORS_CIPHERTEXT_LEN 16

extern const uint8_t AES_GCM_KAT_VECTORS_TAG[];
#define AES_GCM_KAT_VECTORS_TAG_LEN 16

/* AES-ECB 256 bits test vectors for self tests */
extern const uint8_t AES_ECB_KAT_VECTORS_256_KEY[];
extern const size_t AES_ECB_KAT_VECTORS_256_KEY_LEN;

extern const uint8_t AES_ECB_KAT_VECTORS_PLAINTEXT[];
#define AES_ECB_KAT_VECTORS_PLAINTEXT_LEN 16

extern const uint8_t AES_ECB_KAT_VECTORS_CIPHERTEXT[];
#define AES_ECB_KAT_VECTORS_CIPHERTEXT_LEN 16

/* AES-CBC 256 bits test vectors for self tests */
extern const uint8_t AES_CBC_KAT_VECTORS_256_KEY[];
extern const size_t AES_CBC_KAT_VECTORS_256_KEY_LEN;

extern const uint8_t AES_CBC_KAT_VECTORS_PLAINTEXT[];
#define AES_CBC_KAT_VECTORS_PLAINTEXT_LEN 16

extern const uint8_t AES_CBC_KAT_VECTORS_IV[];

extern const uint8_t AES_CBC_KAT_VECTORS_CIPHERTEXT[];
#define AES_CBC_KAT_VECTORS_CIPHERTEXT_LEN 16


/* AES-XTS 256 bits bits test vectors for self tests */
extern const uint8_t AES_XTS_KAT_VECTORS_256_KEY[];
extern const size_t AES_XTS_KAT_VECTORS_256_KEY_LEN;

extern const uint8_t AES_XTS_KAT_VECTORS_PLAINTEXT[];
#define AES_XTS_KAT_VECTORS_PLAINTEXT_LEN 16

extern const uint8_t AES_XTS_KAT_VECTORS_UNIQUE_DATA[];

extern const uint8_t AES_XTS_KAT_VECTORS_CIPHERTEXT[];
#define AES_XTS_KAT_VECTORS_CIPHERTEXT_LEN 16


#endif	/* AES_KAT_VECTORS_H_ */
