// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_GCM_TESTING_H_
#define AES_GCM_TESTING_H_

#include <stddef.h>
#include <stdint.h>


/* Test data for AES-GCM operations. */
extern const uint8_t AES_GCM_TESTING_KEY[];
#define AES_GCM_TESTING_KEY_LEN (256 / 8)

extern const uint8_t AES_GCM_TESTING_IV[];
#define AES_GCM_TESTING_IV_LEN 12

extern const uint8_t AES_GCM_TESTING_ADD_DATA[];
#define AES_GCM_TESTING_ADD_DATA_LEN 6

extern const uint8_t AES_GCM_TESTING_PLAINTEXT[];
extern const size_t AES_GCM_TESTING_PLAINTEXT_LEN;

extern const uint8_t AES_GCM_TESTING_CIPHERTEXT[];
extern const size_t AES_GCM_TESTING_CIPHERTEXT_LEN;

extern const uint8_t AES_GCM_TESTING_TAG[];
extern const uint8_t AES_GCM_TESTING_ADD_DATA_TAG[];
#define AES_GCM_TESTING_TAG_LEN 16

extern const uint8_t AES_GCM_TESTING_RSA_PRIVKEY_DER[];
extern const size_t AES_GCM_TESTING_RSA_PRIVKEY_DER_LEN;

extern const uint8_t AES_GCM_TESTING_RSA_PRIVKEY_GCM_TAG[];


#endif	/* AES_GCM_TESTING_H_ */
