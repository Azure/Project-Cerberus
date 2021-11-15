// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_TESTING_H_
#define AES_TESTING_H_

#include <stdint.h>
#include <stddef.h>


extern const uint8_t AES_KEY[];
#define AES_KEY_LEN (256 / 8)

extern const uint8_t AES_IV[];
#define AES_IV_LEN 12

extern const uint8_t AES_PLAINTEXT[];
extern const size_t AES_PLAINTEXT_LEN;

extern const uint8_t AES_CIPHERTEXT[];
extern const size_t AES_CIPHERTEXT_LEN;

extern const uint8_t AES_GCM_TAG[];
#define AES_GCM_TAG_LEN 16

extern const uint8_t AES_RSA_PRIVKEY_DER[];
extern const size_t AES_RSA_PRIVKEY_DER_LEN;

extern const uint8_t AES_RSA_PRIVKEY_GCM_TAG[];


#endif /* AES_TESTING_H_ */
