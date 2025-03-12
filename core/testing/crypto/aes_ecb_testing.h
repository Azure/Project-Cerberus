// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_ECB_TESTING_H_
#define AES_ECB_TESTING_H_

#include <stddef.h>
#include <stdint.h>


/* Test data for AES-ECB operations.  Values are taken from NIST test vectors. */
extern const uint8_t AES_ECB_TESTING_SINGLE_BLOCK_KEY[];
extern const size_t AES_ECB_TESTING_SINGLE_BLOCK_KEY_LEN;

extern const uint8_t AES_ECB_TESTING_SINGLE_BLOCK_PLAINTEXT[];
extern const uint8_t AES_ECB_TESTING_SINGLE_BLOCK_CIPHERTEXT[];
extern const size_t AES_ECB_TESTING_SINGLE_BLOCK_LEN;

extern const uint8_t AES_ECB_TESTING_MULTI_BLOCK_KEY[];
extern const size_t AES_ECB_TESTING_MULTI_BLOCK_KEY_LEN;

extern const uint8_t AES_ECB_TESTING_MULTI_BLOCK_PLAINTEXT[];
extern const uint8_t AES_ECB_TESTING_MULTI_BLOCK_CIPHERTEXT[];
extern const size_t AES_ECB_TESTING_MULTI_BLOCK_LEN;

extern const uint8_t AES_ECB_TESTING_LONG_DATA_KEY[];
extern const size_t AES_ECB_TESTING_LONG_DATA_KEY_LEN;

extern const uint8_t AES_ECB_TESTING_LONG_DATA_PLAINTEXT[];
extern const uint8_t AES_ECB_TESTING_LONG_DATA_CIPHERTEXT[];
extern const size_t AES_ECB_TESTING_LONG_DATA_LEN;


#endif	/* AES_ECB_TESTING_H_ */
