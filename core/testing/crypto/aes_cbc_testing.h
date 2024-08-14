// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_CBC_TESTING_H_
#define AES_CBC_TESTING_H_

#include <stddef.h>
#include <stdint.h>


/* Test data for AES-CBC operations.  Values are taken from NIST test vectors. */
#define	AES_CBC_TESTING_IV_LEN	16

extern const uint8_t AES_CBC_TESTING_SINGLE_BLOCK_KEY[];
extern const uint8_t AES_CBC_TESTING_SINGLE_BLOCK_IV[];

extern const uint8_t AES_CBC_TESTING_SINGLE_BLOCK_PLAINTEXT[];
extern const uint8_t AES_CBC_TESTING_SINGLE_BLOCK_CIPHERTEXT[];
extern const size_t AES_CBC_TESTING_SINGLE_BLOCK_LEN;

extern const uint8_t AES_CBC_TESTING_MULTI_BLOCK_KEY[];
extern const uint8_t AES_CBC_TESTING_MULTI_BLOCK_IV[];

extern const uint8_t AES_CBC_TESTING_MULTI_BLOCK_PLAINTEXT[];
extern const uint8_t AES_CBC_TESTING_MULTI_BLOCK_CIPHERTEXT[];
extern const size_t AES_CBC_TESTING_MULTI_BLOCK_LEN;

extern const uint8_t AES_CBC_TESTING_LONG_DATA_KEY[];
extern const uint8_t AES_CBC_TESTING_LONG_DATA_IV[];

extern const uint8_t AES_CBC_TESTING_LONG_DATA_PLAINTEXT[];
extern const uint8_t AES_CBC_TESTING_LONG_DATA_CIPHERTEXT[];
extern const size_t AES_CBC_TESTING_LONG_DATA_LEN;


#endif	/* AES_CBC_TESTING_H_ */
