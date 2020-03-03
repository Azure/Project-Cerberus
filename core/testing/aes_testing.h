// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_TESTING_H_
#define AES_TESTING_H_

#include <stdint.h>
#include <stddef.h>


const extern uint8_t AES_KEY[];
#define AES_KEY_LEN (256 / 8)

const extern uint8_t AES_IV[];
#define AES_IV_LEN 12

const extern uint8_t AES_PLAINTEXT[];
const extern size_t AES_PLAINTEXT_LEN;

const extern uint8_t AES_CIPHERTEXT[];
const extern size_t AES_CIPHERTEXT_LEN;

const extern uint8_t AES_GCM_TAG[];
#define AES_GCM_TAG_LEN 16

const extern uint8_t AES_RSA_PRIVKEY_DER[];
const extern size_t AES_RSA_PRIVKEY_DER_LEN;

const extern uint8_t AES_RSA_PRIVKEY_GCM_TAG[];


#endif /* AES_TESTING_H_ */
