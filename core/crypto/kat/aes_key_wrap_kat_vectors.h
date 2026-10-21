// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_KEY_WRAP_KAT_VECTORS_H_
#define AES_KEY_WRAP_KAT_VECTORS_H_

#include <stddef.h>
#include <stdint.h>
#include "crypto/aes_ecb.h"


/* Test vectors for AES Key Wrap self-tests.  These come from RFC3394. */
extern const uint8_t AES_KEY_WRAP_KAT_VECTORS_KW_KEY[];
#define	AES_KEY_WRAP_KAT_VECTORS_KW_KEY_LEN			AES_ECB_256_KEY_LENGTH

extern const uint8_t AES_KEY_WRAP_KAT_VECTORS_KW_DATA[];
#define	AES_KEY_WRAP_KAT_VECTORS_KW_DATA_LEN		16

extern const uint8_t AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED[];
#define	AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED_LEN		24

/* Test vectors for AES Key Wrap with Padding self-tests.  These come from NIST. */
extern const uint8_t AES_KEY_WRAP_KAT_VECTORS_KWP_KEY[];
#define	AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN		AES_ECB_256_KEY_LENGTH

extern const uint8_t AES_KEY_WRAP_KAT_VECTORS_KWP_DATA[];
#define	AES_KEY_WRAP_KAT_VECTORS_KWP_DATA_LEN		9

extern const uint8_t AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED[];
#define	AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN	24


#endif	/* AES_KEY_WRAP_KAT_VECTORS_H_ */
