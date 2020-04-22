// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RSA_TESTING_H_
#define RSA_TESTING_H_

#include <stddef.h>
#include <stdint.h>
#include "crypto/rsa.h"


extern const struct rsa_public_key RSA_PUBLIC_KEY;

extern const char RSA_PUBKEY_PEM[];
extern const size_t RSA_PUBKEY_PEM_LEN;

extern const uint8_t RSA_PUBKEY_DER[];
extern const size_t RSA_PUBKEY_DER_LEN;
extern const uint8_t RSA_PUBKEY_DER_HASH[];
extern const size_t RSA_PUBKEY_DER_HASH_LEN;

extern const char RSA_PRIVKEY_PEM[];
extern const size_t RSA_PRIVKEY_PEM_LEN;

extern const uint8_t RSA_PRIVKEY_DER[];
extern const size_t RSA_PRIVKEY_DER_LEN;
extern const uint8_t RSA_PRIVKEY_DER_HASH[];
extern const size_t RSA_PRIVKEY_DER_HASH_LEN;

extern const char *RSA_ENCRYPT_LABEL;
extern const size_t RSA_ENCRYPT_LABEL_LEN;

extern const uint8_t RSA_ENCRYPT_TEST[];
extern const uint8_t RSA_LABEL_ENCRYPT_TEST[];
extern const uint8_t RSA_SHA256_ENCRYPT_TEST[];
extern const uint8_t RSA_SHA256_LABEL_ENCRYPT_TEST[];
extern const uint8_t RSA_SIGNATURE_TEST[];

extern const uint8_t RSA_ENCRYPT_TEST2[];
extern const uint8_t RSA_LABEL_ENCRYPT_TEST2[];
extern const uint8_t RSA_SHA256_ENCRYPT_TEST2[];
extern const uint8_t RSA_SHA256_LABEL_ENCRYPT_TEST2[];
extern const uint8_t RSA_SIGNATURE_TEST2[];

extern const uint8_t RSA_ENCRYPT_NOPE[];
extern const uint8_t RSA_LABEL_ENCRYPT_NOPE[];
extern const uint8_t RSA_SHA256_ENCRYPT_NOPE[];
extern const uint8_t RSA_SHA256_LABEL_ENCRYPT_NOPE[];
extern const uint8_t RSA_SIGNATURE_NOPE[];

extern const uint8_t RSA_ENCRYPT_BAD[];
extern const uint8_t RSA_LABEL_ENCRYPT_BAD[];
extern const uint8_t RSA_SHA256_ENCRYPT_BAD[];
extern const uint8_t RSA_SHA256_LABEL_ENCRYPT_BAD[];
extern const uint8_t RSA_SIGNATURE_BAD[];

extern const struct rsa_public_key RSA_PUBLIC_KEY2;

extern const char RSA_PUBKEY2_PEM[];
extern const size_t RSA_PUBKEY2_PEM_LEN;

extern const uint8_t RSA_PUBKEY2_DER[];
extern const size_t RSA_PUBKEY2_DER_LEN;

extern const char RSA_PRIVKEY2_PEM[];
extern const size_t RSA_PRIVKEY2_PEM_LEN;

extern const uint8_t RSA_PRIVKEY2_DER[];
extern const size_t RSA_PRIVKEY2_DER_LEN;

extern const uint8_t RSA_SIGNATURE2_TEST[];
extern const uint8_t RSA_SIGNATURE2_TEST2[];
extern const uint8_t RSA_SIGNATURE2_NOPE[];
extern const uint8_t RSA_SIGNATURE2_BAD[];

extern const struct rsa_public_key RSA_PUBLIC_KEY3;

extern const char RSA_PUBKEY3_PEM[];
extern const size_t RSA_PUBKEY3_PEM_LEN;

extern const uint8_t RSA_PUBKEY3_DER[];
extern const size_t RSA_PUBKEY3_DER_LEN;

extern const char RSA_PRIVKEY3_PEM[];
extern const size_t RSA_PRIVKEY3_PEM_LEN;

extern const uint8_t RSA_PRIVKEY3_DER[];
extern const size_t RSA_PRIVKEY3_DER_LEN;

extern const uint8_t RSA_SIGNATURE3_TEST[];
extern const uint8_t RSA_SIGNATURE3_TEST2[];
extern const uint8_t RSA_SIGNATURE3_NOPE[];
extern const uint8_t RSA_SIGNATURE3_BAD[];

#define	RSA_ENCRYPT_LEN		(2048 / 8)


#if (RSA_MAX_KEY_LENGTH >= RSA_KEY_LENGTH_3K)
extern const struct rsa_public_key RSA3K_PUBLIC_KEY;
#endif

extern const char RSA3K_PUBKEY_PEM[];
extern const size_t RSA3K_PUBKEY_PEM_LEN;

extern const uint8_t RSA3K_PUBKEY_DER[];
extern const size_t RSA3K_PUBKEY_DER_LEN;

extern const char RSA3K_PRIVKEY_PEM[];
extern const size_t RSA3K_PRIVKEY_PEM_LEN;

extern const uint8_t RSA3K_PRIVKEY_DER[];
extern const size_t RSA3K_PRIVKEY_DER_LEN;


#if (RSA_MAX_KEY_LENGTH >= RSA_KEY_LENGTH_4K)
extern const struct rsa_public_key RSA4K_PUBLIC_KEY;
#endif

extern const char RSA4K_PUBKEY_PEM[];
extern const size_t RSA4K_PUBKEY_PEM_LEN;

extern const uint8_t RSA4K_PUBKEY_DER[];
extern const size_t RSA4K_PUBKEY_DER_LEN;
extern const uint8_t RSA4K_PUBKEY_DER_HASH[];
extern const size_t RSA4K_PUBKEY_DER_HASH_LEN;

extern const char RSA4K_PRIVKEY_PEM[];
extern const size_t RSA4K_PRIVKEY_PEM_LEN;

extern const uint8_t RSA4K_PRIVKEY_DER[];
extern const size_t RSA4K_PRIVKEY_DER_LEN;
extern const uint8_t RSA4K_PRIVKEY_DER_HASH[];
extern const size_t RSA4K_PRIVKEY_DER_HASH_LEN;


extern const uint8_t RSA5K_PUBKEY_DER[];
extern const size_t RSA5K_PUBKEY_DER_LEN;


#endif /* RSA_TESTING_H_ */
