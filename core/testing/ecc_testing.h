// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ECC_TESTING_H_
#define ECC_TESTING_H_

#include <stdint.h>
#include <stddef.h>


extern const uint8_t ECC_PRIVKEY[];
extern const size_t ECC_PRIVKEY_LEN;

extern const char ECC_PUBKEY_PEM[];
extern const size_t ECC_PUBKEY_PEM_LEN;

extern const uint8_t ECC_PUBKEY_DER[];
extern const size_t ECC_PUBKEY_DER_LEN;

extern const char ECC_PRIVKEY_PEM[];
extern const size_t ECC_PRIVKEY_PEM_LEN;

extern const uint8_t ECC_PRIVKEY_DER[];
extern const size_t ECC_PRIVKEY_DER_LEN;

extern const uint8_t ECC_SIGNATURE_TEST[];
extern const size_t ECC_SIG_TEST_LEN;

extern const uint8_t ECC_SIGNATURE_TEST2[];
extern const size_t ECC_SIG_TEST2_LEN;

extern const uint8_t ECC_SIGNATURE_NOPE[];
extern const size_t ECC_SIG_NOPE_LEN;

extern const uint8_t ECC_SIGNATURE_BAD[];
extern const size_t ECC_SIG_BAD_LEN;

extern const uint8_t ECC_DH_SECRET[];
extern const size_t ECC_DH_SECRET_LEN;

extern const uint8_t ECC_PRIVKEY2[];
extern const size_t ECC_PRIVKEY2_LEN;

extern const char ECC_PUBKEY2_PEM[];
extern const size_t ECC_PUBKEY2_PEM_LEN;

extern const uint8_t ECC_PUBKEY2_DER[];
extern const size_t ECC_PUBKEY2_DER_LEN;

extern const char ECC_PRIVKEY2_PEM[];
extern const size_t ECC_PRIVKEY2_PEM_LEN;

extern const uint8_t ECC_PRIVKEY2_DER[];
extern const size_t ECC_PRIVKEY2_DER_LEN;

#define	ECC_DH_SECRET_MAX_LENGTH	(256 / 8)


extern const uint8_t ECC384_PRIVKEY[];
extern const size_t ECC384_PRIVKEY_LEN;

extern const char ECC384_PUBKEY_PEM[];
extern const size_t ECC384_PUBKEY_PEM_LEN;

extern const uint8_t ECC384_PUBKEY_DER[];
extern const size_t ECC384_PUBKEY_DER_LEN;

extern const char ECC384_PRIVKEY_PEM[];
extern const size_t ECC384_PRIVKEY_PEM_LEN;

extern const uint8_t ECC384_PRIVKEY_DER[];
extern const size_t ECC384_PRIVKEY_DER_LEN;


extern const uint8_t ECC521_PRIVKEY[];
extern const size_t ECC521_PRIVKEY_LEN;

extern const char ECC521_PUBKEY_PEM[];
extern const size_t ECC384_PUBKEY_PEM_LEN;

extern const uint8_t ECC521_PUBKEY_DER[];
extern const size_t ECC521_PUBKEY_DER_LEN;

extern const char ECC521_PRIVKEY_PEM[];
extern const size_t ECC521_PRIVKEY_PEM_LEN;

extern const uint8_t ECC521_PRIVKEY_DER[];
extern const size_t ECC521_PRIVKEY_DER_LEN;


#endif /* ECC_TESTING_H_ */
