// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ECC_TESTING_H_
#define ECC_TESTING_H_

#include <stdint.h>
#include <stddef.h>
#include "crypto/ecc.h"


extern const uint8_t ECC_PRIVKEY[];
extern const size_t ECC_PRIVKEY_LEN;

extern const uint8_t ECC_PUBKEY[];
extern const size_t ECC_PUBKEY_LEN;

extern const uint8_t ECC_PUBKEY_SHA1[];
extern const uint8_t ECC_PUBKEY_SHA256[];
extern const uint8_t ECC_PUBKEY_SHA384[];
extern const uint8_t ECC_PUBKEY_SHA512[];

extern const struct ecc_point_public_key ECC_PUBKEY_POINT;

extern const char ECC_PUBKEY_PEM[];
extern const size_t ECC_PUBKEY_PEM_LEN;

extern const uint8_t ECC_PUBKEY_DER[];
extern const size_t ECC_PUBKEY_DER_LEN;

extern const char ECC_PRIVKEY_PEM[];
extern const size_t ECC_PRIVKEY_PEM_LEN;

extern const uint8_t ECC_PRIVKEY_DER[];
extern const size_t ECC_PRIVKEY_DER_LEN;

extern const uint8_t ECC_PRIVKEY_NO_PUBKEY_DER[];
extern const size_t ECC_PRIVKEY_NO_PUBKEY_DER_LEN;

extern const uint8_t ECC_SIGNATURE_TEST[];
extern const size_t ECC_SIG_TEST_LEN;

extern const struct ecc_ecdsa_signature ECC_SIGNATURE_TEST_STRUCT;

extern const uint8_t ECC_SIGNATURE_TEST_RAW[];
extern const size_t ECC_SIG_TEST_RAW_LEN;

extern const uint8_t ECC_SIGNATURE_TEST2[];
extern const size_t ECC_SIG_TEST2_LEN;

extern const struct ecc_ecdsa_signature ECC_SIGNATURE_TEST2_STRUCT;

extern const uint8_t ECC_SIGNATURE_TEST2_RAW[];
extern const size_t ECC_SIG_TEST2_RAW_LEN;

extern const uint8_t ECC_SIGNATURE_NOPE[];
extern const size_t ECC_SIG_NOPE_LEN;

extern const uint8_t ECC_SIGNATURE_BAD[];
extern const size_t ECC_SIG_BAD_LEN;

extern const uint8_t ECC_DH_SECRET[];
extern const size_t ECC_DH_SECRET_LEN;

extern const uint8_t ECC_PRIVKEY_LEADING_ZERO[];
extern const size_t ECC_PRIVKEY_LEADING_ZERO_LEN;

extern const char ECC_PUBKEY_LEADING_ZERO_PEM[];
extern const size_t ECC_PUBKEY_LEADING_ZERO_PEM_LEN;

extern const uint8_t ECC_PUBKEY_LEADING_ZERO_DER[];
extern const size_t ECC_PUBKEY_LEADING_ZERO_DER_LEN;

extern const char ECC_PRIVKEY_LEADING_ZERO_PEM[];
extern const size_t ECC_PRIVKEY_LEADING_ZERO_PEM_LEN;

extern const uint8_t ECC_PRIVKEY_LEADING_ZERO_DER[];
extern const size_t ECC_PRIVKEY_LEADING_ZERO_DER_LEN;

extern const uint8_t ECC_DH_SECRET_LEADING_ZERO[];
extern const size_t ECC_DH_SECRET_LEADING_ZERO_LEN;

extern const uint8_t ECC_PRIVKEY2[];
extern const size_t ECC_PRIVKEY2_LEN;

extern const uint8_t ECC_PUBKEY2[];
extern const size_t ECC_PUBEY2_LEN;

extern const uint8_t ECC_PUBKEY2_SHA1[];
extern const uint8_t ECC_PUBKEY2_SHA256[];
extern const uint8_t ECC_PUBKEY2_SHA384[];
extern const uint8_t ECC_PUBKEY2_SHA512[];

extern const struct ecc_point_public_key ECC_PUBKEY2_POINT;

extern const char ECC_PUBKEY2_PEM[];
extern const size_t ECC_PUBKEY2_PEM_LEN;

extern const uint8_t ECC_PUBKEY2_DER[];
extern const size_t ECC_PUBKEY2_DER_LEN;

extern const char ECC_PRIVKEY2_PEM[];
extern const size_t ECC_PRIVKEY2_PEM_LEN;

extern const uint8_t ECC_PRIVKEY2_DER[];
extern const size_t ECC_PRIVKEY2_DER_LEN;

extern const uint8_t ECC_PRIVKEY2_NO_PUBKEY_DER[];
extern const size_t ECC_PRIVKEY2_NO_PUBKEY_DER_LEN;


extern const uint8_t ECC384_PRIVKEY[];
extern const size_t ECC384_PRIVKEY_LEN;

extern const uint8_t ECC384_PUBKEY[];
extern const size_t ECC384_PUBKEY_LEN;

extern const uint8_t ECC384_PUBKEY_SHA1[];
extern const uint8_t ECC384_PUBKEY_SHA256[];
extern const uint8_t ECC384_PUBKEY_SHA384[];
extern const uint8_t ECC384_PUBKEY_SHA512[];

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
extern const struct ecc_point_public_key ECC384_PUBKEY_POINT;
#endif

extern const char ECC384_PUBKEY_PEM[];
extern const size_t ECC384_PUBKEY_PEM_LEN;

extern const uint8_t ECC384_PUBKEY_DER[];
extern const size_t ECC384_PUBKEY_DER_LEN;

extern const char ECC384_PRIVKEY_PEM[];
extern const size_t ECC384_PRIVKEY_PEM_LEN;

extern const uint8_t ECC384_PRIVKEY_DER[];
extern const size_t ECC384_PRIVKEY_DER_LEN;

extern const uint8_t ECC384_PRIVKEY_NO_PUBKEY_DER[];
extern const size_t ECC384_PRIVKEY_NO_PUBKEY_DER_LEN;

extern const uint8_t ECC384_SIGNATURE_TEST[];
extern const size_t ECC384_SIG_TEST_LEN;

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
extern const struct ecc_ecdsa_signature ECC384_SIGNATURE_TEST_STRUCT;
#endif

extern const uint8_t ECC384_SIGNATURE_TEST_RAW[];
extern const size_t ECC384_SIG_TEST_RAW_LEN;

extern const uint8_t ECC384_SIGNATURE_TEST2[];
extern const size_t ECC384_SIG_TEST2_LEN;

extern const uint8_t ECC384_SIGNATURE_NOPE[];
extern const size_t ECC384_SIG_NOPE_LEN;

extern const uint8_t ECC384_SIGNATURE_BAD[];
extern const size_t ECC384_SIG_BAD_LEN;

extern const uint8_t ECC384_DH_SECRET[];
extern const size_t ECC384_DH_SECRET_LEN;

extern const uint8_t ECC384_PRIVKEY2[];
extern const size_t ECC384_PRIVKEY2_LEN;

extern const uint8_t ECC384_PUBKEY2[];
extern const size_t ECC384_PUBKEY2_LEN;

extern const uint8_t ECC384_PUBKEY2_SHA1[];
extern const uint8_t ECC384_PUBKEY2_SHA256[];
extern const uint8_t ECC384_PUBKEY2_SHA384[];
extern const uint8_t ECC384_PUBKEY2_SHA512[];

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
extern const struct ecc_point_public_key ECC384_PUBKEY2_POINT;
#endif

extern const char ECC384_PUBKEY2_PEM[];
extern const size_t ECC384_PUBKEY2_PEM_LEN;

extern const uint8_t ECC384_PUBKEY2_DER[];
extern const size_t ECC384_PUBKEY2_DER_LEN;

extern const char ECC384_PRIVKEY2_PEM[];
extern const size_t ECC384_PRIVKEY2_PEM_LEN;

extern const uint8_t ECC384_PRIVKEY2_DER[];
extern const size_t ECC384_PRIVKEY2_DER_LEN;

extern const uint8_t ECC384_PRIVKEY2_NO_PUBKEY_DER[];
extern const size_t ECC384_PRIVKEY2_NO_PUBKEY_DER_LEN;

extern const uint8_t ECC384_PRIVKEY3[];
extern const size_t ECC384_PRIVKEY3_LEN;

extern const uint8_t ECC384_PUBKEY3[];
extern const size_t ECC384_PUBKEY3_LEN;

extern const uint8_t ECC384_PUBKEY3_SHA1[];
extern const uint8_t ECC384_PUBKEY3_SHA256[];
extern const uint8_t ECC384_PUBKEY3_SHA384[];
extern const uint8_t ECC384_PUBKEY3_SHA512[];

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
extern const struct ecc_point_public_key ECC384_PUBKEY3_POINT;
#endif

extern const char ECC384_PUBKEY3_PEM[];
extern const size_t ECC384_PUBKEY3_PEM_LEN;

extern const uint8_t ECC384_PUBKEY3_DER[];
extern const size_t ECC384_PUBKEY3_DER_LEN;

extern const char ECC384_PRIVKEY3_PEM[];
extern const size_t ECC384_PRIVKEY3_PEM_LEN;

extern const uint8_t ECC384_PRIVKEY3_DER[];
extern const size_t ECC384_PRIVKEY3_DER_LEN;

extern const uint8_t ECC384_PRIVKEY3_NO_PUBKEY_DER[];
extern const size_t ECC384_PRIVKEY3_NO_PUBKEY_DER_LEN;


extern const uint8_t ECC521_PRIVKEY[];
extern const size_t ECC521_PRIVKEY_LEN;

extern const uint8_t ECC521_PUBKEY[];
extern const size_t ECC521_PUBKEY_LEN;

extern const uint8_t ECC521_PUBKEY_SHA1[];
extern const uint8_t ECC521_PUBKEY_SHA256[];
extern const uint8_t ECC521_PUBKEY_SHA384[];
extern const uint8_t ECC521_PUBKEY_SHA512[];

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
extern const struct ecc_point_public_key ECC521_PUBKEY_POINT;
#endif

extern const char ECC521_PUBKEY_PEM[];
extern const size_t ECC384_PUBKEY_PEM_LEN;

extern const uint8_t ECC521_PUBKEY_DER[];
extern const size_t ECC521_PUBKEY_DER_LEN;

extern const char ECC521_PRIVKEY_PEM[];
extern const size_t ECC521_PRIVKEY_PEM_LEN;

extern const uint8_t ECC521_PRIVKEY_DER[];
extern const size_t ECC521_PRIVKEY_DER_LEN;

extern const uint8_t ECC521_PRIVKEY_DER_NO_LEADING_ZERO[];
extern const size_t ECC521_PRIVKEY_DER_NO_LEADING_ZERO_LEN;

extern const uint8_t ECC521_PRIVKEY_NO_PUBKEY_DER[];
extern const size_t ECC521_PRIVKEY_NO_PUBKEY_DER_LEN;

extern const uint8_t ECC521_SIGNATURE_TEST[];
extern const size_t ECC521_SIG_TEST_LEN;

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
extern const struct ecc_ecdsa_signature ECC521_SIGNATURE_TEST_STRUCT;
#endif

extern const uint8_t ECC521_SIGNATURE_TEST_RAW[];
extern const size_t ECC521_SIG_TEST_RAW_LEN;

extern const uint8_t ECC521_SIGNATURE_TEST2[];
extern const size_t ECC521_SIG_TEST2_LEN;

extern const uint8_t ECC521_SIGNATURE_NOPE[];
extern const size_t ECC521_SIG_NOPE_LEN;

extern const uint8_t ECC521_SIGNATURE_BAD[];
extern const size_t ECC521_SIG_BAD_LEN;

extern const uint8_t ECC521_DH_SECRET[];
extern const size_t ECC521_DH_SECRET_LEN;


#endif /* ECC_TESTING_H_ */
