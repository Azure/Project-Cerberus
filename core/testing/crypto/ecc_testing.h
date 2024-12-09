// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ECC_TESTING_H_
#define ECC_TESTING_H_

#include <stddef.h>
#include <stdint.h>
#include "crypto/ecc.h"


/* Maximum lengths of DER-encoded ECDSA signatures.
 * Sequence -> 2 bytes overhead (3 for ECC521)
 *	BIT STRING (r) -> 2 bytes overhead (3 if MSB is 1)
 *	BIT STRING (s) -> 2 bytes overhead (3 if MSB is 1) */
#define	ECC_TESTING_ECC256_DSA_MAX_LENGTH		72
#define	ECC_TESTING_ECC384_DSA_MAX_LENGTH		104
#define	ECC_TESTING_ECC521_DSA_MAX_LENGTH		139


extern const uint8_t ECC_PRIVKEY[];
extern const uint8_t ECC_PRIVKEY_LE[];
extern const size_t ECC_PRIVKEY_LEN;

extern const uint8_t ECC_PUBKEY[];
extern const uint8_t ECC_PUBKEY_LE[];
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

extern const struct ecc_ecdsa_signature ECC_SIGNATURE_NOPE_STRUCT;

extern const uint8_t ECC_SIGNATURE_NOPE_RAW[];
extern const size_t ECC_SIG_NOPE_RAW_LEN;

extern const uint8_t ECC_SIGNATURE_BAD[];
extern const size_t ECC_SIG_BAD_LEN;

extern const struct ecc_ecdsa_signature ECC_SIGNATURE_BAD_STRUCT;

extern const uint8_t ECC_SIGNATURE_BAD_RAW[];
extern const size_t ECC_SIG_BAD_RAW_LEN;

extern const uint8_t ECC_DH_SECRET[];
extern const size_t ECC_DH_SECRET_LEN;

extern const uint8_t ECC_PRIVKEY_LEADING_ZERO[];
extern const uint8_t ECC_PRIVKEY_LEADING_ZERO_LE[];
extern const size_t ECC_PRIVKEY_LEADING_ZERO_LEN;

extern const uint8_t ECC_PUBKEY_LEADING_ZERO[];
extern const uint8_t ECC_PUBKEY_LEADING_ZERO_LE[];
extern const size_t ECC_PUBKEY_LEADING_ZERO_LEN;

extern const uint8_t ECC_PUBKEY_LEADING_ZERO_SHA1[];
extern const uint8_t ECC_PUBKEY_LEADING_ZERO_SHA256[];
extern const uint8_t ECC_PUBKEY_LEADING_ZERO_SHA384[];
extern const uint8_t ECC_PUBKEY_LEADING_ZERO_SHA512[];

extern const struct ecc_point_public_key ECC_PUBKEY_LEADING_ZERO_POINT;

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
extern const uint8_t ECC_PRIVKEY2_LE[];
extern const size_t ECC_PRIVKEY2_LEN;

extern const uint8_t ECC_PUBKEY2[];
extern const uint8_t ECC_PUBKEY2_LE[];
extern const size_t ECC_PUBKEY2_LEN;

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

extern const uint8_t ECC_PRIVKEY2_ZERO_PAD_DER[];
extern const size_t ECC_PRIVKEY2_ZERO_PAD_DER_LEN;

extern const uint8_t ECC_PRIVKEY3[];
extern const uint8_t ECC_PRIVKEY3_LE[];
extern const size_t ECC_PRIVKEY3_LEN;

extern const uint8_t ECC_PUBKEY3[];
extern const uint8_t ECC_PUBKEY3_LE[];
extern const size_t ECC_PUBKEY3_LEN;

extern const uint8_t ECC_PUBKEY3_SHA1[];
extern const uint8_t ECC_PUBKEY3_SHA256[];
extern const uint8_t ECC_PUBKEY3_SHA384[];
extern const uint8_t ECC_PUBKEY3_SHA512[];

extern const struct ecc_point_public_key ECC_PUBKEY3_POINT;

extern const char ECC_PUBKEY3_PEM[];
extern const size_t ECC_PUBKEY3_PEM_LEN;

extern const uint8_t ECC_PUBKEY3_DER[];
extern const size_t ECC_PUBKEY3_DER_LEN;

extern const char ECC_PRIVKEY3_PEM[];
extern const size_t ECC_PRIVKEY3_PEM_LEN;

extern const uint8_t ECC_PRIVKEY3_DER[];
extern const size_t ECC_PRIVKEY3_DER_LEN;

extern const uint8_t ECC_PRIVKEY3_NO_PUBKEY_DER[];
extern const size_t ECC_PRIVKEY3_NO_PUBKEY_DER_LEN;

extern const uint8_t ECC_PRIVKEY4[];
extern const uint8_t ECC_PRIVKEY4_LE[];
extern const size_t ECC_PRIVKEY4_LEN;

extern const uint8_t ECC_PUBKEY4[];
extern const uint8_t ECC_PUBKEY4_LE[];
extern const size_t ECC_PUBKEY4_LEN;

extern const uint8_t ECC_PUBKEY4_SHA1[];
extern const uint8_t ECC_PUBKEY4_SHA256[];
extern const uint8_t ECC_PUBKEY4_SHA384[];
extern const uint8_t ECC_PUBKEY4_SHA512[];

extern const struct ecc_point_public_key ECC_PUBKEY4_POINT;

extern const char ECC_PUBKEY4_PEM[];
extern const size_t ECC_PUBKEY4_PEM_LEN;

extern const uint8_t ECC_PUBKEY4_DER[];
extern const size_t ECC_PUBKEY4_DER_LEN;

extern const char ECC_PRIVKEY4_PEM[];
extern const size_t ECC_PRIVKEY4_PEM_LEN;

extern const uint8_t ECC_PRIVKEY4_DER[];
extern const size_t ECC_PRIVKEY4_DER_LEN;

extern const uint8_t ECC_PRIVKEY4_NO_PUBKEY_DER[];
extern const size_t ECC_PRIVKEY4_NO_PUBKEY_DER_LEN;

extern const uint8_t ECC_PRIVKEY5[];
extern const uint8_t ECC_PRIVKEY5_LE[];
extern const size_t ECC_PRIVKEY5_LEN;

extern const uint8_t ECC_PUBKEY5[];
extern const uint8_t ECC_PUBKEY5_LE[];
extern const size_t ECC_PUBKEY5_LEN;

extern const uint8_t ECC_PUBKEY5_SHA1[];
extern const uint8_t ECC_PUBKEY5_SHA256[];
extern const uint8_t ECC_PUBKEY5_SHA384[];
extern const uint8_t ECC_PUBKEY5_SHA512[];

extern const struct ecc_point_public_key ECC_PUBKEY5_POINT;

extern const char ECC_PUBKEY5_PEM[];
extern const size_t ECC_PUBKEY5_PEM_LEN;

extern const uint8_t ECC_PUBKEY5_DER[];
extern const size_t ECC_PUBKEY5_DER_LEN;

extern const char ECC_PRIVKEY5_PEM[];
extern const size_t ECC_PRIVKEY5_PEM_LEN;

extern const uint8_t ECC_PRIVKEY5_DER[];
extern const size_t ECC_PRIVKEY5_DER_LEN;

extern const uint8_t ECC_PRIVKEY5_NO_PUBKEY_DER[];
extern const size_t ECC_PRIVKEY5_NO_PUBKEY_DER_LEN;

extern const uint8_t ECC_PRIVKEY6[];
extern const uint8_t ECC_PRIVKEY6_LE[];
extern const size_t ECC_PRIVKEY6_LEN;

extern const uint8_t ECC_PUBKEY6[];
extern const uint8_t ECC_PUBKEY6_LE[];
extern const size_t ECC_PUBKEY6_LEN;

extern const uint8_t ECC_PUBKEY6_SHA1[];
extern const uint8_t ECC_PUBKEY6_SHA256[];
extern const uint8_t ECC_PUBKEY6_SHA384[];
extern const uint8_t ECC_PUBKEY6_SHA512[];

extern const struct ecc_point_public_key ECC_PUBKEY6_POINT;

extern const char ECC_PUBKEY6_PEM[];
extern const size_t ECC_PUBKEY6_PEM_LEN;

extern const uint8_t ECC_PUBKEY6_DER[];
extern const size_t ECC_PUBKEY6_DER_LEN;

extern const char ECC_PRIVKEY6_PEM[];
extern const size_t ECC_PRIVKEY6_PEM_LEN;

extern const uint8_t ECC_PRIVKEY6_DER[];
extern const size_t ECC_PRIVKEY6_DER_LEN;

extern const uint8_t ECC_PRIVKEY6_NO_PUBKEY_DER[];
extern const size_t ECC_PRIVKEY6_NO_PUBKEY_DER_LEN;

extern const uint8_t ECC_PRIVKEY7[];
extern const uint8_t ECC_PRIVKEY7_LE[];
extern const size_t ECC_PRIVKEY7_LEN;

extern const uint8_t ECC_PUBKEY7[];
extern const uint8_t ECC_PUBKEY7_LE[];
extern const size_t ECC_PUBKEY7_LEN;

extern const uint8_t ECC_PUBKEY7_SHA1[];
extern const uint8_t ECC_PUBKEY7_SHA256[];
extern const uint8_t ECC_PUBKEY7_SHA384[];
extern const uint8_t ECC_PUBKEY7_SHA512[];

extern const struct ecc_point_public_key ECC_PUBKEY7_POINT;

extern const char ECC_PUBKEY7_PEM[];
extern const size_t ECC_PUBKEY7_PEM_LEN;

extern const uint8_t ECC_PUBKEY7_DER[];
extern const size_t ECC_PUBKEY7_DER_LEN;

extern const char ECC_PRIVKEY7_PEM[];
extern const size_t ECC_PRIVKEY7_PEM_LEN;

extern const uint8_t ECC_PRIVKEY7_DER[];
extern const size_t ECC_PRIVKEY7_DER_LEN;

extern const uint8_t ECC_PRIVKEY7_NO_PUBKEY_DER[];
extern const size_t ECC_PRIVKEY7_NO_PUBKEY_DER_LEN;

extern const uint8_t ECC_PRIVKEY8[];
extern const uint8_t ECC_PRIVKEY8_LE[];
extern const size_t ECC_PRIVKEY8_LEN;

extern const uint8_t ECC_PUBKEY8[];
extern const uint8_t ECC_PUBKEY8_LE[];
extern const size_t ECC_PUBKEY8_LEN;

extern const uint8_t ECC_PUBKEY8_SHA1[];
extern const uint8_t ECC_PUBKEY8_SHA256[];
extern const uint8_t ECC_PUBKEY8_SHA384[];
extern const uint8_t ECC_PUBKEY8_SHA512[];

extern const struct ecc_point_public_key ECC_PUBKEY8_POINT;

extern const char ECC_PUBKEY8_PEM[];
extern const size_t ECC_PUBKEY8_PEM_LEN;

extern const uint8_t ECC_PUBKEY8_DER[];
extern const size_t ECC_PUBKEY8_DER_LEN;

extern const char ECC_PRIVKEY8_PEM[];
extern const size_t ECC_PRIVKEY8_PEM_LEN;

extern const uint8_t ECC_PRIVKEY8_DER[];
extern const size_t ECC_PRIVKEY8_DER_LEN;

extern const uint8_t ECC_PRIVKEY8_NO_PUBKEY_DER[];
extern const size_t ECC_PRIVKEY8_NO_PUBKEY_DER_LEN;

extern const uint8_t ECC_PRIVKEY9[];
extern const uint8_t ECC_PRIVKEY9_LE[];
extern const size_t ECC_PRIVKEY9_LEN;

extern const uint8_t ECC_PUBKEY9[];
extern const uint8_t ECC_PUBKEY9_LE[];
extern const size_t ECC_PUBKEY9_LEN;

extern const uint8_t ECC_PUBKEY9_SHA1[];
extern const uint8_t ECC_PUBKEY9_SHA256[];
extern const uint8_t ECC_PUBKEY9_SHA384[];
extern const uint8_t ECC_PUBKEY9_SHA512[];

extern const struct ecc_point_public_key ECC_PUBKEY9_POINT;

extern const char ECC_PUBKEY9_PEM[];
extern const size_t ECC_PUBKEY9_PEM_LEN;

extern const uint8_t ECC_PUBKEY9_DER[];
extern const size_t ECC_PUBKEY9_DER_LEN;

extern const char ECC_PRIVKEY9_PEM[];
extern const size_t ECC_PRIVKEY9_PEM_LEN;

extern const uint8_t ECC_PRIVKEY9_DER[];
extern const size_t ECC_PRIVKEY9_DER_LEN;

extern const uint8_t ECC_PRIVKEY9_NO_PUBKEY_DER[];
extern const size_t ECC_PRIVKEY9_NO_PUBKEY_DER_LEN;

extern const uint8_t ECC_PRIVKEY10[];
extern const uint8_t ECC_PRIVKEY10_LE[];
extern const size_t ECC_PRIVKEY10_LEN;

extern const uint8_t ECC_PUBKEY10[];
extern const uint8_t ECC_PUBKEY10_LE[];
extern const size_t ECC_PUBKEY10_LEN;

extern const uint8_t ECC_PUBKEY10_SHA1[];
extern const uint8_t ECC_PUBKEY10_SHA256[];
extern const uint8_t ECC_PUBKEY10_SHA384[];
extern const uint8_t ECC_PUBKEY10_SHA512[];

extern const struct ecc_point_public_key ECC_PUBKEY10_POINT;

extern const char ECC_PUBKEY10_PEM[];
extern const size_t ECC_PUBKEY10_PEM_LEN;

extern const uint8_t ECC_PUBKEY10_DER[];
extern const size_t ECC_PUBKEY10_DER_LEN;

extern const char ECC_PRIVKEY10_PEM[];
extern const size_t ECC_PRIVKEY10_PEM_LEN;

extern const uint8_t ECC_PRIVKEY10_DER[];
extern const size_t ECC_PRIVKEY10_DER_LEN;

extern const uint8_t ECC_PRIVKEY10_NO_PUBKEY_DER[];
extern const size_t ECC_PRIVKEY10_NO_PUBKEY_DER_LEN;


extern const uint8_t ECC384_PRIVKEY[];
extern const uint8_t ECC384_PRIVKEY_LE[];
extern const size_t ECC384_PRIVKEY_LEN;

extern const uint8_t ECC384_PUBKEY[];
extern const uint8_t ECC384_PUBKEY_LE[];
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

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
extern const struct ecc_ecdsa_signature ECC384_SIGNATURE_TEST2_STRUCT;
#endif

extern const uint8_t ECC384_SIGNATURE_TEST2_RAW[];
extern const size_t ECC384_SIG_TEST2_RAW_LEN;

extern const uint8_t ECC384_SIGNATURE_NOPE[];
extern const size_t ECC384_SIG_NOPE_LEN;

extern const uint8_t ECC384_SIGNATURE_BAD[];
extern const size_t ECC384_SIG_BAD_LEN;

extern const uint8_t ECC384_DH_SECRET[];
extern const size_t ECC384_DH_SECRET_LEN;

extern const uint8_t ECC384_PRIVKEY2[];
extern const uint8_t ECC384_PRIVKEY2_LE[];
extern const size_t ECC384_PRIVKEY2_LEN;

extern const uint8_t ECC384_PUBKEY2[];
extern const uint8_t ECC384_PUBKEY2_LE[];
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
extern const uint8_t ECC384_PRIVKEY3_LE[];
extern const size_t ECC384_PRIVKEY3_LEN;

extern const uint8_t ECC384_PUBKEY3[];
extern const uint8_t ECC384_PUBKEY3_LE[];
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

extern const uint8_t ECC384_PRIVKEY3_ZERO_PAD_DER[];
extern const size_t ECC384_PRIVKEY3_ZERO_PAD_DER_LEN;

extern const uint8_t ECC384_PRIVKEY4[];
extern const uint8_t ECC384_PRIVKEY4_LE[];
extern const size_t ECC384_PRIVKEY4_LEN;

extern const uint8_t ECC384_PUBKEY4[];
extern const uint8_t ECC384_PUBKEY4_LE[];
extern const size_t ECC384_PUBKEY4_LEN;

extern const uint8_t ECC384_PUBKEY4_SHA1[];
extern const uint8_t ECC384_PUBKEY4_SHA256[];
extern const uint8_t ECC384_PUBKEY4_SHA384[];
extern const uint8_t ECC384_PUBKEY4_SHA512[];

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
extern const struct ecc_point_public_key ECC384_PUBKEY4_POINT;
#endif

extern const char ECC384_PUBKEY4_PEM[];
extern const size_t ECC384_PUBKEY4_PEM_LEN;

extern const uint8_t ECC384_PUBKEY4_DER[];
extern const size_t ECC384_PUBKEY4_DER_LEN;

extern const char ECC384_PRIVKEY4_PEM[];
extern const size_t ECC384_PRIVKEY4_PEM_LEN;

extern const uint8_t ECC384_PRIVKEY4_DER[];
extern const size_t ECC384_PRIVKEY4_DER_LEN;

extern const uint8_t ECC384_PRIVKEY4_NO_PUBKEY_DER[];
extern const size_t ECC384_PRIVKEY4_NO_PUBKEY_DER_LEN;

extern const uint8_t ECC384_PRIVKEY5[];
extern const uint8_t ECC384_PRIVKEY5_LE[];
extern const size_t ECC384_PRIVKEY5_LEN;

extern const uint8_t ECC384_PUBKEY5[];
extern const uint8_t ECC384_PUBKEY5_LE[];
extern const size_t ECC384_PUBKEY5_LEN;

extern const uint8_t ECC384_PUBKEY5_SHA1[];
extern const uint8_t ECC384_PUBKEY5_SHA256[];
extern const uint8_t ECC384_PUBKEY5_SHA384[];
extern const uint8_t ECC384_PUBKEY5_SHA512[];

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
extern const struct ecc_point_public_key ECC384_PUBKEY5_POINT;
#endif

extern const char ECC384_PUBKEY5_PEM[];
extern const size_t ECC384_PUBKEY5_PEM_LEN;

extern const uint8_t ECC384_PUBKEY5_DER[];
extern const size_t ECC384_PUBKEY5_DER_LEN;

extern const char ECC384_PRIVKEY5_PEM[];
extern const size_t ECC384_PRIVKEY5_PEM_LEN;

extern const uint8_t ECC384_PRIVKEY5_DER[];
extern const size_t ECC384_PRIVKEY5_DER_LEN;

extern const uint8_t ECC384_PRIVKEY5_NO_PUBKEY_DER[];
extern const size_t ECC384_PRIVKEY5_NO_PUBKEY_DER_LEN;

extern const uint8_t ECC384_PRIVKEY6[];
extern const uint8_t ECC384_PRIVKEY6_LE[];
extern const size_t ECC384_PRIVKEY6_LEN;

extern const uint8_t ECC384_PUBKEY6[];
extern const uint8_t ECC384_PUBKEY6_LE[];
extern const size_t ECC384_PUBKEY6_LEN;

extern const uint8_t ECC384_PUBKEY6_SHA1[];
extern const uint8_t ECC384_PUBKEY6_SHA256[];
extern const uint8_t ECC384_PUBKEY6_SHA384[];
extern const uint8_t ECC384_PUBKEY6_SHA512[];

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
extern const struct ecc_point_public_key ECC384_PUBKEY6_POINT;
#endif

extern const char ECC384_PUBKEY6_PEM[];
extern const size_t ECC384_PUBKEY6_PEM_LEN;

extern const uint8_t ECC384_PUBKEY6_DER[];
extern const size_t ECC384_PUBKEY6_DER_LEN;

extern const char ECC384_PRIVKEY6_PEM[];
extern const size_t ECC384_PRIVKEY6_PEM_LEN;

extern const uint8_t ECC384_PRIVKEY6_DER[];
extern const size_t ECC384_PRIVKEY6_DER_LEN;

extern const uint8_t ECC384_PRIVKEY6_NO_PUBKEY_DER[];
extern const size_t ECC384_PRIVKEY6_NO_PUBKEY_DER_LEN;

extern const uint8_t ECC384_PRIVKEY7[];
extern const uint8_t ECC384_PRIVKEY7_LE[];
extern const size_t ECC384_PRIVKEY7_LEN;

extern const uint8_t ECC384_PUBKEY7[];
extern const uint8_t ECC384_PUBKEY7_LE[];
extern const size_t ECC384_PUBKEY7_LEN;

extern const uint8_t ECC384_PUBKEY7_SHA1[];
extern const uint8_t ECC384_PUBKEY7_SHA256[];
extern const uint8_t ECC384_PUBKEY7_SHA384[];
extern const uint8_t ECC384_PUBKEY7_SHA512[];

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
extern const struct ecc_point_public_key ECC384_PUBKEY7_POINT;
#endif

extern const char ECC384_PUBKEY7_PEM[];
extern const size_t ECC384_PUBKEY7_PEM_LEN;

extern const uint8_t ECC384_PUBKEY7_DER[];
extern const size_t ECC384_PUBKEY7_DER_LEN;

extern const char ECC384_PRIVKEY7_PEM[];
extern const size_t ECC384_PRIVKEY7_PEM_LEN;

extern const uint8_t ECC384_PRIVKEY7_DER[];
extern const size_t ECC384_PRIVKEY7_DER_LEN;

extern const uint8_t ECC384_PRIVKEY7_NO_PUBKEY_DER[];
extern const size_t ECC384_PRIVKEY7_NO_PUBKEY_DER_LEN;

extern const uint8_t ECC384_PRIVKEY8[];
extern const uint8_t ECC384_PRIVKEY8_LE[];
extern const size_t ECC384_PRIVKEY8_LEN;

extern const uint8_t ECC384_PUBKEY8[];
extern const uint8_t ECC384_PUBKEY8_LE[];
extern const size_t ECC384_PUBKEY8_LEN;

extern const uint8_t ECC384_PUBKEY8_SHA1[];
extern const uint8_t ECC384_PUBKEY8_SHA256[];
extern const uint8_t ECC384_PUBKEY8_SHA384[];
extern const uint8_t ECC384_PUBKEY8_SHA512[];

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
extern const struct ecc_point_public_key ECC384_PUBKEY8_POINT;
#endif

extern const char ECC384_PUBKEY8_PEM[];
extern const size_t ECC384_PUBKEY8_PEM_LEN;

extern const uint8_t ECC384_PUBKEY8_DER[];
extern const size_t ECC384_PUBKEY8_DER_LEN;

extern const char ECC384_PRIVKEY8_PEM[];
extern const size_t ECC384_PRIVKEY8_PEM_LEN;

extern const uint8_t ECC384_PRIVKEY8_DER[];
extern const size_t ECC384_PRIVKEY8_DER_LEN;

extern const uint8_t ECC384_PRIVKEY8_NO_PUBKEY_DER[];
extern const size_t ECC384_PRIVKEY8_NO_PUBKEY_DER_LEN;

extern const uint8_t ECC384_PRIVKEY9[];
extern const uint8_t ECC384_PRIVKEY9_LE[];
extern const size_t ECC384_PRIVKEY9_LEN;

extern const uint8_t ECC384_PUBKEY9[];
extern const uint8_t ECC384_PUBKEY9_LE[];
extern const size_t ECC384_PUBKEY9_LEN;

extern const uint8_t ECC384_PUBKEY9_SHA1[];
extern const uint8_t ECC384_PUBKEY9_SHA256[];
extern const uint8_t ECC384_PUBKEY9_SHA384[];
extern const uint8_t ECC384_PUBKEY9_SHA512[];

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
extern const struct ecc_point_public_key ECC384_PUBKEY9_POINT;
#endif

extern const char ECC384_PUBKEY9_PEM[];
extern const size_t ECC384_PUBKEY9_PEM_LEN;

extern const uint8_t ECC384_PUBKEY9_DER[];
extern const size_t ECC384_PUBKEY9_DER_LEN;

extern const char ECC384_PRIVKEY9_PEM[];
extern const size_t ECC384_PRIVKEY9_PEM_LEN;

extern const uint8_t ECC384_PRIVKEY9_DER[];
extern const size_t ECC384_PRIVKEY9_DER_LEN;

extern const uint8_t ECC384_PRIVKEY9_NO_PUBKEY_DER[];
extern const size_t ECC384_PRIVKEY9_NO_PUBKEY_DER_LEN;

extern const uint8_t ECC384_PRIVKEY10[];
extern const uint8_t ECC384_PRIVKEY10_LE[];
extern const size_t ECC384_PRIVKEY10_LEN;

extern const uint8_t ECC384_PUBKEY10[];
extern const uint8_t ECC384_PUBKEY10_LE[];
extern const size_t ECC384_PUBKEY10_LEN;

extern const uint8_t ECC384_PUBKEY10_SHA1[];
extern const uint8_t ECC384_PUBKEY10_SHA256[];
extern const uint8_t ECC384_PUBKEY10_SHA384[];
extern const uint8_t ECC384_PUBKEY10_SHA512[];

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
extern const struct ecc_point_public_key ECC384_PUBKEY10_POINT;
#endif

extern const char ECC384_PUBKEY10_PEM[];
extern const size_t ECC384_PUBKEY10_PEM_LEN;

extern const uint8_t ECC384_PUBKEY10_DER[];
extern const size_t ECC384_PUBKEY10_DER_LEN;

extern const char ECC384_PRIVKEY10_PEM[];
extern const size_t ECC384_PRIVKEY10_PEM_LEN;

extern const uint8_t ECC384_PRIVKEY10_DER[];
extern const size_t ECC384_PRIVKEY10_DER_LEN;

extern const uint8_t ECC384_PRIVKEY10_NO_PUBKEY_DER[];
extern const size_t ECC384_PRIVKEY10_NO_PUBKEY_DER_LEN;


extern const uint8_t ECC521_PRIVKEY[];
extern const uint8_t ECC521_PRIVKEY_LE[];
extern const size_t ECC521_PRIVKEY_LEN;

extern const uint8_t ECC521_PUBKEY[];
extern const uint8_t ECC521_PUBKEY_LE[];
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

extern const uint8_t ECC521_PRIVKEY2[];
extern const uint8_t ECC521_PRIVKEY2_LE[];
extern const size_t ECC521_PRIVKEY2_LEN;

extern const uint8_t ECC521_PUBKEY2[];
extern const uint8_t ECC521_PUBKEY2_LE[];
extern const size_t ECC521_PUBKEY2_LEN;

extern const uint8_t ECC521_PUBKEY2_SHA1[];
extern const uint8_t ECC521_PUBKEY2_SHA256[];
extern const uint8_t ECC521_PUBKEY2_SHA384[];
extern const uint8_t ECC521_PUBKEY2_SHA512[];

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
extern const struct ecc_point_public_key ECC521_PUBKEY2_POINT;
#endif

extern const char ECC521_PUBKEY2_PEM[];
extern const size_t ECC384_PUBKEY2_PEM_LEN;

extern const uint8_t ECC521_PUBKEY2_DER[];
extern const size_t ECC521_PUBKEY2_DER_LEN;

extern const char ECC521_PRIVKEY2_PEM[];
extern const size_t ECC521_PRIVKEY2_PEM_LEN;

extern const uint8_t ECC521_PRIVKEY2_DER[];
extern const size_t ECC521_PRIVKEY2_DER_LEN;

extern const uint8_t ECC521_PRIVKEY2_DER_NO_LEADING_ZERO[];
extern const size_t ECC521_PRIVKEY2_DER_NO_LEADING_ZERO_LEN;

extern const uint8_t ECC521_PRIVKEY2_NO_PUBKEY_DER[];
extern const size_t ECC521_PRIVKEY2_NO_PUBKEY_DER_LEN;

extern const uint8_t ECC521_PRIVKEY3[];
extern const uint8_t ECC521_PRIVKEY3_LE[];
extern const size_t ECC521_PRIVKEY3_LEN;

extern const uint8_t ECC521_PUBKEY3[];
extern const uint8_t ECC521_PUBKEY3_LE[];
extern const size_t ECC521_PUBKEY3_LEN;

extern const uint8_t ECC521_PUBKEY3_SHA1[];
extern const uint8_t ECC521_PUBKEY3_SHA256[];
extern const uint8_t ECC521_PUBKEY3_SHA384[];
extern const uint8_t ECC521_PUBKEY3_SHA512[];

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
extern const struct ecc_point_public_key ECC521_PUBKEY3_POINT;
#endif

extern const char ECC521_PUBKEY3_PEM[];
extern const size_t ECC384_PUBKEY3_PEM_LEN;

extern const uint8_t ECC521_PUBKEY3_DER[];
extern const size_t ECC521_PUBKEY3_DER_LEN;

extern const char ECC521_PRIVKEY3_PEM[];
extern const size_t ECC521_PRIVKEY3_PEM_LEN;

extern const uint8_t ECC521_PRIVKEY3_DER[];
extern const size_t ECC521_PRIVKEY3_DER_LEN;

extern const uint8_t ECC521_PRIVKEY3_DER_NO_LEADING_ZERO[];
extern const size_t ECC521_PRIVKEY3_DER_NO_LEADING_ZERO_LEN;

extern const uint8_t ECC521_PRIVKEY3_NO_PUBKEY_DER[];
extern const size_t ECC521_PRIVKEY3_NO_PUBKEY_DER_LEN;


#endif	/* ECC_TESTING_H_ */
