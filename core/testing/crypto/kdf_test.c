// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "crypto/kdf.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/mock/crypto/hash_mock.h"


TEST_SUITE_LABEL ("kdf");


/**
 * Input key for NIST800-108 counter mode KDF.
 */
const uint8_t KDF_TESTING_NIST800_108_CTR_KI[] = {
	0xf1, 0x3b, 0x43, 0x16, 0x2c, 0xe4, 0x02, 0x34, 0xd6, 0x41, 0x80, 0xfa, 0x1a, 0x0e, 0x0a, 0x04,
	0x0e, 0x9a, 0x37, 0xff, 0x3e, 0xa0, 0x05, 0x75, 0x73, 0xc5, 0x54, 0x10, 0xad, 0xd5, 0xc5, 0xc6
};

const size_t KDF_TESTING_NIST800_108_CTR_KI_LEN = sizeof (KDF_TESTING_NIST800_108_CTR_KI);

/**
 * Input Label for NIST800-108 counter mode KDF.
 */
const uint8_t KDF_TESTING_NIST800_108_CTR_LABEL[] = {
	0x0e, 0x9a, 0x37, 0xff, 0x3e, 0xa0, 0x02, 0x75, 0x73, 0xc5, 0x54, 0x10, 0xad, 0xd5, 0xc5, 0xc6,
	0xf1, 0x3b, 0x43, 0x16, 0x2c, 0xe4, 0x05, 0x34, 0xd6, 0x41, 0x80, 0xfa, 0x1a, 0x0e, 0x0a, 0x04
};

const size_t KDF_TESTING_NIST800_108_CTR_LABEL_LEN = sizeof (KDF_TESTING_NIST800_108_CTR_LABEL);

/**
 * Input Context for NIST800-108 counter mode KDF.
 */
const uint8_t KDF_TESTING_NIST800_CTR_CONTEXT[] = {
	0xf1, 0x3b, 0x43, 0x16, 0x2c, 0x0e, 0x9a, 0x37, 0xe4, 0x05, 0x75, 0x73, 0xc5, 0x54, 0x10, 0xad,
	0xff, 0x3e, 0xa0, 0x02, 0x34, 0xd6, 0x41, 0x80, 0xfa, 0x1a, 0x0e, 0x0a, 0x04, 0xd5, 0xc5, 0xc6
};

const size_t KDF_TESTING_NIST800_CTR_CONTEXT_LEN = sizeof (KDF_TESTING_NIST800_CTR_CONTEXT);

/**
 * Expected key output for NIST800-108 counter mode KDF using SHA-1 HMAC.  The output key is the
 * same size as the HMAC output.
 */
const uint8_t KDF_TESTING_NIST800_108_CTR_KO_SHA1[] = {
	0x06, 0x3b, 0x74, 0x13, 0x1d, 0xf3, 0xf9, 0xb2, 0xf7, 0x25, 0x4e, 0xab, 0xae, 0xd3, 0xc4, 0x9b,
	0x20, 0xf5, 0x22, 0x61
};

const size_t KDF_TESTING_NIST800_108_CTR_KO_SHA1_LEN = sizeof (KDF_TESTING_NIST800_108_CTR_KO_SHA1);

/**
 * Expected key output for NIST800-108 counter mode KDF using SHA-256 HMAC.  The output key is the
 * same size as the HMAC output.
 */
const uint8_t KDF_TESTING_NIST800_108_CTR_KO_SHA256[] = {
	0xe6, 0x48, 0xd4, 0xc7, 0x0d, 0xc1, 0x59, 0x75, 0xa1, 0x4b, 0x0a, 0x91, 0x75, 0xd9, 0x17, 0x10,
	0x21, 0x75, 0xbc, 0x9a, 0x92, 0x6f, 0x6d, 0x24, 0x93, 0xda, 0xf3, 0x98, 0x11, 0xc3, 0x97, 0xf8
};

const size_t KDF_TESTING_NIST800_108_CTR_KO_SHA256_LEN =
	sizeof (KDF_TESTING_NIST800_108_CTR_KO_SHA256);

/**
 * Expected key output for NIST800-108 counter mode KDF using SHA-256 HMAC.  The output key is twice
 * as large as the HMAC output.
 */
const uint8_t KDF_TESTING_NIST800_108_CTR_KO_SHA256_TWICE[] = {
	0x42, 0xa1, 0xd9, 0x7c, 0x1b, 0xb4, 0x83, 0x78, 0xc1, 0xa9, 0xb9, 0xb0, 0xc6, 0x13, 0xfc, 0x5d,
	0xa4, 0xab, 0x5c, 0x9e, 0x69, 0xe2, 0xc8, 0xfd, 0x72, 0xa3, 0x32, 0x8f, 0xb9, 0x20, 0xf9, 0x0a,
	0x76, 0x4d, 0xa3, 0xb8, 0x4c, 0xa1, 0x77, 0x03, 0xad, 0xbc, 0xa0, 0x57, 0x05, 0xb0, 0xb1, 0x61,
	0x9f, 0x7b, 0x97, 0xc7, 0x33, 0xd6, 0xfa, 0xe1, 0xf1, 0x8a, 0xc5, 0xdc, 0x64, 0x79, 0xdc, 0x5a
};

const size_t KDF_TESTING_NIST800_108_CTR_KO_SHA256_TWICE_LEN =
	sizeof (KDF_TESTING_NIST800_108_CTR_KO_SHA256_TWICE);

/**
 * Expected key output for NIST800-108 counter mode KDF using SHA-256 HMAC.  The output key is three
 * times as large as the HMAC output.
 */
const uint8_t KDF_TESTING_NIST800_108_CTR_KO_SHA256_THRICE[] = {
	0x63, 0x8e, 0x99, 0x88, 0x0c, 0xe0, 0x2f, 0x4c, 0xde, 0xc2, 0xb5, 0xac, 0x39, 0x81, 0x17, 0xc7,
	0x0c, 0x97, 0x9c, 0x97, 0xee, 0x69, 0xe5, 0xda, 0x00, 0x5e, 0x6c, 0x2c, 0x02, 0x26, 0x79, 0x3a,
	0xc8, 0x99, 0x1c, 0x1a, 0x2f, 0xa7, 0x5e, 0x8c, 0x08, 0x2f, 0xf5, 0x88, 0x7e, 0xc3, 0xea, 0xea,
	0x39, 0x8c, 0xd0, 0xa0, 0x83, 0xcc, 0xf4, 0x59, 0x0a, 0x72, 0xb3, 0x34, 0xf6, 0x69, 0x3c, 0x90,
	0x6b, 0x3e, 0x31, 0x5f, 0x68, 0x22, 0x3b, 0x9e, 0x59, 0x3a, 0xee, 0xb6, 0x82, 0x5f, 0xb4, 0x6d,
	0x2e, 0x3d, 0x3d, 0x99, 0x84, 0x86, 0xcc, 0xee, 0x93, 0x35, 0x97, 0x4a, 0x0a, 0x1a, 0x65, 0x20
};

const size_t KDF_TESTING_NIST800_108_CTR_KO_SHA256_THRICE_LEN =
	sizeof (KDF_TESTING_NIST800_108_CTR_KO_SHA256_THRICE);

/**
 * Expected key output for NIST800-108 counter mode KDF using SHA-256 HMAC.  The output key requires
 * multiple rounds but is not an exact multiple of the HMAC output.
 */
static const uint8_t KDF_TESTING_NIST800_108_CTR_KO_SHA256_NOT_EVEN_MULTIPLE[] = {
	0x0d, 0xec, 0xbe, 0xd2, 0x23, 0x8f, 0x09, 0x54, 0xb9, 0x2c, 0xe6, 0xff, 0x44, 0x48, 0xd9, 0x08,
	0xa4, 0x52, 0x96, 0x19, 0x30, 0x63, 0x80, 0x15, 0x0d, 0x5a, 0xfe, 0x42, 0xd4, 0x93, 0xee, 0xe9,
	0x27, 0x4a, 0x75, 0xae, 0x2b, 0x07, 0x88, 0x28, 0x9a, 0x91, 0xb1, 0xbc, 0x05, 0x0e, 0x18, 0xd4,
	0x5b, 0x00
};

const size_t KDF_TESTING_NIST800_108_CTR_KO_SHA256_NOT_EVEN_MULTIPLE_LEN =
	sizeof (KDF_TESTING_NIST800_108_CTR_KO_SHA256_NOT_EVEN_MULTIPLE);

/**
 * Expected key output for NIST800-108 counter mode KDF using SHA-384 HMAC.  The output key is less
 * than the HMAC output and does not take an context input.
 */
const uint8_t KDF_TESTING_NIST800_108_CTR_KO_SHA384_NO_CONTEXT[] = {
	0x1c, 0x83, 0x6c, 0xac, 0x2b, 0xa9, 0xe5, 0x8e, 0xc2, 0xf8, 0x6f, 0xaa, 0x7b, 0x62, 0xac, 0xf8,
	0xf9, 0x13, 0x14, 0x43
};

const size_t KDF_TESTING_NIST800_108_CTR_KO_SHA384_NO_CONTEXT_LEN =
	sizeof (KDF_TESTING_NIST800_108_CTR_KO_SHA384_NO_CONTEXT);


/**
 * Additional KDF input for HKDF-Expand.
 */
const uint8_t KDF_TESTING_HKDF_EXPAND_INFO[] = {
	0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9
};

const size_t KDF_TESTING_HKDF_EXPAND_INFO_LEN = sizeof (KDF_TESTING_HKDF_EXPAND_INFO);

/**
 * Long additional KDF input for HKDF-Expand
 */
const uint8_t KDF_TESTING_HKDF_EXPAND_INFO_LONG[] = {
	0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
	0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
	0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
	0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
	0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

const size_t KDF_TESTING_HKDF_EXPAND_INFO_LONG_LEN = sizeof (KDF_TESTING_HKDF_EXPAND_INFO_LONG);

/**
 * Psuedorandom KDF input key for HKDF-Expand using SHA-256 HMAC.
 */
const uint8_t KDF_TESTING_HKDF_EXPAND_SHA256_PRK[] = {
	0x19, 0xef, 0x24, 0xa3, 0x2c, 0x71, 0x7b, 0x16, 0x7f, 0x33, 0xa9, 0x1d, 0x6f, 0x64, 0x8b, 0xdf,
	0x96, 0x59, 0x67, 0x76, 0xaf, 0xdb, 0x63, 0x77, 0xac, 0x43, 0x4c, 0x1c, 0x29, 0x3c, 0xcb, 0x04
};

const size_t KDF_TESTING_HKDF_EXPAND_SHA256_PRK_LEN = sizeof (KDF_TESTING_HKDF_EXPAND_SHA256_PRK);

/**
 * Expected output for HKDF-Expand using SHA-256 HMAC.  The output key is the same sized as the HMAC
 * output.
 */
const uint8_t KDF_TESTING_HKDF_EXPAND_SHA256_OKM[] = {
	0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f, 0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c, 0x5a, 0x31,
	0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e, 0xc3, 0x45, 0x4e, 0x5f, 0x3c, 0x73, 0x8d, 0x2d
};

const size_t KDF_TESTING_HKDF_EXPAND_SHA256_OKM_LEN = sizeof (KDF_TESTING_HKDF_EXPAND_SHA256_OKM);

/**
 * Psuedorandom KDF input key for HKDF-Expand using SHA-256 HMAC to generate a key a different size
 * from the HMAC output.
 */
uint8_t KDF_TESTING_HKDF_EXPAND_SHA256_PRK_DIFFERENT_OUTPUT[] = {
	0x06, 0xa6, 0xb8, 0x8c, 0x58, 0x53, 0x36, 0x1a, 0x06, 0x10, 0x4c, 0x9c, 0xeb, 0x35, 0xb4, 0x5c,
	0xef, 0x76, 0x00, 0x14, 0x90, 0x46, 0x71, 0x01, 0x4a, 0x19, 0x3f, 0x40, 0xc1, 0x5f, 0xc2, 0x44
};

const size_t KDF_TESTING_HKDF_EXPAND_SHA256_PRK_DIFFERENT_OUTPUT_LEN =
	sizeof (KDF_TESTING_HKDF_EXPAND_SHA256_PRK_DIFFERENT_OUTPUT);

/**
 * Expected output for HKDF-Expand using SHA-256 HMAC.  The output key is longer than the HMAC
 * output.
 */
uint8_t KDF_TESTING_HKDF_EXPAND_SHA256_OKM_LONGER_OUTPUT[] = {
	0xbc, 0xc6, 0x71, 0x47, 0xe9, 0x1c, 0x9a, 0x6e, 0xe4, 0x1f, 0x85, 0xd2, 0x72, 0x4c, 0x90, 0x94,
	0x76, 0x6d, 0xa1, 0x28, 0x0b, 0xfe, 0x71, 0x1a, 0x0a, 0x64, 0x68, 0xc3, 0x62, 0x83, 0xb6, 0xcb,
	0x3a, 0x13, 0x3f, 0x7e, 0xc5, 0xdc, 0xd3, 0x3b, 0x3d, 0x6c, 0x43, 0x42, 0xba, 0xdd, 0x36, 0x46,
	0x1d, 0x3a, 0x1a, 0xdb, 0x92, 0x38, 0x28, 0x57, 0xd9, 0x09, 0x89, 0x67, 0x8c, 0x46, 0x8b, 0x3f,
	0x16, 0xca, 0xbe, 0x2d, 0xe8, 0xbf, 0xb7, 0x33, 0xa5, 0xc9, 0x95, 0xb0, 0x5b, 0xbc, 0x40, 0x56,
	0x81, 0xa5
};

const size_t KDF_TESTING_HKDF_EXPAND_SHA256_OKM_LONGER_OUTPUT_LEN =
	sizeof (KDF_TESTING_HKDF_EXPAND_SHA256_OKM_LONGER_OUTPUT);

/**
 * Expected output for HKDF-Expand using SHA-256 HMAC.  The output key is shorter than the HMAC
 * output.
 */
uint8_t KDF_TESTING_HKDF_EXPAND_SHA256_OKM_SHORTER_OUTPUT[] = {
	0xbc, 0xc6, 0x71, 0x47, 0xe9, 0x1c, 0x9a, 0x6e, 0xe4, 0x1f, 0x85, 0xd2, 0x72, 0x4c, 0x90, 0x94,
	0x76, 0x6d, 0xa1, 0x28, 0x0b, 0xfe, 0x71, 0x1a, 0x0a, 0x64, 0x68, 0xc3, 0x62, 0x83
};

const size_t KDF_TESTING_HKDF_EXPAND_SHA256_OKM_SHORTER_OUTPUT_LEN =
	sizeof (KDF_TESTING_HKDF_EXPAND_SHA256_OKM_SHORTER_OUTPUT);

/**
 * Psuedorandom KDF input key for HKDF-Expand using SHA-256 HMAC.  The KDF using additional info
 * context in the calculation.
 */
uint8_t KDF_TESTING_HKDF_EXPAND_SHA256_PRK_WITH_INFO[] = {
	0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
	0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5
};

const size_t KDF_TESTING_HKDF_EXPAND_SHA256_PRK_WITH_INFO_LEN =
	sizeof (KDF_TESTING_HKDF_EXPAND_SHA256_PRK_WITH_INFO);

/**
 * Expected output for HKDF-Expand using SHA-256 HMAC with additional info context.  The output key
 * is the same sized as the HMAC output.
 */
const uint8_t KDF_TESTING_HKDF_EXPAND_SHA256_OKM_WITH_INFO[] = {
	0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
	0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf
};

const size_t KDF_TESTING_HKDF_EXPAND_SHA256_OKM_WITH_INFO_LEN =
	sizeof (KDF_TESTING_HKDF_EXPAND_SHA256_OKM_WITH_INFO);

/**
 * Expected output for HKDF-Expand using SHA-256 HMAC with the long input info context.  The output
 * key is longer than the HMAC output.
 */
const uint8_t KDF_TESTING_HKDF_EXPAND_SHA256_OKM_WITH_INFO_LONGER_OUTPUT[] = {
	0xdb, 0xe9, 0x79, 0x18, 0x44, 0xda, 0x73, 0xe6, 0x62, 0x31, 0x49, 0x6f, 0xbb, 0x2e, 0x71, 0xf5,
	0x53, 0x01, 0x7d, 0x0d, 0xdc, 0x0a, 0xda, 0xde, 0xf8, 0x0e, 0x97, 0x1b, 0xaf, 0x44, 0xd6, 0xb0,
	0xec, 0x4f, 0x26, 0xd7, 0x90, 0xee, 0xc9, 0x1b, 0xbe, 0xef, 0x53, 0x45, 0xa7, 0xce, 0x45, 0x75,
	0x6e, 0xa9, 0xc8, 0xa9, 0x4d, 0xb2, 0xe8, 0xf5, 0x43, 0x25, 0x6c, 0x52, 0x87, 0x74, 0x24, 0x79,
	0x50, 0xba, 0xba, 0xed, 0x45, 0xc5, 0x64, 0x26, 0xc1, 0xea, 0x30, 0xfa, 0x72, 0x78, 0x35, 0xb5,
	0xef, 0x03
};

const size_t KDF_TESTING_HKDF_EXPAND_SHA256_OKM_WITH_INFO_LONGER_OUTPUT_LEN =
	sizeof (KDF_TESTING_HKDF_EXPAND_SHA256_OKM_WITH_INFO_LONGER_OUTPUT);

/**
 * Expected output for HKDF-Expand using SHA-256 HMAC with the long input info context.  The output
 * key is shorter than the HMAC output.
 */
const uint8_t KDF_TESTING_HKDF_EXPAND_SHA256_OKM_WITH_INFO_SHORTER_OUTPUT[] = {
	0xdb, 0xe9, 0x79, 0x18, 0x44, 0xda, 0x73, 0xe6, 0x62, 0x31, 0x49, 0x6f, 0xbb, 0x2e, 0x71, 0xf5,
	0x53, 0x01, 0x7d, 0x0d, 0xdc, 0x0a, 0xda, 0xde, 0xf8, 0x0e, 0x97, 0x1b, 0xaf, 0x44
};

const size_t KDF_TESTING_HKDF_EXPAND_SHA256_OKM_WITH_INFO_SHORTER_OUTPUT_LEN =
	sizeof (KDF_TESTING_HKDF_EXPAND_SHA256_OKM_WITH_INFO_SHORTER_OUTPUT);

/**
 * Psuedorandom KDF input key for HKDF-Expand using SHA-384 HMAC.
 */
const uint8_t KDF_TESTING_HKDF_EXPAND_SHA384_PRK[] = {
	0xb5, 0x7d, 0xc5, 0x23, 0x54, 0xaf, 0xee, 0x11, 0xed, 0xb4, 0xc9, 0x05, 0x2a, 0x52, 0x83, 0x44,
	0x34, 0x8b, 0x2c, 0x6b, 0x6c, 0x39, 0xf3, 0x21, 0x33, 0xed, 0x3b, 0xb7, 0x20, 0x35, 0xa4, 0xab,
	0x55, 0xd6, 0x64, 0x8c, 0x15, 0x29, 0xef, 0x7a, 0x91, 0x70, 0xfe, 0xc9, 0xef, 0x26, 0xa8, 0x1e
};

const size_t KDF_TESTING_HKDF_EXPAND_SHA384_PRK_LEN = sizeof (KDF_TESTING_HKDF_EXPAND_SHA384_PRK);

/**
 * Expected output for HKDF-Expand using SHA-384 HMAC.  The output key is the same sized as the HMAC
 * output.
 */
const uint8_t KDF_TESTING_HKDF_EXPAND_SHA384_OKM[] = {
	0xf2, 0x28, 0xb8, 0x14, 0x80, 0xa2, 0xd1, 0xfd, 0x24, 0xfd, 0x6f, 0x0b, 0x87, 0xbb, 0x3b, 0x39,
	0xa9, 0x24, 0x19, 0xd8, 0x88, 0x78, 0x86, 0x60, 0x08, 0x9a, 0xa2, 0xce, 0x28, 0xd3, 0xb7, 0xef,
	0x04, 0xbc, 0x67, 0x4a, 0x49, 0x7b, 0x92, 0xe9, 0x7c, 0x9b, 0x0a, 0xec, 0xf8, 0x32, 0x1f, 0x24
};

const size_t KDF_TESTING_HKDF_EXPAND_SHA384_OKM_LEN = sizeof (KDF_TESTING_HKDF_EXPAND_SHA384_OKM);

/**
 * Expected output for HKDF-Expand using SHA-384 HMAC.  The output key is the longer than the HMAC
 * output.
 */
const uint8_t KDF_TESTING_HKDF_EXPAND_SHA384_OKM_LONGER_OUTPUT[] = {
	0xf2, 0x28, 0xb8, 0x14, 0x80, 0xa2, 0xd1, 0xfd, 0x24, 0xfd, 0x6f, 0x0b, 0x87, 0xbb, 0x3b, 0x39,
	0xa9, 0x24, 0x19, 0xd8, 0x88, 0x78, 0x86, 0x60, 0x08, 0x9a, 0xa2, 0xce, 0x28, 0xd3, 0xb7, 0xef,
	0x04, 0xbc, 0x67, 0x4a, 0x49, 0x7b, 0x92, 0xe9, 0x7c, 0x9b, 0x0a, 0xec, 0xf8, 0x32, 0x1f, 0x24,
	0x98, 0x89, 0xc9, 0x39, 0x67, 0xd9, 0x08, 0xda, 0x42, 0x0d, 0xd3, 0x21, 0x86, 0x83, 0xa0, 0x04,
	0xed, 0xa2, 0xbb, 0x6a, 0xcf, 0x48, 0xf4, 0xdb, 0x14, 0xfb, 0x15, 0xc9, 0xd0, 0x56, 0x2f, 0x77,
	0x96, 0x9e
};

const size_t KDF_TESTING_HKDF_EXPAND_SHA384_OKM_LONGER_OUTPUT_LEN =
	sizeof (KDF_TESTING_HKDF_EXPAND_SHA384_OKM_LONGER_OUTPUT);

/**
 * Expected output for HKDF-Expand using SHA-384 HMAC.  The output key is the shorter than the HMAC
 * output.
 */
const uint8_t KDF_TESTING_HKDF_EXPAND_SHA384_OKM_SHORTER_OUTPUT[] = {
	0xf2, 0x28, 0xb8, 0x14, 0x80, 0xa2, 0xd1, 0xfd, 0x24, 0xfd, 0x6f, 0x0b, 0x87, 0xbb, 0x3b, 0x39,
	0xa9, 0x24, 0x19, 0xd8, 0x88, 0x78, 0x86, 0x60, 0x08, 0x9a, 0xa2, 0xce, 0x28, 0xd3, 0xb7, 0xef,
	0x04, 0xbc, 0x67, 0x4a, 0x49, 0x7b, 0x92, 0xe9, 0x7c, 0x9b
};

const size_t KDF_TESTING_HKDF_EXPAND_SHA384_OKM_SHORTER_OUTPUT_LEN =
	sizeof (KDF_TESTING_HKDF_EXPAND_SHA384_OKM_SHORTER_OUTPUT);

/**
 * Expected output for HKDF-Expand using SHA-384 HMAC with additional info context.  The output key
 * is the same sized as the HMAC output.
 */
const uint8_t KDF_TESTING_HKDF_EXPAND_SHA384_OKM_WITH_INFO[] = {
	0xd5, 0x2a, 0x9c, 0x23, 0xd8, 0x53, 0x27, 0x76, 0x6b, 0x5a, 0x22, 0x1e, 0x15, 0x88, 0x1d, 0x71,
	0xf9, 0x06, 0x56, 0x54, 0x6a, 0x07, 0x38, 0x8f, 0x6d, 0x6d, 0x4b, 0xba, 0x96, 0x29, 0xd3, 0x7e,
	0x5d, 0x0d, 0x64, 0xe6, 0xb5, 0x27, 0x8e, 0xdf, 0x89, 0x3a, 0xe4, 0x3a, 0x63, 0x60, 0x63, 0x23
};

const size_t KDF_TESTING_HKDF_EXPAND_SHA384_OKM_WITH_INFO_LEN =
	sizeof (KDF_TESTING_HKDF_EXPAND_SHA384_OKM_WITH_INFO);

/**
 * Expected output for HKDF-Expand using SHA-384 HMAC with additional info context.  The output key
 * is longer than the HMAC output.
 */
const uint8_t KDF_TESTING_HKDF_EXPAND_SHA384_OKM_WITH_INFO_LONGER_OUTPUT[] = {
	0xd5, 0x2a, 0x9c, 0x23, 0xd8, 0x53, 0x27, 0x76, 0x6b, 0x5a, 0x22, 0x1e, 0x15, 0x88, 0x1d, 0x71,
	0xf9, 0x06, 0x56, 0x54, 0x6a, 0x07, 0x38, 0x8f, 0x6d, 0x6d, 0x4b, 0xba, 0x96, 0x29, 0xd3, 0x7e,
	0x5d, 0x0d, 0x64, 0xe6, 0xb5, 0x27, 0x8e, 0xdf, 0x89, 0x3a, 0xe4, 0x3a, 0x63, 0x60, 0x63, 0x23,
	0x6b, 0x7d, 0x90, 0x5d, 0x1b, 0xfc, 0x1a, 0x4d, 0x97, 0x7b, 0x7e, 0x45, 0xce, 0x98, 0xe6, 0x4e,
	0xfe, 0x6d, 0xa8, 0x8f, 0x62, 0xe8, 0xfb, 0x4a, 0x8a, 0xd2, 0x19, 0x10, 0xba, 0x57, 0xfe, 0x63,
	0x26, 0x1d
};

const size_t KDF_TESTING_HKDF_EXPAND_SHA384_OKM_WITH_INFO_LONGER_OUTPUT_LEN =
	sizeof (KDF_TESTING_HKDF_EXPAND_SHA384_OKM_WITH_INFO_LONGER_OUTPUT);

/**
 * Expected output for HKDF-Expand using SHA-384 HMAC with additional info context.  The output key
 * is shorter than the HMAC output.
 */
const uint8_t KDF_TESTING_HKDF_EXPAND_SHA384_OKM_WITH_INFO_SHORTER_OUTPUT[] = {
	0xd5, 0x2a, 0x9c, 0x23, 0xd8, 0x53, 0x27, 0x76, 0x6b, 0x5a, 0x22, 0x1e, 0x15, 0x88, 0x1d, 0x71,
	0xf9, 0x06, 0x56, 0x54, 0x6a, 0x07, 0x38, 0x8f, 0x6d, 0x6d, 0x4b, 0xba, 0x96, 0x29, 0xd3, 0x7e,
	0x5d, 0x0d, 0x64, 0xe6, 0xb5, 0x27, 0x8e, 0xdf, 0x89, 0x3a
};

const size_t KDF_TESTING_HKDF_EXPAND_SHA384_OKM_WITH_INFO_SHORTER_OUTPUT_LEN =
	sizeof (KDF_TESTING_HKDF_EXPAND_SHA384_OKM_WITH_INFO_SHORTER_OUTPUT);


/**
 * Set up expectations for running a NIST800-108 counter mode KDF with a mock hash engine.
 *
 * @param hash The hash mock being used.
 * @param hash_algo The hash algorithm to use for the KDF.
 * @param ki The input HMAC key for the KDF.
 * @param ki_length Length of the input key.
 * @param round The KDF round being executed.
 * @param label The KDF Label value.
 * @param label_length Length of the KDF Label.
 * @param context The KDF Context value.  Null if no Context is expected.
 * @param context_length Length of the KDF Context.
 * @param bytes_out The number of bytes being requested for the KDF.
 * @param result Output to provide from at the end of the KDF round.
 * @param result_length Length of the KDF output.
 *
 * @return 0 if the expectations were set up successfully or non-zero on error.
 */
int kdf_testing_expect_nist800_108_counter_mode (struct hash_engine_mock *hash,
	enum hash_type hash_algo, const uint8_t *ki, size_t ki_length, uint32_t round,
	const uint8_t *label, size_t label_length, const uint8_t *context, size_t context_length,
	uint32_t bytes_out, const uint8_t *result, size_t result_length)
{
	uint8_t separator = 0;
	int status;

	round = platform_htonl (round);
	bytes_out = platform_htonl (bytes_out * 8);

	status = hash_mock_expect_hmac_init (hash, ki, ki_length, hash_algo);

	status |= mock_expect (&hash->mock, hash->base.update, hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&round, sizeof (round)), MOCK_ARG (sizeof (round)));

	status |= mock_expect (&hash->mock, hash->base.update, hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (label, label_length), MOCK_ARG (label_length));

	status |= mock_expect (&hash->mock, hash->base.update, hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));

	if (context != NULL) {
		status |= mock_expect (&hash->mock, hash->base.update, hash, 0,
			MOCK_ARG_PTR_CONTAINS_TMP (context, context_length), MOCK_ARG (context_length));
	}

	status |= mock_expect (&hash->mock, hash->base.update, hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&bytes_out, sizeof (bytes_out)), MOCK_ARG (sizeof (bytes_out)));

	status |= hash_mock_expect_hmac_finish (hash, ki, ki_length, NULL, result_length, hash_algo,
		result, result_length);

	return status;
}

/**
 * Set up expectations for running an HKDF-Expand KDF with a mock hash engine.
 *
 * @param hash The hash mock being used.
 * @param hash_algo The hash algorithm to use for the KDF.
 * @param prk The input HMAC key for the KDF.
 * @param prk_length Length of the input key.
 * @param t HMAC input from the previous round.
 * @param t_length Length of the previous round data.
 * @param info The KDF info value.
 * @param info_length Length of the KDF info.
 * @param round The KDF round being executed.
 * @param result Output to provide from at the end of the KDF round.
 * @param result_length Length of the KDF output.
 *
 * @return 0 if the expectations were set up successfully or non-zero on error.
 */
int kdf_testing_expect_hkdf_expand (struct hash_engine_mock *hash, enum hash_type hash_algo,
	const uint8_t *prk, size_t prk_length, const uint8_t *t, size_t t_length, const uint8_t *info,
	size_t info_length, uint8_t round, const uint8_t *result, size_t result_length)
{
	int status;

	status = hash_mock_expect_hmac_init (hash, prk, prk_length, hash_algo);

	if (t != NULL) {
		status |= mock_expect (&hash->mock, hash->base.update, hash, 0,
			MOCK_ARG_PTR_CONTAINS_TMP (t, t_length), MOCK_ARG (t_length));
	}

	if (info != NULL) {
		status |= mock_expect (&hash->mock, hash->base.update, hash, 0,
			MOCK_ARG_PTR_CONTAINS_TMP (info, info_length), MOCK_ARG (info_length));
	}

	status |= mock_expect (&hash->mock, hash->base.update, hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (&round, sizeof (round)), MOCK_ARG (sizeof (round)));

	status |= hash_mock_expect_hmac_finish (hash, prk, prk_length, NULL, 0, hash_algo, result,
		result_length);

	return status;
}


/*******************
 * Test cases
 *******************/

static void kdf_test_nist800_108_counter_mode_sha1 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	uint8_t ko[sizeof (KDF_TESTING_NIST800_108_CTR_KO_SHA1)] = {0};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_nist800_108_counter_mode (&hash.base, HMAC_SHA1, KDF_TESTING_NIST800_108_CTR_KI,
		KDF_TESTING_NIST800_108_CTR_KI_LEN, KDF_TESTING_NIST800_108_CTR_LABEL,
		KDF_TESTING_NIST800_108_CTR_LABEL_LEN, KDF_TESTING_NIST800_CTR_CONTEXT,
		KDF_TESTING_NIST800_CTR_CONTEXT_LEN, ko, sizeof (ko));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (KDF_TESTING_NIST800_108_CTR_KO_SHA1, ko, sizeof (ko));
#ifdef HASH_ENABLE_SHA1
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, HASH_ENGINE_UNSUPPORTED_HASH, status);
#endif

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void kdf_test_nist800_108_counter_mode_sha256 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	uint8_t ko[sizeof (KDF_TESTING_NIST800_108_CTR_KO_SHA256)];
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_nist800_108_counter_mode (&hash.base, HMAC_SHA256, KDF_TESTING_NIST800_108_CTR_KI,
		KDF_TESTING_NIST800_108_CTR_KI_LEN, KDF_TESTING_NIST800_108_CTR_LABEL,
		KDF_TESTING_NIST800_108_CTR_LABEL_LEN, KDF_TESTING_NIST800_CTR_CONTEXT,
		KDF_TESTING_NIST800_CTR_CONTEXT_LEN, ko, sizeof (ko));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (KDF_TESTING_NIST800_108_CTR_KO_SHA256, ko, sizeof (ko));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void kdf_test_nist800_108_counter_mode_sha256_two_rounds (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	uint8_t ko[sizeof (KDF_TESTING_NIST800_108_CTR_KO_SHA256_TWICE)] = {0};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_nist800_108_counter_mode (&hash.base, HMAC_SHA256, KDF_TESTING_NIST800_108_CTR_KI,
		KDF_TESTING_NIST800_108_CTR_KI_LEN, KDF_TESTING_NIST800_108_CTR_LABEL,
		KDF_TESTING_NIST800_108_CTR_LABEL_LEN, KDF_TESTING_NIST800_CTR_CONTEXT,
		KDF_TESTING_NIST800_CTR_CONTEXT_LEN, ko, sizeof (ko));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (KDF_TESTING_NIST800_108_CTR_KO_SHA256_TWICE, ko, sizeof (ko));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void kdf_test_nist800_108_counter_mode_sha256_three_rounds (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	uint8_t ko[sizeof (KDF_TESTING_NIST800_108_CTR_KO_SHA256_THRICE)] = {0};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_nist800_108_counter_mode (&hash.base, HMAC_SHA256, KDF_TESTING_NIST800_108_CTR_KI,
		KDF_TESTING_NIST800_108_CTR_KI_LEN, KDF_TESTING_NIST800_108_CTR_LABEL,
		KDF_TESTING_NIST800_108_CTR_LABEL_LEN, KDF_TESTING_NIST800_CTR_CONTEXT,
		KDF_TESTING_NIST800_CTR_CONTEXT_LEN, ko, sizeof (ko));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (KDF_TESTING_NIST800_108_CTR_KO_SHA256_THRICE, ko, sizeof (ko));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void kdf_test_nist800_108_counter_mode_sha256_key_larger_than_hash_not_exact_multiple (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	uint8_t ko[sizeof (KDF_TESTING_NIST800_108_CTR_KO_SHA256_NOT_EVEN_MULTIPLE)] = {0};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_nist800_108_counter_mode (&hash.base, HMAC_SHA256, KDF_TESTING_NIST800_108_CTR_KI,
		KDF_TESTING_NIST800_108_CTR_KI_LEN, KDF_TESTING_NIST800_108_CTR_LABEL,
		KDF_TESTING_NIST800_108_CTR_LABEL_LEN, KDF_TESTING_NIST800_CTR_CONTEXT,
		KDF_TESTING_NIST800_CTR_CONTEXT_LEN, ko, sizeof (ko));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (KDF_TESTING_NIST800_108_CTR_KO_SHA256_NOT_EVEN_MULTIPLE, ko,
		sizeof (ko));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void kdf_test_nist800_108_counter_mode_sha384_no_context (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	uint8_t ko[sizeof (KDF_TESTING_NIST800_108_CTR_KO_SHA384_NO_CONTEXT)] = {0};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_nist800_108_counter_mode (&hash.base, HMAC_SHA384, KDF_TESTING_NIST800_108_CTR_KI,
		KDF_TESTING_NIST800_108_CTR_KI_LEN, KDF_TESTING_NIST800_108_CTR_LABEL,
		KDF_TESTING_NIST800_108_CTR_LABEL_LEN, NULL, 0, ko, sizeof (ko));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (KDF_TESTING_NIST800_108_CTR_KO_SHA384_NO_CONTEXT, ko,
		sizeof (ko));
#ifdef HASH_ENABLE_SHA384
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, HASH_ENGINE_UNSUPPORTED_HASH, status);
#endif

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void kdf_test_nist800_108_counter_mode_null (CuTest *test)
{
	struct hash_engine_mock hash;
	uint8_t ko[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_nist800_108_counter_mode (NULL, HMAC_SHA256, KDF_TESTING_NIST800_108_CTR_KI,
		KDF_TESTING_NIST800_108_CTR_KI_LEN, KDF_TESTING_NIST800_108_CTR_LABEL,
		KDF_TESTING_NIST800_108_CTR_LABEL_LEN, KDF_TESTING_NIST800_CTR_CONTEXT,
		KDF_TESTING_NIST800_CTR_CONTEXT_LEN, ko, sizeof (ko));
	CuAssertIntEquals (test, KDF_INVALID_ARGUMENT, status);

	status = kdf_nist800_108_counter_mode (&hash.base, HMAC_SHA256, NULL,
		KDF_TESTING_NIST800_108_CTR_KI_LEN, KDF_TESTING_NIST800_108_CTR_LABEL,
		KDF_TESTING_NIST800_108_CTR_LABEL_LEN, KDF_TESTING_NIST800_CTR_CONTEXT,
		KDF_TESTING_NIST800_CTR_CONTEXT_LEN, ko, sizeof (ko));
	CuAssertIntEquals (test, KDF_INVALID_ARGUMENT, status);

	status = kdf_nist800_108_counter_mode (&hash.base, HMAC_SHA256, KDF_TESTING_NIST800_108_CTR_KI,
		KDF_TESTING_NIST800_108_CTR_KI_LEN, NULL, KDF_TESTING_NIST800_108_CTR_LABEL_LEN,
		KDF_TESTING_NIST800_CTR_CONTEXT, KDF_TESTING_NIST800_CTR_CONTEXT_LEN, ko, sizeof (ko));
	CuAssertIntEquals (test, KDF_INVALID_ARGUMENT, status);

	status = kdf_nist800_108_counter_mode (&hash.base, HMAC_SHA256, KDF_TESTING_NIST800_108_CTR_KI,
		KDF_TESTING_NIST800_108_CTR_KI_LEN, KDF_TESTING_NIST800_108_CTR_LABEL,
		KDF_TESTING_NIST800_108_CTR_LABEL_LEN, KDF_TESTING_NIST800_CTR_CONTEXT,
		KDF_TESTING_NIST800_CTR_CONTEXT_LEN, NULL, sizeof (ko));
	CuAssertIntEquals (test, KDF_INVALID_ARGUMENT, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_nist800_108_counter_mode_unknown_hmac (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	uint8_t ko[sizeof (KDF_TESTING_NIST800_108_CTR_KO_SHA1)] = {0};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_nist800_108_counter_mode (&hash.base, HMAC_INVALID, KDF_TESTING_NIST800_108_CTR_KI,
		KDF_TESTING_NIST800_108_CTR_KI_LEN, KDF_TESTING_NIST800_108_CTR_LABEL,
		KDF_TESTING_NIST800_108_CTR_LABEL_LEN, KDF_TESTING_NIST800_CTR_CONTEXT,
		KDF_TESTING_NIST800_CTR_CONTEXT_LEN, ko, sizeof (ko));
	CuAssertIntEquals (test, HASH_ENGINE_UNKNOWN_HASH, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void kdf_test_nist800_108_counter_mode_init_hmac_fail (CuTest *test)
{
	struct hash_engine_mock hash;
	uint8_t ko[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, HASH_ENGINE_NO_MEMORY);
	CuAssertIntEquals (test, 0, status);

	status = kdf_nist800_108_counter_mode (&hash.base, HMAC_SHA256, KDF_TESTING_NIST800_108_CTR_KI,
		KDF_TESTING_NIST800_108_CTR_KI_LEN, KDF_TESTING_NIST800_108_CTR_LABEL,
		KDF_TESTING_NIST800_108_CTR_LABEL_LEN, KDF_TESTING_NIST800_CTR_CONTEXT,
		KDF_TESTING_NIST800_CTR_CONTEXT_LEN, ko, sizeof (ko));
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_nist800_108_counter_mode_update_index_hmac_fail (CuTest *test)
{
	struct hash_engine_mock hash;
	uint8_t ko[SHA256_HASH_LENGTH];
	uint32_t i_1 = platform_htonl (1);
	int status;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&hash, KDF_TESTING_NIST800_108_CTR_KI,
		KDF_TESTING_NIST800_108_CTR_KI_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_NO_MEMORY,
		MOCK_ARG_PTR_CONTAINS (&i_1, sizeof (i_1)), MOCK_ARG (sizeof (i_1)));
	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = kdf_nist800_108_counter_mode (&hash.base, HMAC_SHA256, KDF_TESTING_NIST800_108_CTR_KI,
		KDF_TESTING_NIST800_108_CTR_KI_LEN, KDF_TESTING_NIST800_108_CTR_LABEL,
		KDF_TESTING_NIST800_108_CTR_LABEL_LEN, KDF_TESTING_NIST800_CTR_CONTEXT,
		KDF_TESTING_NIST800_CTR_CONTEXT_LEN, ko, sizeof (ko));
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_nist800_108_counter_mode_update_label_hmac_fail (CuTest *test)
{
	struct hash_engine_mock hash;
	uint8_t ko[SHA256_HASH_LENGTH];
	uint32_t i_1 = platform_htonl (1);
	int status;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&hash, KDF_TESTING_NIST800_108_CTR_KI,
		KDF_TESTING_NIST800_108_CTR_KI_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&i_1, sizeof (i_1)), MOCK_ARG (sizeof (i_1)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_NO_MEMORY,
		MOCK_ARG_PTR_CONTAINS (KDF_TESTING_NIST800_108_CTR_LABEL,
		KDF_TESTING_NIST800_108_CTR_LABEL_LEN),	MOCK_ARG (KDF_TESTING_NIST800_108_CTR_LABEL_LEN));
	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = kdf_nist800_108_counter_mode (&hash.base, HMAC_SHA256, KDF_TESTING_NIST800_108_CTR_KI,
		KDF_TESTING_NIST800_108_CTR_KI_LEN, KDF_TESTING_NIST800_108_CTR_LABEL,
		KDF_TESTING_NIST800_108_CTR_LABEL_LEN, KDF_TESTING_NIST800_CTR_CONTEXT,
		KDF_TESTING_NIST800_CTR_CONTEXT_LEN, ko, sizeof (ko));
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_nist800_108_counter_mode_update_separator_hmac_fail (CuTest *test)
{
	struct hash_engine_mock hash;
	uint8_t ko[SHA256_HASH_LENGTH];
	uint8_t separator = 0;
	uint32_t i_1 = platform_htonl (1);
	int status;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&hash, KDF_TESTING_NIST800_108_CTR_KI,
		KDF_TESTING_NIST800_108_CTR_KI_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&i_1, sizeof (i_1)), MOCK_ARG (sizeof (i_1)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (KDF_TESTING_NIST800_108_CTR_LABEL,
		KDF_TESTING_NIST800_108_CTR_LABEL_LEN),	MOCK_ARG (KDF_TESTING_NIST800_108_CTR_LABEL_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_NO_MEMORY,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = kdf_nist800_108_counter_mode (&hash.base, HMAC_SHA256, KDF_TESTING_NIST800_108_CTR_KI,
		KDF_TESTING_NIST800_108_CTR_KI_LEN, KDF_TESTING_NIST800_108_CTR_LABEL,
		KDF_TESTING_NIST800_108_CTR_LABEL_LEN, KDF_TESTING_NIST800_CTR_CONTEXT,
		KDF_TESTING_NIST800_CTR_CONTEXT_LEN, ko, sizeof (ko));
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_nist800_108_counter_mode_update_context_hmac_fail (CuTest *test)
{
	struct hash_engine_mock hash;
	uint8_t ko[SHA256_HASH_LENGTH];
	uint8_t separator = 0;
	uint32_t i_1 = platform_htonl (1);
	int status;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&hash, KDF_TESTING_NIST800_108_CTR_KI,
		KDF_TESTING_NIST800_108_CTR_KI_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&i_1, sizeof (i_1)), MOCK_ARG (sizeof (i_1)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (KDF_TESTING_NIST800_108_CTR_LABEL,
		KDF_TESTING_NIST800_108_CTR_LABEL_LEN),	MOCK_ARG (KDF_TESTING_NIST800_108_CTR_LABEL_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_NO_MEMORY,
		MOCK_ARG_PTR_CONTAINS (KDF_TESTING_NIST800_CTR_CONTEXT,
		KDF_TESTING_NIST800_CTR_CONTEXT_LEN), MOCK_ARG (KDF_TESTING_NIST800_CTR_CONTEXT_LEN));
	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = kdf_nist800_108_counter_mode (&hash.base, HMAC_SHA256, KDF_TESTING_NIST800_108_CTR_KI,
		KDF_TESTING_NIST800_108_CTR_KI_LEN, KDF_TESTING_NIST800_108_CTR_LABEL,
		KDF_TESTING_NIST800_108_CTR_LABEL_LEN, KDF_TESTING_NIST800_CTR_CONTEXT,
		KDF_TESTING_NIST800_CTR_CONTEXT_LEN, ko, sizeof (ko));
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_nist800_108_counter_mode_update_ko_len_hmac_fail (CuTest *test)
{
	struct hash_engine_mock hash;
	uint8_t ko[SHA256_HASH_LENGTH];
	uint8_t separator = 0;
	uint32_t L = platform_htonl (SHA256_HASH_LENGTH * 8);
	uint32_t i_1 = platform_htonl (1);
	int status;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&hash, KDF_TESTING_NIST800_108_CTR_KI,
		KDF_TESTING_NIST800_108_CTR_KI_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&i_1, sizeof (i_1)), MOCK_ARG (sizeof (i_1)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (KDF_TESTING_NIST800_108_CTR_LABEL,
		KDF_TESTING_NIST800_108_CTR_LABEL_LEN),	MOCK_ARG (KDF_TESTING_NIST800_108_CTR_LABEL_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (KDF_TESTING_NIST800_CTR_CONTEXT,
		KDF_TESTING_NIST800_CTR_CONTEXT_LEN), MOCK_ARG (KDF_TESTING_NIST800_CTR_CONTEXT_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_NO_MEMORY,
		MOCK_ARG_PTR_CONTAINS (&L, sizeof (L)), MOCK_ARG (sizeof (L)));
	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = kdf_nist800_108_counter_mode (&hash.base, HMAC_SHA256, KDF_TESTING_NIST800_108_CTR_KI,
		KDF_TESTING_NIST800_108_CTR_KI_LEN, KDF_TESTING_NIST800_108_CTR_LABEL,
		KDF_TESTING_NIST800_108_CTR_LABEL_LEN, KDF_TESTING_NIST800_CTR_CONTEXT,
		KDF_TESTING_NIST800_CTR_CONTEXT_LEN, ko, sizeof (ko));
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_nist800_108_counter_mode_finish_hmac_fail (CuTest *test)
{
	struct hash_engine_mock hash;
	uint8_t ko[SHA256_HASH_LENGTH];
	uint8_t separator = 0;
	uint32_t L = platform_htonl (SHA256_HASH_LENGTH * 8);
	uint32_t i_1 = platform_htonl (1);
	int status;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&hash, KDF_TESTING_NIST800_108_CTR_KI,
		KDF_TESTING_NIST800_108_CTR_KI_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&i_1, sizeof (i_1)), MOCK_ARG (sizeof (i_1)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (KDF_TESTING_NIST800_108_CTR_LABEL,
		KDF_TESTING_NIST800_108_CTR_LABEL_LEN),	MOCK_ARG (KDF_TESTING_NIST800_108_CTR_LABEL_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (KDF_TESTING_NIST800_CTR_CONTEXT,
		KDF_TESTING_NIST800_CTR_CONTEXT_LEN), MOCK_ARG (KDF_TESTING_NIST800_CTR_CONTEXT_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&L, sizeof (L)), MOCK_ARG (sizeof (L)));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, HASH_ENGINE_NO_MEMORY,
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = kdf_nist800_108_counter_mode (&hash.base, HMAC_SHA256, KDF_TESTING_NIST800_108_CTR_KI,
		KDF_TESTING_NIST800_108_CTR_KI_LEN, KDF_TESTING_NIST800_108_CTR_LABEL,
		KDF_TESTING_NIST800_108_CTR_LABEL_LEN, KDF_TESTING_NIST800_CTR_CONTEXT,
		KDF_TESTING_NIST800_CTR_CONTEXT_LEN, ko, sizeof (ko));
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_hkdf_expand_sha256 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	uint8_t okm[sizeof (KDF_TESTING_HKDF_EXPAND_SHA256_OKM)] = {0};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_hkdf_expand (&hash.base, HMAC_SHA256, KDF_TESTING_HKDF_EXPAND_SHA256_PRK,
		KDF_TESTING_HKDF_EXPAND_SHA256_PRK_LEN, NULL, 0, okm, sizeof (okm));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (KDF_TESTING_HKDF_EXPAND_SHA256_OKM, okm, sizeof (okm));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void kdf_test_hkdf_expand_sha256_longer_output (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	uint8_t okm[sizeof (KDF_TESTING_HKDF_EXPAND_SHA256_OKM_LONGER_OUTPUT)] = {0};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_hkdf_expand (&hash.base, HMAC_SHA256,
		KDF_TESTING_HKDF_EXPAND_SHA256_PRK_DIFFERENT_OUTPUT,
		KDF_TESTING_HKDF_EXPAND_SHA256_PRK_DIFFERENT_OUTPUT_LEN, NULL, 0, okm, sizeof (okm));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (KDF_TESTING_HKDF_EXPAND_SHA256_OKM_LONGER_OUTPUT, okm,
		sizeof (okm));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void kdf_test_hkdf_expand_sha256_shorter_output (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	uint8_t okm[sizeof (KDF_TESTING_HKDF_EXPAND_SHA256_OKM_SHORTER_OUTPUT)] = {0};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_hkdf_expand (&hash.base, HMAC_SHA256,
		KDF_TESTING_HKDF_EXPAND_SHA256_PRK_DIFFERENT_OUTPUT,
		KDF_TESTING_HKDF_EXPAND_SHA256_PRK_DIFFERENT_OUTPUT_LEN, NULL, 0, okm, sizeof (okm));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (KDF_TESTING_HKDF_EXPAND_SHA256_OKM_SHORTER_OUTPUT, okm,
		sizeof (okm));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void kdf_test_hkdf_expand_sha256_with_info (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	uint8_t okm[sizeof (KDF_TESTING_HKDF_EXPAND_SHA256_OKM_WITH_INFO)] = {0};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_hkdf_expand (&hash.base, HMAC_SHA256, KDF_TESTING_HKDF_EXPAND_SHA256_PRK_WITH_INFO,
		KDF_TESTING_HKDF_EXPAND_SHA256_PRK_WITH_INFO_LEN, KDF_TESTING_HKDF_EXPAND_INFO,
		KDF_TESTING_HKDF_EXPAND_INFO_LEN, okm, sizeof (okm));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (KDF_TESTING_HKDF_EXPAND_SHA256_OKM_WITH_INFO, okm,
		sizeof (okm));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void kdf_test_hkdf_expand_sha256_with_info_longer_output (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	uint8_t okm[sizeof (KDF_TESTING_HKDF_EXPAND_SHA256_OKM_WITH_INFO_LONGER_OUTPUT)] = {0};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_hkdf_expand (&hash.base, HMAC_SHA256, KDF_TESTING_HKDF_EXPAND_SHA256_PRK_WITH_INFO,
		KDF_TESTING_HKDF_EXPAND_SHA256_PRK_WITH_INFO_LEN, KDF_TESTING_HKDF_EXPAND_INFO_LONG,
		KDF_TESTING_HKDF_EXPAND_INFO_LONG_LEN, okm, sizeof (okm));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (KDF_TESTING_HKDF_EXPAND_SHA256_OKM_WITH_INFO_LONGER_OUTPUT,
		okm, sizeof (okm));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void kdf_test_hkdf_expand_sha256_with_info_shorter_output (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	uint8_t okm[sizeof (KDF_TESTING_HKDF_EXPAND_SHA256_OKM_WITH_INFO_SHORTER_OUTPUT)] = {0};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_hkdf_expand (&hash.base, HMAC_SHA256, KDF_TESTING_HKDF_EXPAND_SHA256_PRK_WITH_INFO,
		KDF_TESTING_HKDF_EXPAND_SHA256_PRK_WITH_INFO_LEN, KDF_TESTING_HKDF_EXPAND_INFO_LONG,
		KDF_TESTING_HKDF_EXPAND_INFO_LONG_LEN, okm, sizeof (okm));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (KDF_TESTING_HKDF_EXPAND_SHA256_OKM_WITH_INFO_SHORTER_OUTPUT,
		okm, sizeof (okm));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void kdf_test_hkdf_expand_sha384 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	uint8_t okm[sizeof (KDF_TESTING_HKDF_EXPAND_SHA384_OKM)] = {0};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_hkdf_expand (&hash.base, HMAC_SHA384, KDF_TESTING_HKDF_EXPAND_SHA384_PRK,
		KDF_TESTING_HKDF_EXPAND_SHA384_PRK_LEN, NULL, 0, okm, sizeof (okm));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (KDF_TESTING_HKDF_EXPAND_SHA384_OKM, okm, sizeof (okm));
#ifdef HASH_ENABLE_SHA384
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, HASH_ENGINE_UNSUPPORTED_HASH, status);
#endif

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

#ifdef HASH_ENABLE_SHA384
static void kdf_test_hkdf_expand_sha384_longer_output (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	uint8_t okm[sizeof (KDF_TESTING_HKDF_EXPAND_SHA384_OKM_LONGER_OUTPUT)] = {0};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_hkdf_expand (&hash.base, HMAC_SHA384, KDF_TESTING_HKDF_EXPAND_SHA384_PRK,
		KDF_TESTING_HKDF_EXPAND_SHA384_PRK_LEN, NULL, 0, okm, sizeof (okm));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (KDF_TESTING_HKDF_EXPAND_SHA384_OKM_LONGER_OUTPUT, okm,
		sizeof (okm));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void kdf_test_hkdf_expand_sha384_shorter_output (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	uint8_t okm[sizeof (KDF_TESTING_HKDF_EXPAND_SHA384_OKM_SHORTER_OUTPUT)] = {0};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_hkdf_expand (&hash.base, HMAC_SHA384, KDF_TESTING_HKDF_EXPAND_SHA384_PRK,
		KDF_TESTING_HKDF_EXPAND_SHA384_PRK_LEN, NULL, 0, okm, sizeof (okm));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (KDF_TESTING_HKDF_EXPAND_SHA384_OKM_SHORTER_OUTPUT, okm,
		sizeof (okm));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void kdf_test_hkdf_expand_sha384_with_info (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	uint8_t okm[sizeof (KDF_TESTING_HKDF_EXPAND_SHA384_OKM_WITH_INFO)] = {0};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_hkdf_expand (&hash.base, HMAC_SHA384, KDF_TESTING_HKDF_EXPAND_SHA384_PRK,
		KDF_TESTING_HKDF_EXPAND_SHA384_PRK_LEN, KDF_TESTING_HKDF_EXPAND_INFO,
		KDF_TESTING_HKDF_EXPAND_INFO_LEN, okm, sizeof (okm));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (KDF_TESTING_HKDF_EXPAND_SHA384_OKM_WITH_INFO, okm,
		sizeof (okm));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void kdf_test_hkdf_expand_sha384_with_info_longer_output (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	uint8_t okm[sizeof (KDF_TESTING_HKDF_EXPAND_SHA384_OKM_WITH_INFO_LONGER_OUTPUT)] = {0};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_hkdf_expand (&hash.base, HMAC_SHA384, KDF_TESTING_HKDF_EXPAND_SHA384_PRK,
		KDF_TESTING_HKDF_EXPAND_SHA384_PRK_LEN, KDF_TESTING_HKDF_EXPAND_INFO,
		KDF_TESTING_HKDF_EXPAND_INFO_LEN, okm, sizeof (okm));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (KDF_TESTING_HKDF_EXPAND_SHA384_OKM_WITH_INFO_LONGER_OUTPUT,
		okm, sizeof (okm));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void kdf_test_hkdf_expand_sha384_with_info_shorter_output (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	uint8_t okm[sizeof (KDF_TESTING_HKDF_EXPAND_SHA384_OKM_WITH_INFO_SHORTER_OUTPUT)] = {0};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_hkdf_expand (&hash.base, HMAC_SHA384, KDF_TESTING_HKDF_EXPAND_SHA384_PRK,
		KDF_TESTING_HKDF_EXPAND_SHA384_PRK_LEN, KDF_TESTING_HKDF_EXPAND_INFO,
		KDF_TESTING_HKDF_EXPAND_INFO_LEN, okm, sizeof (okm));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (KDF_TESTING_HKDF_EXPAND_SHA384_OKM_WITH_INFO_SHORTER_OUTPUT,
		okm, sizeof (okm));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}
#endif

static void kdf_test_hkdf_expand_null (CuTest *test)
{
	struct hash_engine_mock hash;
	uint8_t okm[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_hkdf_expand (NULL, HMAC_SHA256, KDF_TESTING_HKDF_EXPAND_SHA256_PRK,
		KDF_TESTING_HKDF_EXPAND_SHA256_PRK_LEN, NULL, 0, okm, sizeof (okm));
	CuAssertIntEquals (test, KDF_INVALID_ARGUMENT, status);

	status = kdf_hkdf_expand (&hash.base, HMAC_SHA256, NULL, KDF_TESTING_HKDF_EXPAND_SHA256_PRK_LEN,
		NULL, 0, okm, sizeof (okm));
	CuAssertIntEquals (test, KDF_INVALID_ARGUMENT, status);

	status = kdf_hkdf_expand (&hash.base, HMAC_SHA256, KDF_TESTING_HKDF_EXPAND_SHA256_PRK,
		KDF_TESTING_HKDF_EXPAND_SHA256_PRK_LEN, NULL, 0, NULL, sizeof (okm));
	CuAssertIntEquals (test, KDF_INVALID_ARGUMENT, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_hkdf_expand_unknown_hmac (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	uint8_t okm[SHA256_HASH_LENGTH] = {0};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_hkdf_expand (&hash.base, HMAC_INVALID, KDF_TESTING_HKDF_EXPAND_SHA256_PRK,
		KDF_TESTING_HKDF_EXPAND_SHA256_PRK_LEN, NULL, 0, okm, sizeof (okm));
	CuAssertIntEquals (test, HASH_ENGINE_UNKNOWN_HASH, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void kdf_test_hkdf_expand_prk_too_short (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	uint8_t okm[SHA256_HASH_LENGTH] = {0};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_hkdf_expand (&hash.base, HMAC_SHA256, KDF_TESTING_HKDF_EXPAND_SHA256_PRK,
		SHA256_HASH_LENGTH - 1, NULL, 0, okm, sizeof (okm));
	CuAssertIntEquals (test, KDF_INPUT_KEY_TOO_SHORT, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void kdf_test_hkdf_expand_okm_too_long (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	uint8_t okm[SHA256_HASH_LENGTH] = {0};
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_hkdf_expand (&hash.base, HMAC_SHA256, KDF_TESTING_HKDF_EXPAND_SHA256_PRK,
		KDF_TESTING_HKDF_EXPAND_SHA256_PRK_LEN, NULL, 0, okm, (SHA256_HASH_LENGTH * 255) + 1);
	CuAssertIntEquals (test, KDF_OUTPUT_KEY_TOO_LONG, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void kdf_test_hkdf_expand_init_hmac_fail (CuTest *test)
{
	struct hash_engine_mock hash;
	uint8_t okm[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash,
		HASH_ENGINE_START_SHA256_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = kdf_hkdf_expand (&hash.base, HMAC_SHA256, KDF_TESTING_HKDF_EXPAND_SHA256_PRK,
		KDF_TESTING_HKDF_EXPAND_SHA256_PRK_LEN, NULL, 0, okm, sizeof (okm));
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_hkdf_expand_update_info_hmac_fail (CuTest *test)
{
	struct hash_engine_mock hash;
	uint8_t okm[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&hash, KDF_TESTING_HKDF_EXPAND_SHA256_PRK,
		KDF_TESTING_HKDF_EXPAND_SHA256_PRK_LEN, HASH_TYPE_SHA256);

	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (KDF_TESTING_HKDF_EXPAND_INFO, KDF_TESTING_HKDF_EXPAND_INFO_LEN),
		MOCK_ARG (KDF_TESTING_HKDF_EXPAND_INFO_LEN));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = kdf_hkdf_expand (&hash.base, HMAC_SHA256, KDF_TESTING_HKDF_EXPAND_SHA256_PRK,
		KDF_TESTING_HKDF_EXPAND_SHA256_PRK_LEN, KDF_TESTING_HKDF_EXPAND_INFO,
		KDF_TESTING_HKDF_EXPAND_INFO_LEN, okm, sizeof (okm));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_hkdf_expand_update_constant_hmac_fail (CuTest *test)
{
	struct hash_engine_mock hash;
	uint8_t okm[SHA256_HASH_LENGTH];
	int status;
	uint8_t c = 1;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&hash, KDF_TESTING_HKDF_EXPAND_SHA256_PRK,
		KDF_TESTING_HKDF_EXPAND_SHA256_PRK_LEN, HASH_TYPE_SHA256);

	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (&c, sizeof (c)), MOCK_ARG (sizeof (c)));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = kdf_hkdf_expand (&hash.base, HMAC_SHA256, KDF_TESTING_HKDF_EXPAND_SHA256_PRK,
		KDF_TESTING_HKDF_EXPAND_SHA256_PRK_LEN, NULL, 0, okm, sizeof (okm));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_hkdf_expand_update_finish_hmac_fail (CuTest *test)
{
	struct hash_engine_mock hash;
	uint8_t okm[SHA256_HASH_LENGTH];
	int status;
	uint8_t c = 1;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&hash, KDF_TESTING_HKDF_EXPAND_SHA256_PRK,
		KDF_TESTING_HKDF_EXPAND_SHA256_PRK_LEN, HASH_TYPE_SHA256);

	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&c, sizeof (c)), MOCK_ARG (sizeof (c)));

	status |= mock_expect (&hash.mock, hash.base.finish, &hash, HASH_ENGINE_FINISH_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (HASH_MAX_HASH_LEN));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = kdf_hkdf_expand (&hash.base, HMAC_SHA256, KDF_TESTING_HKDF_EXPAND_SHA256_PRK,
		KDF_TESTING_HKDF_EXPAND_SHA256_PRK_LEN, NULL, 0, okm, sizeof (okm));
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void kdf_test_hkdf_expand_update_t_hmac_fail (CuTest *test)
{
	struct hash_engine_mock hash;
	uint8_t okm[SHA256_HASH_LENGTH * 2];
	int status;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = kdf_testing_expect_hkdf_expand (&hash, HASH_TYPE_SHA256,
		KDF_TESTING_HKDF_EXPAND_SHA256_PRK, KDF_TESTING_HKDF_EXPAND_SHA256_PRK_LEN, NULL, 0, NULL,
		0, 1, KDF_TESTING_HKDF_EXPAND_SHA256_OKM_LONGER_OUTPUT, SHA256_HASH_LENGTH);

	status |= hash_mock_expect_hmac_init (&hash, KDF_TESTING_HKDF_EXPAND_SHA256_PRK,
		KDF_TESTING_HKDF_EXPAND_SHA256_PRK_LEN, HASH_TYPE_SHA256);

	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (KDF_TESTING_HKDF_EXPAND_SHA256_OKM_LONGER_OUTPUT,
		SHA256_HASH_LENGTH), MOCK_ARG (SHA256_HASH_LENGTH));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = kdf_hkdf_expand (&hash.base, HMAC_SHA256, KDF_TESTING_HKDF_EXPAND_SHA256_PRK,
		KDF_TESTING_HKDF_EXPAND_SHA256_PRK_LEN, NULL, 0, okm, sizeof (okm));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}


// *INDENT-OFF*
TEST_SUITE_START (kdf);

TEST (kdf_test_nist800_108_counter_mode_sha1);
TEST (kdf_test_nist800_108_counter_mode_sha256);
TEST (kdf_test_nist800_108_counter_mode_sha256_two_rounds);
TEST (kdf_test_nist800_108_counter_mode_sha256_three_rounds);
TEST (kdf_test_nist800_108_counter_mode_sha256_key_larger_than_hash_not_exact_multiple);
TEST (kdf_test_nist800_108_counter_mode_sha384_no_context);
TEST (kdf_test_nist800_108_counter_mode_null);
TEST (kdf_test_nist800_108_counter_mode_unknown_hmac);
TEST (kdf_test_nist800_108_counter_mode_init_hmac_fail);
TEST (kdf_test_nist800_108_counter_mode_update_index_hmac_fail);
TEST (kdf_test_nist800_108_counter_mode_update_label_hmac_fail);
TEST (kdf_test_nist800_108_counter_mode_update_separator_hmac_fail);
TEST (kdf_test_nist800_108_counter_mode_update_context_hmac_fail);
TEST (kdf_test_nist800_108_counter_mode_update_ko_len_hmac_fail);
TEST (kdf_test_nist800_108_counter_mode_finish_hmac_fail);
TEST (kdf_test_hkdf_expand_sha256);
TEST (kdf_test_hkdf_expand_sha256_longer_output);
TEST (kdf_test_hkdf_expand_sha256_shorter_output);
TEST (kdf_test_hkdf_expand_sha256_with_info);
TEST (kdf_test_hkdf_expand_sha256_with_info_longer_output);
TEST (kdf_test_hkdf_expand_sha256_with_info_shorter_output);
TEST (kdf_test_hkdf_expand_sha384);
#ifdef HASH_ENABLE_SHA384
TEST (kdf_test_hkdf_expand_sha384_longer_output);
TEST (kdf_test_hkdf_expand_sha384_shorter_output);
TEST (kdf_test_hkdf_expand_sha384_with_info);
TEST (kdf_test_hkdf_expand_sha384_with_info_longer_output);
TEST (kdf_test_hkdf_expand_sha384_with_info_shorter_output);
#endif
TEST (kdf_test_hkdf_expand_null);
TEST (kdf_test_hkdf_expand_unknown_hmac);
TEST (kdf_test_hkdf_expand_prk_too_short);
TEST (kdf_test_hkdf_expand_okm_too_long);
TEST (kdf_test_hkdf_expand_init_hmac_fail);
TEST (kdf_test_hkdf_expand_update_info_hmac_fail);
TEST (kdf_test_hkdf_expand_update_constant_hmac_fail);
TEST (kdf_test_hkdf_expand_update_finish_hmac_fail);
TEST (kdf_test_hkdf_expand_update_t_hmac_fail);

TEST_SUITE_END;
// *INDENT-ON*
