// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "asn1/ecc_der_util.h"
#include "crypto/aes_key_wrap_with_padding.h"
#include "crypto/aes_key_wrap_with_padding_static.h"
#include "testing/engines/aes_testing_engine.h"
#include "testing/mock/crypto/aes_ecb_mock.h"


TEST_SUITE_LABEL ("aes_key_wrap_with_padding");


/**
 * Test key for AES-256 wrapping 4096-bit data from NIST test vectors.
 */
const uint8_t AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_KEY[] = {
	0x20, 0xf3, 0x1c, 0xde, 0xd6, 0x0b, 0x8e, 0xd8, 0xd9, 0xd3, 0xfd, 0x1e, 0x1f, 0xa6, 0x24, 0x4e,
	0x76, 0xc7, 0xcb, 0x76, 0x28, 0xbf, 0xd2, 0x8a, 0x5d, 0x63, 0xce, 0x8a, 0xa2, 0xc9, 0x49, 0x4d
};

const size_t AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_KEY_LEN =
	sizeof (AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_KEY);

/**
 * 4096-bit test data for AES-256 wrapping from NIST test vectors.
 */
const uint8_t AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_DATA[] = {
	0xf0, 0x72, 0x25, 0x20, 0x28, 0x42, 0xc8, 0xde, 0xde, 0x42, 0x21, 0x53, 0x01, 0xe4, 0x4b, 0x9b,
	0xb7, 0xe6, 0x25, 0xd3, 0x81, 0x2f, 0x74, 0xf9, 0xb6, 0xdd, 0xbc, 0xd0, 0x24, 0xeb, 0xd1, 0xf3,
	0x3e, 0x2c, 0xbf, 0x28, 0x0b, 0x90, 0x04, 0x94, 0x1f, 0x3c, 0xbf, 0x86, 0xc8, 0x80, 0xa2, 0x35,
	0x7f, 0x88, 0xf9, 0x2a, 0x6d, 0xcf, 0x8d, 0xad, 0x9d, 0xa7, 0xdd, 0xdc, 0xd0, 0x0f, 0x36, 0x35,
	0xef, 0xdf, 0xf0, 0xaf, 0x43, 0x82, 0x02, 0x4e, 0x93, 0xc2, 0xaf, 0x66, 0xb9, 0x91, 0xe5, 0x65,
	0xea, 0xcc, 0xa6, 0xb8, 0x86, 0xf0, 0x71, 0x78, 0xc9, 0xb4, 0xad, 0xad, 0x6f, 0x0d, 0x6a, 0xda,
	0x5f, 0xf6, 0xaa, 0x7c, 0xd0, 0x71, 0x25, 0x19, 0xa9, 0x47, 0xa8, 0x08, 0x9c, 0xea, 0x5e, 0x1e,
	0x3e, 0x40, 0xff, 0xe1, 0x80, 0x60, 0x10, 0xb0, 0x14, 0x9f, 0x9f, 0xfc, 0x7c, 0x4d, 0xd3, 0xc3,
	0x1b, 0x3d, 0x08, 0xd5, 0xae, 0x19, 0x97, 0xc5, 0x23, 0x69, 0x39, 0x3d, 0x58, 0x61, 0x1d, 0xff,
	0x9b, 0xec, 0x50, 0x1c, 0x1a, 0xb3, 0x5e, 0x6e, 0xd3, 0xe7, 0xf9, 0x44, 0x5a, 0x34, 0xe2, 0x11,
	0x01, 0x0a, 0x82, 0x36, 0x68, 0x6f, 0x15, 0x4e, 0x0a, 0x5a, 0xe3, 0x43, 0x3d, 0x6a, 0x84, 0x4e,
	0xb3, 0x88, 0x49, 0x61, 0xaa, 0x65, 0x92, 0x21, 0x6d, 0x93, 0x95, 0x2b, 0x46, 0xbb, 0x58, 0xa4,
	0x19, 0x5a, 0xa8, 0x09, 0x66, 0xad, 0x0c, 0xcd, 0x4a, 0x7e, 0x23, 0x82, 0x39, 0x12, 0x55, 0x6a,
	0x90, 0xd5, 0xee, 0x9c, 0x3b, 0xb9, 0x52, 0xec, 0xbb, 0x9d, 0x89, 0x5d, 0xab, 0xd3, 0xb1, 0x1a,
	0xb4, 0xf2, 0xe3, 0xa6, 0xc2, 0x58, 0x2d, 0xe5, 0x04, 0x03, 0x28, 0x92, 0x30, 0xef, 0x4d, 0xc4,
	0x6e, 0x7c, 0x0d, 0x87, 0x0a, 0x3f, 0x0c, 0xba, 0x9d, 0x64, 0x3a, 0x03, 0x49, 0x50, 0x3c, 0x1b,
	0x16, 0x2d, 0xdb, 0x63, 0x50, 0xe6, 0x99, 0x58, 0x9e, 0xb4, 0x7b, 0xd5, 0x63, 0x99, 0x9f, 0x55,
	0xa1, 0xad, 0xb6, 0xb7, 0x8b, 0x52, 0xf0, 0x06, 0x90, 0x1b, 0x04, 0x27, 0xea, 0x7d, 0x33, 0x94,
	0xbb, 0x0a, 0xda, 0xe4, 0x63, 0x7b, 0x4f, 0x1a, 0xd5, 0xd5, 0x42, 0x5e, 0x2c, 0x8f, 0xf3, 0x08,
	0x35, 0x06, 0xd7, 0xad, 0x7b, 0xa4, 0xc7, 0x40, 0x5a, 0x77, 0x8b, 0x0a, 0x3a, 0x11, 0x76, 0x0c,
	0x96, 0x90, 0x0a, 0x52, 0x56, 0x95, 0x6c, 0xc9, 0x71, 0x00, 0x91, 0xd0, 0x73, 0xa1, 0x9f, 0x46,
	0xa9, 0x85, 0xd0, 0x04, 0x65, 0x1f, 0xe2, 0xb6, 0x44, 0x8e, 0xd7, 0x61, 0xbf, 0x9b, 0xc8, 0x16,
	0x19, 0xcf, 0x27, 0x3a, 0x67, 0x83, 0xd8, 0x68, 0xd0, 0x90, 0x75, 0x3b, 0xf0, 0x13, 0x18, 0xbe,
	0x21, 0xaf, 0xd8, 0x8d, 0x9f, 0x3a, 0x96, 0x1a, 0x69, 0xf9, 0x3e, 0x9d, 0x9f, 0xb8, 0x22, 0xc8,
	0x0a, 0xcc, 0x7b, 0x48, 0xcf, 0x14, 0xa0, 0x8b, 0x5b, 0x7e, 0xf1, 0x5c, 0x66, 0x97, 0x57, 0x21,
	0xb7, 0xcd, 0xe9, 0x76, 0x1a, 0x14, 0x5b, 0x67, 0x91, 0x55, 0x47, 0x2a, 0x44, 0xde, 0xa8, 0xfe,
	0xdc, 0x0f, 0x86, 0xae, 0x7e, 0xbf, 0x62, 0x83, 0xec, 0xfd, 0xe5, 0xf2, 0x44, 0x4b, 0x51, 0x56,
	0x9e, 0x67, 0x23, 0xa7, 0xa1, 0x9e, 0x28, 0xcd, 0xf8, 0xde, 0xc6, 0x79, 0x1c, 0xcc, 0x14, 0xaf,
	0x95, 0xab, 0xad, 0x01, 0x8f, 0x74, 0x15, 0x75, 0xb3, 0x43, 0xcb, 0x1a, 0x20, 0xa2, 0xa9, 0xad,
	0xf4, 0x24, 0x8f, 0x99, 0x72, 0x80, 0x69, 0xa1, 0xe2, 0xe7, 0x8a, 0xd8, 0x96, 0x6c, 0x41, 0xc9,
	0x91, 0x8f, 0xb7, 0x01, 0x9e, 0xf5, 0x6c, 0x15, 0x3a, 0x18, 0x3a, 0x62, 0x47, 0xd2, 0x2d, 0x99,
	0x56, 0x56, 0x4b, 0xb0, 0x30, 0x75, 0xcb, 0xfd, 0x1b, 0x43, 0xd9, 0x68, 0x18, 0xb2, 0x84, 0x84
};

const size_t AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_DATA_LEN =
	sizeof (AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_DATA);


/**
 * Block aligned length of the 4096-bit data.
 */
#define	AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_DATA_ALIGNED_LEN  \
	AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_DATA_LEN

/**
 * Wrapped 4096-bit test data with AES-256 from NIST test vectors.
 */
const uint8_t AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_DATA_WRAPPED[] = {
	0xa5, 0xb6, 0x36, 0x18, 0xfc, 0x0c, 0x45, 0x12, 0x96, 0x0f, 0x00, 0xa1, 0xf2, 0x26, 0xd9, 0x83,
	0x7a, 0x90, 0x48, 0x0b, 0xae, 0xa7, 0x52, 0x65, 0x45, 0x3b, 0x95, 0x53, 0xb1, 0x2a, 0x58, 0xc7,
	0x21, 0x53, 0x08, 0x08, 0x42, 0xd7, 0xf8, 0x71, 0x0f, 0x31, 0x7f, 0x88, 0xfb, 0xbb, 0xf9, 0x7c,
	0xaf, 0x87, 0x9a, 0xb4, 0xbf, 0x41, 0x6b, 0xa7, 0x67, 0xee, 0x9a, 0xeb, 0x34, 0x35, 0x7f, 0x4a,
	0x2d, 0x0e, 0x8b, 0x95, 0x71, 0x05, 0x4d, 0x98, 0xe2, 0x88, 0x04, 0xa7, 0x0b, 0xc4, 0xd7, 0x48,
	0x07, 0xf2, 0xbf, 0xd9, 0x5e, 0xe9, 0x55, 0xbf, 0xdb, 0xb6, 0xf4, 0xd6, 0x96, 0x9a, 0x0c, 0x3c,
	0x3b, 0x54, 0x1a, 0x51, 0x46, 0x47, 0xd5, 0xcd, 0x8c, 0x97, 0x40, 0xac, 0x34, 0x96, 0x09, 0x5c,
	0x3f, 0x14, 0x5c, 0x50, 0xc9, 0x7e, 0xc9, 0x8b, 0x93, 0x51, 0x58, 0xfb, 0xdf, 0x89, 0x70, 0x5d,
	0x53, 0x30, 0x01, 0x5e, 0x48, 0xec, 0xe8, 0x91, 0x88, 0xb8, 0xc1, 0xbc, 0xb2, 0xad, 0x68, 0x25,
	0xd8, 0x65, 0xb3, 0x75, 0xa9, 0xb9, 0x05, 0x6b, 0x74, 0x3d, 0xac, 0x72, 0x0f, 0xee, 0xac, 0x03,
	0x3c, 0x9f, 0x75, 0x7f, 0x6f, 0xe7, 0x3d, 0xd7, 0xc4, 0xa7, 0x47, 0x66, 0x1b, 0x64, 0xcf, 0x49,
	0x0a, 0x0d, 0xd4, 0x3b, 0x54, 0x7c, 0xd7, 0x91, 0xa5, 0xd7, 0x8d, 0xac, 0x97, 0xef, 0xcd, 0x35,
	0x5f, 0x7e, 0xba, 0xc2, 0x48, 0xfa, 0x2a, 0x33, 0xe4, 0xfa, 0xd6, 0x40, 0xdc, 0x34, 0xe0, 0xd4,
	0x0b, 0x0d, 0x36, 0x58, 0x8a, 0xa3, 0x2f, 0x08, 0x64, 0xc9, 0x44, 0x67, 0x39, 0xa6, 0xb4, 0x4f,
	0xf8, 0x46, 0x66, 0xd7, 0x23, 0xbd, 0x7d, 0x64, 0x6c, 0x51, 0x72, 0xcd, 0xa9, 0x32, 0xfe, 0xc3,
	0x4d, 0xda, 0xab, 0xa3, 0x42, 0xb0, 0x2a, 0x96, 0x04, 0x08, 0x7e, 0xf0, 0x42, 0xa2, 0xbe, 0x47,
	0x74, 0x19, 0x4b, 0x5d, 0x32, 0xcb, 0x3f, 0xb1, 0x12, 0x43, 0x8f, 0xbf, 0x28, 0x01, 0x05, 0x0b,
	0x54, 0x24, 0x63, 0x5f, 0xa2, 0xd3, 0xd3, 0xfb, 0x10, 0x33, 0x29, 0x65, 0xc7, 0x3e, 0x66, 0x69,
	0xe6, 0x51, 0x95, 0x31, 0x0a, 0x3a, 0x30, 0x60, 0x26, 0x40, 0xe9, 0x80, 0x91, 0x79, 0xcd, 0xfc,
	0x50, 0xde, 0x58, 0x5a, 0xa1, 0xc0, 0x07, 0x24, 0x23, 0xc6, 0x26, 0x81, 0x5d, 0x28, 0x1a, 0x06,
	0xea, 0xc3, 0xb6, 0xff, 0xa1, 0x37, 0x71, 0x63, 0x18, 0xe2, 0x88, 0xe3, 0xf9, 0x97, 0x0e, 0x41,
	0x5e, 0xf0, 0x45, 0x1b, 0xdc, 0x55, 0x79, 0x68, 0xfe, 0xbf, 0x9e, 0xb6, 0x77, 0x2c, 0x1f, 0x77,
	0xcb, 0x8e, 0x95, 0x70, 0x12, 0x46, 0xd9, 0xc5, 0x67, 0x04, 0x81, 0x42, 0xbb, 0x25, 0xe3, 0x40,
	0x35, 0x1b, 0x87, 0xd7, 0x39, 0x18, 0x22, 0xd9, 0xee, 0x7f, 0xe5, 0x13, 0x78, 0xbc, 0x0d, 0x08,
	0x13, 0x5f, 0x9f, 0x39, 0xcf, 0x44, 0xb3, 0x48, 0xb8, 0x79, 0x37, 0x93, 0x9d, 0xc6, 0x1f, 0x43,
	0x0d, 0xfe, 0x30, 0x8c, 0xad, 0xa6, 0x32, 0x72, 0x2e, 0x23, 0xae, 0xd5, 0xa0, 0x69, 0x9e, 0x03,
	0x9c, 0xf0, 0x56, 0x3a, 0xb8, 0x02, 0x51, 0x63, 0x74, 0x4b, 0x13, 0x6a, 0x13, 0xce, 0x3c, 0x62,
	0xc7, 0x48, 0xc8, 0x9f, 0x5e, 0x17, 0x54, 0x0f, 0x10, 0x5e, 0x7c, 0x6e, 0xc9, 0xba, 0x13, 0x51,
	0x5b, 0x50, 0x43, 0x42, 0xf9, 0xe6, 0xdc, 0x7d, 0x65, 0xb9, 0xa6, 0x33, 0xd8, 0xc0, 0xb5, 0xc9,
	0xfa, 0x85, 0x8d, 0xbb, 0x9b, 0x3a, 0x59, 0x44, 0x06, 0xd4, 0x78, 0xa8, 0x1b, 0xb9, 0xab, 0xfa,
	0x28, 0x97, 0x30, 0x40, 0x8c, 0x1e, 0x30, 0x3c, 0x66, 0x3a, 0x61, 0xd5, 0xca, 0xca, 0x00, 0xf6,
	0x15, 0x06, 0x53, 0x12, 0x58, 0x00, 0x42, 0x86, 0x23, 0x97, 0xb9, 0xaa, 0x8c, 0x80, 0xca, 0x81,
	0x28, 0x87, 0x66, 0x4c, 0x43, 0x9c, 0x8c, 0x68
};

const size_t AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_DATA_WRAPPED_LEN =
	sizeof (AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_DATA_WRAPPED);

/**
 * Test key for AES-256 wrapping 248-bit data from NIST test vectors.
 */
const uint8_t AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_KEY[] = {
	0xe9, 0xbb, 0x7f, 0x44, 0xc7, 0xba, 0xaf, 0xbf, 0x39, 0x2a, 0xb9, 0x12, 0x58, 0x9a, 0x2f, 0x8d,
	0xb5, 0x32, 0x68, 0x10, 0x6e, 0xaf, 0xb7, 0x46, 0x89, 0xbb, 0x18, 0x33, 0x13, 0x6e, 0x61, 0x13
};

const size_t AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_KEY_LEN =
	sizeof (AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_KEY);

/**
 * 248-bit test data for AES-256 wrapping from NIST test vectors.
 */
const uint8_t AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA[] = {
	0xff, 0xe9, 0x52, 0x60, 0x48, 0x34, 0xbf, 0xf8, 0x99, 0xe6, 0x36, 0x58, 0xf3, 0x42, 0x46, 0x81,
	0x5c, 0x91, 0x59, 0x7e, 0xb4, 0x0a, 0x21, 0x72, 0x9e, 0x0a, 0x8a, 0x95, 0x9b, 0x61, 0xf2
};

const size_t AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA_LEN =
	sizeof (AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA);


/**
 * Block aligned length of the 248-bit data.
 */
#define	AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA_ALIGNED_LEN   \
	(AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA_LEN + 1)

/**
 * Wrapped 248-bit test data with AES-256 from NIST test vectors.
 */
const uint8_t AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA_WRAPPED[] = {
	0x15, 0xb9, 0xf0, 0x6f, 0xbc, 0x76, 0x5e, 0x5e, 0x3d, 0x55, 0xd6, 0xb8, 0x24, 0x61, 0x6f, 0x21,
	0x92, 0x1d, 0x2a, 0x69, 0x18, 0xee, 0x7b, 0xf1, 0x40, 0x6b, 0x52, 0x42, 0x74, 0xe1, 0x70, 0xb4,
	0xa7, 0x83, 0x33, 0xca, 0x5e, 0xe9, 0x2a, 0xf5
};

const size_t AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA_WRAPPED_LEN =
	sizeof (AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA_WRAPPED);

/**
 * Test key for AES-256 wrapping 72-bit data from NIST test vectors.
 */
const uint8_t AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_KEY[] = {
	0x70, 0xda, 0x43, 0xaa, 0xc8, 0x23, 0xc6, 0xdd, 0x37, 0xd1, 0x10, 0x9f, 0x5b, 0x18, 0xfe, 0xb4,
	0x50, 0x3c, 0x97, 0x32, 0x88, 0x98, 0x97, 0x45, 0xe2, 0xcc, 0x1c, 0xc2, 0x1d, 0x95, 0x70, 0xc6
};

const size_t AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_KEY_LEN =
	sizeof (AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_KEY);

/**
 * 72-bit test data for AES-256 wrapping from NIST test vectors.
 */
const uint8_t AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA[] = {
	0xed, 0xf1, 0x7d, 0x96, 0x6e, 0xd8, 0x96, 0xae, 0xe3
};

const size_t AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_LEN =
	sizeof (AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA);


/**
 * Block aligned length of the 72-bit data.
 */
#define	AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_ALIGNED_LEN    \
	(AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_LEN + 7)

/**
 * Wrapped 72-bit test data with AES-256 from NIST test vectors.
 */
const uint8_t AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_WRAPPED[] = {
	0xd6, 0x7b, 0x5b, 0x2a, 0xd1, 0x5c, 0x64, 0x54, 0x50, 0xe2, 0x3b, 0x5e, 0x7b, 0x6d, 0x68, 0x2f,
	0x8a, 0xe2, 0x0e, 0x71, 0x6d, 0x47, 0x0d, 0xb7
};

const size_t AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_WRAPPED_LEN =
	sizeof (AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_WRAPPED);

/**
 * Test key for AES-256 wrapping 64-bit data from NIST test vectors.
 */
const uint8_t AES_KEY_WRAP_WITH_PADDING_TESTING_64BIT_KEY[] = {
	0x35, 0x17, 0xf0, 0xef, 0xa7, 0xf0, 0xc4, 0xd7, 0x4f, 0x91, 0xaf, 0x83, 0xec, 0xe5, 0xe7, 0x50,
	0x3b, 0xcc, 0x5a, 0xb8, 0x29, 0x07, 0xa6, 0xe4, 0xb7, 0xed, 0x34, 0xd8, 0x7b, 0x69, 0xab, 0x1d
};

const size_t AES_KEY_WRAP_WITH_PADDING_TESTING_64BIT_KEY_LEN =
	sizeof (AES_KEY_WRAP_WITH_PADDING_TESTING_64BIT_KEY);

/**
 * 64-bit test data for AES-256 wrapping from NIST test vectors.
 */
const uint8_t AES_KEY_WRAP_WITH_PADDING_TESTING_64BIT_DATA[] = {
	0x89, 0x7e, 0x04, 0x56, 0xb2, 0x89, 0xad, 0x31
};

const size_t AES_KEY_WRAP_WITH_PADDING_TESTING_64BIT_DATA_LEN =
	sizeof (AES_KEY_WRAP_WITH_PADDING_TESTING_64BIT_DATA);


/**
 * Block aligned length of the 64-bit data.
 */
#define	AES_KEY_WRAP_WITH_PADDING_TESTING_64BIT_DATA_ALIGNED_LEN    \
	AES_KEY_WRAP_WITH_PADDING_TESTING_64BIT_DATA_LEN

/**
 * Wrapped 64-bit test data with AES-256 from NIST test vectors.
 */
const uint8_t AES_KEY_WRAP_WITH_PADDING_TESTING_64BIT_DATA_WRAPPED[] = {
	0x0b, 0x06, 0xa9, 0xb6, 0x35, 0xd5, 0x0c, 0xda, 0x9d, 0x42, 0x10, 0xcb, 0x3a, 0x71, 0xf9, 0x90
};

const size_t AES_KEY_WRAP_WITH_PADDING_TESTING_64BIT_DATA_WRAPPED_LEN =
	sizeof (AES_KEY_WRAP_WITH_PADDING_TESTING_64BIT_DATA_WRAPPED);

/**
 * Test key for AES-256 wrapping 8-bit data from NIST test vectors.
 */
const uint8_t AES_KEY_WRAP_WITH_PADDING_TESTING_8BIT_KEY[] = {
	0x95, 0xda, 0x27, 0x00, 0xca, 0x6f, 0xd9, 0xa5, 0x25, 0x54, 0xee, 0x2a, 0x8d, 0xf1, 0x38, 0x6f,
	0x5b, 0x94, 0xa1, 0xa6, 0x0e, 0xd8, 0xa4, 0xae, 0xf6, 0x0a, 0x8d, 0x61, 0xab, 0x5f, 0x22, 0x5a
};

const size_t AES_KEY_WRAP_WITH_PADDING_TESTING_8BIT_KEY_LEN =
	sizeof (AES_KEY_WRAP_WITH_PADDING_TESTING_8BIT_KEY);

/**
 * 8-bit test data for AES-256 wrapping from NIST test vectors.
 */
const uint8_t AES_KEY_WRAP_WITH_PADDING_TESTING_8BIT_DATA[] = {
	0xd1
};

const size_t AES_KEY_WRAP_WITH_PADDING_TESTING_8BIT_DATA_LEN =
	sizeof (AES_KEY_WRAP_WITH_PADDING_TESTING_8BIT_DATA);


/**
 * Block aligned length of the 8-bit data.
 */
#define	AES_KEY_WRAP_WITH_PADDING_TESTING_8BIT_DATA_ALIGNED_LEN \
	(AES_KEY_WRAP_WITH_PADDING_TESTING_8BIT_DATA_LEN + 7)

/**
 * Wrapped 8-bit test data with AES-256 from NIST test vectors.
 */
const uint8_t AES_KEY_WRAP_WITH_PADDING_TESTING_8BIT_DATA_WRAPPED[] = {
	0x06, 0xba, 0x7a, 0xe6, 0xf3, 0x24, 0x8c, 0xfd, 0xcf, 0x26, 0x75, 0x07, 0xfa, 0x00, 0x1b, 0xc4
};

const size_t AES_KEY_WRAP_WITH_PADDING_TESTING_8BIT_DATA_WRAPPED_LEN =
	sizeof (AES_KEY_WRAP_WITH_PADDING_TESTING_8BIT_DATA_WRAPPED);

/**
 * Test key for AES-256 a failed unwrapping due to invalid Message Length Indicator (MLI) or
 * padding.
 */
#define	AES_KEY_WRAP_WITH_PADDING_TESTING_FAILED_KEY	AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_KEY

#define	AES_KEY_WRAP_WITH_PADDING_TESTING_FAILED_KEY_LEN \
	AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_KEY_LEN

/**
 * Wrapped test data with AES-256 that will fail unwrapping due to non-zero padding bytes.
 */
const uint8_t AES_KEY_WRAP_WITH_PADDING_TESTING_FAILED_NON_ZERO_PADDING_DATA[] = {
	0xc4, 0x29, 0xad, 0x7b, 0x5e, 0x62, 0xf6, 0x7f, 0x1b, 0xbd, 0xf0, 0xf3, 0x6d, 0x60, 0x63, 0xd9,
	0xf2, 0x5e, 0xd9, 0x6e, 0x9b, 0xdb, 0x50, 0x79
};

const size_t AES_KEY_WRAP_WITH_PADDING_TESTING_FAILED_NON_ZERO_PADDING_DATA_LEN =
	sizeof (AES_KEY_WRAP_WITH_PADDING_TESTING_FAILED_NON_ZERO_PADDING_DATA);

/**
 * Wrapped test data with AES-256 that will fail unwrapping due to Message Length Indicator (MLI)
 * not being large enough.
 */
const uint8_t AES_KEY_WRAP_WITH_PADDING_TESTING_FAILED_SMALL_MLI_DATA[] = {
	0xc6, 0xd1, 0x7f, 0xab, 0xad, 0xca, 0x56, 0x8b, 0xb1, 0xea, 0x04, 0x1b, 0x60, 0x01, 0xd3, 0xfa,
	0xba, 0x79, 0x21, 0x8f, 0xa8, 0x6c, 0xf3, 0x96
};

const size_t AES_KEY_WRAP_WITH_PADDING_TESTING_FAILED_SMALL_MLI_DATA_LEN =
	sizeof (AES_KEY_WRAP_WITH_PADDING_TESTING_FAILED_SMALL_MLI_DATA);

/**
 * Wrapped test data with AES-256 that will fail unwrapping due to Message Length Indicator (MLI)
 * being too large.
 */
const uint8_t AES_KEY_WRAP_WITH_PADDING_TESTING_FAILED_LARGE_MLI_DATA[] = {
	0x1a, 0x58, 0xdc, 0x35, 0x92, 0x2d, 0x24, 0x66, 0x55, 0xa5, 0x09, 0xdd, 0xc6, 0x7b, 0xbe, 0x70,
	0x2e, 0x4a, 0x14, 0x26, 0xfa, 0x89, 0x6e, 0xb6, 0x0b, 0xf3, 0x7d, 0xe8, 0x80, 0x98, 0x9d, 0x17,
	0xef, 0xca, 0x9d, 0x8d, 0x04, 0xf9, 0x14, 0xf7
};

const size_t AES_KEY_WRAP_WITH_PADDING_TESTING_FAILED_LARGE_MLI_DATA_LEN =
	sizeof (AES_KEY_WRAP_WITH_PADDING_TESTING_FAILED_LARGE_MLI_DATA);


/**
 * Dependencies for testing AES key wrap with padding..
 */
struct aes_key_wrap_with_padding_testing {
	AES_ECB_TESTING_ENGINE (ecb);			/**< AES-ECB engine to use for testing. */
	struct aes_ecb_engine_mock ecb_mock;	/**< Mock for AES-ECB operations. */
	struct aes_key_wrap_with_padding test;	/**< AES key wrapping under test. */
};


/**
 * Initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param aes_kwp Testing dependencies to initialize.
 */
static void aes_key_wrap_with_padding_testing_init_dependencies (CuTest *test,
	struct aes_key_wrap_with_padding_testing *aes_kwp)
{
	int status;

	status = AES_ECB_TESTING_ENGINE_INIT (&aes_kwp->ecb);
	CuAssertIntEquals (test, 0, status);

	status = aes_ecb_mock_init (&aes_kwp->ecb_mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release all testing dependencies and validate mocks.
 *
 * @param test The test framework.
 * @param aes_kwp Testing dependencies to release.
 */
static void aes_key_wrap_with_padding_testing_release_dependencies (CuTest *test,
	struct aes_key_wrap_with_padding_testing *aes_kwp)
{
	int status;

	status = aes_ecb_mock_validate_and_release (&aes_kwp->ecb_mock);
	CuAssertIntEquals (test, 0, status);

	AES_ECB_TESTING_ENGINE_RELEASE (&aes_kwp->ecb);
}

/**
 * Initialize AES key wrap with padding for testing.
 *
 * @param test The test framework.
 * @param aes_kwp Testing components to initialize.
 */
static void aes_key_wrap_with_padding_testing_init (CuTest *test,
	struct aes_key_wrap_with_padding_testing *aes_kwp)
{
	int status;

	aes_key_wrap_with_padding_testing_init_dependencies (test, aes_kwp);

	status = aes_key_wrap_with_padding_init (&aes_kwp->test, &aes_kwp->ecb.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize AES key wrap with padding for testing using a mock for AES-ECB operations.
 *
 * @param test The test framework.
 * @param aes_kwp Testing components to initialize.
 */
static void aes_key_wrap_with_padding_testing_init_with_mock (CuTest *test,
	struct aes_key_wrap_with_padding_testing *aes_kwp)
{
	int status;

	aes_key_wrap_with_padding_testing_init_dependencies (test, aes_kwp);

	status = aes_key_wrap_with_padding_init (&aes_kwp->test, &aes_kwp->ecb_mock.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release test components and validate all mocks.
 *
 * @param test The test framework.
 * @param aes_kwp Testing components to release.
 */
static void aes_key_wrap_with_padding_testing_release (CuTest *test,
	struct aes_key_wrap_with_padding_testing *aes_kwp)
{
	aes_key_wrap_with_padding_testing_release_dependencies (test, aes_kwp);

	aes_key_wrap_with_padding_release (&aes_kwp->test);
}


/*******************
 * Test cases
 *******************/

static void aes_key_wrap_with_padding_test_init (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;

	TEST_START;

	aes_key_wrap_with_padding_testing_init_dependencies (test, &aes_kwp);

	status = aes_key_wrap_with_padding_init (&aes_kwp.test, &aes_kwp.ecb.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, aes_kwp.test.base.base.set_kek);
	CuAssertPtrNotNull (test, aes_kwp.test.base.base.clear_kek);
	CuAssertPtrNotNull (test, aes_kwp.test.base.base.wrap);
	CuAssertPtrNotNull (test, aes_kwp.test.base.base.unwrap);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_init_null (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;

	TEST_START;

	aes_key_wrap_with_padding_testing_init_dependencies (test, &aes_kwp);

	status = aes_key_wrap_with_padding_init (NULL, &aes_kwp.ecb.base);
	CuAssertIntEquals (test, AES_KEY_WRAP_INVALID_ARGUMENT, status);

	status = aes_key_wrap_with_padding_init (&aes_kwp.test, NULL);
	CuAssertIntEquals (test, AES_KEY_WRAP_INVALID_ARGUMENT, status);

	aes_key_wrap_with_padding_testing_release_dependencies (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_static_init (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp = {
		.test = aes_key_wrap_with_padding_static_init (&aes_kwp.ecb.base)
	};

	TEST_START;

	CuAssertPtrNotNull (test, aes_kwp.test.base.base.set_kek);
	CuAssertPtrNotNull (test, aes_kwp.test.base.base.clear_kek);
	CuAssertPtrNotNull (test, aes_kwp.test.base.base.wrap);
	CuAssertPtrNotNull (test, aes_kwp.test.base.base.unwrap);

	aes_key_wrap_with_padding_testing_init_dependencies (test, &aes_kwp);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_release_null (CuTest *test)
{
	TEST_START;

	aes_key_wrap_with_padding_release (NULL);
}

static void aes_key_wrap_with_padding_test_set_kek (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;

	TEST_START;

	aes_key_wrap_with_padding_testing_init_with_mock (test, &aes_kwp);

	status = mock_expect (&aes_kwp.ecb_mock.mock, aes_kwp.ecb_mock.base.set_key, &aes_kwp.ecb_mock,
		0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_KEY,
		AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_KEY_LEN),
		MOCK_ARG (AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_KEY_LEN));
	CuAssertIntEquals (test, 0, status);

	status = aes_kwp.test.base.base.set_kek (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_KEY,
		AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_set_kek_static_init (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp = {
		.test = aes_key_wrap_with_padding_static_init (&aes_kwp.ecb_mock.base)
	};
	int status;

	TEST_START;

	aes_key_wrap_with_padding_testing_init_dependencies (test, &aes_kwp);

	status = mock_expect (&aes_kwp.ecb_mock.mock, aes_kwp.ecb_mock.base.set_key, &aes_kwp.ecb_mock,
		0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_KEY,
		AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_KEY_LEN),
		MOCK_ARG (AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_KEY_LEN));
	CuAssertIntEquals (test, 0, status);

	status = aes_kwp.test.base.base.set_kek (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_KEY,
		AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_set_kek_null (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;

	TEST_START;

	aes_key_wrap_with_padding_testing_init_with_mock (test, &aes_kwp);

	status = aes_kwp.test.base.base.set_kek (NULL, AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_KEY,
		AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_KEY_LEN);
	CuAssertIntEquals (test, AES_KEY_WRAP_INVALID_ARGUMENT, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_set_kek_error (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;

	TEST_START;

	aes_key_wrap_with_padding_testing_init_with_mock (test, &aes_kwp);

	status = mock_expect (&aes_kwp.ecb_mock.mock, aes_kwp.ecb_mock.base.set_key, &aes_kwp.ecb_mock,
		AES_ECB_ENGINE_SET_KEY_FAILED,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_KEY,
		AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_KEY_LEN),
		MOCK_ARG (AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_KEY_LEN));
	CuAssertIntEquals (test, 0, status);

	status = aes_kwp.test.base.base.set_kek (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_KEY,
		AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_KEY_LEN);
	CuAssertIntEquals (test, AES_ECB_ENGINE_SET_KEY_FAILED, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_clear_kek (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;

	TEST_START;

	aes_key_wrap_with_padding_testing_init_with_mock (test, &aes_kwp);

	status = mock_expect (&aes_kwp.ecb_mock.mock, aes_kwp.ecb_mock.base.clear_key,
		&aes_kwp.ecb_mock, 0);
	CuAssertIntEquals (test, 0, status);

	status = aes_kwp.test.base.base.clear_kek (&aes_kwp.test.base.base);
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_clear_kek_static_init (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp = {
		.test = aes_key_wrap_with_padding_static_init (&aes_kwp.ecb_mock.base)
	};
	int status;

	TEST_START;

	aes_key_wrap_with_padding_testing_init_dependencies (test, &aes_kwp);

	status = mock_expect (&aes_kwp.ecb_mock.mock, aes_kwp.ecb_mock.base.clear_key,
		&aes_kwp.ecb_mock, 0);
	CuAssertIntEquals (test, 0, status);

	status = aes_kwp.test.base.base.clear_kek (&aes_kwp.test.base.base);
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_clear_kek_null (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;

	TEST_START;

	aes_key_wrap_with_padding_testing_init_with_mock (test, &aes_kwp);

	status = aes_kwp.test.base.base.clear_kek (NULL);
	CuAssertIntEquals (test, AES_KEY_WRAP_INVALID_ARGUMENT, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_clear_kek_error (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;

	TEST_START;

	aes_key_wrap_with_padding_testing_init_with_mock (test, &aes_kwp);

	status = mock_expect (&aes_kwp.ecb_mock.mock, aes_kwp.ecb_mock.base.clear_key,
		&aes_kwp.ecb_mock, AES_ECB_ENGINE_CLEAR_KEY_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = aes_kwp.test.base.base.clear_kek (&aes_kwp.test.base.base);
	CuAssertIntEquals (test, AES_ECB_ENGINE_CLEAR_KEY_FAILED, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_wrap_4096bit (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;
	uint8_t wrapped[
		AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_DATA_LEN)];

	TEST_START;

	CuAssertIntEquals (test, AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_DATA_WRAPPED_LEN,
		sizeof (wrapped));

	aes_key_wrap_with_padding_testing_init (test, &aes_kwp);

	status = aes_kwp.test.base.base.set_kek (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_KEY,
		AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kwp.test.base.base.wrap (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_DATA,
		AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_DATA_LEN, wrapped, sizeof (wrapped));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_DATA_WRAPPED,
		wrapped, sizeof (wrapped));
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_wrap_248bit (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;
	uint8_t wrapped[
		AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA_LEN)];

	TEST_START;

	CuAssertIntEquals (test, AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA_WRAPPED_LEN,
		sizeof (wrapped));

	/* Ensure the wrapped buffer is not zeroized. */
	memset (wrapped, 0xff, sizeof (wrapped));

	aes_key_wrap_with_padding_testing_init (test, &aes_kwp);

	status = aes_kwp.test.base.base.set_kek (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_KEY,
		AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kwp.test.base.base.wrap (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA,
		AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA_LEN, wrapped, sizeof (wrapped));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA_WRAPPED, wrapped,
		sizeof (wrapped));
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_wrap_72bit (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;
	uint8_t wrapped[
		AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_LEN)];

	TEST_START;

	CuAssertIntEquals (test, AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_WRAPPED_LEN,
		sizeof (wrapped));

	/* Ensure the wrapped buffer is not zeroized. */
	memset (wrapped, 0xff, sizeof (wrapped));

	aes_key_wrap_with_padding_testing_init (test, &aes_kwp);

	status = aes_kwp.test.base.base.set_kek (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_KEY,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kwp.test.base.base.wrap (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_LEN, wrapped, sizeof (wrapped));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_WRAPPED, wrapped,
		sizeof (wrapped));
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_wrap_64bit (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;
	uint8_t wrapped[
		AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (AES_KEY_WRAP_WITH_PADDING_TESTING_64BIT_DATA_LEN)];

	TEST_START;

	CuAssertIntEquals (test, AES_KEY_WRAP_WITH_PADDING_TESTING_64BIT_DATA_WRAPPED_LEN,
		sizeof (wrapped));

	/* Ensure the wrapped buffer is not zeroized. */
	memset (wrapped, 0xff, sizeof (wrapped));

	aes_key_wrap_with_padding_testing_init (test, &aes_kwp);

	status = aes_kwp.test.base.base.set_kek (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_64BIT_KEY,
		AES_KEY_WRAP_WITH_PADDING_TESTING_64BIT_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kwp.test.base.base.wrap (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_64BIT_DATA,
		AES_KEY_WRAP_WITH_PADDING_TESTING_64BIT_DATA_LEN, wrapped, sizeof (wrapped));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_KEY_WRAP_WITH_PADDING_TESTING_64BIT_DATA_WRAPPED, wrapped,
		sizeof (wrapped));
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_wrap_8bit (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;
	uint8_t wrapped[
		AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (AES_KEY_WRAP_WITH_PADDING_TESTING_8BIT_DATA_LEN)];

	TEST_START;

	CuAssertIntEquals (test, AES_KEY_WRAP_WITH_PADDING_TESTING_8BIT_DATA_WRAPPED_LEN,
		sizeof (wrapped));

	/* Ensure the wrapped buffer is not zeroized. */
	memset (wrapped, 0xff, sizeof (wrapped));

	aes_key_wrap_with_padding_testing_init (test, &aes_kwp);

	status = aes_kwp.test.base.base.set_kek (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_8BIT_KEY, AES_KEY_WRAP_WITH_PADDING_TESTING_8BIT_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kwp.test.base.base.wrap (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_8BIT_DATA,
		AES_KEY_WRAP_WITH_PADDING_TESTING_8BIT_DATA_LEN, wrapped, sizeof (wrapped));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_KEY_WRAP_WITH_PADDING_TESTING_8BIT_DATA_WRAPPED, wrapped,
		sizeof (wrapped));
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_wrap_same_buffer_wrapped_offset_from_data (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;
	uint8_t wrapped[
		AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_LEN)];

	TEST_START;

	memcpy (&wrapped[8], AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_LEN);

	aes_key_wrap_with_padding_testing_init (test, &aes_kwp);

	status = aes_kwp.test.base.base.set_kek (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_KEY,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kwp.test.base.base.wrap (&aes_kwp.test.base.base, &wrapped[8],
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_LEN, wrapped, sizeof (wrapped));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_WRAPPED, wrapped,
		sizeof (wrapped));
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_wrap_same_buffer_wrapped_same_as_data (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;
	uint8_t wrapped[
		AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_LEN)];

	TEST_START;

	memcpy (wrapped, AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_LEN);

	aes_key_wrap_with_padding_testing_init (test, &aes_kwp);

	status = aes_kwp.test.base.base.set_kek (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_KEY,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kwp.test.base.base.wrap (&aes_kwp.test.base.base, wrapped,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_LEN, wrapped, sizeof (wrapped));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_WRAPPED, wrapped,
		sizeof (wrapped));
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_wrap_static_init (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp = {
		.test = aes_key_wrap_with_padding_static_init (&aes_kwp.ecb.base)
	};
	int status;
	uint8_t wrapped[
		AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA_LEN)];

	TEST_START;

	CuAssertIntEquals (test, AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA_WRAPPED_LEN,
		sizeof (wrapped));

	aes_key_wrap_with_padding_testing_init_dependencies (test, &aes_kwp);

	status = aes_kwp.test.base.base.set_kek (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_KEY,
		AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kwp.test.base.base.wrap (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA,
		AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA_LEN, wrapped, sizeof (wrapped));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA_WRAPPED, wrapped,
		sizeof (wrapped));
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_wrap_null (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;
	uint8_t wrapped[
		AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_LEN)];

	TEST_START;

	aes_key_wrap_with_padding_testing_init (test, &aes_kwp);

	status = aes_kwp.test.base.base.set_kek (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_KEY,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kwp.test.base.base.wrap (NULL, AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_LEN, wrapped, sizeof (wrapped));
	CuAssertIntEquals (test, AES_KEY_WRAP_INVALID_ARGUMENT, status);

	status = aes_kwp.test.base.base.wrap (&aes_kwp.test.base.base, NULL,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_LEN, wrapped, sizeof (wrapped));
	CuAssertIntEquals (test, AES_KEY_WRAP_INVALID_ARGUMENT, status);

	status = aes_kwp.test.base.base.wrap (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_LEN, NULL, sizeof (wrapped));
	CuAssertIntEquals (test, AES_KEY_WRAP_INVALID_ARGUMENT, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_wrap_data_too_short (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;
	uint8_t wrapped[
		AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (AES_KEY_WRAP_WITH_PADDING_TESTING_8BIT_DATA_LEN)];

	TEST_START;

	aes_key_wrap_with_padding_testing_init (test, &aes_kwp);

	status = aes_kwp.test.base.base.set_kek (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_8BIT_KEY, AES_KEY_WRAP_WITH_PADDING_TESTING_8BIT_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kwp.test.base.base.wrap (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_8BIT_DATA, 0, wrapped, sizeof (wrapped));
	CuAssertIntEquals (test, AES_KEY_WRAP_NOT_ENOUGH_DATA, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_wrap_data_too_long (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;
	uint8_t wrapped[
		AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_DATA_LEN)];

	TEST_START;

	aes_key_wrap_with_padding_testing_init (test, &aes_kwp);

	status = aes_kwp.test.base.base.set_kek (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_KEY,
		AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kwp.test.base.base.wrap (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_DATA, 0xfffffff9, wrapped, sizeof (wrapped));
	CuAssertIntEquals (test, AES_KEY_WRAP_TOO_MUCH_DATA, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_wrap_wrapped_buffer_too_small (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;
	uint8_t wrapped[
		AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_LEN)];

	TEST_START;

	aes_key_wrap_with_padding_testing_init (test, &aes_kwp);

	status = aes_kwp.test.base.base.set_kek (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_KEY,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kwp.test.base.base.wrap (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_LEN, wrapped, sizeof (wrapped) - 1);
	CuAssertIntEquals (test, AES_KEY_WRAP_SMALL_OUTPUT_BUFFER, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_wrap_ecb_wrap_error (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;
	uint8_t wrapped[
		AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_LEN)];
	uint8_t zero[sizeof (wrapped)];

	TEST_START;

	memset (zero, 0, sizeof (zero));

	aes_key_wrap_with_padding_testing_init (test, &aes_kwp);

	status = aes_kwp.test.base.base.wrap (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_LEN, wrapped, sizeof (wrapped));
	CuAssertIntEquals (test, AES_ECB_ENGINE_NO_KEY, status);

	status = testing_validate_array (zero, wrapped, sizeof (wrapped));
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_wrap_ecb_single_error (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;
	uint8_t wrapped[
		AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (AES_KEY_WRAP_WITH_PADDING_TESTING_64BIT_DATA_LEN)];
	uint8_t zero[sizeof (wrapped)];

	TEST_START;

	memset (zero, 0, sizeof (zero));

	aes_key_wrap_with_padding_testing_init (test, &aes_kwp);

	status = aes_kwp.test.base.base.wrap (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_64BIT_DATA,
		AES_KEY_WRAP_WITH_PADDING_TESTING_64BIT_DATA_LEN, wrapped, sizeof (wrapped));
	CuAssertIntEquals (test, AES_ECB_ENGINE_NO_KEY, status);

	status = testing_validate_array (zero, wrapped, sizeof (wrapped));
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_unwrap_4096bit (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;
	uint8_t data[AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_DATA_ALIGNED_LEN];
	size_t length = sizeof (data);

	TEST_START;

	aes_key_wrap_with_padding_testing_init (test, &aes_kwp);

	status = aes_kwp.test.base.base.set_kek (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_KEY,
		AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kwp.test.base.base.unwrap (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_DATA_WRAPPED,
		AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_DATA_WRAPPED_LEN, data, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_DATA_LEN, length);

	status = testing_validate_array (AES_KEY_WRAP_WITH_PADDING_TESTING_4096BIT_DATA, data, length);
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_unwrap_248bit (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;
	uint8_t data[AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA_ALIGNED_LEN];
	size_t length = sizeof (data);

	TEST_START;

	aes_key_wrap_with_padding_testing_init (test, &aes_kwp);

	status = aes_kwp.test.base.base.set_kek (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_KEY,
		AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kwp.test.base.base.unwrap (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA_WRAPPED,
		AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA_WRAPPED_LEN, data, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA_LEN, length);

	status = testing_validate_array (AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA, data, length);
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_unwrap_72bit (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;
	uint8_t data[AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_ALIGNED_LEN];
	size_t length = sizeof (data);

	TEST_START;

	aes_key_wrap_with_padding_testing_init (test, &aes_kwp);

	status = aes_kwp.test.base.base.set_kek (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_KEY,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kwp.test.base.base.unwrap (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_WRAPPED,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_WRAPPED_LEN, data, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_LEN, length);

	status = testing_validate_array (AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA, data, length);
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_unwrap_64bit (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;
	uint8_t data[AES_KEY_WRAP_WITH_PADDING_TESTING_64BIT_DATA_ALIGNED_LEN];
	size_t length = sizeof (data);

	TEST_START;

	aes_key_wrap_with_padding_testing_init (test, &aes_kwp);

	status = aes_kwp.test.base.base.set_kek (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_64BIT_KEY,
		AES_KEY_WRAP_WITH_PADDING_TESTING_64BIT_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kwp.test.base.base.unwrap (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_64BIT_DATA_WRAPPED,
		AES_KEY_WRAP_WITH_PADDING_TESTING_64BIT_DATA_WRAPPED_LEN, data, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, AES_KEY_WRAP_WITH_PADDING_TESTING_64BIT_DATA_LEN, length);

	status = testing_validate_array (AES_KEY_WRAP_WITH_PADDING_TESTING_64BIT_DATA, data, length);
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_unwrap_8bit (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;
	uint8_t data[AES_KEY_WRAP_WITH_PADDING_TESTING_8BIT_DATA_ALIGNED_LEN];
	size_t length = sizeof (data);

	TEST_START;

	aes_key_wrap_with_padding_testing_init (test, &aes_kwp);

	status = aes_kwp.test.base.base.set_kek (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_8BIT_KEY, AES_KEY_WRAP_WITH_PADDING_TESTING_8BIT_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kwp.test.base.base.unwrap (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_8BIT_DATA_WRAPPED,
		AES_KEY_WRAP_WITH_PADDING_TESTING_8BIT_DATA_WRAPPED_LEN, data, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, AES_KEY_WRAP_WITH_PADDING_TESTING_8BIT_DATA_LEN, length);

	status = testing_validate_array (AES_KEY_WRAP_WITH_PADDING_TESTING_8BIT_DATA, data, length);
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_unwrap_same_buffer_data_offset_from_wrapped (
	CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;
	uint8_t data[AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_WRAPPED_LEN];
	size_t length = AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_ALIGNED_LEN;

	TEST_START;

	memcpy (data, AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_WRAPPED,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_WRAPPED_LEN);

	aes_key_wrap_with_padding_testing_init (test, &aes_kwp);

	status = aes_kwp.test.base.base.set_kek (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_KEY,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kwp.test.base.base.unwrap (&aes_kwp.test.base.base, data, sizeof (data), &data[8],
		&length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_LEN, length);

	status = testing_validate_array (AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA, &data[8],
		length);
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_unwrap_same_buffer_data_same_as_wrapped (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;
	uint8_t data[AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA_WRAPPED_LEN];
	size_t length = sizeof (data);

	TEST_START;

	memcpy (data, AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA_WRAPPED,
		AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA_WRAPPED_LEN);

	aes_key_wrap_with_padding_testing_init (test, &aes_kwp);

	status = aes_kwp.test.base.base.set_kek (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_KEY,
		AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kwp.test.base.base.unwrap (&aes_kwp.test.base.base, data, sizeof (data), data,
		&length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA_LEN, length);

	status = testing_validate_array (AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA, data, length);
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_unwrap_static_init (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp = {
		.test = aes_key_wrap_with_padding_static_init (&aes_kwp.ecb.base)
	};
	int status;
	uint8_t data[AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA_ALIGNED_LEN];
	size_t length = sizeof (data);

	TEST_START;

	aes_key_wrap_with_padding_testing_init_dependencies (test, &aes_kwp);

	status = aes_kwp.test.base.base.set_kek (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_KEY,
		AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kwp.test.base.base.unwrap (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA_WRAPPED,
		AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA_WRAPPED_LEN, data, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA_LEN, length);

	status = testing_validate_array (AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA, data, length);
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_unwrap_null (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;
	uint8_t data[AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_ALIGNED_LEN];
	size_t length = sizeof (data);

	TEST_START;

	aes_key_wrap_with_padding_testing_init (test, &aes_kwp);

	status = aes_kwp.test.base.base.set_kek (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_KEY,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kwp.test.base.base.unwrap (NULL,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_WRAPPED,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_WRAPPED_LEN, data, &length);
	CuAssertIntEquals (test, AES_KEY_WRAP_INVALID_ARGUMENT, status);

	status = aes_kwp.test.base.base.unwrap (&aes_kwp.test.base.base, NULL,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_WRAPPED_LEN, data, &length);
	CuAssertIntEquals (test, AES_KEY_WRAP_INVALID_ARGUMENT, status);

	status = aes_kwp.test.base.base.unwrap (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_WRAPPED,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_WRAPPED_LEN, NULL, &length);
	CuAssertIntEquals (test, AES_KEY_WRAP_INVALID_ARGUMENT, status);

	status = aes_kwp.test.base.base.unwrap (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_WRAPPED,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_WRAPPED_LEN, data, NULL);
	CuAssertIntEquals (test, AES_KEY_WRAP_INVALID_ARGUMENT, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_unwrap_not_64bit_aligned (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;
	uint8_t data[AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA_ALIGNED_LEN];
	size_t length = sizeof (data);

	TEST_START;

	aes_key_wrap_with_padding_testing_init (test, &aes_kwp);

	status = aes_kwp.test.base.base.set_kek (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_KEY,
		AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kwp.test.base.base.unwrap (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA_WRAPPED,
		AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA_WRAPPED_LEN - 1, data, &length);
	CuAssertIntEquals (test, AES_KEY_WRAP_NOT_BLOCK_ALIGNED, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_unwrap_wrapped_too_short (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;
	uint8_t data[AES_KEY_WRAP_WITH_PADDING_TESTING_64BIT_DATA_LEN];
	size_t length = sizeof (data);

	TEST_START;

	aes_key_wrap_with_padding_testing_init (test, &aes_kwp);

	status = aes_kwp.test.base.base.set_kek (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_64BIT_KEY,
		AES_KEY_WRAP_WITH_PADDING_TESTING_64BIT_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kwp.test.base.base.unwrap (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_64BIT_DATA_WRAPPED,
		AES_KEY_WRAP_WITH_PADDING_TESTING_64BIT_DATA_WRAPPED_LEN - 8, data, &length);
	CuAssertIntEquals (test, AES_KEY_WRAP_NOT_ENOUGH_DATA, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_unwrap_data_buffer_too_small (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;
	uint8_t data[AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_ALIGNED_LEN];
	size_t length = sizeof (data) - 1;

	TEST_START;

	aes_key_wrap_with_padding_testing_init (test, &aes_kwp);

	status = aes_kwp.test.base.base.set_kek (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_KEY,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kwp.test.base.base.unwrap (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_WRAPPED,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_WRAPPED_LEN, data, &length);
	CuAssertIntEquals (test, AES_KEY_WRAP_SMALL_OUTPUT_BUFFER, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_unwrap_corrupt_wrapped_data (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;
	uint8_t wrapped[AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_WRAPPED_LEN];
	uint8_t data[AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_ALIGNED_LEN];
	size_t length = sizeof (data);
	uint8_t zero[sizeof (data)];

	TEST_START;

	memset (zero, 0, sizeof (zero));

	memcpy (wrapped, AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_WRAPPED,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_WRAPPED_LEN);
	wrapped[10] ^= 0x55;	/* Corrupt the data region of the wrapped buffer. */

	aes_key_wrap_with_padding_testing_init (test, &aes_kwp);

	status = aes_kwp.test.base.base.set_kek (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_KEY,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kwp.test.base.base.unwrap (&aes_kwp.test.base.base, wrapped, sizeof (wrapped),
		data, &length);
	CuAssertIntEquals (test, AES_KEY_WRAP_INTEGRITY_CHECK_FAIL, status);

	status = testing_validate_array (zero, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_unwrap_corrupt_integrity_check (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;
	uint8_t wrapped[AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_WRAPPED_LEN];
	uint8_t data[AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_ALIGNED_LEN];
	size_t length = sizeof (data);
	uint8_t zero[sizeof (data)];

	TEST_START;

	memset (zero, 0, sizeof (zero));

	memcpy (wrapped, AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_WRAPPED,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_WRAPPED_LEN);
	wrapped[2] ^= 0x55;	/* Corrupt the integrity check region of the wrapped buffer. */

	aes_key_wrap_with_padding_testing_init (test, &aes_kwp);

	status = aes_kwp.test.base.base.set_kek (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_KEY,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kwp.test.base.base.unwrap (&aes_kwp.test.base.base, wrapped, sizeof (wrapped),
		data, &length);
	CuAssertIntEquals (test, AES_KEY_WRAP_INTEGRITY_CHECK_FAIL, status);

	status = testing_validate_array (zero, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_unwrap_non_zero_padding_bytes (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;
	uint8_t data[AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_ALIGNED_LEN];
	size_t length = sizeof (data);
	uint8_t zero[sizeof (data)];

	TEST_START;

	memset (zero, 0, sizeof (zero));

	aes_key_wrap_with_padding_testing_init (test, &aes_kwp);

	status = aes_kwp.test.base.base.set_kek (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_FAILED_KEY,
		AES_KEY_WRAP_WITH_PADDING_TESTING_FAILED_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kwp.test.base.base.unwrap (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_FAILED_NON_ZERO_PADDING_DATA,
		AES_KEY_WRAP_WITH_PADDING_TESTING_FAILED_NON_ZERO_PADDING_DATA_LEN, data, &length);
	CuAssertIntEquals (test, AES_KEY_WRAP_PADDING_CHECK_FAIL, status);

	status = testing_validate_array (zero, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_unwrap_mli_too_small (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;
	uint8_t data[AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_ALIGNED_LEN];
	size_t length = sizeof (data);
	uint8_t zero[sizeof (data)];

	TEST_START;

	memset (zero, 0, sizeof (zero));

	aes_key_wrap_with_padding_testing_init (test, &aes_kwp);

	status = aes_kwp.test.base.base.set_kek (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_FAILED_KEY,
		AES_KEY_WRAP_WITH_PADDING_TESTING_FAILED_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kwp.test.base.base.unwrap (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_FAILED_SMALL_MLI_DATA,
		AES_KEY_WRAP_WITH_PADDING_TESTING_FAILED_SMALL_MLI_DATA_LEN, data, &length);
	CuAssertIntEquals (test, AES_KEY_WRAP_LENGTH_CHECK_FAIL, status);

	status = testing_validate_array (zero, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_unwrap_mli_too_large (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;
	uint8_t data[AES_KEY_WRAP_WITH_PADDING_TESTING_248BIT_DATA_ALIGNED_LEN];
	size_t length = sizeof (data);
	uint8_t zero[sizeof (data)];

	TEST_START;

	memset (zero, 0, sizeof (zero));

	aes_key_wrap_with_padding_testing_init (test, &aes_kwp);

	status = aes_kwp.test.base.base.set_kek (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_FAILED_KEY,
		AES_KEY_WRAP_WITH_PADDING_TESTING_FAILED_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kwp.test.base.base.unwrap (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_FAILED_LARGE_MLI_DATA,
		AES_KEY_WRAP_WITH_PADDING_TESTING_FAILED_LARGE_MLI_DATA_LEN, data, &length);
	CuAssertIntEquals (test, AES_KEY_WRAP_LENGTH_CHECK_FAIL, status);

	status = testing_validate_array (zero, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_unwrap_ecb_unwrap_error (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;
	uint8_t data[AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_ALIGNED_LEN];
	size_t length = sizeof (data);
	uint8_t zero[sizeof (data)];

	TEST_START;

	memset (zero, 0, sizeof (zero));

	aes_key_wrap_with_padding_testing_init (test, &aes_kwp);

	status = aes_kwp.test.base.base.unwrap (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_WRAPPED,
		AES_KEY_WRAP_WITH_PADDING_TESTING_72BIT_DATA_WRAPPED_LEN, data, &length);
	CuAssertIntEquals (test, AES_ECB_ENGINE_NO_KEY, status);

	status = testing_validate_array (zero, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}

static void aes_key_wrap_with_padding_test_unwrap_ecb_single_error (CuTest *test)
{
	struct aes_key_wrap_with_padding_testing aes_kwp;
	int status;
	uint8_t data[AES_KEY_WRAP_WITH_PADDING_TESTING_64BIT_DATA_ALIGNED_LEN];
	size_t length = sizeof (data);
	uint8_t zero[sizeof (data)];

	TEST_START;

	memset (zero, 0, sizeof (zero));

	aes_key_wrap_with_padding_testing_init (test, &aes_kwp);

	status = aes_kwp.test.base.base.unwrap (&aes_kwp.test.base.base,
		AES_KEY_WRAP_WITH_PADDING_TESTING_64BIT_DATA_WRAPPED,
		AES_KEY_WRAP_WITH_PADDING_TESTING_64BIT_DATA_WRAPPED_LEN, data, &length);
	CuAssertIntEquals (test, AES_ECB_ENGINE_NO_KEY, status);

	status = testing_validate_array (zero, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_with_padding_testing_release (test, &aes_kwp);
}


// *INDENT-OFF*
TEST_SUITE_START (aes_key_wrap_with_padding);

TEST (aes_key_wrap_with_padding_test_init);
TEST (aes_key_wrap_with_padding_test_init_null);
TEST (aes_key_wrap_with_padding_test_static_init);
TEST (aes_key_wrap_with_padding_test_release_null);
TEST (aes_key_wrap_with_padding_test_set_kek);
TEST (aes_key_wrap_with_padding_test_set_kek_static_init);
TEST (aes_key_wrap_with_padding_test_set_kek_null);
TEST (aes_key_wrap_with_padding_test_set_kek_error);
TEST (aes_key_wrap_with_padding_test_clear_kek);
TEST (aes_key_wrap_with_padding_test_clear_kek_static_init);
TEST (aes_key_wrap_with_padding_test_clear_kek_null);
TEST (aes_key_wrap_with_padding_test_clear_kek_error);
TEST (aes_key_wrap_with_padding_test_wrap_4096bit);
TEST (aes_key_wrap_with_padding_test_wrap_248bit);
TEST (aes_key_wrap_with_padding_test_wrap_72bit);
TEST (aes_key_wrap_with_padding_test_wrap_64bit);
TEST (aes_key_wrap_with_padding_test_wrap_8bit);
TEST (aes_key_wrap_with_padding_test_wrap_same_buffer_wrapped_offset_from_data);
TEST (aes_key_wrap_with_padding_test_wrap_same_buffer_wrapped_same_as_data);
TEST (aes_key_wrap_with_padding_test_wrap_static_init);
TEST (aes_key_wrap_with_padding_test_wrap_null);
TEST (aes_key_wrap_with_padding_test_wrap_data_too_short);
TEST (aes_key_wrap_with_padding_test_wrap_data_too_long);
TEST (aes_key_wrap_with_padding_test_wrap_wrapped_buffer_too_small);
TEST (aes_key_wrap_with_padding_test_wrap_ecb_wrap_error);
TEST (aes_key_wrap_with_padding_test_wrap_ecb_single_error);
TEST (aes_key_wrap_with_padding_test_unwrap_4096bit);
TEST (aes_key_wrap_with_padding_test_unwrap_248bit);
TEST (aes_key_wrap_with_padding_test_unwrap_72bit);
TEST (aes_key_wrap_with_padding_test_unwrap_64bit);
TEST (aes_key_wrap_with_padding_test_unwrap_8bit);
TEST (aes_key_wrap_with_padding_test_unwrap_same_buffer_data_offset_from_wrapped);
TEST (aes_key_wrap_with_padding_test_unwrap_same_buffer_data_same_as_wrapped);
TEST (aes_key_wrap_with_padding_test_unwrap_static_init);
TEST (aes_key_wrap_with_padding_test_unwrap_null);
TEST (aes_key_wrap_with_padding_test_unwrap_not_64bit_aligned);
TEST (aes_key_wrap_with_padding_test_unwrap_wrapped_too_short);
TEST (aes_key_wrap_with_padding_test_unwrap_data_buffer_too_small);
TEST (aes_key_wrap_with_padding_test_unwrap_corrupt_wrapped_data);
TEST (aes_key_wrap_with_padding_test_unwrap_corrupt_integrity_check);
TEST (aes_key_wrap_with_padding_test_unwrap_non_zero_padding_bytes);
TEST (aes_key_wrap_with_padding_test_unwrap_mli_too_small);
TEST (aes_key_wrap_with_padding_test_unwrap_mli_too_large);
TEST (aes_key_wrap_with_padding_test_unwrap_ecb_unwrap_error);
TEST (aes_key_wrap_with_padding_test_unwrap_ecb_single_error);

TEST_SUITE_END;
// *INDENT-ON*
