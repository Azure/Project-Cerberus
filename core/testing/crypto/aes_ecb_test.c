// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "aes_ecb_testing.h"


/**
 * AES key for testing encrypt/decrypt of a single block of data.
 */
const uint8_t AES_ECB_TESTING_SINGLE_BLOCK_KEY[] = {
	0xcc, 0x22, 0xda, 0x78, 0x7f, 0x37, 0x57, 0x11, 0xc7, 0x63, 0x02, 0xbe, 0xf0, 0x97, 0x9d, 0x8e,
	0xdd, 0xf8, 0x42, 0x82, 0x9c, 0x2b, 0x99, 0xef, 0x3d, 0xd0, 0x4e, 0x23, 0xe5, 0x4c, 0xc2, 0x4b
};

const size_t AES_ECB_TESTING_SINGLE_BLOCK_KEY_LEN = sizeof (AES_ECB_TESTING_SINGLE_BLOCK_KEY);

/**
 * Single AES block of plaintext data.
 */
const uint8_t AES_ECB_TESTING_SINGLE_BLOCK_PLAINTEXT[] = {
	0xcc, 0xc6, 0x2c, 0x6b, 0x0a, 0x09, 0xa6, 0x71, 0xd6, 0x44, 0x56, 0x81, 0x8d, 0xb2, 0x9a, 0x4d
};

/**
 * Single AES block of ciphertext data.
 */
const uint8_t AES_ECB_TESTING_SINGLE_BLOCK_CIPHERTEXT[] = {
	0xdf, 0x86, 0x34, 0xca, 0x02, 0xb1, 0x3a, 0x12, 0x5b, 0x78, 0x6e, 0x1d, 0xce, 0x90, 0x65, 0x8b
};

/**
 * Length of the single block of data.
 */
const size_t AES_ECB_TESTING_SINGLE_BLOCK_LEN = sizeof (AES_ECB_TESTING_SINGLE_BLOCK_PLAINTEXT);

/**
 * AES key for testing encrypt/decrypt of multiple blocks of data.
 */
const uint8_t AES_ECB_TESTING_MULTI_BLOCK_KEY[] = {
	0xf9, 0x84, 0xb0, 0xf5, 0x34, 0xfc, 0x0a, 0xe2, 0xc0, 0xa8, 0x59, 0x3e, 0x16, 0xab, 0x83, 0x65,
	0xf2, 0x5f, 0xcc, 0x9c, 0x59, 0x47, 0xf9, 0xa2, 0xdb, 0x45, 0xb5, 0x88, 0x16, 0x0d, 0x35, 0xc3
};

const size_t AES_ECB_TESTING_MULTI_BLOCK_KEY_LEN = sizeof (AES_ECB_TESTING_MULTI_BLOCK_KEY);

/**
 * Multiple AES blocks of plaintext data.
 */
const uint8_t AES_ECB_TESTING_MULTI_BLOCK_PLAINTEXT[] = {
	0x35, 0x1f, 0xee, 0x09, 0x91, 0x22, 0xe3, 0x71, 0xc4, 0x83, 0x0f, 0x40, 0x9c, 0x6c, 0x44, 0x11,
	0x18, 0x6d, 0x22, 0x17, 0x6f, 0x71, 0x38, 0xb0, 0x54, 0xf1, 0x6b, 0x3c, 0x79, 0x67, 0x9c, 0x2f,
	0x52, 0x06, 0x85, 0x65, 0x1b, 0xa8, 0xe4, 0xb6, 0x1c, 0x08, 0xdc, 0xcb, 0x2c, 0x31, 0x98, 0x2f,
	0x74, 0x36, 0x31, 0xa9, 0x75, 0x24, 0xd2, 0xca, 0x4d, 0x35, 0x1a, 0xc2, 0x35, 0x46, 0xc1, 0x78
};

/**
 * Multiple AES blocks of ciphertext data.
 */
const uint8_t AES_ECB_TESTING_MULTI_BLOCK_CIPHERTEXT[] = {
	0x8b, 0x9c, 0x9e, 0x69, 0x2c, 0x16, 0xe7, 0x05, 0x98, 0x18, 0xe2, 0x85, 0xe8, 0x5d, 0x8f, 0xa5,
	0x43, 0x3d, 0xee, 0x2a, 0xff, 0x9f, 0xec, 0x61, 0xd6, 0xa0, 0xa7, 0x81, 0xe2, 0x4b, 0x24, 0xf6,
	0x49, 0x02, 0xfb, 0xd1, 0x8c, 0xef, 0x74, 0x61, 0xad, 0x77, 0x60, 0xcf, 0xb2, 0x44, 0x2f, 0xb7,
	0x4f, 0xfd, 0x9b, 0xe1, 0x08, 0xa3, 0x86, 0x54, 0x5f, 0x2a, 0x21, 0x64, 0x30, 0xef, 0x16, 0xfb
};

/**
 * Length of the multi-block data.
 */
const size_t AES_ECB_TESTING_MULTI_BLOCK_LEN = sizeof (AES_ECB_TESTING_MULTI_BLOCK_PLAINTEXT);

/**
 * AES key for testing encrypt/decrypt of a longest test vectors from the NIST vectors.
 */
const uint8_t AES_ECB_TESTING_LONG_DATA_KEY[] = {
	0x44, 0xa2, 0xb5, 0xa7, 0x45, 0x3e, 0x49, 0xf3, 0x82, 0x61, 0x90, 0x4f, 0x21, 0xac, 0x79, 0x76,
	0x41, 0xd1, 0xbc, 0xd8, 0xdd, 0xed, 0xd2, 0x93, 0xf3, 0x19, 0x44, 0x9f, 0xe6, 0x3b, 0x29, 0x48
};

const size_t AES_ECB_TESTING_LONG_DATA_KEY_LEN = sizeof (AES_ECB_TESTING_LONG_DATA_KEY);

/**
 * Longest plaintext data from the NIST vectors.
 */
const uint8_t AES_ECB_TESTING_LONG_DATA_PLAINTEXT[] = {
	0xc9, 0x1b, 0x8a, 0x7b, 0x9c, 0x51, 0x17, 0x84, 0xb6, 0xa3, 0x7f, 0x73, 0xb2, 0x90, 0x51, 0x6b,
	0xb9, 0xef, 0x1e, 0x8d, 0xf6, 0x8d, 0x89, 0xbf, 0x49, 0x16, 0x9e, 0xac, 0x40, 0x39, 0x65, 0x0c,
	0x43, 0x07, 0xb6, 0x26, 0x0e, 0x9c, 0x4e, 0x93, 0x65, 0x02, 0x23, 0x44, 0x02, 0x52, 0xf5, 0xc7,
	0xd3, 0x1c, 0x26, 0xc5, 0x62, 0x09, 0xcb, 0xd0, 0x95, 0xbf, 0x03, 0x5b, 0x97, 0x05, 0x88, 0x0a,
	0x16, 0x28, 0x83, 0x2d, 0xaf, 0x9d, 0xa5, 0x87, 0xa6, 0xe7, 0x73, 0x53, 0xdb, 0xbc, 0xe1, 0x89,
	0xf9, 0x63, 0x23, 0x5d, 0xf1, 0x60, 0xc0, 0x08, 0xa7, 0x53, 0xe8, 0xcc, 0xea, 0x1e, 0x07, 0x32,
	0xaa, 0x46, 0x9a, 0x97, 0x65, 0x9c, 0x42, 0xe6, 0xe3, 0x1c, 0x16, 0xa7, 0x23, 0x15, 0x3e, 0x39,
	0x95, 0x8a, 0xbe, 0x5b, 0x8a, 0xd8, 0x8f, 0xf2, 0xe8, 0x9a, 0xf4, 0x06, 0x22, 0xca, 0x0b, 0x0d,
	0x67, 0x29, 0xa2, 0x6c, 0x1a, 0xe0, 0x4d, 0x3b, 0x83, 0x67, 0xb5, 0x48, 0xc4, 0xa6, 0x33, 0x5f,
	0x0e, 0x5a, 0x9e, 0xc9, 0x14, 0xbb, 0x61, 0x13, 0xc0, 0x5c, 0xd0, 0x11, 0x25, 0x52, 0xbc, 0x21
};

/**
 * Longest ciphertext data from the NIST vectors.
 */
const uint8_t AES_ECB_TESTING_LONG_DATA_CIPHERTEXT[] = {
	0x05, 0xd5, 0x1a, 0xf0, 0xe2, 0xb6, 0x1e, 0x2c, 0x06, 0xcb, 0x1e, 0x84, 0x3f, 0xee, 0x31, 0x72,
	0x82, 0x5e, 0x63, 0xb5, 0xd1, 0xce, 0x81, 0x83, 0xb7, 0xe1, 0xdb, 0x62, 0x68, 0xdb, 0x5a, 0xa7,
	0x26, 0x52, 0x1f, 0x46, 0xe9, 0x48, 0x02, 0x8a, 0xa4, 0x43, 0xaf, 0x9e, 0xbd, 0x8b, 0x7c, 0x6b,
	0xaf, 0x95, 0x80, 0x67, 0xab, 0x0d, 0x4a, 0x8a, 0xc5, 0x30, 0xec, 0xbb, 0x68, 0xcd, 0xfc, 0x3e,
	0xb9, 0x30, 0x34, 0xa4, 0x28, 0xeb, 0x7e, 0x8f, 0x6a, 0x38, 0x13, 0xce, 0xa6, 0x18, 0x90, 0x68,
	0xdf, 0xec, 0xfa, 0x26, 0x8b, 0x7e, 0xcd, 0x59, 0x87, 0xf8, 0xcb, 0x27, 0x32, 0xc6, 0x88, 0x2b,
	0xbe, 0xc8, 0xf7, 0x16, 0xba, 0xc2, 0x54, 0xd7, 0x22, 0x69, 0x23, 0x0a, 0xec, 0x5d, 0xc7, 0xf5,
	0xa6, 0xb8, 0x66, 0xfd, 0x30, 0x52, 0x42, 0x55, 0x2d, 0x40, 0x0f, 0x5b, 0x04, 0x04, 0xf1, 0x9c,
	0xbf, 0xe7, 0x29, 0x1f, 0xab, 0x69, 0x0e, 0xcf, 0xe6, 0x01, 0x8c, 0x43, 0x09, 0xfc, 0x63, 0x9d,
	0x1b, 0x65, 0xfc, 0xb6, 0x5e, 0x64, 0x3e, 0xdb, 0x0a, 0xd1, 0xf0, 0x9c, 0xfe, 0x9c, 0xee, 0x4a
};

/**
 * Length of the long test data.
 */
const size_t AES_ECB_TESTING_LONG_DATA_LEN = sizeof (AES_ECB_TESTING_LONG_DATA_PLAINTEXT);
