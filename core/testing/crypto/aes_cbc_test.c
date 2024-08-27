// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "aes_cbc_testing.h"


const uint8_t AES_CBC_TESTING_SINGLE_BLOCK_KEY[] = {
	0x6e, 0xd7, 0x6d, 0x2d, 0x97, 0xc6, 0x9f, 0xd1, 0x33, 0x95, 0x89, 0x52, 0x39, 0x31, 0xf2, 0xa6,
	0xcf, 0xf5, 0x54, 0xb1, 0x5f, 0x73, 0x8f, 0x21, 0xec, 0x72, 0xdd, 0x97, 0xa7, 0x33, 0x09, 0x07
};

const uint8_t AES_CBC_TESTING_SINGLE_BLOCK_IV[] = {
	0x85, 0x1e, 0x87, 0x64, 0x77, 0x6e, 0x67, 0x96, 0xaa, 0xb7, 0x22, 0xdb, 0xb6, 0x44, 0xac, 0xe8
};

const uint8_t AES_CBC_TESTING_SINGLE_BLOCK_PLAINTEXT[] = {
	0x62, 0x82, 0xb8, 0xc0, 0x5c, 0x5c, 0x15, 0x30, 0xb9, 0x7d, 0x48, 0x16, 0xca, 0x43, 0x47, 0x62
};

const uint8_t AES_CBC_TESTING_SINGLE_BLOCK_CIPHERTEXT[] = {
	0x6a, 0xcc, 0x04, 0x14, 0x2e, 0x10, 0x0a, 0x65, 0xf5, 0x1b, 0x97, 0xad, 0xf5, 0x17, 0x2c, 0x41
};

const size_t AES_CBC_TESTING_SINGLE_BLOCK_LEN = sizeof (AES_CBC_TESTING_SINGLE_BLOCK_PLAINTEXT);

const uint8_t AES_CBC_TESTING_MULTI_BLOCK_KEY[] = {
	0x04, 0x93, 0xff, 0x63, 0x71, 0x08, 0xaf, 0x6a, 0x5b, 0x8e, 0x90, 0xac, 0x1f, 0xdf, 0x03, 0x5a,
	0x3d, 0x4b, 0xaf, 0xd1, 0xaf, 0xb5, 0x73, 0xbe, 0x7a, 0xde, 0x9e, 0x86, 0x82, 0xe6, 0x63, 0xe5
};

const uint8_t AES_CBC_TESTING_MULTI_BLOCK_IV[] = {
	0xc0, 0xcd, 0x2b, 0xeb, 0xcc, 0xbb, 0x6c, 0x49, 0x92, 0x0b, 0xd5, 0x48, 0x2a, 0xc7, 0x56, 0xe8
};

const uint8_t AES_CBC_TESTING_MULTI_BLOCK_PLAINTEXT[] = {
	0x8b, 0x37, 0xf9, 0x14, 0x8d, 0xf4, 0xbb, 0x25, 0x95, 0x6b, 0xe6, 0x31, 0x0c, 0x73, 0xc8, 0xdc,
	0x58, 0xea, 0x97, 0x14, 0xff, 0x49, 0xb6, 0x43, 0x10, 0x7b, 0x34, 0xc9, 0xbf, 0xf0, 0x96, 0xa9,
	0x4f, 0xed, 0xd6, 0x82, 0x35, 0x26, 0xab, 0xc2, 0x7a, 0x8e, 0x0b, 0x16, 0x61, 0x6e, 0xee, 0x25,
	0x4a, 0xb4, 0x56, 0x7d, 0xd6, 0x8e, 0x8c, 0xcd, 0x4c, 0x38, 0xac, 0x56, 0x3b, 0x13, 0x63, 0x9c
};

const uint8_t AES_CBC_TESTING_MULTI_BLOCK_CIPHERTEXT[] = {
	0x05, 0xd5, 0xc7, 0x77, 0x29, 0x42, 0x1b, 0x08, 0xb7, 0x37, 0xe4, 0x11, 0x19, 0xfa, 0x44, 0x38,
	0xd1, 0xf5, 0x70, 0xcc, 0x77, 0x2a, 0x4d, 0x6c, 0x3d, 0xf7, 0xff, 0xed, 0xa0, 0x38, 0x4e, 0xf8,
	0x42, 0x88, 0xce, 0x37, 0xfc, 0x4c, 0x4c, 0x7d, 0x11, 0x25, 0xa4, 0x99, 0xb0, 0x51, 0x36, 0x4c,
	0x38, 0x9f, 0xd6, 0x39, 0xbd, 0xda, 0x64, 0x7d, 0xaa, 0x3b, 0xda, 0xda, 0xb2, 0xeb, 0x55, 0x94
};

const size_t AES_CBC_TESTING_MULTI_BLOCK_LEN = sizeof (AES_CBC_TESTING_MULTI_BLOCK_PLAINTEXT);

const uint8_t AES_CBC_TESTING_LONG_DATA_KEY[] = {
	0x48, 0xbe, 0x59, 0x7e, 0x63, 0x2c, 0x16, 0x77, 0x23, 0x24, 0xc8, 0xd3, 0xfa, 0x1d, 0x9c, 0x5a,
	0x9e, 0xcd, 0x01, 0x0f, 0x14, 0xec, 0x5d, 0x11, 0x0d, 0x3b, 0xfe, 0xc3, 0x76, 0xc5, 0x53, 0x2b
};

const uint8_t AES_CBC_TESTING_LONG_DATA_IV[] = {
	0xd6, 0xd5, 0x81, 0xb8, 0xcf, 0x04, 0xeb, 0xd3, 0xb6, 0xea, 0xa1, 0xb5, 0x3f, 0x04, 0x7e, 0xe1
};

const uint8_t AES_CBC_TESTING_LONG_DATA_PLAINTEXT[] = {
	0x0c, 0x63, 0xd4, 0x13, 0xd3, 0x86, 0x45, 0x70, 0xe7, 0x0b, 0xb6, 0x61, 0x8b, 0xf8, 0xa4, 0xb9,
	0x58, 0x55, 0x86, 0x68, 0x8c, 0x32, 0xbb, 0xa0, 0xa5, 0xec, 0xc1, 0x36, 0x2f, 0xad, 0xa7, 0x4a,
	0xda, 0x32, 0xc5, 0x2a, 0xcf, 0xd1, 0xaa, 0x74, 0x44, 0xba, 0x56, 0x7b, 0x4e, 0x7d, 0xaa, 0xec,
	0xf7, 0xcc, 0x1c, 0xb2, 0x91, 0x82, 0xaf, 0x16, 0x4a, 0xe5, 0x23, 0x2b, 0x00, 0x28, 0x68, 0x69,
	0x56, 0x35, 0x59, 0x98, 0x07, 0xa9, 0xa7, 0xf0, 0x7a, 0x1f, 0x13, 0x7e, 0x97, 0xb1, 0xe1, 0xc9,
	0xda, 0xbc, 0x89, 0xb6, 0xa5, 0xe4, 0xaf, 0xa9, 0xdb, 0x58, 0x55, 0xed, 0xaa, 0x57, 0x50, 0x56,
	0xa8, 0xf4, 0xf8, 0x24, 0x22, 0x16, 0x24, 0x2b, 0xb0, 0xc2, 0x56, 0x31, 0x0d, 0x9d, 0x32, 0x98,
	0x26, 0xac, 0x35, 0x3d, 0x71, 0x5f, 0xa3, 0x9f, 0x80, 0xce, 0xc1, 0x44, 0xd6, 0x42, 0x45, 0x58,
	0xf9, 0xf7, 0x0b, 0x98, 0xc9, 0x20, 0x09, 0x6e, 0x0f, 0x2c, 0x85, 0x5d, 0x59, 0x48, 0x85, 0xa0,
	0x06, 0x25, 0x88, 0x0e, 0x9d, 0xfb, 0x73, 0x41, 0x63, 0xce, 0xce, 0xf7, 0x2c, 0xf0, 0x30, 0xb8
};

const uint8_t AES_CBC_TESTING_LONG_DATA_CIPHERTEXT[] = {
	0xfc, 0x58, 0x73, 0xe5, 0x0d, 0xe8, 0xfa, 0xf4, 0xc6, 0xb8, 0x4b, 0xa7, 0x07, 0xb0, 0x85, 0x4e,
	0x9d, 0xb9, 0xab, 0x2e, 0x9f, 0x7d, 0x70, 0x7f, 0xbb, 0xa3, 0x38, 0xc6, 0x84, 0x3a, 0x18, 0xfc,
	0x6f, 0xac, 0xeb, 0xaf, 0x66, 0x3d, 0x26, 0x29, 0x6f, 0xb3, 0x29, 0xb4, 0xd2, 0x6f, 0x18, 0x49,
	0x4c, 0x79, 0xe0, 0x9e, 0x77, 0x96, 0x47, 0xf9, 0xba, 0xfa, 0x87, 0x48, 0x96, 0x30, 0xd7, 0x9f,
	0x43, 0x01, 0x61, 0x0c, 0x23, 0x00, 0xc1, 0x9d, 0xbf, 0x31, 0x48, 0xb7, 0xca, 0xc8, 0xc4, 0xf4,
	0x94, 0x41, 0x02, 0x75, 0x4f, 0x33, 0x2e, 0x92, 0xb6, 0xf7, 0xc5, 0xe7, 0x5b, 0xc6, 0x17, 0x9e,
	0xb8, 0x77, 0xa0, 0x78, 0xd4, 0x71, 0x90, 0x09, 0x02, 0x17, 0x44, 0xc1, 0x4f, 0x13, 0xfd, 0x2a,
	0x55, 0xa2, 0xb9, 0xc4, 0x4d, 0x18, 0x00, 0x06, 0x85, 0xa8, 0x45, 0xa4, 0xf6, 0x32, 0xc7, 0xc5,
	0x6a, 0x77, 0x30, 0x6e, 0xfa, 0x66, 0xa2, 0x4d, 0x05, 0xd0, 0x88, 0xdc, 0xd7, 0xc1, 0x3f, 0xe2,
	0x4f, 0xc4, 0x47, 0x27, 0x59, 0x65, 0xdb, 0x9e, 0x4d, 0x37, 0xfb, 0xc9, 0x30, 0x44, 0x48, 0xcd
};

const size_t AES_CBC_TESTING_LONG_DATA_LEN = sizeof (AES_CBC_TESTING_LONG_DATA_PLAINTEXT);