// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "attestation/pcr.h"
#include "attestation/pcr_data.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/flash/flash_mock.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/crypto/hash_testing.h"


TEST_SUITE_LABEL ("pcr");


/**
 * SHA256 hash of event type 0xaabbccdd.
 */
const uint8_t PCR_TESTING_SHA256_EVENT_TYPE[] = {
	0x98,0x63,0x26,0xcb,0xf3,0x8b,0x9d,0x1a,0x87,0xb4,0x3d,0xf3,0x66,0x0f,0xe2,0xcc,
	0x57,0x14,0xbc,0xc1,0x8c,0xaa,0x5b,0xab,0x61,0x08,0xf5,0xa4,0xaf,0xf2,0xaf,0x89
};

/**
 * SHA256 hash of version 0x24.
 */
const uint8_t PCR_TESTING_SHA256_VERSIONED[] = {
	0x09,0xfc,0x96,0x08,0x2d,0x34,0xc2,0xdf,0xc1,0x29,0x5d,0x92,0x07,0x3b,0x5e,0xa1,
	0xdc,0x8e,0xf8,0xda,0x95,0xf1,0x4d,0xfd,0xed,0x01,0x1f,0xfb,0x96,0xd3,0xe5,0x4b
};

/**
 * SHA256 hash of 1-byte data 0x11.
 */
const uint8_t PCR_TESTING_SHA256_1BYTE_DATA[] = {
	0x4a,0x64,0xa1,0x07,0xf0,0xcb,0x32,0x53,0x6e,0x5b,0xce,0x6c,0x98,0xc3,0x93,0xdb,
	0x21,0xcc,0xa7,0xf4,0xea,0x18,0x7b,0xa8,0xc4,0xdc,0xa8,0xb5,0x1d,0x4e,0xa8,0x0a
};

/**
 * SHA256 hash of 1-byte data 0x11 with event type 0xaabbccdd.
 */
const uint8_t PCR_TESTING_SHA256_1BYTE_DATA_WITH_EVENT[] = {
	0x09,0x2b,0xce,0x3a,0x53,0xe8,0xe3,0x86,0x12,0xda,0x90,0x05,0x7a,0xbf,0x84,0xb3,
	0x81,0x24,0xfb,0x05,0xe3,0xbb,0xfc,0xec,0x07,0x00,0x25,0x26,0x42,0x96,0xa2,0x6c
};

/**
 * SHA256 hash of 1-byte data 0x11 with version 0x24.
 */
const uint8_t PCR_TESTING_SHA256_1BYTE_DATA_VERSIONED[] = {
	0x33,0xa1,0xda,0x07,0xef,0xee,0x0b,0x95,0x45,0xa8,0x3b,0x05,0xa7,0xf9,0x8b,0x5d,
	0x47,0x41,0xd0,0x38,0xfb,0xc3,0x60,0x42,0xfb,0x49,0x28,0x98,0x5d,0xad,0x50,0x4d
};

/**
 * SHA256 hash of 1-byte data 0x11 with event type 0xaabbccdd and version 0x24.
 */
const uint8_t PCR_TESTING_SHA256_1BYTE_DATA_VERSIONED_WITH_EVENT[] = {
	0x04,0xdf,0x33,0xa5,0x56,0x93,0xe8,0xb3,0x19,0xf8,0x08,0x51,0x35,0xec,0x48,0x47,
	0x96,0xa6,0x86,0x1f,0x66,0x06,0x2e,0x8a,0x7c,0xbe,0x89,0x4b,0x08,0x01,0xe9,0xdf
};

/**
 * SHA256 hash of 2-byte data 0x1122.
 */
const uint8_t PCR_TESTING_SHA256_2BYTE_DATA[] = {
	0xb2,0x9b,0x08,0xef,0x69,0x3e,0x9a,0x43,0x81,0x8a,0x00,0xcd,0xf3,0x84,0xad,0xec,
	0xf5,0x6d,0x8d,0x4b,0xe8,0x01,0x9a,0xd4,0xf2,0x8f,0xbf,0x5f,0x84,0x20,0x99,0x50
};

/**
 * SHA256 hash of 2-byte data 0x1122 with event type 0xaabbccdd.
 */
const uint8_t PCR_TESTING_SHA256_2BYTE_DATA_WITH_EVENT[] = {
	0xfd,0xff,0x04,0x6c,0x1e,0xa7,0xe1,0x64,0x02,0x46,0x1d,0xca,0x4f,0x61,0x8f,0x15,
	0x0b,0xbc,0xfc,0x54,0x2e,0xf8,0x4d,0x61,0xed,0x2e,0x01,0x9c,0x70,0x39,0x0d,0x6c
};

/**
 * SHA256 hash of 2-byte data 0x1122 with version 0x24.
 */
const uint8_t PCR_TESTING_SHA256_2BYTE_DATA_VERSIONED[] = {
	0x01,0x07,0x19,0xea,0x3a,0x97,0x71,0x95,0x81,0x77,0xd0,0x2f,0xfa,0x46,0x35,0x67,
	0xb7,0xb4,0x0c,0x23,0x9b,0xc7,0x9b,0xd2,0xe6,0x8e,0x17,0x00,0x01,0xc9,0x7c,0x1a
};

/**
 * SHA256 hash of 2-byte data 0x1122 with event type 0xaabbccdd and version 0x24.
 */
const uint8_t PCR_TESTING_SHA256_2BYTE_DATA_VERSIONED_WITH_EVENT[] = {
	0xf9,0x7b,0x20,0x44,0xc1,0x55,0x95,0x8d,0xf1,0x12,0x1f,0xc0,0x96,0x03,0xcc,0xe4,
	0x53,0xbd,0x95,0xee,0x82,0x1d,0xcc,0xa8,0x07,0x95,0x74,0xd9,0x9a,0xfb,0x32,0x05
};

/**
 * SHA256 hash of 4-byte data 0x11223344.
 */
const uint8_t PCR_TESTING_SHA256_4BYTE_DATA[] = {
	0xc8,0x32,0xfb,0xe8,0xa6,0x9c,0x86,0x94,0xf8,0x5d,0x3f,0x3d,0x6b,0xda,0xce,0x5b,
	0x99,0xc4,0xc4,0x15,0x3c,0x4f,0x5c,0xa5,0xe3,0xd2,0x1e,0x22,0xeb,0x21,0x8c,0xe3
};

/**
 * SHA256 hash of 4-byte data 0x11223344 with event type 0xaabbccdd.
 */
const uint8_t PCR_TESTING_SHA256_4BYTE_DATA_WITH_EVENT[] = {
	0x9d,0xfb,0x54,0x35,0xa0,0x1c,0x05,0x3c,0x63,0x5e,0x80,0x8b,0xd5,0x16,0x51,0x03,
	0xaf,0x09,0xd2,0x51,0x21,0xf8,0x7e,0xe7,0xa7,0xfc,0x4c,0x91,0x65,0x0b,0x65,0xd0
};

/**
 * SHA256 hash of 4-byte data 0x11223344 with version 0x24.
 */
const uint8_t PCR_TESTING_SHA256_4BYTE_DATA_VERSIONED[] = {
	0xac,0x09,0xe6,0xba,0xa1,0xce,0x8c,0xe4,0xb9,0xc1,0x23,0x92,0x98,0x92,0x1e,0x27,
	0x6a,0x75,0x01,0x79,0x30,0x28,0xa5,0x54,0x73,0xfd,0x61,0x8c,0x03,0x1e,0x7b,0xae
};

/**
 * SHA256 hash of 4-byte data 0x11223344 with event type 0xaabbccdd and version 0x24.
 */
const uint8_t PCR_TESTING_SHA256_4BYTE_DATA_VERSIONED_WITH_EVENT[] = {
	0xe1,0x15,0xc9,0xad,0x91,0x15,0x9a,0xfa,0xc1,0xa1,0x6e,0x2c,0xfa,0x29,0x8e,0xc7,
	0x9e,0x2b,0x80,0x2b,0xef,0x72,0x21,0x3f,0xcb,0x10,0x3f,0x39,0x6e,0x2b,0x69,0x56
};

/**
 * SHA256 hash of 8-byte data 0x1122334455667788.
 */
const uint8_t PCR_TESTING_SHA256_8BYTE_DATA[] = {
	0x80,0x4d,0x56,0x2d,0x22,0x47,0x0f,0xb7,0xbe,0x7f,0x06,0xaa,0x07,0x66,0x21,0xcb,
	0x26,0x89,0x32,0xbe,0x33,0xd8,0xf9,0xfb,0x28,0x44,0xf9,0x58,0xdb,0xd7,0x4c,0x17
};

/**
 * SHA256 hash of 8-byte data 0x1122334455667788 with event type 0xaabbccdd.
 */
const uint8_t PCR_TESTING_SHA256_8BYTE_DATA_WITH_EVENT[] = {
	0x19,0x24,0x57,0xe0,0x82,0xa5,0xfe,0x44,0xb2,0x81,0x36,0x44,0x24,0xb8,0xb6,0x9c,
	0x23,0x3a,0x98,0xaa,0x46,0x0d,0x0b,0xa8,0x36,0x85,0x94,0x60,0x53,0x23,0x84,0x8a
};

/**
 * SHA256 hash of 8-byte data 0x1122334455667788 with version 0x24.
 */
const uint8_t PCR_TESTING_SHA256_8BYTE_DATA_VERSIONED[] = {
	0x91,0xf5,0x3f,0x1c,0x6f,0x0a,0xf0,0xad,0xe2,0x74,0x45,0xcd,0x38,0x70,0x48,0xdd,
	0xfd,0xa6,0x38,0x3c,0xf4,0x39,0xc3,0x6c,0x2e,0x4b,0x1c,0xc3,0x88,0xdf,0x2c,0xee
};

/**
 * SHA256 hash of 8-byte data 0x1122334455667788 with event type 0xaabbccdd and version 0x24.
 */
const uint8_t PCR_TESTING_SHA256_8BYTE_DATA_VERSIONED_WITH_EVENT[] = {
	0x5b,0x0b,0x10,0x4b,0x2b,0x95,0xca,0xdd,0x76,0xf4,0x74,0x9e,0xea,0x94,0x85,0xc4,
	0x20,0xae,0xae,0xd2,0xec,0x01,0xdd,0x09,0x8b,0x40,0x5d,0x1b,0x62,0x64,0xec,0x98
};

/**
 * SHA256 hash of HASH_TESTING_FULL_BLOCK_512 including event type 0xaabbccdd.
 */
const uint8_t PCR_TESTING_SHA256_FULL_BLOCK_512_HASH_WITH_EVENT[] = {
	0x1a,0x0d,0x64,0x3f,0xa8,0x93,0xda,0x74,0x86,0xa8,0xdf,0x1c,0xe2,0xf3,0x33,0x6a,
	0xbe,0x8b,0x35,0x92,0x09,0x57,0xe5,0x74,0x00,0x87,0x3f,0xf5,0x48,0xad,0x00,0xc9
};

/**
 * SHA256 hash of HASH_TESTING_FULL_BLOCK_512 with version 0x24.
 */
const uint8_t PCR_TESTING_SHA256_FULL_BLOCK_512_HASH_VERSIONED[] = {
	0xa4,0x59,0x1a,0x4d,0x24,0x3b,0x45,0x48,0x1d,0x1b,0xcc,0x1a,0x11,0x9c,0xf4,0x2e,
	0x7a,0x26,0x44,0x93,0x67,0xbf,0xe4,0x21,0xe1,0x20,0xb4,0x9b,0xbb,0xbc,0x35,0x3b
};

/**
 * SHA256 hash of HASH_TESTING_FULL_BLOCK_512 with version 0x24 including event type 0xaabbccdd.
 */
const uint8_t PCR_TESTING_SHA256_FULL_BLOCK_512_HASH_VERSIONED_WITH_EVENT[] = {
	0xce,0x90,0x2d,0x00,0xb7,0x1e,0x40,0xcb,0x90,0xf1,0x98,0x51,0x09,0xc8,0x71,0x05,
	0xae,0xf0,0x9d,0x4b,0x2f,0xad,0x15,0x31,0x37,0x61,0x81,0x83,0x5d,0x70,0xc7,0xc8
};

/**
 * Extended SHA256 PCR value for the first of three measurements using SHA256_TEST_HASH as the
 * digest.
 */
const uint8_t PCR_TESTING_SHA256_PCR_MEASUREMENT0[] = {
	0xf3,0xb4,0x4f,0x77,0x4c,0x97,0x2c,0xb2,0x2e,0x0c,0x97,0xd6,0x3a,0xb2,0x06,0x92,
	0x51,0xcd,0xdd,0x68,0x6d,0xf8,0x7f,0x98,0x49,0xa9,0x3e,0x5a,0xef,0xb4,0xd0,0x60
};

/**
 * Extended SHA256 PCR value for the second of three measurements using all zeros as the digest.
 */
const uint8_t PCR_TESTING_SHA256_PCR_MEASUREMENT1[] = {
	0x53,0x7b,0x62,0xb5,0xcb,0xd4,0x62,0x3f,0xf2,0x42,0x88,0x29,0xfb,0x18,0xe9,0x4b,
	0x26,0xe6,0xce,0x22,0xa8,0x2e,0x97,0x29,0x78,0x9c,0x2e,0xc8,0xe5,0x1b,0xf7,0x46
};

/**
 * Extended SHA256 PCR value for the last of three measurements using SHA256_TEST2_HASH as the
 * digest.
 */
const uint8_t PCR_TESTING_SHA256_PCR_MEASUREMENT2[] = {
	0x15,0x90,0xc5,0x39,0xb4,0x2d,0x8d,0xfd,0x43,0xe3,0xd4,0x72,0x3d,0xd9,0xd2,0x2b,
	0xf7,0xb8,0xf7,0x5d,0x68,0x2c,0x73,0xf6,0xbc,0xf4,0x61,0x31,0xc1,0xfe,0x2e,0x53
};

/**
 * Extended SHA256 PCR value for the first of two measurements using all zeros as the digest.
 */
const uint8_t PCR_TESTING_SHA256_PCR_NONE_VALID_MEASUREMENT0[] = {
	0xf5,0xa5,0xfd,0x42,0xd1,0x6a,0x20,0x30,0x27,0x98,0xef,0x6e,0xd3,0x09,0x97,0x9b,
	0x43,0x00,0x3d,0x23,0x20,0xd9,0xf0,0xe8,0xea,0x98,0x31,0xa9,0x27,0x59,0xfb,0x4b
};

/**
 * Extended SHA256 PCR value for the second of two measurements using all zeros as the digest.
 */
const uint8_t PCR_TESTING_SHA256_PCR_NONE_VALID_MEASUREMENT1[] = {
	0x7a,0x05,0x01,0xf5,0x95,0x7b,0xdf,0x9c,0xb3,0xa8,0xff,0x49,0x66,0xf0,0x22,0x65,
	0xf9,0x68,0x65,0x8b,0x7a,0x9c,0x62,0x64,0x2c,0xba,0x11,0x65,0xe8,0x66,0x42,0xf5
};

/**
 * SHA384 hash of event type 0xaabbccdd.
 */
const uint8_t PCR_TESTING_SHA384_EVENT_TYPE[] = {
	0x65,0xc1,0x2e,0xab,0x44,0x5f,0x05,0xa3,0xda,0x34,0x12,0x96,0xa6,0x7a,0x8f,0xf8,
	0xdd,0xca,0xe5,0x84,0x58,0x0f,0x24,0xfc,0xb4,0x8a,0x61,0xdd,0x0f,0x98,0xbd,0x72,
	0x64,0x45,0xbb,0xd5,0x28,0x41,0x9a,0xe1,0x30,0xbc,0xe2,0x1c,0xeb,0xfc,0xfb,0x54
};

/**
 * SHA384 hash of version 0x24.
 */
const uint8_t PCR_TESTING_SHA384_VERSIONED[] = {
	0xb1,0x58,0x3f,0x4b,0x2e,0x1b,0xf5,0x3f,0xc3,0x1e,0x9d,0xfb,0x8e,0x8d,0x94,0x5a,
	0x62,0x95,0x5d,0xa7,0x09,0xf2,0x80,0xa9,0x06,0x6a,0xa8,0xf3,0x1e,0xf6,0x88,0xd6,
	0x5e,0x0e,0x98,0x16,0xa5,0xf1,0xf1,0x13,0x63,0xb3,0x89,0x88,0x20,0xbd,0x15,0x76
};

/**
 * SHA384 hash of 1-byte data 0x11.
 */
const uint8_t PCR_TESTING_SHA384_1BYTE_DATA[] = {
	0x74,0x27,0x78,0xad,0x96,0xc7,0xc7,0x33,0x14,0x5a,0x22,0x87,0x99,0x94,0xe0,0x35,
	0x73,0xfc,0xda,0x24,0x47,0xa3,0xf8,0x06,0xea,0x08,0x36,0xbd,0xdb,0xc7,0x7f,0xbb,
	0xee,0x25,0x91,0xc2,0x88,0x8e,0xfd,0xa4,0x2f,0x99,0x36,0x92,0x21,0x49,0x2c,0x3d
};

/**
 * SHA384 hash of 1-byte data 0x11 with event type 0xaabbccdd.
 */
const uint8_t PCR_TESTING_SHA384_1BYTE_DATA_WITH_EVENT[] = {
	0x4a,0x69,0x6f,0xf8,0xee,0x2e,0x31,0x88,0xf5,0xd3,0xa7,0xa9,0x8d,0xfd,0xf5,0x0c,
	0x3a,0x92,0x1c,0x7f,0x84,0xb4,0x91,0x51,0xaa,0x7b,0x60,0x8c,0xed,0xed,0xf0,0xba,
	0x84,0x60,0xf9,0x45,0x52,0xf3,0xbb,0xdc,0x05,0x1a,0x91,0xc3,0x87,0x40,0x3e,0xf7
};

/**
 * SHA384 hash of 1-byte data 0x11 with version 0x24.
 */
const uint8_t PCR_TESTING_SHA384_1BYTE_DATA_VERSIONED[] = {
	0xe8,0x81,0xaf,0x7a,0xae,0xc7,0xc5,0xf0,0x65,0xef,0xfb,0xf1,0xec,0xc5,0x56,0x52,
	0xaa,0x60,0x4c,0x98,0x46,0xc3,0x47,0x42,0xdc,0x9e,0x4e,0xb1,0x25,0x8a,0xac,0xc1,
	0xb8,0xc6,0xab,0x4f,0x45,0x87,0xa6,0x1f,0xe0,0x91,0x40,0x6a,0xbd,0x44,0xec,0x31
};

/**
 * SHA384 hash of 1-byte data 0x11 with event type 0xaabbccdd and version 0x24.
 */
const uint8_t PCR_TESTING_SHA384_1BYTE_DATA_VERSIONED_WITH_EVENT[] = {
	0x76,0x56,0x30,0x1e,0xc7,0xe8,0x7d,0x71,0x30,0x6e,0xbe,0xe8,0x11,0xb1,0x48,0x9a,
	0xac,0xa1,0x91,0x79,0x83,0xfb,0xc0,0xa3,0x3a,0xa8,0xdf,0x70,0x27,0x15,0x3a,0x83,
	0xb8,0xf6,0x10,0x03,0x2b,0xf8,0xa4,0x1a,0xfb,0xae,0x15,0xe2,0x90,0x34,0x99,0xdd
};

/**
 * SHA384 hash of 2-byte data 0x1122.
 */
const uint8_t PCR_TESTING_SHA384_2BYTE_DATA[] = {
	0xe4,0x14,0x0d,0x8b,0xc4,0x38,0x9c,0x32,0xd1,0x6c,0xd0,0x2c,0x49,0xe9,0xd7,0x90,
	0xda,0x13,0x98,0x02,0x44,0x8f,0x13,0x75,0xcd,0x9c,0xd1,0x60,0xcb,0xd8,0xb7,0x4c,
	0xe8,0xd3,0xc4,0x25,0x74,0x4c,0xd1,0xbf,0xcd,0xa4,0xaa,0xde,0x0e,0x66,0x04,0xc7
};

/**
 * SHA384 hash of 2-byte data 0x1122 with event type 0xaabbccdd.
 */
const uint8_t PCR_TESTING_SHA384_2BYTE_DATA_WITH_EVENT[] = {
	0x3c,0x29,0xde,0xd3,0x41,0x25,0x75,0x0d,0xae,0x1f,0x0a,0x7b,0x2f,0x91,0x51,0x9b,
	0x5e,0x78,0x63,0xf1,0x6d,0xf3,0xf6,0xf1,0x75,0x96,0xad,0x65,0xbc,0x13,0xa9,0x13,
	0xb8,0x04,0x8b,0x1b,0xf6,0x51,0xfa,0xbf,0xc7,0x90,0xc1,0x4f,0x47,0x18,0xef,0x74
};

/**
 * SHA384 hash of 2-byte data 0x1122 with version 0x24.
 */
const uint8_t PCR_TESTING_SHA384_2BYTE_DATA_VERSIONED[] = {
	0xc6,0xea,0xa7,0x48,0xa2,0x4b,0xcf,0x19,0xac,0x9a,0xa8,0x01,0xed,0x74,0xf5,0xbb,
	0x9e,0x1c,0xae,0x52,0x1a,0xa1,0x6c,0x5d,0x4f,0x88,0x45,0x76,0xbb,0x4e,0x4a,0xa0,
	0xff,0xf3,0x91,0x78,0x3a,0xc9,0x09,0xb2,0x5c,0xad,0x2d,0x3e,0xc3,0xd2,0x7e,0xf3
};

/**
 * SHA384 hash of 2-byte data 0x1122 with event type 0xaabbccdd and version 0x24.
 */
const uint8_t PCR_TESTING_SHA384_2BYTE_DATA_VERSIONED_WITH_EVENT[] = {
	0x86,0x9d,0x2b,0x45,0x88,0x1f,0x14,0x12,0x59,0x46,0x5b,0x8e,0x19,0x37,0x31,0x4e,
	0x3a,0x60,0x34,0x0a,0xbe,0xe9,0xd9,0xd2,0x50,0x2d,0xda,0x62,0x23,0x5a,0xb9,0xa7,
	0xec,0xe7,0x17,0x22,0xee,0x87,0x9e,0x84,0xfb,0x3f,0x6e,0x6a,0xe8,0xf9,0x69,0x3c
};

/**
 * SHA384 hash of 4-byte data 0x11223344.
 */
const uint8_t PCR_TESTING_SHA384_4BYTE_DATA[] = {
	0xa5,0x6f,0x05,0x5b,0x3e,0xe1,0x8d,0x2e,0x68,0x85,0xc4,0xdf,0xaf,0x17,0x47,0xc3,
	0x25,0xb1,0xe0,0xab,0x59,0xa0,0x9b,0x7e,0xf6,0x48,0x84,0xf7,0x32,0x40,0xcb,0xee,
	0xa7,0x9e,0x89,0xed,0xdf,0x4c,0xd2,0x34,0xdd,0x56,0x16,0x63,0x3e,0x22,0x1b,0xc9
};

/**
 * SHA384 hash of 4-byte data 0x11223344 with event type 0xaabbccdd.
 */
const uint8_t PCR_TESTING_SHA384_4BYTE_DATA_WITH_EVENT[] = {
	0xd9,0x8b,0xb6,0x2a,0x28,0x35,0xf6,0x69,0x9b,0xbe,0xbd,0xe3,0xd8,0x6e,0x4c,0x99,
	0xb5,0x06,0xc2,0xbb,0x7e,0x71,0x09,0xdf,0xd8,0x08,0x25,0xe2,0xae,0x7c,0xf9,0x19,
	0x9a,0x83,0x90,0x02,0x48,0x63,0x2c,0x40,0x96,0x27,0x18,0x30,0xec,0x82,0x35,0xfe
};

/**
 * SHA384 hash of 4-byte data 0x11223344 with version 0x24.
 */
const uint8_t PCR_TESTING_SHA384_4BYTE_DATA_VERSIONED[] = {
	0x40,0x81,0x7e,0x81,0xfe,0xde,0x02,0xb0,0xb3,0xdf,0xff,0x3e,0xad,0xba,0x16,0x24,
	0x65,0x41,0x37,0xc5,0x6a,0x9a,0x42,0xfc,0xa2,0x5b,0x42,0xf5,0x6a,0x86,0x26,0xb7,
	0x6d,0x0a,0xdd,0x6f,0x77,0x52,0xdc,0x9f,0x71,0x3c,0xfe,0x48,0x41,0xfa,0x02,0x48
};

/**
 * SHA384 hash of 4-byte data 0x11223344 with event type 0xaabbccdd and version 0x24.
 */
const uint8_t PCR_TESTING_SHA384_4BYTE_DATA_VERSIONED_WITH_EVENT[] = {
	0x40,0x5c,0xc2,0xfd,0x51,0xd9,0xeb,0xc6,0x6d,0x13,0x16,0xf4,0x97,0x8a,0xbe,0x4b,
	0x9d,0xde,0xa4,0x4c,0xe1,0xc1,0xe6,0x5a,0x65,0xf4,0x3b,0x5f,0xc3,0xf0,0x0a,0x36,
	0xf5,0xcd,0x5f,0xd9,0xce,0xaf,0x03,0xb4,0x29,0x38,0x48,0xca,0xaf,0x58,0x6a,0x42
};

/**
 * SHA384 hash of 8-byte data 0x1122334455667788.
 */
const uint8_t PCR_TESTING_SHA384_8BYTE_DATA[] = {
	0x2a,0xa2,0x2c,0xbc,0x7a,0xdb,0xd3,0x81,0x5e,0xf7,0x6c,0x7c,0x6b,0x6b,0xfa,0x04,
	0xa8,0x77,0xe3,0x25,0x6c,0xb2,0x3a,0x3e,0xc3,0x36,0xf7,0xf1,0xcd,0xd4,0x50,0x8f,
	0xc0,0x62,0x9b,0x8f,0x3e,0x70,0xda,0x66,0xa2,0x8e,0x83,0x52,0xa2,0x6d,0x6a,0xbb
};

/**
 * SHA384 hash of 8-byte data 0x1122334455667788 with event type 0xaabbccdd.
 */
const uint8_t PCR_TESTING_SHA384_8BYTE_DATA_WITH_EVENT[] = {
	0x0d,0x60,0x0d,0x58,0xb1,0x74,0x81,0xea,0x7c,0x77,0x6c,0x2c,0x27,0xdb,0xd9,0x35,
	0xcb,0xf1,0x97,0x5e,0x0e,0xc0,0xaf,0xa6,0xf2,0x4c,0x38,0xb3,0x1c,0x52,0x04,0xf6,
	0xe8,0x35,0xf3,0xab,0xc2,0xfe,0x2d,0x9b,0x78,0x2a,0x3e,0x86,0x66,0x2f,0x56,0x97
};

/**
 * SHA384 hash of 8-byte data 0x1122334455667788 with version 0x24.
 */
const uint8_t PCR_TESTING_SHA384_8BYTE_DATA_VERSIONED[] = {
	0x58,0x00,0x60,0xea,0x81,0x92,0x27,0x14,0x2a,0x1d,0x19,0x95,0x59,0xe2,0x0e,0xf4,
	0xf8,0x7f,0xe9,0xc9,0x74,0xfb,0x5f,0xdd,0xfc,0x8b,0xca,0xa7,0x2a,0x2f,0xf0,0xab,
	0x67,0x01,0x5d,0xc6,0x97,0xe2,0x74,0xda,0x36,0x7d,0x8e,0x5b,0x51,0xc3,0x78,0x6d
};

/**
 * SHA384 hash of 8-byte data 0x1122334455667788 with event type 0xaabbccdd and version 0x24.
 */
const uint8_t PCR_TESTING_SHA384_8BYTE_DATA_VERSIONED_WITH_EVENT[] = {
	0x60,0x43,0x96,0xd5,0xe0,0x39,0x62,0xb6,0x39,0xff,0xa5,0x0d,0xf8,0x72,0x77,0x66,
	0xdb,0x1b,0x87,0xdb,0xce,0x7d,0x82,0xad,0xd2,0x78,0xa0,0x87,0x85,0x13,0x76,0xdd,
	0x1c,0x85,0x90,0xfc,0x66,0x7e,0xb7,0x9e,0xa8,0xc6,0x1f,0x49,0xff,0xed,0x2a,0xf0
};

/**
 * SHA384 hash of HASH_TESTING_FULL_BLOCK_512 including event type 0xaabbccdd.
 */
const uint8_t PCR_TESTING_SHA384_FULL_BLOCK_512_HASH_WITH_EVENT[] = {
	0x5d,0xd2,0x0c,0xbe,0x7d,0x69,0x77,0x8b,0x51,0x1a,0xe5,0x2a,0xa6,0x22,0x60,0xd5,
	0x4a,0x8a,0x6e,0x67,0x95,0xf9,0x9b,0x8e,0x3d,0xd2,0xac,0x6d,0x33,0xe4,0xa7,0xa1,
	0x7d,0xbf,0x3b,0xda,0x01,0x27,0x1a,0x15,0x5e,0x07,0xe7,0xd5,0x17,0x6e,0x40,0x28
};

/**
 * SHA384 hash of HASH_TESTING_FULL_BLOCK_512 with version 0x24.
 */
const uint8_t PCR_TESTING_SHA384_FULL_BLOCK_512_HASH_VERSIONED[] = {
	0x1c,0x28,0x90,0x22,0x37,0x99,0xe7,0x35,0xdb,0x01,0xc3,0x47,0x91,0x99,0x41,0x44,
	0xe9,0x64,0x2e,0xda,0x91,0xd5,0x47,0x8d,0xd8,0xd8,0x4a,0x62,0xdb,0x04,0x81,0x67,
	0x7d,0xc3,0xeb,0xb4,0xff,0x8d,0x17,0x92,0xa5,0x07,0x4d,0xa7,0xd4,0xcf,0xde,0x58
};

/**
 * SHA384 hash of HASH_TESTING_FULL_BLOCK_512 with version 0x24 including event type 0xaabbccdd.
 */
const uint8_t PCR_TESTING_SHA384_FULL_BLOCK_512_HASH_VERSIONED_WITH_EVENT[] = {
	0x32,0x2d,0x84,0xd5,0x58,0x35,0x1b,0x31,0x95,0x8d,0x04,0x25,0x09,0x12,0x3a,0x77,
	0x69,0x0c,0xc4,0x25,0xaf,0x6e,0x91,0x27,0xee,0xb7,0x49,0x8d,0xa6,0x53,0x12,0x68,
	0xb8,0x37,0xb6,0x9d,0x44,0x61,0x1f,0xfa,0x33,0x66,0xe9,0xd4,0x97,0x20,0x21,0xb4
};

/**
 * Extended SHA384 PCR value for the first of three measurements using SHA384_TEST_HASH as the
 * digest.
 */
const uint8_t PCR_TESTING_SHA384_PCR_MEASUREMENT0[] = {
	0x5b,0x85,0x5b,0x16,0xc7,0x22,0x54,0xcf,0x09,0xf1,0xd7,0x07,0x81,0xff,0x7a,0x00,
	0x14,0xf0,0x6d,0x7d,0x79,0xa9,0x77,0x08,0x68,0x4d,0x7e,0xd9,0x27,0x27,0x7a,0x4a,
	0x76,0xc9,0xd0,0x04,0x99,0xcd,0x6f,0x26,0x98,0x94,0x32,0xa6,0x3d,0x25,0xe0,0xf3
};

/**
 * Extended SHA384 PCR value for the second of three measurements using all zeros as the digest.
 */
const uint8_t PCR_TESTING_SHA384_PCR_MEASUREMENT1[] = {
	0x06,0x0a,0x17,0xe7,0x10,0xb9,0x13,0x42,0xd8,0x14,0xf5,0xd5,0x0a,0xdb,0x5c,0x2f,
	0xb8,0xea,0xfb,0x53,0x78,0xcc,0xf6,0x5f,0xc7,0xc9,0xb7,0xd1,0xb9,0x61,0x21,0xa0,
	0xbc,0xd6,0xaf,0x32,0xc6,0xc7,0x4e,0x8b,0x19,0xf7,0x61,0x3d,0xff,0xd2,0x8c,0xc9
};

/**
 * Extended SHA384 PCR value for the last of three measurements using SHA384_TEST2_HASH as the
 * digest.
 */
const uint8_t PCR_TESTING_SHA384_PCR_MEASUREMENT2[] = {
	0xd4,0xc5,0x0b,0xb8,0x49,0xec,0x5f,0x3f,0xfc,0xad,0xbe,0x32,0x25,0xe4,0x34,0x2a,
	0xc4,0xba,0xef,0x3f,0x9d,0x65,0x28,0x8b,0x25,0xa5,0xb1,0x90,0x57,0x02,0xac,0x55,
	0xea,0xf4,0x40,0xfb,0xc3,0x34,0x59,0x6d,0x59,0x07,0xe4,0x8c,0x34,0x40,0x87,0xcb
};

/**
 * Extended SHA384 PCR value for the first of two measurements using all zeros as the digest.
 */
const uint8_t PCR_TESTING_SHA384_PCR_NONE_VALID_MEASUREMENT0[] = {
	0xf5,0x7b,0xb7,0xed,0x82,0xc6,0xae,0x4a,0x29,0xe6,0xc9,0x87,0x93,0x38,0xc5,0x92,
	0xc7,0xd4,0x2a,0x39,0x13,0x55,0x83,0xe8,0xcc,0xbe,0x39,0x40,0xf2,0x34,0x4b,0x0e,
	0xb6,0xeb,0x85,0x03,0xdb,0x0f,0xfd,0x6a,0x39,0xdd,0xd0,0x0c,0xd0,0x7d,0x83,0x17
};

/**
 * Extended SHA384 PCR value for the second of two measurements using all zeros as the digest.
 */
const uint8_t PCR_TESTING_SHA384_PCR_NONE_VALID_MEASUREMENT1[] = {
	0x11,0x14,0x31,0x21,0xbe,0xb3,0x65,0xe6,0x38,0x26,0xe7,0xde,0x89,0xf9,0xc7,0x6a,
	0xe1,0x10,0x04,0x11,0xfb,0x96,0x43,0xd1,0x98,0xe7,0x30,0xb7,0x60,0x3a,0x83,0xa4,
	0x97,0x7c,0x76,0xee,0xe6,0xdd,0xf7,0x4f,0xa0,0xb4,0x3f,0xbf,0x49,0x89,0x79,0x78
};

/**
 * SHA512 hash of event type 0xaabbccdd.
 */
const uint8_t PCR_TESTING_SHA512_EVENT_TYPE[] = {
	0x61,0xfc,0xbc,0xfc,0x3b,0xd0,0x8f,0xe3,0x18,0xc5,0x03,0x67,0x8a,0x95,0xd9,0x1f,
	0x6a,0x59,0x2f,0x2c,0x8b,0x8d,0x74,0xb2,0x5b,0x16,0x57,0x9c,0x8e,0x89,0x1e,0x5e,
	0x34,0x16,0x1d,0xc1,0xa6,0xfb,0xbb,0xde,0xcd,0x5e,0x65,0x14,0xe7,0xa6,0xd4,0x02,
	0x71,0xf0,0xf9,0x4d,0xc7,0xd8,0x09,0x10,0xb6,0xb8,0xb2,0x7a,0x8e,0x16,0x51,0x4d
};

/**
 * SHA512 hash of version 0x24.
 */
const uint8_t PCR_TESTING_SHA512_VERSIONED[] = {
	0x84,0x0c,0xfc,0x62,0x85,0x87,0x84,0x64,0xc3,0x6c,0x9a,0xa8,0x19,0xd8,0x37,0x37,
	0x29,0xed,0xa1,0x4c,0x3e,0x70,0x1f,0xd3,0x7a,0xfe,0xc1,0xd5,0xba,0xa2,0x89,0x39,
	0x44,0xc6,0x96,0xfc,0x40,0x17,0xa5,0x20,0xab,0xfb,0xb1,0x34,0x7b,0x62,0xe6,0xb8,
	0x58,0x21,0x1d,0x3e,0xa7,0xc7,0xdd,0x26,0x31,0x96,0x01,0xfd,0xe1,0x19,0xc3,0xb4
};

/**
 * SHA512 hash of 1-byte data 0x11.
 */
const uint8_t PCR_TESTING_SHA512_1BYTE_DATA[] = {
	0x4d,0xab,0x24,0x9e,0x3e,0xf1,0xf2,0x7d,0x32,0x3f,0xea,0x6d,0x44,0x3d,0xd6,0xf2,
	0xab,0x36,0x55,0xe2,0xb4,0xfa,0xf1,0x07,0x8c,0x7a,0xd6,0xaf,0x83,0xa1,0x8f,0x2e,
	0xfb,0xbe,0xd8,0x8b,0x2a,0x63,0xb1,0xaf,0xff,0x3d,0x19,0x6f,0x8b,0x97,0x07,0xf2,
	0x8c,0xfa,0x8c,0xc0,0x85,0x79,0xdb,0x54,0x28,0xd2,0xa5,0xdc,0x1c,0x5c,0x9d,0x63
};

/**
 * SHA512 hash of 1-byte data 0x11 with event type 0xaabbccdd.
 */
const uint8_t PCR_TESTING_SHA512_1BYTE_DATA_WITH_EVENT[] = {
	0xa8,0x65,0x7a,0xd9,0x40,0x54,0x8f,0x9c,0x3b,0x88,0x49,0x0f,0xd4,0x21,0x4e,0xee,
	0x7c,0xe6,0x34,0x77,0x0f,0xe6,0xd0,0xba,0x81,0xfd,0x5f,0x21,0xae,0xa7,0xdc,0x3f,
	0xb3,0x94,0x4f,0xa2,0x9b,0x49,0xfa,0x01,0x6d,0x09,0x54,0x63,0xf0,0x38,0x38,0xe2,
	0x1a,0xc1,0xbf,0xd2,0x28,0x19,0xe6,0x32,0xcc,0xb9,0x98,0x8c,0xef,0x24,0x11,0xc9
};

/**
 * SHA512 hash of 1-byte data 0x11 with version 0x24.
 */
const uint8_t PCR_TESTING_SHA512_1BYTE_DATA_VERSIONED[] = {
	0x58,0xfa,0xa7,0x52,0x29,0x91,0x45,0x7d,0x08,0x98,0xb3,0xe7,0xe0,0xd7,0xfb,0xfe,
	0x04,0xb4,0xa2,0x38,0xae,0x2f,0xc6,0x3f,0x76,0xdd,0x42,0x95,0x8e,0xf9,0x6a,0x13,
	0xa6,0xe0,0x9f,0xda,0x02,0x3c,0x7d,0xae,0xa3,0x9e,0x98,0x74,0x93,0x98,0x0f,0xe5,
	0xfc,0x3a,0x83,0x08,0x77,0xad,0x5e,0xeb,0xc9,0x65,0xf4,0x4f,0x4f,0xf7,0x2a,0xcf
};

/**
 * SHA512 hash of 1-byte data 0x11 with event type 0xaabbccdd and version 0x24.
 */
const uint8_t PCR_TESTING_SHA512_1BYTE_DATA_VERSIONED_WITH_EVENT[] = {
	0x30,0xfc,0xbb,0x03,0x59,0x24,0x3f,0x4d,0xb5,0x57,0x29,0xe0,0x99,0x2a,0x0e,0x46,
	0xe8,0x68,0xe1,0x82,0xdf,0xab,0xac,0xec,0x62,0x7c,0x22,0x02,0xee,0x9f,0xe0,0xc6,
	0x04,0x7d,0x42,0xc0,0x93,0xf0,0x68,0x57,0x3a,0xc8,0x8e,0xb7,0x3d,0xc8,0xe6,0xaa,
	0x3a,0x17,0xad,0xe4,0xbb,0x39,0xce,0x1d,0xe2,0x48,0xe4,0x5b,0x47,0xdd,0x40,0xc2
};

/**
 * SHA512 hash of 2-byte data 0x1122.
 */
const uint8_t PCR_TESTING_SHA512_2BYTE_DATA[] = {
	0x5c,0xdd,0xf8,0x99,0xff,0xbe,0x6b,0x2f,0x77,0x5a,0x41,0x18,0x16,0x2d,0xfc,0x70,
	0x56,0xca,0xb5,0x9c,0x06,0xc7,0xaf,0x27,0x4e,0x9f,0xef,0xaa,0x8a,0xf0,0x32,0x10,
	0x58,0x05,0x81,0x8b,0x25,0xb6,0x09,0x84,0xff,0x09,0xc1,0x9f,0x97,0xae,0x5e,0xbf,
	0x27,0x13,0xa1,0x46,0xf8,0x1f,0x4a,0x9e,0x58,0x02,0xa4,0x9d,0xef,0x48,0xcc,0xa1
};

/**
 * SHA512 hash of 2-byte data 0x1122 with event type 0xaabbccdd.
 */
const uint8_t PCR_TESTING_SHA512_2BYTE_DATA_WITH_EVENT[] = {
	0xbf,0x3c,0xaf,0x00,0xdd,0x07,0xaa,0xf1,0x74,0xab,0x99,0x9c,0x3d,0x74,0x68,0xc3,
	0x4c,0xfd,0x24,0xd2,0x64,0x8b,0x94,0xb3,0x28,0x62,0x5c,0x01,0x4e,0xc4,0xd3,0x79,
	0x3a,0x8c,0x20,0xe1,0xf7,0x71,0xcb,0x65,0x55,0xe2,0x76,0x21,0x28,0x47,0xc4,0x60,
	0x62,0x06,0x2c,0xb2,0xb6,0x2d,0x2e,0xd0,0xca,0x4d,0xfd,0xb0,0xc1,0x1b,0x4c,0x77
};

/**
 * SHA512 hash of 2-byte data 0x1122 with version 0x24.
 */
const uint8_t PCR_TESTING_SHA512_2BYTE_DATA_VERSIONED[] = {
	0xc3,0x74,0x2a,0x49,0x83,0xb1,0x63,0xf5,0xa8,0xbd,0x3f,0x1a,0x84,0x01,0x86,0x77,
	0x51,0x88,0xc6,0x43,0x62,0xa4,0x20,0x10,0xf5,0xb7,0x52,0x3e,0xf2,0x6d,0x1a,0x0f,
	0x3c,0x93,0x5a,0x6d,0x49,0x41,0xe9,0x4b,0x96,0xbb,0x3d,0x06,0x2c,0xe7,0xe0,0xdd,
	0x3d,0x7b,0xe8,0x22,0x20,0x9e,0x84,0x58,0xc5,0x6e,0x29,0x1a,0xeb,0x29,0x54,0x3d
};

/**
 * SHA512 hash of 2-byte data 0x1122 with event type 0xaabbccdd and version 0x24.
 */
const uint8_t PCR_TESTING_SHA512_2BYTE_DATA_VERSIONED_WITH_EVENT[] = {
	0xa3,0x20,0xcc,0xd6,0xe1,0x85,0x94,0xd7,0xe5,0xc8,0xf6,0x34,0x80,0x02,0xcc,0x71,
	0x1e,0x55,0xaa,0x39,0x42,0x95,0xd6,0xcb,0x7c,0xc6,0xa4,0xe1,0x7a,0x19,0x09,0x6d,
	0xf0,0xa5,0x00,0x63,0xe2,0x78,0x46,0xab,0xc0,0xe5,0xd5,0x6d,0x03,0x9f,0x44,0x43,
	0x6b,0x43,0xa1,0xb0,0xe5,0x67,0x89,0x41,0xe2,0x67,0xab,0xec,0x6a,0xd3,0x02,0xec
};

/**
 * SHA512 hash of 4-byte data 0x11223344.
 */
const uint8_t PCR_TESTING_SHA512_4BYTE_DATA[] = {
	0x1a,0x7f,0x65,0x62,0xdc,0x41,0x82,0xb6,0x12,0x19,0xca,0x86,0xc7,0x01,0x21,0xaa,
	0x91,0x0e,0x42,0xf9,0x49,0x61,0xbe,0x3e,0xcd,0x0a,0x2f,0xf4,0x12,0x4e,0xd4,0x13,
	0x1b,0x08,0xaf,0xa4,0x41,0xf5,0x81,0xd4,0x63,0xcd,0x30,0x26,0x65,0x69,0xb9,0x88,
	0xfe,0x3c,0xa5,0x3a,0x9a,0x43,0xfd,0x6c,0x64,0x2a,0x7f,0xb9,0xc1,0x3b,0x05,0x7b
};

/**
 * SHA512 hash of 4-byte data 0x11223344 with event type 0xaabbccdd.
 */
const uint8_t PCR_TESTING_SHA512_4BYTE_DATA_WITH_EVENT[] = {
	0xf8,0x08,0x20,0xa0,0x77,0x37,0x28,0xa3,0xf2,0xbe,0x9d,0xac,0xb2,0x03,0x48,0x41,
	0xa5,0xfd,0xbc,0xf1,0xb6,0x1a,0x19,0xcb,0x24,0xee,0x03,0x35,0xc1,0xc7,0x78,0x49,
	0xd4,0x52,0xb3,0x16,0x7e,0xe5,0xa2,0xad,0x0c,0xd2,0x3d,0xf1,0xc9,0x02,0x76,0x0c,
	0xae,0x89,0x14,0xfc,0xa9,0x75,0xde,0x43,0xd5,0xb6,0xaf,0x79,0x09,0xcd,0xd9,0x79
};

/**
 * SHA512 hash of 4-byte data 0x11223344 with version 0x24.
 */
const uint8_t PCR_TESTING_SHA512_4BYTE_DATA_VERSIONED[] = {
	0x44,0x23,0xed,0x99,0xe4,0xc1,0xee,0x3d,0x51,0x6a,0xc4,0x6e,0xc7,0x2d,0x1b,0x4b,
	0x7a,0x6f,0x3b,0xca,0x42,0x50,0xc1,0x23,0x4d,0xf6,0x60,0xb1,0x31,0x9d,0x64,0xae,
	0x53,0x51,0xed,0xfd,0x74,0xa3,0xe1,0x70,0x5e,0x6b,0x62,0xb7,0x3b,0xea,0x0d,0xca,
	0x8b,0x10,0xc9,0x09,0xcd,0x99,0xd8,0x85,0x40,0x62,0xcd,0x0f,0xc2,0xd0,0x8f,0x6e
};

/**
 * SHA512 hash of 4-byte data 0x11223344 with event type 0xaabbccdd and version 0x24.
 */
const uint8_t PCR_TESTING_SHA512_4BYTE_DATA_VERSIONED_WITH_EVENT[] = {
	0xe9,0xaa,0x73,0x8c,0xe8,0x5c,0xc5,0xb8,0x70,0xf1,0xef,0x02,0x99,0x6f,0x30,0x75,
	0x99,0x11,0xee,0x85,0x60,0x7c,0x26,0x54,0x86,0x87,0xce,0x41,0xb1,0x9c,0x92,0x73,
	0xae,0xa4,0x89,0x9a,0xc7,0x2a,0x38,0xb0,0x78,0x9e,0xf8,0x53,0x7b,0xd6,0x8c,0xa5,
	0xb8,0xf4,0x61,0x8f,0x16,0x12,0x52,0x9c,0x6a,0x40,0x27,0x79,0x6d,0x86,0xa4,0x5c
};

/**
 * SHA512 hash of 8-byte data 0x1122334455667788.
 */
const uint8_t PCR_TESTING_SHA512_8BYTE_DATA[] = {
	0x02,0x19,0x9a,0x71,0xd7,0x2c,0x35,0xba,0x7f,0x20,0x34,0x53,0x08,0x82,0x85,0x45,
	0x78,0x61,0x1d,0x05,0x98,0x03,0xf5,0x0f,0xf4,0x70,0xbc,0xed,0xee,0xde,0xe3,0x30,
	0xbc,0xaa,0x22,0xf9,0xff,0x42,0x5a,0xb1,0x13,0xdf,0xcd,0x84,0xae,0x1d,0x9c,0x29,
	0x57,0x8f,0x07,0x12,0xe8,0xc2,0xbe,0x87,0xab,0xfe,0xa9,0xfb,0x28,0x05,0x6d,0xff
};

/**
 * SHA512 hash of 8-byte data 0x1122334455667788 with event type 0xaabbccdd.
 */
const uint8_t PCR_TESTING_SHA512_8BYTE_DATA_WITH_EVENT[] = {
	0x16,0xef,0x5c,0x5f,0x09,0xf2,0xc8,0x22,0xc2,0x34,0x87,0x05,0xda,0x61,0x19,0xc1,
	0x6a,0x08,0x7c,0x74,0x34,0x4f,0x62,0x90,0x7f,0x97,0xff,0x1e,0xa2,0xbe,0xfd,0x7e,
	0xf8,0x18,0x66,0xfa,0x4e,0x21,0xde,0x03,0x94,0x34,0x95,0x12,0xd4,0x2f,0x42,0xa9,
	0x2e,0x6f,0xa6,0x85,0x3d,0xa6,0xd5,0x5b,0xa2,0x7a,0x33,0x0b,0x78,0x80,0x7f,0xdc
};

/**
 * SHA512 hash of 8-byte data 0x1122334455667788 with version 0x24.
 */
const uint8_t PCR_TESTING_SHA512_8BYTE_DATA_VERSIONED[] = {
	0x1f,0x87,0x79,0x0b,0x54,0xda,0xd2,0x8a,0xc3,0xbf,0x53,0x54,0x70,0x66,0x81,0x24,
	0xe7,0x02,0xeb,0x13,0x12,0xa0,0x5c,0x84,0x1e,0xcc,0x6e,0xe4,0x47,0x26,0xe6,0xf9,
	0xc5,0xd4,0x71,0xda,0xc4,0xf1,0x8e,0xad,0x0a,0x81,0x3d,0x58,0x65,0x99,0xac,0xcf,
	0x20,0x58,0x58,0x5f,0x30,0xbe,0x73,0xe9,0x91,0x1f,0x7d,0xd7,0x9d,0x6d,0xd9,0x1e
};

/**
 * SHA512 hash of 8-byte data 0x1122334455667788 with event type 0xaabbccdd and version 0x24.
 */
const uint8_t PCR_TESTING_SHA512_8BYTE_DATA_VERSIONED_WITH_EVENT[] = {
	0x14,0x6d,0x84,0x2a,0xb7,0xad,0x5e,0x9e,0xe9,0x87,0xa1,0x7a,0x53,0x03,0xf6,0x63,
	0x0a,0x6a,0x22,0x40,0x13,0x0c,0x9f,0xf5,0xd4,0x1a,0xfb,0x6d,0x99,0x06,0x57,0x7f,
	0xf6,0x3a,0xd3,0xed,0x90,0xdd,0xd9,0x48,0x85,0x42,0x01,0x35,0x5e,0x79,0x8d,0x23,
	0x0d,0xb4,0x47,0x60,0xc0,0x6d,0x4f,0x89,0x73,0xbb,0x35,0x6b,0xab,0xa2,0x7b,0xd6
};

/**
 * SHA512 hash of HASH_TESTING_FULL_BLOCK_512 including event type 0xaabbccdd.
 */
const uint8_t PCR_TESTING_SHA512_FULL_BLOCK_512_HASH_WITH_EVENT[] = {
	0x2e,0x0f,0x6a,0x8f,0x97,0x96,0x4f,0xd6,0xe2,0xb6,0xf4,0x57,0xc9,0x1e,0xe9,0xd8,
	0x22,0xaa,0x28,0xa7,0x31,0x80,0x74,0x66,0x36,0xb6,0xd5,0xf1,0x36,0xe5,0xd8,0xb2,
	0x07,0x7d,0x53,0x25,0x25,0x1a,0x27,0x5e,0x77,0x10,0x4b,0x4c,0x1e,0x3b,0x0f,0x22,
	0x93,0xdd,0x1a,0x18,0xdc,0x38,0x02,0x61,0x8b,0x42,0x5a,0x46,0x53,0x62,0xe1,0xaf
};

/**
 * SHA512 hash of HASH_TESTING_FULL_BLOCK_512 with version 0x24.
 */
const uint8_t PCR_TESTING_SHA512_FULL_BLOCK_512_HASH_VERSIONED[] = {
	0x01,0xce,0x5b,0x31,0x8f,0x07,0x22,0x2d,0x5b,0xca,0x8e,0x7f,0x17,0x89,0xb4,0x29,
	0x0a,0x86,0x24,0x19,0x53,0x04,0x86,0x9d,0xfc,0x54,0xd5,0x53,0x99,0xd5,0xd3,0x73,
	0xd8,0xed,0xab,0x44,0x5d,0x16,0x91,0x49,0x15,0x90,0x7f,0xbc,0x25,0x67,0x08,0x97,
	0x0f,0x5d,0x55,0x31,0xd8,0x8e,0x3c,0x46,0x61,0x4f,0xac,0x5b,0xb7,0xdf,0x21,0xe7
};

/**
 * SHA512 hash of HASH_TESTING_FULL_BLOCK_512 with version 0x24 including event type 0xaabbccdd.
 */
const uint8_t PCR_TESTING_SHA512_FULL_BLOCK_512_HASH_VERSIONED_WITH_EVENT[] = {
	0xd0,0x5a,0xfa,0xa3,0xa5,0x71,0x25,0xc4,0x2d,0x29,0x25,0x50,0xae,0xc3,0x43,0xa1,
	0x77,0xd6,0xf4,0xc7,0xb1,0x86,0x76,0x2b,0xc5,0xfe,0xa2,0xc3,0x8b,0x2a,0xd0,0x83,
	0xb8,0x47,0x90,0x0a,0x3a,0xe7,0xe8,0x53,0xc4,0x1f,0x3a,0xda,0x2f,0xbe,0x4a,0xbe,
	0x8c,0x30,0x8c,0x93,0xc8,0xa6,0x31,0x52,0xb0,0xd3,0xea,0xc9,0xa2,0xcf,0xb0,0xbc
};

/**
 * Extended SHA512 PCR value for the first of three measurements using SHA512_TEST_HASH as the
 * digest.
 */
const uint8_t PCR_TESTING_SHA512_PCR_MEASUREMENT0[] = {
	0xde,0x87,0x48,0x1d,0xe9,0x74,0xfe,0x2b,0x46,0xc2,0x4d,0xeb,0x7f,0xfd,0xcd,0x24,
	0x88,0x38,0x4e,0x04,0x19,0xd2,0x0e,0xab,0x98,0xf5,0x0d,0x9d,0xd4,0xcc,0xb2,0x42,
	0xfc,0xf2,0x91,0xc6,0xc3,0x40,0x43,0xeb,0xb6,0xcc,0x39,0xdd,0x30,0xa4,0x92,0xd4,
	0x61,0x38,0xe5,0xc7,0x44,0x49,0xd9,0xd9,0x6c,0xa9,0x2b,0x20,0x0e,0x0c,0x2d,0xb5
};

/**
 * Extended SHA512 PCR value for the second of three measurements using all zeros as the digest.
 */
const uint8_t PCR_TESTING_SHA512_PCR_MEASUREMENT1[] = {
	0x2c,0x10,0x15,0x25,0x0d,0xc2,0x33,0x0f,0x60,0xa4,0xb6,0x61,0x9a,0x74,0x7e,0xb8,
	0x2b,0x43,0xe6,0x41,0x28,0xe3,0xd8,0x92,0x38,0x32,0xc0,0x4d,0x41,0x17,0xb5,0xda,
	0x9f,0xfd,0x13,0x8a,0xfa,0xc8,0x73,0xfa,0x82,0xd0,0x3b,0x33,0xca,0xe2,0xdd,0x5b,
	0x3d,0xb2,0x5c,0xd6,0x39,0xc3,0xa0,0xa8,0xbf,0xe3,0x9e,0xd8,0xc6,0xf8,0x99,0xd6
};

/**
 * Extended SHA512 PCR value for the last of three measurements using SHA512_TEST2_HASH as the
 * digest.
 */
const uint8_t PCR_TESTING_SHA512_PCR_MEASUREMENT2[] = {
	0xf5,0xe4,0xbf,0x08,0x5c,0x9d,0xf6,0x00,0xb8,0xd1,0x93,0xbc,0xf2,0x12,0xe9,0xe2,
	0xc2,0x00,0x24,0xfa,0xf8,0xcf,0x43,0x62,0x54,0xb7,0xb5,0x99,0x8c,0x01,0x21,0x54,
	0x93,0x0a,0xe3,0x2d,0x81,0x2b,0xd9,0xa5,0x10,0x99,0x83,0x77,0x07,0x7b,0xd5,0xa8,
	0xca,0xbb,0xbf,0x7d,0x3f,0x9b,0xf7,0x9c,0x88,0xe9,0xe0,0x1f,0x4e,0x69,0x9f,0x35
};

/**
 * Extended SHA512 PCR value for the first of two measurements using all zeros as the digest.
 */
const uint8_t PCR_TESTING_SHA512_PCR_NONE_VALID_MEASUREMENT0[] = {
	0xab,0x94,0x2f,0x52,0x62,0x72,0xe4,0x56,0xed,0x68,0xa9,0x79,0xf5,0x02,0x02,0x90,
	0x5c,0xa9,0x03,0xa1,0x41,0xed,0x98,0x44,0x35,0x67,0xb1,0x1e,0xf0,0xbf,0x25,0xa5,
	0x52,0xd6,0x39,0x05,0x1a,0x01,0xbe,0x58,0x55,0x81,0x22,0xc5,0x8e,0x3d,0xe0,0x7d,
	0x74,0x9e,0xe5,0x9d,0xed,0x36,0xac,0xf0,0xc5,0x5c,0xd9,0x19,0x24,0xd6,0xba,0x11
};

/**
 * Extended SHA512 PCR value for the second of two measurements using all zeros as the digest.
 */
const uint8_t PCR_TESTING_SHA512_PCR_NONE_VALID_MEASUREMENT1[] = {
	0xdf,0x26,0xae,0xa7,0xcc,0x99,0xce,0x0a,0x16,0x18,0xdc,0x53,0x52,0x27,0xbe,0xfb,
	0x29,0xe1,0x0a,0x63,0x18,0xcd,0x03,0x16,0xe9,0x13,0x47,0x25,0x5a,0xc7,0x33,0x9d,
	0x35,0xbe,0x22,0x3d,0x97,0x21,0x29,0x99,0x07,0x24,0xeb,0x0b,0xb7,0x9c,0xdd,0x54,
	0x0d,0xad,0xa8,0x3e,0x73,0xec,0xd5,0x86,0xcf,0xf6,0x1b,0x2f,0x95,0x60,0x7b,0xec
};


/**
 * Dependencies for testing measurements and PCRs.
 */
struct pcr_testing {
	HASH_TESTING_ENGINE hash;				/**< Hash engine for testing measurements. */
	struct hash_engine_mock hash_mock;		/**< Mock for hash operations. */
	struct flash_mock flash;				/**< Mock for flash operations. */
	struct pcr_bank test;					/**< PCR under test. */
};


/**
 * Initialize dependencies for testing PCRs and measurements.
 *
 * @param test The test framework.
 * @param pcr The testing dependencies.
 */
static void pcr_testing_init_dependencies (CuTest *test, struct pcr_testing *pcr)
{
	int status;

	status = HASH_TESTING_ENGINE_INIT (&pcr->hash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&pcr->hash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&pcr->flash);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release dependencies for PCR and measurement testing and validate mocks.
 *
 * @param test The test framework.
 * @param pcr The testing dependencies.
 */
static void pcr_testing_release_dependencies (CuTest *test, struct pcr_testing *pcr)
{
	int status;

	status = hash_mock_validate_and_release (&pcr->hash_mock);
	status |= flash_mock_validate_and_release (&pcr->flash);

	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&pcr->hash);
}

/**
 * Initialize a PCR for testing.
 *
 * @param test The test framework.
 * @param pcr The testing components to initialize.
 * @param num_measurements The number of measurements in the PCR.
 * @param hash_algo The hash algorithm to use for the PCR.
 */
static void pcr_testing_init (CuTest *test, struct pcr_testing *pcr, uint8_t num_measurements,
	enum hash_type hash_algo)
{
	struct pcr_config config = {
		.num_measurements = num_measurements,
		.measurement_algo = hash_algo
	};
	int status;

	pcr_testing_init_dependencies (test, pcr);

	status = pcr_init (&pcr->test, &config);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release a test instance for PCR handling and all dependencies
 *
 * @param test The test framework.
 * @param pcr The testing components to release.
 */
static void pcr_testing_release (CuTest *test, struct pcr_testing *pcr)
{
	pcr_release (&pcr->test);

	pcr_testing_release_dependencies (test, pcr);
}

/**
 * Callback function to test callback based PCR measurement data.
 *
 * @param context The data to return from the callback.  It is assumed to be 4 bytes of data.
 * @param offset The offset for the requested data.
 * @param buffer Output buffer for the data.
 * @param length Size of the output buffer.
 * @param total_len Total length of measurement data.
 *
 * @return The number of bytes returned.
 */
static int pcr_testing_measurement_data_callback (void *context, size_t offset, uint8_t *buffer,
	size_t length, uint32_t *total_len)
{
	int bytes = (4 - offset);

	if (context == NULL) {
		return PCR_NO_MEMORY;
	}

	if (bytes <= 0) {
		return 0;
	}

	bytes = (bytes <= (int) length) ? bytes : (int) length;
	memcpy (buffer, &((uint8_t*) context)[offset], bytes);
	*total_len = 4;

	return bytes;
}

/**
 * Callback function to test callback based PCR measurement data hashing.
 *
 * @param context The data to hash in the callback.  It is assumed to be 4 bytes of data.
 * @param hash The hash engine to use for hashing.
 *
 * @return 0 if the hash was successful or an error code.
 */
static int pcr_testing_measurement_hash_callback (void *context, struct hash_engine *hash)
{
	if (context == NULL) {
		return PCR_NO_MEMORY;
	}

	return hash->update (hash, context, 4);
}

/*******************
 * Test cases
 *******************/

static void pcr_test_init_sha256 (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_config config = {
		.num_measurements = 5,
		.measurement_algo = HASH_TYPE_SHA256
	};
	int status;

	TEST_START;

	pcr_testing_init_dependencies (test, &pcr);

	status = pcr_init (&pcr.test, &config);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_num_measurements (&pcr.test);
	CuAssertIntEquals (test, 5, status);

	status = pcr_get_digest_length (&pcr.test);
	CuAssertIntEquals (test, status, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, pcr_get_hash_algorithm (&pcr.test));

	pcr_testing_release (test, &pcr);
}

static void pcr_test_init_sha384 (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_config config = {
		.num_measurements = 3,
		.measurement_algo = HASH_TYPE_SHA384
	};
	int status;

	TEST_START;

	pcr_testing_init_dependencies (test, &pcr);

	status = pcr_init (&pcr.test, &config);
#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_num_measurements (&pcr.test);
	CuAssertIntEquals (test, 3, status);

	status = pcr_get_digest_length (&pcr.test);
	CuAssertIntEquals (test, status, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, HASH_TYPE_SHA384, pcr_get_hash_algorithm (&pcr.test));

	pcr_testing_release (test, &pcr);
#else
	CuAssertIntEquals (test, PCR_UNSUPPORTED_ALGO, status);

	pcr_testing_release_dependencies (test, &pcr);
#endif
}

static void pcr_test_init_sha512 (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_config config = {
		.num_measurements = 1,
		.measurement_algo = HASH_TYPE_SHA512
	};
	int status;

	TEST_START;

	pcr_testing_init_dependencies (test, &pcr);

	status = pcr_init (&pcr.test, &config);
#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_num_measurements (&pcr.test);
	CuAssertIntEquals (test, 1, status);

	status = pcr_get_digest_length (&pcr.test);
	CuAssertIntEquals (test, status, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, HASH_TYPE_SHA512, pcr_get_hash_algorithm (&pcr.test));

	pcr_testing_release (test, &pcr);
#else
	CuAssertIntEquals (test, PCR_UNSUPPORTED_ALGO, status);

	pcr_testing_release_dependencies (test, &pcr);
#endif
}

static void pcr_test_init_explicit (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_config config = {
		.num_measurements = 0,
		.measurement_algo = HASH_TYPE_SHA256
	};
	int status;

	TEST_START;

	pcr_testing_init_dependencies (test, &pcr);

	status = pcr_init (&pcr.test, &config);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_num_measurements (&pcr.test);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_digest_length (&pcr.test);
	CuAssertIntEquals (test, status, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, pcr_get_hash_algorithm (&pcr.test));

	pcr_testing_release (test, &pcr);
}

static void pcr_test_init_null (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_config config = {
		.num_measurements = 5,
		.measurement_algo = HASH_TYPE_SHA256
	};
	int status;

	TEST_START;

	pcr_testing_init_dependencies (test, &pcr);

	status = pcr_init (NULL, &config);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_init (&pcr.test, NULL);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	pcr_testing_release_dependencies (test, &pcr);
}

static void pcr_test_init_sha1 (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_config config = {
		.num_measurements = 5,
		.measurement_algo = HASH_TYPE_SHA1
	};
	int status;

	TEST_START;

	pcr_testing_init_dependencies (test, &pcr);

	status = pcr_init (&pcr.test, &config);
	CuAssertIntEquals (test, PCR_UNSUPPORTED_ALGO, status);

	pcr_testing_release_dependencies (test, &pcr);
}

static void pcr_test_init_unknown_hash_algorithm (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_config config = {
		.num_measurements = 5,
		.measurement_algo = HASH_TYPE_INVALID
	};
	int status;

	TEST_START;

	pcr_testing_init_dependencies (test, &pcr);

	status = pcr_init (&pcr.test, &config);
	CuAssertIntEquals (test, PCR_UNSUPPORTED_ALGO, status);

	pcr_testing_release_dependencies (test, &pcr);
}

static void pcr_test_release_null (CuTest *test)
{
	TEST_START;

	pcr_release (NULL);
}

static void pcr_test_get_num_measurements_null (CuTest *test)
{
	int status;

	TEST_START;

	status = pcr_get_num_measurements (NULL);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);
}

static void pcr_test_get_digest_length_null (CuTest *test)
{
	int status;

	TEST_START;

	status = pcr_get_digest_length (NULL);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);
}

static void pcr_test_get_hash_algorithm_null (CuTest *test)
{
	int status;

	TEST_START;

	status = pcr_get_hash_algorithm (NULL);
	CuAssertIntEquals (test, HASH_TYPE_INVALID, status);
}

static void pcr_test_check_measurement_index (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_check_measurement_index (&pcr.test, 4);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_check_measurement_index_explicit (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 0, HASH_TYPE_SHA256);

	status = pcr_check_measurement_index (&pcr.test, 0);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_check_measurement_index_bad_index (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_check_measurement_index (&pcr.test, 5);
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_check_measurement_index_bad_index_explicit (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 0, HASH_TYPE_SHA256);

	status = pcr_check_measurement_index (&pcr.test, 1);
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_check_measurement_index_null (CuTest *test)
{
	int status;

	TEST_START;

	status = pcr_check_measurement_index (NULL, 4);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);
}

static void pcr_test_update_digest_sha256 (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_update_digest (&pcr.test, 2, SHA256_TEST_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_TEST_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_digest_sha256_explicit (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 0, HASH_TYPE_SHA256);

	status = pcr_update_digest (&pcr.test, 0, SHA256_TEST_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 0, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_TEST_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
static void pcr_test_update_digest_sha384 (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 3, HASH_TYPE_SHA384);

	status = pcr_update_digest (&pcr.test, 1, SHA384_TEST_HASH, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 1, &measurement);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (SHA384_TEST_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_digest_sha384_explicit (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 0, HASH_TYPE_SHA384);

	status = pcr_update_digest (&pcr.test, 0, SHA384_TEST_HASH, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 0, &measurement);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (SHA384_TEST_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}
#endif

#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
static void pcr_test_update_digest_sha512 (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA512);

	status = pcr_update_digest (&pcr.test, 4, SHA512_TEST_HASH, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 4, &measurement);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (SHA512_TEST_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_digest_sha512_explicit (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 0, HASH_TYPE_SHA512);

	status = pcr_update_digest (&pcr.test, 0, SHA512_TEST_HASH, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 0, &measurement);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (SHA512_TEST_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}
#endif

static void pcr_test_update_digest_twice (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_update_digest (&pcr.test, 2, SHA256_TEST_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_TEST_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_digest (&pcr.test, 2, SHA256_TEST2_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_TEST2_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_digest_null (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_update_digest (NULL, 2, SHA256_TEST_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_update_digest (&pcr.test, 2, NULL, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_digest_wrong_digest_length (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_update_digest (&pcr.test, 2, SHA256_TEST_HASH, SHA256_HASH_LENGTH - 1);
	CuAssertIntEquals (test, PCR_INCORRECT_DIGEST_LENGTH, status);

	status = pcr_update_digest (&pcr.test, 2, SHA256_TEST_HASH, SHA256_HASH_LENGTH + 1);
	CuAssertIntEquals (test, PCR_INCORRECT_DIGEST_LENGTH, status);

	pcr_testing_release (test, &pcr);
}

#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
static void pcr_test_update_digest_sha384_with_sha256 (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 3, HASH_TYPE_SHA384);

	status = pcr_update_digest (&pcr.test, 1, SHA256_TEST_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, PCR_INCORRECT_DIGEST_LENGTH, status);

	pcr_testing_release (test, &pcr);
}
#endif

static void pcr_test_update_digest_invalid_index (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 1, HASH_TYPE_SHA256);

	status = pcr_update_digest (&pcr.test, 2, SHA256_TEST_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_null (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_get_measurement (NULL, 2, &measurement);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_get_measurement (&pcr.test, 2, NULL);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_invalid_index (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_get_measurement (&pcr.test, 6, &measurement);
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_buffer_sha256 (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_FULL_BLOCK_512_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_buffer_sha256_explicit (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 0, HASH_TYPE_SHA256);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 0, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 0, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_FULL_BLOCK_512_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_buffer_sha256_with_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_EVENT, measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA256_FULL_BLOCK_512_HASH_WITH_EVENT,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_buffer_sha256_with_event_no_data (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_tcg_event_type (&pcr.test, 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 1, NULL, 0, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 1, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_EVENT, measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA256_EVENT_TYPE, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
static void pcr_test_update_buffer_sha384 (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 4, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 4, &measurement);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (SHA384_FULL_BLOCK_512_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_buffer_sha384_explicit (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 0, HASH_TYPE_SHA384);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 0, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 0, &measurement);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (SHA384_FULL_BLOCK_512_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_buffer_sha384_with_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_tcg_event_type (&pcr.test, 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 1, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 1, &measurement);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_EVENT, measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA384_FULL_BLOCK_512_HASH_WITH_EVENT,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_buffer_sha384_with_event_no_data (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_tcg_event_type (&pcr.test, 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 1, NULL, 0, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 1, &measurement);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_EVENT, measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA384_EVENT_TYPE, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}
#endif

#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
static void pcr_test_update_buffer_sha512 (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA512);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (SHA512_FULL_BLOCK_512_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_buffer_sha512_explicit (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 0, HASH_TYPE_SHA512);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 0, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 0, &measurement);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (SHA512_FULL_BLOCK_512_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_buffer_sha512_with_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA512);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_EVENT, measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA512_FULL_BLOCK_512_HASH_WITH_EVENT,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_buffer_sha512_with_event_no_data (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA512);

	status = pcr_set_tcg_event_type (&pcr.test, 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 1, NULL, 0, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 1, &measurement);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_EVENT, measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA512_EVENT_TYPE, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}
#endif

static void pcr_test_update_buffer_twice (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_FULL_BLOCK_512_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_1024,
		HASH_TESTING_FULL_BLOCK_1024_LEN, false);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_FULL_BLOCK_1024_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_buffer_with_event_then_update_digest (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_EVENT, measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA256_FULL_BLOCK_512_HASH_WITH_EVENT,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_digest (&pcr.test, 2, SHA256_TEST_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_TEST_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, measurement.measurement_config);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_buffer_null (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_update_buffer (NULL, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_update_buffer (&pcr.test, NULL, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, NULL,
		HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_512,
		0, false);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_buffer_sha256_start_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock,
		HASH_ENGINE_START_SHA256_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash_mock.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	pcr_testing_release (test, &pcr);
}

#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
static void pcr_test_update_buffer_sha384_start_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha384, &pcr.hash_mock,
		HASH_ENGINE_START_SHA384_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash_mock.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA384_FAILED, status);

	pcr_testing_release (test, &pcr);
}
#endif

#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
static void pcr_test_update_buffer_sha512_start_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA512);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha512, &pcr.hash_mock,
		HASH_ENGINE_START_SHA512_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash_mock.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA512_FAILED, status);

	pcr_testing_release (test, &pcr);
}
#endif

static void pcr_test_update_buffer_update_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock, 0);

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock,
		HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_512_LEN));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.cancel, &pcr.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash_mock.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_buffer_finish_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock, 0);

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_512_LEN));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.finish, &pcr.hash_mock,
		HASH_ENGINE_FINISH_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.cancel, &pcr.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash_mock.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_buffer_with_event_sha256_start_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock,
		HASH_ENGINE_START_SHA256_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash_mock.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, true);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, 0, measurement.measurement_config);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_buffer_with_event_event_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock, 0);

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock,
		HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (&event, sizeof (event)), MOCK_ARG (sizeof (event)));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.cancel, &pcr.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash_mock.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, true);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, 0, measurement.measurement_config);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_buffer_with_event_update_buffer_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock, 0);

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&event, sizeof (event)), MOCK_ARG (sizeof (event)));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock,
		HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_512_LEN));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.cancel, &pcr.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash_mock.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, true);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, 0, measurement.measurement_config);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_buffer_with_event_finish_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock, 0);

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&event, sizeof (event)), MOCK_ARG (sizeof (event)));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_512_LEN));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.finish, &pcr.hash_mock,
		HASH_ENGINE_FINISH_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.cancel, &pcr.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash_mock.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, true);
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, 0, measurement.measurement_config);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_buffer_update_digest_fail (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init(test, &pcr, 1, HASH_TYPE_SHA256);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_versioned_buffer_sha256 (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_VERSION, measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA256_FULL_BLOCK_512_HASH_VERSIONED,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_versioned_buffer_sha256_explicit (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 0, HASH_TYPE_SHA256);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 0, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 0, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_VERSION, measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA256_FULL_BLOCK_512_HASH_VERSIONED,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_versioned_buffer_sha256_no_data (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 4, NULL, 0, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 4, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_VERSION, measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA256_VERSIONED, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_versioned_buffer_sha256_with_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_tcg_event_type (&pcr.test, 3, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 3, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 3, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_EVENT | PCR_MEASUREMENT_FLAG_VERSION,
		measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA256_FULL_BLOCK_512_HASH_VERSIONED_WITH_EVENT,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
static void pcr_test_update_versioned_buffer_sha384 (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_VERSION, measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA384_FULL_BLOCK_512_HASH_VERSIONED,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_versioned_buffer_sha384_explicit (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 0, HASH_TYPE_SHA384);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 0, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 0, &measurement);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_VERSION, measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA384_FULL_BLOCK_512_HASH_VERSIONED,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_versioned_buffer_sha384_no_data (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 4, NULL, 0, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 4, &measurement);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_VERSION, measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA384_VERSIONED, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_versioned_buffer_sha384_with_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_tcg_event_type (&pcr.test, 3, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 3, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 3, &measurement);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_EVENT | PCR_MEASUREMENT_FLAG_VERSION,
		measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA384_FULL_BLOCK_512_HASH_VERSIONED_WITH_EVENT,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}
#endif

#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
static void pcr_test_update_versioned_buffer_sha512 (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA512);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_VERSION, measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA512_FULL_BLOCK_512_HASH_VERSIONED,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_versioned_buffer_sha512_explicit (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 0, HASH_TYPE_SHA512);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 0, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 0, &measurement);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_VERSION, measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA512_FULL_BLOCK_512_HASH_VERSIONED,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_versioned_buffer_sha512_no_data (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA512);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 4, NULL, 0, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 4, &measurement);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_VERSION, measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA512_VERSIONED, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_versioned_buffer_sha512_with_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA512);

	status = pcr_set_tcg_event_type (&pcr.test, 3, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 3, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 3, &measurement);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_EVENT | PCR_MEASUREMENT_FLAG_VERSION,
		measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA512_FULL_BLOCK_512_HASH_VERSIONED_WITH_EVENT,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}
#endif

static void pcr_test_update_versioned_buffer_twice (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint32_t data = 0x11223344;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_VERSION, measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA256_FULL_BLOCK_512_HASH_VERSIONED,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data,
		sizeof (data), false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_VERSION, measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA256_4BYTE_DATA_VERSIONED, measurement.digest,
		status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_versioned_buffer_with_event_then_update_digest (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_tcg_event_type (&pcr.test, 3, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 3, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 3, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_EVENT | PCR_MEASUREMENT_FLAG_VERSION,
		measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA256_FULL_BLOCK_512_HASH_VERSIONED_WITH_EVENT,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_digest (&pcr.test, 3, SHA256_TEST_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 3, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_TEST_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, measurement.measurement_config);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_versioned_buffer_null (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_update_versioned_buffer (NULL, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_update_versioned_buffer (&pcr.test, NULL, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_versioned_buffer_sha256_start_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock,
		HASH_ENGINE_START_SHA256_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash_mock.base, 2,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true, version);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, 0, measurement.version);
	CuAssertIntEquals (test, 0, measurement.measurement_config);

	pcr_testing_release (test, &pcr);
}

#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
static void pcr_test_update_versioned_buffer_sha384_start_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha384, &pcr.hash_mock,
		HASH_ENGINE_START_SHA384_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash_mock.base, 2,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true, version);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA384_FAILED, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);
	CuAssertIntEquals (test, 0, measurement.version);
	CuAssertIntEquals (test, 0, measurement.measurement_config);

	pcr_testing_release (test, &pcr);
}
#endif

#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
static void pcr_test_update_versioned_buffer_sha512_start_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA512);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha512, &pcr.hash_mock,
		HASH_ENGINE_START_SHA512_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash_mock.base, 2,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true, version);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA512_FAILED, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);
	CuAssertIntEquals (test, 0, measurement.version);
	CuAssertIntEquals (test, 0, measurement.measurement_config);

	pcr_testing_release (test, &pcr);
}
#endif

static void pcr_test_update_versioned_buffer_with_event_update_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock, 0);

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock,
		HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (&event, sizeof (event)), MOCK_ARG (sizeof (event)));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.cancel, &pcr.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash_mock.base, 2,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true, version);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, 0, measurement.version);
	CuAssertIntEquals (test, 0, measurement.measurement_config);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_versioned_buffer_update_version_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock, 0);

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock,
		HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (&version, sizeof (version)), MOCK_ARG (sizeof (version)));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.cancel, &pcr.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash_mock.base, 2,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, 0, measurement.version);
	CuAssertIntEquals (test, 0, measurement.measurement_config);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_versioned_buffer_update_buffer_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock, 0);

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&version, sizeof (version)), MOCK_ARG (sizeof (version)));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock,
		HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_512_LEN));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.cancel, &pcr.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash_mock.base, 2,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, 0, measurement.version);
	CuAssertIntEquals (test, 0, measurement.measurement_config);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_versioned_buffer_finish_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock, 0);

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&version, sizeof (version)), MOCK_ARG (sizeof (version)));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_512_LEN));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.finish, &pcr.hash_mock,
		HASH_ENGINE_FINISH_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.cancel, &pcr.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash_mock.base, 2,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, 0, measurement.version);
	CuAssertIntEquals (test, 0, measurement.measurement_config);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_update_versioned_buffer_update_digest_fail (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 1, HASH_TYPE_SHA256);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_set_tcg_event_type_null (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_tcg_event_type (NULL, 2, 0x0a);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_set_tcg_event_type_invalid_index (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 1, HASH_TYPE_SHA256);

	status = pcr_set_tcg_event_type (&pcr.test, 2, 0x0a);
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_digest_sha256 (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_const_update_digest (&pcr.test, 2, SHA256_TEST_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_TEST_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_digest_sha256_explicit (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 0, HASH_TYPE_SHA256);

	status = pcr_const_update_digest (&pcr.test, 0, SHA256_TEST_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 0, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_TEST_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
static void pcr_test_const_update_digest_sha384 (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 3, HASH_TYPE_SHA384);

	status = pcr_const_update_digest (&pcr.test, 1, SHA384_TEST_HASH, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 1, &measurement);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (SHA384_TEST_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_digest_sha384_explicit (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 0, HASH_TYPE_SHA384);

	status = pcr_const_update_digest (&pcr.test, 0, SHA384_TEST_HASH, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 0, &measurement);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (SHA384_TEST_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}
#endif

#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
static void pcr_test_const_update_digest_sha512 (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA512);

	status = pcr_const_update_digest (&pcr.test, 4, SHA512_TEST_HASH, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 4, &measurement);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (SHA512_TEST_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_digest_sha512_explicit (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 0, HASH_TYPE_SHA512);

	status = pcr_const_update_digest (&pcr.test, 0, SHA512_TEST_HASH, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 0, &measurement);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (SHA512_TEST_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}
#endif

static void pcr_test_const_update_digest_then_update_different_measurement (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_const_update_digest (&pcr.test, 2, SHA256_TEST_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_TEST_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	status = pcr_const_update_digest (&pcr.test, 4, SHA256_TEST2_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 4, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_TEST2_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_digest_null (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_const_update_digest (NULL, 2, SHA256_TEST_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_const_update_digest (&pcr.test, 2, NULL, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_digest_twice (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_const_update_digest (&pcr.test, 2, SHA256_TEST_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_TEST_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	status = pcr_const_update_digest (&pcr.test, 2, SHA256_TEST2_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, PCR_CONSTANT_MEASUREMENT, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_TEST_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_digest_then_update_with_other_calls (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_const_update_digest (&pcr.test, 2, SHA256_TEST_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_TEST_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_digest (&pcr.test, 2, SHA256_TEST2_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, PCR_CONSTANT_MEASUREMENT, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, PCR_CONSTANT_MEASUREMENT, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false, 0x23);
	CuAssertIntEquals (test, PCR_CONSTANT_MEASUREMENT, status);

	status = pcr_const_update_buffer (&pcr.test, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, PCR_CONSTANT_MEASUREMENT, status);

	status = pcr_const_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false, 0x23);
	CuAssertIntEquals (test, PCR_CONSTANT_MEASUREMENT, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_TEST_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_digest_wrong_digest_length (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_const_update_digest (&pcr.test, 2, SHA256_TEST_HASH, SHA256_HASH_LENGTH - 1);
	CuAssertIntEquals (test, PCR_INCORRECT_DIGEST_LENGTH, status);

	status = pcr_const_update_digest (&pcr.test, 2, SHA256_TEST_HASH, SHA256_HASH_LENGTH + 1);
	CuAssertIntEquals (test, PCR_INCORRECT_DIGEST_LENGTH, status);

	pcr_testing_release (test, &pcr);
}

#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
static void pcr_test_const_update_digest_sha384_with_sha256 (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 3, HASH_TYPE_SHA384);

	status = pcr_const_update_digest (&pcr.test, 1, SHA256_TEST_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, PCR_INCORRECT_DIGEST_LENGTH, status);

	pcr_testing_release (test, &pcr);
}
#endif

static void pcr_test_const_update_digest_invalid_index (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 1, HASH_TYPE_SHA256);

	status = pcr_const_update_digest (&pcr.test, 2, SHA256_TEST_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_buffer_sha256 (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_const_update_buffer (&pcr.test, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_FULL_BLOCK_512_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_buffer_sha256_explicit (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 0, HASH_TYPE_SHA256);

	status = pcr_const_update_buffer (&pcr.test, &pcr.hash.base, 0, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 0, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_FULL_BLOCK_512_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_buffer_sha256_with_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_const_update_buffer (&pcr.test, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_EVENT | PCR_MEASUREMENT_FLAG_CONSTANT,
		measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA256_FULL_BLOCK_512_HASH_WITH_EVENT,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_buffer_sha256_with_event_no_data (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_tcg_event_type (&pcr.test, 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_const_update_buffer (&pcr.test, &pcr.hash.base, 1, NULL, 0, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 1, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_EVENT | PCR_MEASUREMENT_FLAG_CONSTANT,
		measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA256_EVENT_TYPE, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
static void pcr_test_const_update_buffer_sha384 (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_const_update_buffer (&pcr.test, &pcr.hash.base, 4, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 4, &measurement);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (SHA384_FULL_BLOCK_512_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_buffer_sha384_explicit (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 0, HASH_TYPE_SHA384);

	status = pcr_const_update_buffer (&pcr.test, &pcr.hash.base, 0, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 0, &measurement);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (SHA384_FULL_BLOCK_512_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_buffer_sha384_with_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_tcg_event_type (&pcr.test, 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_const_update_buffer (&pcr.test, &pcr.hash.base, 1, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 1, &measurement);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_EVENT | PCR_MEASUREMENT_FLAG_CONSTANT,
		measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA384_FULL_BLOCK_512_HASH_WITH_EVENT,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_buffer_sha384_with_event_no_data (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_tcg_event_type (&pcr.test, 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_const_update_buffer (&pcr.test, &pcr.hash.base, 1, NULL, 0, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 1, &measurement);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_EVENT | PCR_MEASUREMENT_FLAG_CONSTANT,
		measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA384_EVENT_TYPE, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}
#endif

#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
static void pcr_test_const_update_buffer_sha512 (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA512);

	status = pcr_const_update_buffer (&pcr.test, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (SHA512_FULL_BLOCK_512_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_buffer_sha512_explicit (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 0, HASH_TYPE_SHA512);

	status = pcr_const_update_buffer (&pcr.test, &pcr.hash.base, 0, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 0, &measurement);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (SHA512_FULL_BLOCK_512_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_buffer_sha512_with_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA512);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_const_update_buffer (&pcr.test, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_EVENT | PCR_MEASUREMENT_FLAG_CONSTANT,
		measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA512_FULL_BLOCK_512_HASH_WITH_EVENT,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_buffer_sha512_with_event_no_data (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA512);

	status = pcr_set_tcg_event_type (&pcr.test, 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_const_update_buffer (&pcr.test, &pcr.hash.base, 1, NULL, 0, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 1, &measurement);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_EVENT | PCR_MEASUREMENT_FLAG_CONSTANT,
		measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA512_EVENT_TYPE, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}
#endif

static void pcr_test_const_update_buffer_then_update_different_measurement (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_const_update_buffer (&pcr.test, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_FULL_BLOCK_512_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	status = pcr_const_update_buffer (&pcr.test, &pcr.hash.base, 3, HASH_TESTING_FULL_BLOCK_1024,
		HASH_TESTING_FULL_BLOCK_1024_LEN, false);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 3, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_FULL_BLOCK_1024_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_buffer_null (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_const_update_buffer (NULL, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_const_update_buffer (&pcr.test, NULL, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_const_update_buffer (&pcr.test, &pcr.hash.base, 2, NULL,
		HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_const_update_buffer (&pcr.test, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_512,
		0, false);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_buffer_twice (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_const_update_buffer (&pcr.test, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_FULL_BLOCK_512_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	status = pcr_const_update_buffer (&pcr.test, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_1024,
		HASH_TESTING_FULL_BLOCK_1024_LEN, false);
	CuAssertIntEquals (test, PCR_CONSTANT_MEASUREMENT, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_FULL_BLOCK_512_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_buffer_then_update_with_other_calls (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_const_update_buffer (&pcr.test, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_FULL_BLOCK_512_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_digest (&pcr.test, 2, SHA256_TEST2_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, PCR_CONSTANT_MEASUREMENT, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_1024,
		HASH_TESTING_FULL_BLOCK_1024_LEN, false);
	CuAssertIntEquals (test, PCR_CONSTANT_MEASUREMENT, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN, false, 0x23);
	CuAssertIntEquals (test, PCR_CONSTANT_MEASUREMENT, status);

	status = pcr_const_update_digest (&pcr.test, 2, SHA256_TEST2_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, PCR_CONSTANT_MEASUREMENT, status);

	status = pcr_const_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN, false, 0x23);
	CuAssertIntEquals (test, PCR_CONSTANT_MEASUREMENT, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_FULL_BLOCK_512_HASH, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_buffer_sha256_start_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock,
		HASH_ENGINE_START_SHA256_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = pcr_const_update_buffer (&pcr.test, &pcr.hash_mock.base, 2,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	pcr_testing_release (test, &pcr);
}

#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
static void pcr_test_const_update_buffer_sha384_start_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha384, &pcr.hash_mock,
		HASH_ENGINE_START_SHA384_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = pcr_const_update_buffer (&pcr.test, &pcr.hash_mock.base, 2,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA384_FAILED, status);

	pcr_testing_release (test, &pcr);
}
#endif

#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
static void pcr_test_const_update_buffer_sha512_start_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA512);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha512, &pcr.hash_mock,
		HASH_ENGINE_START_SHA512_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = pcr_const_update_buffer (&pcr.test, &pcr.hash_mock.base, 2,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA512_FAILED, status);

	pcr_testing_release (test, &pcr);
}
#endif

static void pcr_test_const_update_buffer_update_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock, 0);

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock,
		HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_512_LEN));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.cancel, &pcr.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = pcr_const_update_buffer (&pcr.test, &pcr.hash_mock.base, 2,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_buffer_finish_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock, 0);

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_512_LEN));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.finish, &pcr.hash_mock,
		HASH_ENGINE_FINISH_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.cancel, &pcr.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = pcr_const_update_buffer (&pcr.test, &pcr.hash_mock.base, 2,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_buffer_with_event_sha256_start_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock,
		HASH_ENGINE_START_SHA256_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = pcr_const_update_buffer (&pcr.test, &pcr.hash_mock.base, 2,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, 0, measurement.measurement_config);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_buffer_with_event_event_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock, 0);

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock,
		HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (&event, sizeof (event)), MOCK_ARG (sizeof (event)));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.cancel, &pcr.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = pcr_const_update_buffer (&pcr.test, &pcr.hash_mock.base, 2,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, 0, measurement.measurement_config);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_buffer_with_event_update_buffer_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock, 0);

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&event, sizeof (event)), MOCK_ARG (sizeof (event)));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock,
		HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_512_LEN));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.cancel, &pcr.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = pcr_const_update_buffer (&pcr.test, &pcr.hash_mock.base, 2,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, 0, measurement.measurement_config);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_buffer_with_event_finish_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint32_t event = 0xaabbccdd;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock, 0);

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&event, sizeof (event)), MOCK_ARG (sizeof (event)));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_512_LEN));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.finish, &pcr.hash_mock,
		HASH_ENGINE_FINISH_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.cancel, &pcr.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = pcr_const_update_buffer (&pcr.test, &pcr.hash_mock.base, 2,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true);
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, 0, measurement.measurement_config);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_buffer_update_digest_fail (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init(test, &pcr, 1, HASH_TYPE_SHA256);

	status = pcr_const_update_buffer (&pcr.test, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_versioned_buffer_sha256 (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_const_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_VERSION | PCR_MEASUREMENT_FLAG_CONSTANT,
		measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA256_FULL_BLOCK_512_HASH_VERSIONED,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_versioned_buffer_sha256_explicit (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 0, HASH_TYPE_SHA256);

	status = pcr_const_update_versioned_buffer (&pcr.test, &pcr.hash.base, 0,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 0, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_VERSION | PCR_MEASUREMENT_FLAG_CONSTANT,
		measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA256_FULL_BLOCK_512_HASH_VERSIONED,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_versioned_buffer_sha256_no_data (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_const_update_versioned_buffer (&pcr.test, &pcr.hash.base, 4, NULL, 0, false,
		version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 4, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_VERSION | PCR_MEASUREMENT_FLAG_CONSTANT,
		measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA256_VERSIONED, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_versioned_buffer_sha256_with_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_tcg_event_type (&pcr.test, 3, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_const_update_versioned_buffer (&pcr.test, &pcr.hash.base, 3,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 3, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test,
		PCR_MEASUREMENT_FLAG_EVENT | PCR_MEASUREMENT_FLAG_VERSION | PCR_MEASUREMENT_FLAG_CONSTANT,
		measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA256_FULL_BLOCK_512_HASH_VERSIONED_WITH_EVENT,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
static void pcr_test_const_update_versioned_buffer_sha384 (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_const_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_VERSION | PCR_MEASUREMENT_FLAG_CONSTANT,
		measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA384_FULL_BLOCK_512_HASH_VERSIONED,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_versioned_buffer_sha384_explicit (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 0, HASH_TYPE_SHA384);

	status = pcr_const_update_versioned_buffer (&pcr.test, &pcr.hash.base, 0,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 0, &measurement);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_VERSION | PCR_MEASUREMENT_FLAG_CONSTANT,
		measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA384_FULL_BLOCK_512_HASH_VERSIONED,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_versioned_buffer_sha384_no_data (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_const_update_versioned_buffer (&pcr.test, &pcr.hash.base, 4, NULL, 0, false,
		version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 4, &measurement);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_VERSION | PCR_MEASUREMENT_FLAG_CONSTANT,
		measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA384_VERSIONED, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_versioned_buffer_sha384_with_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_tcg_event_type (&pcr.test, 3, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_const_update_versioned_buffer (&pcr.test, &pcr.hash.base, 3,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 3, &measurement);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);
	CuAssertIntEquals (test,
		PCR_MEASUREMENT_FLAG_EVENT | PCR_MEASUREMENT_FLAG_VERSION | PCR_MEASUREMENT_FLAG_CONSTANT,
		measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA384_FULL_BLOCK_512_HASH_VERSIONED_WITH_EVENT,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}
#endif

#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
static void pcr_test_const_update_versioned_buffer_sha512 (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA512);

	status = pcr_const_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_VERSION | PCR_MEASUREMENT_FLAG_CONSTANT,
		measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA512_FULL_BLOCK_512_HASH_VERSIONED,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_versioned_buffer_sha512_explicit (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 0, HASH_TYPE_SHA512);

	status = pcr_const_update_versioned_buffer (&pcr.test, &pcr.hash.base, 0,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 0, &measurement);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_VERSION | PCR_MEASUREMENT_FLAG_CONSTANT,
		measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA512_FULL_BLOCK_512_HASH_VERSIONED,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_versioned_buffer_sha512_no_data (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA512);

	status = pcr_const_update_versioned_buffer (&pcr.test, &pcr.hash.base, 4, NULL, 0, false,
		version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 4, &measurement);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_VERSION | PCR_MEASUREMENT_FLAG_CONSTANT,
		measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA512_VERSIONED, measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_versioned_buffer_sha512_with_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA512);

	status = pcr_set_tcg_event_type (&pcr.test, 3, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_const_update_versioned_buffer (&pcr.test, &pcr.hash.base, 3,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 3, &measurement);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);
	CuAssertIntEquals (test,
		PCR_MEASUREMENT_FLAG_EVENT | PCR_MEASUREMENT_FLAG_VERSION | PCR_MEASUREMENT_FLAG_CONSTANT,
		measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA512_FULL_BLOCK_512_HASH_VERSIONED_WITH_EVENT,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}
#endif

static void pcr_test_const_update_versioned_buffer_then_update_different_measurement (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint32_t data = 0x11223344;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_const_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_VERSION | PCR_MEASUREMENT_FLAG_CONSTANT,
		measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA256_FULL_BLOCK_512_HASH_VERSIONED,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	status = pcr_const_update_versioned_buffer (&pcr.test, &pcr.hash.base, 4, (uint8_t*) &data,
		sizeof (data), false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 4, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_VERSION | PCR_MEASUREMENT_FLAG_CONSTANT,
		measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA256_4BYTE_DATA_VERSIONED, measurement.digest,
		status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_versioned_buffer_null (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_const_update_versioned_buffer (NULL, &pcr.hash.base, 2,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_const_update_versioned_buffer (&pcr.test, NULL, 2,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_versioned_buffer_twice (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_const_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_VERSION | PCR_MEASUREMENT_FLAG_CONSTANT,
		measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA256_FULL_BLOCK_512_HASH_VERSIONED,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	status = pcr_const_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN, false, version);
	CuAssertIntEquals (test, PCR_CONSTANT_MEASUREMENT, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_VERSION | PCR_MEASUREMENT_FLAG_CONSTANT,
		measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA256_FULL_BLOCK_512_HASH_VERSIONED,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_versioned_buffer_then_update_with_other_calls (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_const_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_VERSION | PCR_MEASUREMENT_FLAG_CONSTANT,
		measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA256_FULL_BLOCK_512_HASH_VERSIONED,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_digest (&pcr.test, 2, SHA256_TEST2_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, PCR_CONSTANT_MEASUREMENT, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_1024,
		HASH_TESTING_FULL_BLOCK_1024_LEN, false);
	CuAssertIntEquals (test, PCR_CONSTANT_MEASUREMENT, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN, false, 0x23);
	CuAssertIntEquals (test, PCR_CONSTANT_MEASUREMENT, status);

	status = pcr_const_update_digest (&pcr.test, 2, SHA256_TEST2_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, PCR_CONSTANT_MEASUREMENT, status);

	status = pcr_const_update_buffer (&pcr.test, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_1024,
		HASH_TESTING_FULL_BLOCK_1024_LEN, false);
	CuAssertIntEquals (test, PCR_CONSTANT_MEASUREMENT, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, PCR_MEASUREMENT_FLAG_VERSION | PCR_MEASUREMENT_FLAG_CONSTANT,
		measurement.measurement_config);

	status = testing_validate_array (PCR_TESTING_SHA256_FULL_BLOCK_512_HASH_VERSIONED,
		measurement.digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_versioned_buffer_sha256_start_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock,
		HASH_ENGINE_START_SHA256_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = pcr_const_update_versioned_buffer (&pcr.test, &pcr.hash_mock.base, 2,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true, version);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, 0, measurement.version);
	CuAssertIntEquals (test, 0, measurement.measurement_config);

	pcr_testing_release (test, &pcr);
}

#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
static void pcr_test_const_update_versioned_buffer_sha384_start_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha384, &pcr.hash_mock,
		HASH_ENGINE_START_SHA384_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = pcr_const_update_versioned_buffer (&pcr.test, &pcr.hash_mock.base, 2,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true, version);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA384_FAILED, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);
	CuAssertIntEquals (test, 0, measurement.version);
	CuAssertIntEquals (test, 0, measurement.measurement_config);

	pcr_testing_release (test, &pcr);
}
#endif

#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
static void pcr_test_const_update_versioned_buffer_sha512_start_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA512);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha512, &pcr.hash_mock,
		HASH_ENGINE_START_SHA512_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = pcr_const_update_versioned_buffer (&pcr.test, &pcr.hash_mock.base, 2,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true, version);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA512_FAILED, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);
	CuAssertIntEquals (test, 0, measurement.version);
	CuAssertIntEquals (test, 0, measurement.measurement_config);

	pcr_testing_release (test, &pcr);
}
#endif

static void pcr_test_const_update_versioned_buffer_with_event_update_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock, 0);

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock,
		HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (&event, sizeof (event)), MOCK_ARG (sizeof (event)));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.cancel, &pcr.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = pcr_const_update_versioned_buffer (&pcr.test, &pcr.hash_mock.base, 2,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true, version);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, 0, measurement.version);
	CuAssertIntEquals (test, 0, measurement.measurement_config);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_versioned_buffer_update_version_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock, 0);

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock,
		HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (&version, sizeof (version)), MOCK_ARG (sizeof (version)));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.cancel, &pcr.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = pcr_const_update_versioned_buffer (&pcr.test, &pcr.hash_mock.base, 2,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, 0, measurement.version);
	CuAssertIntEquals (test, 0, measurement.measurement_config);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_versioned_buffer_update_buffer_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock, 0);

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&version, sizeof (version)), MOCK_ARG (sizeof (version)));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock,
		HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_512_LEN));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.cancel, &pcr.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = pcr_const_update_versioned_buffer (&pcr.test, &pcr.hash_mock.base, 2,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, 0, measurement.version);
	CuAssertIntEquals (test, 0, measurement.measurement_config);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_versioned_buffer_finish_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock, 0);

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&version, sizeof (version)), MOCK_ARG (sizeof (version)));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_512_LEN));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.finish, &pcr.hash_mock,
		HASH_ENGINE_FINISH_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.cancel, &pcr.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = pcr_const_update_versioned_buffer (&pcr.test, &pcr.hash_mock.base, 2,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, 0, measurement.version);
	CuAssertIntEquals (test, 0, measurement.measurement_config);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_const_update_versioned_buffer_update_digest_fail (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 1, HASH_TYPE_SHA256);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_tcg_event_type (CuTest *test)
{
	struct pcr_testing pcr;
	uint32_t event;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_tcg_event_type (&pcr.test, 2, 0x0a);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_tcg_event_type (&pcr.test, 2, &event);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x0a, event);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_tcg_event_type_explicit (CuTest *test)
{
	struct pcr_testing pcr;
	uint32_t event;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 0, HASH_TYPE_SHA256);

	status = pcr_set_tcg_event_type (&pcr.test, 0, 0x0a);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_tcg_event_type (&pcr.test, 0, &event);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x0a, event);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_tcg_event_type_null (CuTest *test)
{
	struct pcr_testing pcr;
	uint32_t event;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_get_tcg_event_type (NULL, 2, &event);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_get_tcg_event_type (&pcr.test, 2, NULL);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_tcg_event_type_invalid_index (CuTest *test)
{
	struct pcr_testing pcr;
	uint32_t event;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 1, HASH_TYPE_SHA256);

	status = pcr_get_tcg_event_type (&pcr.test, 2, &event);
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_set_dmtf_value_type (CuTest *test)
{
	struct pcr_testing pcr;
	enum pcr_dmtf_value_type type;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_dmtf_value_type (&pcr.test, 2, PCR_DMTF_VALUE_TYPE_FIRMWARE, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_dmtf_value_type (&pcr.test, 2, &type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, PCR_DMTF_VALUE_TYPE_FIRMWARE, type);

	status = pcr_is_measurement_in_tcb (&pcr.test, 2);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_set_dmtf_value_type_change_type (CuTest *test)
{
	struct pcr_testing pcr;
	enum pcr_dmtf_value_type type;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_dmtf_value_type (&pcr.test, 4, PCR_DMTF_VALUE_TYPE_FIRMWARE, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_dmtf_value_type (&pcr.test, 4, &type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, PCR_DMTF_VALUE_TYPE_FIRMWARE, type);

	status = pcr_is_measurement_in_tcb (&pcr.test, 4);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_dmtf_value_type (&pcr.test, 4, PCR_DMTF_VALUE_TYPE_FW_CONFIG, false);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_dmtf_value_type (&pcr.test, 4, &type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, PCR_DMTF_VALUE_TYPE_FW_CONFIG, type);

	status = pcr_is_measurement_in_tcb (&pcr.test, 4);
	CuAssertIntEquals (test, 1, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_set_dmtf_value_type_null (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_dmtf_value_type (NULL, 2, PCR_DMTF_VALUE_TYPE_FIRMWARE, false);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_set_dmtf_value_type_invalid_index (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_dmtf_value_type (&pcr.test, 5, PCR_DMTF_VALUE_TYPE_FIRMWARE, true);
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_set_dmtf_value_type_invalid_type (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_dmtf_value_type (&pcr.test, 2, PCR_DMTF_VALUE_TYPE_UNUSED, false);
	CuAssertIntEquals (test, PCR_INVALID_VALUE_TYPE, status);

	status = pcr_set_dmtf_value_type (&pcr.test, 2, PCR_DMTF_VALUE_TYPE_RESERVED, true);
	CuAssertIntEquals (test, PCR_INVALID_VALUE_TYPE, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_dmtf_value_type_unset (CuTest *test)
{
	struct pcr_testing pcr;
	enum pcr_dmtf_value_type type;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_get_dmtf_value_type (&pcr.test, 2, &type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, PCR_DMTF_VALUE_TYPE_ROM, type);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_dmtf_value_type_null (CuTest *test)
{
	struct pcr_testing pcr;
	enum pcr_dmtf_value_type type;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_get_dmtf_value_type (NULL, 2, &type);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_get_dmtf_value_type (&pcr.test, 2, NULL);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_dmtf_value_type_invalid_index (CuTest *test)
{
	struct pcr_testing pcr;
	enum pcr_dmtf_value_type type;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_get_dmtf_value_type (&pcr.test, 5, &type);
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_is_measurement_in_tcb_unset (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_is_measurement_in_tcb (&pcr.test, 2);
	CuAssertIntEquals (test, 1, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_is_measurement_in_tcb_null (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_is_measurement_in_tcb (NULL, 2);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_is_measurement_in_tcb_invalid_index (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_is_measurement_in_tcb (&pcr.test, 5);
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_all_measurements_sha256 (CuTest *test)
{
	struct pcr_testing pcr;
	const struct pcr_measurement *measurement_list;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 2, HASH_TYPE_SHA256);

	status = pcr_update_digest (&pcr.test, 0, SHA256_TEST_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_digest (&pcr.test, 1, SHA256_TEST2_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_all_measurements (&pcr.test, &measurement_list);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_TEST_HASH, measurement_list[0].digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_TEST2_HASH, measurement_list[1].digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_all_measurements_sha256_explicit (CuTest *test)
{
	struct pcr_testing pcr;
	const struct pcr_measurement *measurement_list;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 0, HASH_TYPE_SHA256);

	status = pcr_update_digest (&pcr.test, 0, SHA256_TEST_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_all_measurements (&pcr.test, &measurement_list);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_TEST_HASH, measurement_list[0].digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
static void pcr_test_get_all_measurements_sha384 (CuTest *test)
{
	struct pcr_testing pcr;
	const struct pcr_measurement *measurement_list;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 2, HASH_TYPE_SHA384);

	status = pcr_update_digest (&pcr.test, 0, SHA384_TEST_HASH, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_digest (&pcr.test, 1, SHA384_TEST2_HASH, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_all_measurements (&pcr.test, &measurement_list);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (SHA384_TEST_HASH, measurement_list[0].digest,
		SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_TEST2_HASH, measurement_list[1].digest,
		SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_all_measurements_sha384_explicit (CuTest *test)
{
	struct pcr_testing pcr;
	const struct pcr_measurement *measurement_list;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 0, HASH_TYPE_SHA384);

	status = pcr_update_digest (&pcr.test, 0, SHA384_TEST_HASH, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_all_measurements (&pcr.test, &measurement_list);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (SHA384_TEST_HASH, measurement_list[0].digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}
#endif

#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
static void pcr_test_get_all_measurements_sha512 (CuTest *test)
{
	struct pcr_testing pcr;
	const struct pcr_measurement *measurement_list;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 2, HASH_TYPE_SHA512);

	status = pcr_update_digest (&pcr.test, 0, SHA512_TEST_HASH, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_digest (&pcr.test, 1, SHA512_TEST2_HASH, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_all_measurements (&pcr.test, &measurement_list);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (SHA512_TEST_HASH, measurement_list[0].digest,
		SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_TEST2_HASH, measurement_list[1].digest,
		SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_all_measurements_sha512_explicit (CuTest *test)
{
	struct pcr_testing pcr;
	const struct pcr_measurement *measurement_list;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 0, HASH_TYPE_SHA512);

	status = pcr_update_digest (&pcr.test, 0, SHA512_TEST_HASH, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_all_measurements (&pcr.test, &measurement_list);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (SHA512_TEST_HASH, measurement_list[0].digest, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}
#endif

static void pcr_test_get_all_measurements_null (CuTest *test)
{
	struct pcr_testing pcr;
	const struct pcr_measurement *measurement_list;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_get_all_measurements (NULL, &measurement_list);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_get_all_measurements (&pcr.test, NULL);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_invalidate_measurement (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t invalid_measurement[PCR_MAX_DIGEST_LENGTH] = {0};
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_update_digest (&pcr.test, 2, SHA256_TEST_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_TEST_HASH, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_invalidate_measurement (&pcr.test, 2);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, measurement.digest,
		sizeof (invalid_measurement));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_invalidate_measurement_explicit (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	uint8_t invalid_measurement[PCR_MAX_DIGEST_LENGTH] = {0};
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 0, HASH_TYPE_SHA256);

	status = pcr_update_digest (&pcr.test, 0, SHA256_TEST_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 0, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_TEST_HASH, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_invalidate_measurement (&pcr.test, 0);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 0, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (invalid_measurement, measurement.digest,
		sizeof (invalid_measurement));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_invalidate_measurement_constant (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_const_update_digest (&pcr.test, 2, SHA256_TEST_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_TEST_HASH, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_invalidate_measurement (&pcr.test, 2);
	CuAssertIntEquals (test, PCR_CONSTANT_MEASUREMENT, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_TEST_HASH, measurement.digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_invalidate_measurement_null (CuTest *test)
{
	int status;

	TEST_START;

	status = pcr_invalidate_measurement (NULL, 2);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);
}

static void pcr_test_invalidate_measurement_bad_index (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_invalidate_measurement (&pcr.test, 5);
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_compute_sha256 (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t measurement[SHA256_HASH_LENGTH];
	const struct pcr_measurement *measurement_list;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 3, HASH_TYPE_SHA256);

	status = pcr_update_digest (&pcr.test, 0, SHA256_TEST_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_digest (&pcr.test, 2, SHA256_TEST2_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_compute (&pcr.test, &pcr.hash.base, true, measurement, sizeof (measurement));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_PCR_MEASUREMENT2, measurement, status);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_all_measurements (&pcr.test, &measurement_list);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_PCR_MEASUREMENT0,
		measurement_list[0].measurement, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PCR_TESTING_SHA256_PCR_MEASUREMENT1,
		measurement_list[1].measurement, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PCR_TESTING_SHA256_PCR_MEASUREMENT2,
		measurement_list[2].measurement, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_compute_sha256_explicit (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t measurement[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 0, HASH_TYPE_SHA256);

	status = pcr_update_digest (&pcr.test, 0, SHA256_TEST_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_compute (&pcr.test, &pcr.hash.base, true, measurement, sizeof (measurement));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_TEST_HASH, measurement, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_compute_sha256_no_valid_measurements (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t measurement[SHA256_HASH_LENGTH];
	const struct pcr_measurement *measurement_list;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 2, HASH_TYPE_SHA256);

	status = pcr_compute (&pcr.test, &pcr.hash.base, true, measurement, sizeof (measurement));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_PCR_NONE_VALID_MEASUREMENT1, measurement,
		status);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_all_measurements (&pcr.test, &measurement_list);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_PCR_NONE_VALID_MEASUREMENT0,
		measurement_list[0].measurement, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PCR_TESTING_SHA256_PCR_NONE_VALID_MEASUREMENT1,
		measurement_list[1].measurement, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_compute_sha256_no_valid_measurements_explicit (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t measurement[SHA256_HASH_LENGTH];
	uint8_t expected[SHA256_HASH_LENGTH] = {0};
	int status;

	TEST_START;

	memset (measurement, 1, sizeof (measurement));

	pcr_testing_init (test, &pcr, 0, HASH_TYPE_SHA256);

	status = pcr_compute (&pcr.test, &pcr.hash.base, true, measurement, sizeof (measurement));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (expected, measurement, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
static void pcr_test_compute_sha384 (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t measurement[SHA384_HASH_LENGTH];
	const struct pcr_measurement *measurement_list;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 3, HASH_TYPE_SHA384);

	status = pcr_update_digest (&pcr.test, 0, SHA384_TEST_HASH, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_digest (&pcr.test, 2, SHA384_TEST2_HASH, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_compute (&pcr.test, &pcr.hash.base, true, measurement, sizeof (measurement));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA384_PCR_MEASUREMENT2, measurement, status);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_all_measurements (&pcr.test, &measurement_list);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA384_PCR_MEASUREMENT0,
		measurement_list[0].measurement, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PCR_TESTING_SHA384_PCR_MEASUREMENT1,
		measurement_list[1].measurement, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PCR_TESTING_SHA384_PCR_MEASUREMENT2,
		measurement_list[2].measurement, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_compute_sha384_explicit (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t measurement[SHA384_HASH_LENGTH];
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 0, HASH_TYPE_SHA384);

	status = pcr_update_digest (&pcr.test, 0, SHA384_TEST_HASH, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_compute (&pcr.test, &pcr.hash.base, true, measurement, sizeof (measurement));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (SHA384_TEST_HASH, measurement, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_compute_sha384_no_valid_measurements (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t measurement[SHA384_HASH_LENGTH];
	const struct pcr_measurement *measurement_list;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 2, HASH_TYPE_SHA384);

	status = pcr_compute (&pcr.test, &pcr.hash.base, true, measurement, sizeof (measurement));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA384_PCR_NONE_VALID_MEASUREMENT1, measurement,
		status);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_all_measurements (&pcr.test, &measurement_list);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA384_PCR_NONE_VALID_MEASUREMENT0,
		measurement_list[0].measurement, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PCR_TESTING_SHA384_PCR_NONE_VALID_MEASUREMENT1,
		measurement_list[1].measurement, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_compute_sha384_no_valid_measurements_explicit (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t measurement[SHA384_HASH_LENGTH];
	uint8_t expected[SHA384_HASH_LENGTH] = {0};
	int status;

	TEST_START;

	memset (measurement, 1, sizeof (measurement));

	pcr_testing_init (test, &pcr, 0, HASH_TYPE_SHA384);

	status = pcr_compute (&pcr.test, &pcr.hash.base, true, measurement, sizeof (measurement));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (expected, measurement, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}
#endif

#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
static void pcr_test_compute_sha512 (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t measurement[SHA512_HASH_LENGTH];
	const struct pcr_measurement *measurement_list;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 3, HASH_TYPE_SHA512);

	status = pcr_update_digest (&pcr.test, 0, SHA512_TEST_HASH, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_digest (&pcr.test, 2, SHA512_TEST2_HASH, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_compute (&pcr.test, &pcr.hash.base, true, measurement, sizeof (measurement));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA512_PCR_MEASUREMENT2, measurement, status);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_all_measurements (&pcr.test, &measurement_list);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA512_PCR_MEASUREMENT0,
		measurement_list[0].measurement, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PCR_TESTING_SHA512_PCR_MEASUREMENT1,
		measurement_list[1].measurement, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PCR_TESTING_SHA512_PCR_MEASUREMENT2,
		measurement_list[2].measurement, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_compute_sha512_explicit (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t measurement[SHA512_HASH_LENGTH];
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 0, HASH_TYPE_SHA512);

	status = pcr_update_digest (&pcr.test, 0, SHA512_TEST_HASH, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_compute (&pcr.test, &pcr.hash.base, true, measurement, sizeof (measurement));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (SHA512_TEST_HASH, measurement, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_compute_sha512_no_valid_measurements (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t measurement[SHA512_HASH_LENGTH];
	const struct pcr_measurement *measurement_list;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 2, HASH_TYPE_SHA512);

	status = pcr_compute (&pcr.test, &pcr.hash.base, true, measurement, sizeof (measurement));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA512_PCR_NONE_VALID_MEASUREMENT1, measurement,
		status);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_all_measurements (&pcr.test, &measurement_list);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA512_PCR_NONE_VALID_MEASUREMENT0,
		measurement_list[0].measurement, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PCR_TESTING_SHA512_PCR_NONE_VALID_MEASUREMENT1,
		measurement_list[1].measurement, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_compute_sha512_no_valid_measurements_explicit (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t measurement[SHA512_HASH_LENGTH];
	uint8_t expected[SHA512_HASH_LENGTH] = {0};
	int status;

	TEST_START;

	memset (measurement, 1, sizeof (measurement));

	pcr_testing_init (test, &pcr, 0, HASH_TYPE_SHA512);

	status = pcr_compute (&pcr.test, &pcr.hash.base, true, measurement, sizeof (measurement));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (expected, measurement, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}
#endif

static void pcr_test_compute_no_lock (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t measurement[SHA256_HASH_LENGTH];
	const struct pcr_measurement *measurement_list;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 3, HASH_TYPE_SHA256);

	status = pcr_update_digest (&pcr.test, 0, SHA256_TEST_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_digest (&pcr.test, 2, SHA256_TEST2_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_lock (&pcr.test);
	CuAssertIntEquals (test, 0, status);

	status = pcr_compute (&pcr.test, &pcr.hash.base, false, measurement, sizeof (measurement));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = pcr_unlock (&pcr.test);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PCR_TESTING_SHA256_PCR_MEASUREMENT2, measurement, status);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_all_measurements (&pcr.test, &measurement_list);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_PCR_MEASUREMENT0,
		measurement_list[0].measurement, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PCR_TESTING_SHA256_PCR_MEASUREMENT1,
		measurement_list[1].measurement, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PCR_TESTING_SHA256_PCR_MEASUREMENT2,
		measurement_list[2].measurement, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_compute_no_out (CuTest *test)
{
	struct pcr_testing pcr;
	const struct pcr_measurement *measurement_list;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 3, HASH_TYPE_SHA256);

	status = pcr_update_digest (&pcr.test, 0, SHA256_TEST_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_digest (&pcr.test, 2, SHA256_TEST2_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_compute (&pcr.test, &pcr.hash.base, true, NULL, 0);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = pcr_get_all_measurements (&pcr.test, &measurement_list);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_PCR_MEASUREMENT0,
		measurement_list[0].measurement, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PCR_TESTING_SHA256_PCR_MEASUREMENT1,
		measurement_list[1].measurement, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PCR_TESTING_SHA256_PCR_MEASUREMENT2,
		measurement_list[2].measurement, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_compute_no_out_explicit (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 0, HASH_TYPE_SHA256);

	status = pcr_update_digest (&pcr.test, 0, SHA256_TEST_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_compute (&pcr.test, &pcr.hash.base, true, NULL, 0);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_compute_null (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t measurement[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 2, HASH_TYPE_SHA256);

	status = pcr_compute (NULL, &pcr.hash.base, true, measurement, sizeof (measurement));
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_compute (&pcr.test, NULL, true, measurement, sizeof (measurement));
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_compute_sha256_small_output_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t measurement[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 2, HASH_TYPE_SHA256);

	status = pcr_compute (&pcr.test, &pcr.hash.base, true, measurement, sizeof (measurement) - 1);
	CuAssertIntEquals (test, PCR_SMALL_OUTPUT_BUFFER, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_compute_sha256_start_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t measurement[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 3, HASH_TYPE_SHA256);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock,
		HASH_ENGINE_START_SHA256_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_digest (&pcr.test, 0, SHA256_TEST_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_compute (&pcr.test, &pcr.hash_mock.base, true, measurement, sizeof (measurement));
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	pcr_testing_release (test, &pcr);
}

#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
static void pcr_test_compute_sha384_small_output_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t measurement[SHA384_HASH_LENGTH];
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 2, HASH_TYPE_SHA384);

	status = pcr_compute (&pcr.test, &pcr.hash.base, true, measurement, sizeof (measurement) - 1);
	CuAssertIntEquals (test, PCR_SMALL_OUTPUT_BUFFER, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_compute_sha384_start_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t measurement[SHA384_HASH_LENGTH];
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 3, HASH_TYPE_SHA384);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha384, &pcr.hash_mock,
		HASH_ENGINE_START_SHA384_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_digest (&pcr.test, 0, SHA384_TEST_HASH, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_compute (&pcr.test, &pcr.hash_mock.base, true, measurement, sizeof (measurement));
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA384_FAILED, status);

	pcr_testing_release (test, &pcr);
}
#endif

#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
static void pcr_test_compute_sha512_small_output_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t measurement[SHA512_HASH_LENGTH];
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 2, HASH_TYPE_SHA512);

	status = pcr_compute (&pcr.test, &pcr.hash.base, true, measurement, sizeof (measurement) - 1);
	CuAssertIntEquals (test, PCR_SMALL_OUTPUT_BUFFER, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_compute_sha512_start_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t measurement[SHA512_HASH_LENGTH];
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 3, HASH_TYPE_SHA512);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha512, &pcr.hash_mock,
		HASH_ENGINE_START_SHA512_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_digest (&pcr.test, 0, SHA512_TEST_HASH, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_compute (&pcr.test, &pcr.hash_mock.base, true, measurement, sizeof (measurement));
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA512_FAILED, status);

	pcr_testing_release (test, &pcr);
}
#endif

static void pcr_test_compute_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t measurement[SHA256_HASH_LENGTH];
	uint8_t zeros[SHA256_HASH_LENGTH] = {0};
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 3, HASH_TYPE_SHA256);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock, 0);

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock,
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_PTR_CONTAINS (zeros, sizeof (zeros)),
		MOCK_ARG (sizeof (zeros)));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.cancel, &pcr.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = pcr_update_digest (&pcr.test, 0, SHA256_TEST_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_compute (&pcr.test, &pcr.hash_mock.base, true, measurement, sizeof (measurement));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_compute_extend_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t measurement[SHA256_HASH_LENGTH];
	uint8_t zeros[SHA256_HASH_LENGTH] = {0};
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 3, HASH_TYPE_SHA256);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock, 0);

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (zeros, sizeof (zeros)), MOCK_ARG (sizeof (zeros)));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock,
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_PTR_CONTAINS (SHA256_TEST_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.cancel, &pcr.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = pcr_update_digest (&pcr.test, 0, SHA256_TEST_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_compute (&pcr.test, &pcr.hash_mock.base, true, measurement, sizeof (measurement));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_compute_finish_hash_fail (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t measurement[SHA256_HASH_LENGTH];
	uint8_t zeros[SHA256_HASH_LENGTH] = {0};
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 3, HASH_TYPE_SHA256);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock, 0);

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (zeros, sizeof (zeros)), MOCK_ARG (sizeof (zeros)));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (SHA256_TEST_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.finish, &pcr.hash_mock,
		HASH_ENGINE_FINISH_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.cancel, &pcr.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = pcr_update_digest (&pcr.test, 0, SHA256_TEST_HASH, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = pcr_compute (&pcr.test, &pcr.hash_mock.base, true, measurement, sizeof (measurement));
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_lock_then_unlock (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 1, HASH_TYPE_SHA256);

	status = pcr_lock (&pcr.test);
	CuAssertIntEquals (test, 0, status);

	status = pcr_unlock (&pcr.test);
	CuAssertIntEquals (test, 0, status);

	status = pcr_lock (&pcr.test);
	CuAssertIntEquals (test, 0, status);

	status = pcr_unlock (&pcr.test);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_lock_null (CuTest *test)
{
	int status;

	TEST_START;

	status = pcr_lock (NULL);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);
}

static void pcr_test_unlock_null (CuTest *test)
{
	int status;

	TEST_START;

	status = pcr_unlock (NULL);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);
}

static void pcr_test_set_measurement_data (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	struct pcr_measurement measurement;
	uint8_t data = 0x11;
	uint8_t data_mem[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_is_measurement_data_available (&pcr.test, 2);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_is_measurement_data_available (&pcr.test, 2);
	CuAssertIntEquals (test, 1, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertPtrEquals (test, &measurement_data, (void*) measurement.measured_data);

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data_mem;
	measurement_data.data.memory.length = sizeof (data_mem);

	status = pcr_is_measurement_data_available (&pcr.test, 4);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_measurement_data (&pcr.test, 4, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_is_measurement_data_available (&pcr.test, 2);
	CuAssertIntEquals (test, 1, status);

	status = pcr_get_measurement (&pcr.test, 4, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertPtrEquals (test, &measurement_data, (void*) measurement.measured_data);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_set_measurement_data_memory_no_data (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	struct pcr_measurement measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = NULL;
	measurement_data.data.memory.length = 0;

	status = pcr_set_measurement_data (&pcr.test, 4, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 4, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertPtrEquals (test, &measurement_data, (void*) measurement.measured_data);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_set_measurement_data_remove (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	struct pcr_measurement measurement;
	uint8_t data = 0x11;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_is_measurement_data_available (&pcr.test, 2);
	CuAssertIntEquals (test, 1, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertPtrEquals (test, &measurement_data, (void*) measurement.measured_data);

	status = pcr_set_measurement_data (&pcr.test, 2, NULL);
	CuAssertIntEquals (test, 0, status);

	status = pcr_is_measurement_data_available (&pcr.test, 2);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement (&pcr.test, 2, &measurement);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertPtrEquals (test, NULL, (void*) measurement.measured_data);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_set_measurement_data_null (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (NULL, 2, &measurement_data);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	memset (&measurement_data, 0, sizeof (measurement_data));

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = NULL;

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, PCR_MEASURED_DATA_INVALID_FLASH_DEVICE, status);

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = NULL;

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, PCR_MEASURED_DATA_INVALID_CALLBACK, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_set_measurement_data_bad_measurement_index (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 6, &measurement_data);
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_set_measurement_data_bad_measurement_data_type (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	int status;

	TEST_START;

	measurement_data.type = NUM_PCR_DATA_TYPE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, PCR_INVALID_DATA_TYPE, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_is_measurement_data_available_null (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_is_measurement_data_available (NULL, 2);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_is_measurement_data_available_bad_measurement_index (CuTest *test)
{
	struct pcr_testing pcr;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_is_measurement_data_available (&pcr.test, 5);
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_1byte (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	uint8_t buffer[4];
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, 1, status);
	CuAssertIntEquals (test, 1, total_len);

	status = testing_validate_array (&data, buffer, 1);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_1byte_zero_length (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	uint8_t buffer[1];
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, 0, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, total_len);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_1byte_invalid_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	uint8_t buffer[4];
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 1, buffer, length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, total_len);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_1byte_include_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	uint32_t event = 0xaabbccdd;
	uint8_t buffer[5];
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, &measurement_data.data.value_1byte, 1,
		true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, 1 + sizeof (event), total_len);
	CuAssertIntEquals (test, event, *((uint32_t*) &buffer[0]));
	CuAssertIntEquals (test, data, buffer[4]);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_1byte_include_event_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[5] = {0};
	size_t length = sizeof (buffer);
	size_t offset = 1;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, &measurement_data.data.value_1byte, 1,
		true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, length - offset, status);
	CuAssertIntEquals (test, 1 + sizeof (event), total_len);
	CuAssertIntEquals (test, 0, buffer[4]);
	CuAssertIntEquals (test, 0x11aabbcc, *((uint32_t*) &buffer[0]));

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_1byte_include_event_with_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[5] = {0};
	uint8_t zero[1] = {0};
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, &measurement_data.data.value_1byte, 1,
		true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, sizeof (event), &total_len);
	CuAssertIntEquals (test, sizeof (event), status);
	CuAssertIntEquals (test, 1 + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, sizeof (event));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (event), sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_1byte_include_event_with_event_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[5] = {0};
	uint8_t zero[3] = {0};
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, &measurement_data.data.value_1byte, 1,
		true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 2, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, 1 + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + offset, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_1byte_include_event_with_event_small_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	uint32_t event = 0xaabbccdd;
	uint8_t buffer[5] = {0};
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, &measurement_data.data.value_1byte, 1,
		true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length - 1, &total_len);
	CuAssertIntEquals (test, length - 1, status);
	CuAssertIntEquals (test, 1 + sizeof (event), total_len);
	CuAssertIntEquals (test, event, *((uint32_t*) &buffer[0]));
	CuAssertIntEquals (test, 0, buffer[4]);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_1byte_include_event_with_event_small_buffer_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[4] = {0};
	size_t offset = 1;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, &measurement_data.data.value_1byte, 1,
		true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 2, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, 1 + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_1byte_include_event_offset_with_data (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	uint32_t event = 0xaabbccdd;
	uint8_t buffer[5] = {0};
	uint8_t zero[4] = {0};
	size_t length = sizeof (buffer);
	size_t total_len;
	size_t offset = 4;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, &measurement_data.data.value_1byte, 1,
		true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, 1, status);
	CuAssertIntEquals (test, 1 + sizeof (event), total_len);
	CuAssertIntEquals (test, data, buffer[0]);

	status = testing_validate_array (zero, buffer + 1, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_1byte_include_event_invalid_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[5] = {0};
	uint8_t zero[5] = {0};
	size_t length = sizeof (buffer);
	size_t offset = 5;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, &measurement_data.data.value_1byte, 1,
		true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1 + sizeof (event), total_len);

	status = testing_validate_array (zero, buffer, length);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_1byte_include_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	uint8_t buffer[5];
	size_t length = sizeof (buffer);
	size_t total_len;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		&measurement_data.data.value_1byte, 1, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, 1 + sizeof (version), total_len);
	CuAssertIntEquals (test, version, buffer[0]);
	CuAssertIntEquals (test, data, buffer[1]);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_1byte_include_version_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	uint8_t buffer[5];
	size_t length = sizeof (buffer);
	size_t total_len;
	uint8_t version = 0x24;
	size_t offset = 1;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		&measurement_data.data.value_1byte, 1, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, 1, status);
	CuAssertIntEquals (test, 1 + sizeof (version), total_len);
	CuAssertIntEquals (test, data, buffer[0]);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_1byte_include_version_with_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	uint8_t buffer[5] = {0};
	uint8_t zero[4] = {0};
	uint8_t version = 0x24;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		&measurement_data.data.value_1byte, 1, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, 1, &total_len);
	CuAssertIntEquals (test, 1, status);
	CuAssertIntEquals (test, 1 + sizeof (version), total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array (zero, &buffer[1], sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_1byte_include_version_invalid_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	uint8_t buffer[5];
	size_t length = sizeof (buffer);
	size_t total_len;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		&measurement_data.data.value_1byte, 1, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 2, buffer, length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1 + sizeof (version), total_len);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_1byte_include_event_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	uint8_t buffer[10];
	size_t length = sizeof (buffer);
	size_t total_len;
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		&measurement_data.data.value_1byte, 1, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, 6, status);
	CuAssertIntEquals (test, 1 + sizeof (version) + sizeof (event), total_len);
	CuAssertIntEquals (test, event, *((uint32_t*) &buffer[0]));
	CuAssertIntEquals (test, version, buffer[4]);
	CuAssertIntEquals (test, data, buffer[5]);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_1byte_include_event_version_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	uint8_t buffer[10];
	size_t length = sizeof (buffer);
	size_t total_len;
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		&measurement_data.data.value_1byte, 1, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, 6 - offset, status);
	CuAssertIntEquals (test, 1 + sizeof (version) + sizeof (event), total_len);
	CuAssertIntEquals (test, version, buffer[2]);
	CuAssertIntEquals (test, data, buffer[3]);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_1byte_include_event_version_with_event_version (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	uint8_t buffer[10] = {0};
	uint8_t zero[5] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		&measurement_data.data.value_1byte, 1, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, 5, &total_len);
	CuAssertIntEquals (test, 5, status);
	CuAssertIntEquals (test, 1 + sizeof (version) + sizeof (event), total_len);
	CuAssertIntEquals (test, version, buffer[4]);

	status = testing_validate_array ((uint8_t*) &event, buffer, 4);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 5, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_1byte_include_event_version_with_event_version_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	uint8_t buffer[10] = {0};
	uint8_t zero[7] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		&measurement_data.data.value_1byte, 1, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 3, &total_len);
	CuAssertIntEquals (test, 3, status);
	CuAssertIntEquals (test, 1 + sizeof (version) + sizeof (event), total_len);
	CuAssertIntEquals (test, version, buffer[2]);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 3, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_1byte_include_event_version_with_version_data (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	uint8_t buffer[10];
	size_t length = sizeof (buffer);
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 4;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		&measurement_data.data.value_1byte, 1, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, 1 + sizeof (version) + sizeof (event), total_len);
	CuAssertIntEquals (test, version, buffer[0]);
	CuAssertIntEquals (test, data, buffer[1]);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_1byte_include_event_version_with_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	uint8_t buffer[10] = {0};
	uint8_t zero[6] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		&measurement_data.data.value_1byte, 1, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, 4, &total_len);
	CuAssertIntEquals (test, 4, status);
	CuAssertIntEquals (test, 1 + sizeof (version) + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, 4);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 4, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_1byte_include_event_version_with_event_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	uint8_t buffer[10] = {0};
	uint8_t zero[8] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		&measurement_data.data.value_1byte, 1, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 2, buffer, 2, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, 1 + sizeof (version) + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event + 2, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_1byte_include_event_version_with_event_small_buffer (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	uint8_t buffer[10] = {0};
	uint8_t zero[7] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		&measurement_data.data.value_1byte, 1, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, 3, &total_len);
	CuAssertIntEquals (test, 3, status);
	CuAssertIntEquals (test, 1 + sizeof (version) + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, 3);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 3, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_1byte_include_event_version_with_event_small_buffer_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	uint8_t buffer[10] = {0};
	uint8_t zero[8] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		&measurement_data.data.value_1byte, 1, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 1, buffer, 2, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, 1 + sizeof (version) + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event + 1, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_1byte_include_event_version_with_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	uint8_t buffer[10] = {0};
	uint8_t zero[9] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 4;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		&measurement_data.data.value_1byte, 1, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 1, &total_len);
	CuAssertIntEquals (test, 1, status);
	CuAssertIntEquals (test, 1 + sizeof (version) + sizeof (event), total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array (zero, buffer + 1, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_1byte_include_event_version_with_data (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	uint8_t buffer[10];
	size_t length = sizeof (buffer);
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 5;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		&measurement_data.data.value_1byte, 1, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, 1, status);
	CuAssertIntEquals (test, 1 + sizeof (version) + sizeof (event), total_len);
	CuAssertIntEquals (test, data, buffer[0]);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_1byte_include_event_version_invalid_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	uint8_t buffer[10];
	size_t length = sizeof (buffer);
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 6;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		&measurement_data.data.value_1byte, 1, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1 + sizeof (version) + sizeof (event), total_len);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint8_t buffer[2];
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, 2, total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_zero_length (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint8_t buffer[2];
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, 0, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, total_len);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_with_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint8_t buffer[2];
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 1, buffer, length, &total_len);
	CuAssertIntEquals (test, 1, status);
	CuAssertIntEquals (test, 2, total_len);

	status = testing_validate_array (((uint8_t*) &data + 1), buffer, 1);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_small_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint8_t buffer[1];
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, 1, status);
	CuAssertIntEquals (test, 2, total_len);

	status = testing_validate_array (((uint8_t*) &data + 0), buffer, 1);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_small_buffer_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x1122;
	uint8_t buffer[2];
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 1, buffer, 0, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, total_len);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_invalid_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint8_t buffer[2];
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 2, buffer, length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, total_len);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_include_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[6];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_2byte, 2, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, 2 + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, sizeof (event));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + sizeof (event), sizeof (data));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_include_event_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint32_t event = 0xaabbccdd;
	uint8_t buffer[6] = {0};
	size_t length = sizeof (buffer);
	size_t total_len;
	size_t offset = 1;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_2byte, 2, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, length - offset, status);
	CuAssertIntEquals (test, 2 + sizeof (event), total_len);
	CuAssertIntEquals (test, 0, buffer[5]);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, sizeof (event) - offset);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + (sizeof (event) - offset),
		sizeof (data));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_include_event_small_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint32_t event = 0xaabbccdd;
	uint8_t buffer[6] = {0};
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_2byte, 2, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length - 1, &total_len);
	CuAssertIntEquals (test, length - 1, status);
	CuAssertIntEquals (test, 2 + sizeof (event), total_len);
	CuAssertIntEquals (test, *((uint8_t*) &data), buffer[4]);
	CuAssertIntEquals (test, 0, buffer[5]);

	status = testing_validate_array ((uint8_t*) &event, buffer, sizeof (event));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_include_event_small_buffer_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[6] = {0};
	uint8_t zero[3] = {0};
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_2byte, 2, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 3, &total_len);
	CuAssertIntEquals (test, 3, status);
	CuAssertIntEquals (test, 2 + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + 2, 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 3, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_include_event_with_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[6] = {0};
	uint8_t zero[2] = {0};
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_2byte, 2, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, sizeof (event), &total_len);
	CuAssertIntEquals (test, sizeof (event), status);
	CuAssertIntEquals (test, 2 + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, sizeof (event));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (event), sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_include_event_with_event_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[6] = {0};
	uint8_t zero[4] = {0};
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_2byte, 2, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 2, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, 2 + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event + 2, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_include_event_with_event_small_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[6] = {0};
	uint8_t zero[4] = {0};
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_2byte, 2, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, 2, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, 2 + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_include_event_with_event_small_buffer_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[6] = {0};
	uint8_t zero[4] = {0};
	size_t offset = 1;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_2byte, 2, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 2, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, 2 + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_include_event_with_data (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[6] = {0};
	uint8_t zero[4] = {0};
	size_t length = sizeof (buffer);
	size_t offset = 4;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_2byte, 2, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (data), status);
	CuAssertIntEquals (test, 2 + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data), sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_include_event_with_data_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint32_t event = 0xaabbccdd;
	uint8_t buffer[6] = {0};
	uint8_t zero[5] = {0};
	size_t length = sizeof (buffer);
	size_t total_len;
	size_t offset = 5;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_2byte, 2, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, 1, status);
	CuAssertIntEquals (test, 2 + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &data + 1, buffer, 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 1, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_include_event_with_data_small_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[6] = {0};
	uint8_t zero[5] = {0};
	size_t offset = 4;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_2byte, 2, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 1, &total_len);
	CuAssertIntEquals (test, 1, status);
	CuAssertIntEquals (test, 2 + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 1, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_include_event_invalid_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint32_t event = 0xaabbccdd;
	uint8_t buffer[6] = {0};
	uint8_t zero[6] = {0};
	size_t length = sizeof (buffer);
	size_t total_len;
	size_t offset = 6;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_2byte, 2, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2 + sizeof (event), total_len);

	status = testing_validate_array (zero, buffer, length);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_include_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint8_t buffer[10];
	size_t length = sizeof (buffer);
	size_t total_len;
	uint8_t version = 0x24;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_2byte, 2, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, 3, status);
	CuAssertIntEquals (test, 2 + sizeof (version), total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array ((uint8_t*) &data, buffer + 1, 2);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_include_version_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint8_t buffer[10];
	size_t length = sizeof (buffer);
	size_t total_len;
	uint8_t version = 0x24;
	size_t offset = 1;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_2byte, 2, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, 2 + sizeof (version), total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_include_version_small_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint8_t buffer[10];
	uint8_t version = 0x24;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_2byte, 2, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, 2, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, 2 + sizeof (version), total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array ((uint8_t*) &data, &buffer[1], 1);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_include_version_small_buffer_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint8_t buffer[10];
	uint8_t version = 0x24;
	size_t offset = 1;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_2byte, 2, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 1, &total_len);
	CuAssertIntEquals (test, 1, status);
	CuAssertIntEquals (test, 2 + sizeof (version), total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, 1);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_include_version_invalid_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint8_t buffer[10];
	size_t length = sizeof (buffer);
	size_t total_len;
	uint8_t version = 0x24;
	size_t offset = 3;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_2byte, 2, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2 + sizeof (version), total_len);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_include_event_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint8_t buffer[10];
	size_t length = sizeof (buffer);
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_2byte, 2, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, 7, status);
	CuAssertIntEquals (test, 2 + sizeof (version) + sizeof (event), total_len);
	CuAssertIntEquals (test, version, buffer[4]);

	status = testing_validate_array ((uint8_t*) &event, buffer, 4);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + 5, 2);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_include_event_version_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint8_t buffer[10];
	size_t length = sizeof (buffer);
	size_t total_len;
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_2byte, 2, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, 5, status);
	CuAssertIntEquals (test, 2 + sizeof (version) + sizeof (event), total_len);
	CuAssertIntEquals (test, version, buffer[2]);

	status = testing_validate_array ((uint8_t*) &event + 2, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + 3, 2);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_include_event_version_small_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint8_t buffer[10] = {0};
	uint8_t zero[4] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_2byte, 2, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, 6, &total_len);
	CuAssertIntEquals (test, 6, status);
	CuAssertIntEquals (test, 2 + sizeof (version) + sizeof (event), total_len);
	CuAssertIntEquals (test, version, buffer[4]);

	status = testing_validate_array ((uint8_t*) &event, buffer, 4);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + 5, 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 6, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_include_event_version_small_buffer_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint8_t buffer[10] = {0};
	uint8_t zero[6] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_2byte, 2, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 4, &total_len);
	CuAssertIntEquals (test, 4, status);
	CuAssertIntEquals (test, 2 + sizeof (version) + sizeof (event), total_len);
	CuAssertIntEquals (test, version, buffer[2]);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + 3, 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 4, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_include_event_version_with_event_version (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint8_t buffer[10] = {0};
	uint8_t zero[5] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_2byte, 2, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, 5, &total_len);
	CuAssertIntEquals (test, 5, status);
	CuAssertIntEquals (test, 2 + sizeof (version) + sizeof (event), total_len);
	CuAssertIntEquals (test, version, buffer[4]);

	status = testing_validate_array ((uint8_t*) &event, buffer, 4);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 5, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_include_event_version_with_event_version_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint8_t buffer[10] = {0};
	uint8_t zero[7] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_2byte, 2, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 3, &total_len);
	CuAssertIntEquals (test, 3, status);
	CuAssertIntEquals (test, 2 + sizeof (version) + sizeof (event), total_len);
	CuAssertIntEquals (test, version, buffer[2]);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 3, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_include_event_version_with_version_data (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint8_t buffer[10] = {0};
	uint8_t zero[7] = {0};
	size_t length = sizeof (buffer);
	size_t total_len;
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t offset = 4;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_2byte, 2, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, 3, status);
	CuAssertIntEquals (test, 2 + sizeof (version) + sizeof (event), total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array ((uint8_t*) &data, buffer + 1, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 3, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_include_event_version_with_version_data_small_buffer (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint8_t buffer[10] = {0};
	uint8_t zero[8] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 4;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_2byte, 2, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 2, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, 2 + sizeof (version) + sizeof (event), total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array ((uint8_t*) &data, buffer + 1, 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_include_event_version_with_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint8_t buffer[10] = {0};
	uint8_t zero[6] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_2byte, 2, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, 4, &total_len);
	CuAssertIntEquals (test, 4, status);
	CuAssertIntEquals (test, 2 + sizeof (version) + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, 4);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 4, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_include_event_version_with_event_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint8_t buffer[10] = {0};
	uint8_t zero[8] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_2byte, 2, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 2, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, 2 + sizeof (version) + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_include_event_version_with_event_small_buffer (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint8_t buffer[10] = {0};
	uint8_t zero[7] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_2byte, 2, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, 3, &total_len);
	CuAssertIntEquals (test, 3, status);
	CuAssertIntEquals (test, 2 + sizeof (version) + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, 3);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 3, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_include_event_version_with_event_small_buffer_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint8_t buffer[10] = {0};
	uint8_t zero[9] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_2byte, 2, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 1, &total_len);
	CuAssertIntEquals (test, 1, status);
	CuAssertIntEquals (test, 2 + sizeof (version) + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 1, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_include_event_version_with_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint8_t buffer[10] = {0};
	uint8_t zero[9] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 4;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_2byte, 2, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 1, &total_len);
	CuAssertIntEquals (test, 1, status);
	CuAssertIntEquals (test, 2 + sizeof (version) + sizeof (event), total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array (zero, buffer + 1, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_include_event_version_with_data (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint8_t buffer[10] = {0};
	uint8_t zero[8] = {0};
	size_t length = sizeof (buffer);
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 5;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_2byte, 2, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, 2 + sizeof (version) + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_include_event_version_with_data_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint8_t buffer[10] = {0};
	uint8_t zero[9] = {0};
	size_t length = sizeof (buffer);
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 6;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_2byte, 2, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, 1, status);
	CuAssertIntEquals (test, 2 + sizeof (version) + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &data + 1, buffer, 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 1, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_include_event_version_with_data_small_buffer (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint8_t buffer[10] = {0};
	uint8_t zero[9] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 5;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_2byte, 2, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 1, &total_len);
	CuAssertIntEquals (test, 1, status);
	CuAssertIntEquals (test, 2 + sizeof (version) + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 1, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_2byte_include_event_version_invalid_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint16_t data = 0x1122;
	uint8_t buffer[10];
	size_t length = sizeof (buffer);
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 7;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_2byte, 2, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2 + sizeof (version) + sizeof (event), total_len);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[4];
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, 4, status);
	CuAssertIntEquals (test, 4, total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, 4);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_zero_length (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[4];
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, 0, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 4, total_len);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[4];
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 2, buffer, length, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, 4, total_len);

	status = testing_validate_array (((uint8_t*) &data + 2), buffer, 2);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_small_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[2];
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, 4, total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_small_buffer_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[2];
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 1, buffer, length, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, 4, total_len);

	status = testing_validate_array (((uint8_t*) &data + 1), buffer, 2);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_invalid_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[2];
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 4, buffer, length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 4, total_len);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint32_t event = 0xaabbccdd;
	uint8_t buffer[10];
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (event) + sizeof (data), status);
	CuAssertIntEquals (test, sizeof (event) + 4, total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, sizeof (event));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + sizeof (event), sizeof (data));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_event_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint32_t event = 0xaabbccdd;
	uint8_t buffer[10] = {0};
	size_t length = sizeof (buffer);
	size_t total_len;
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (event) + sizeof (data) - offset, status);
	CuAssertIntEquals (test, sizeof (event) + 4, total_len);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, sizeof (event) - offset);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + (sizeof (event) - offset),
		sizeof (data));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_event_small_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint32_t event = 0xaabbccdd;
	uint8_t buffer[10] = {0};
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length - 2, &total_len);
	CuAssertIntEquals (test, length - 2, status);
	CuAssertIntEquals (test, sizeof (event) + 4, total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, sizeof (event));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + sizeof (event),	sizeof (data) - 2);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_event_small_buffer_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[10] = {0};
	uint8_t zero[6] = {0};
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 4, &total_len);
	CuAssertIntEquals (test, 4, status);
	CuAssertIntEquals (test, sizeof (event) + 4, total_len);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + 2, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 4, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_event_with_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[10] = {0};
	uint8_t zero[6] = {0};
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, sizeof (event), &total_len);
	CuAssertIntEquals (test, sizeof (event), status);
	CuAssertIntEquals (test, sizeof (event) + 4, total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, sizeof (event));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (event), sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_event_with_event_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[10] = {0};
	uint8_t zero[8] = {0};
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 2, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, sizeof (event) + 4, total_len);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + offset, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_event_with_event_small_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[10] = {0};
	uint8_t zero[8] = {0};
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, 2, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, sizeof (event) + 4, total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_event_with_event_small_buffer_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[10] = {0};
	uint8_t zero[8] = {0};
	size_t offset = 1;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 2, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, sizeof (event) + 4, total_len);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_event_with_data (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[10] = {0};
	uint8_t zero[6] = {0};
	size_t offset = 4;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, sizeof (data), &total_len);
	CuAssertIntEquals (test, sizeof (data), status);
	CuAssertIntEquals (test, sizeof (event) + 4, total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data), sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_event_with_data_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[10] = {0};
	uint8_t zero[7] = {0};
	size_t offset = 5;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 3, &total_len);
	CuAssertIntEquals (test, 3, status);
	CuAssertIntEquals (test, sizeof (event) + 4, total_len);

	status = testing_validate_array ((uint8_t*) &data + 1, buffer, sizeof (data) - 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 3, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_event_with_data_small_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[10] = {0};
	uint8_t zero[7] = {0};
	size_t offset = 4;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 3, &total_len);
	CuAssertIntEquals (test, 3, status);
	CuAssertIntEquals (test, sizeof (event) + 4, total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, 3);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 3, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_event_with_data_small_buffer_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[10] = {0};
	uint8_t zero[8] = {0};
	size_t offset = 5;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 2, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, sizeof (event) + 4, total_len);

	status = testing_validate_array ((uint8_t*) &data + 1, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_event_invalid_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[8] = {0};
	uint8_t zero[8] = {0};
	size_t length = sizeof (buffer);
	size_t offset = 8;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (event) + 4, total_len);

	status = testing_validate_array (zero, buffer, length);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10];
	uint8_t version = 0x24;
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (version) + sizeof (data), status);
	CuAssertIntEquals (test, sizeof (version) + 4, total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array ((uint8_t*) &data, buffer + 1, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_version_small_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[6] = {0};
	uint8_t version = 0x24;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, 4, &total_len);
	CuAssertIntEquals (test, 4, status);
	CuAssertIntEquals (test, sizeof (version) + 4, total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array ((uint8_t*) &data, buffer + 1, 3);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 4, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_version_with_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[9] = {0};
	uint8_t version = 0x24;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, 1, &total_len);
	CuAssertIntEquals (test, 1, status);
	CuAssertIntEquals (test, sizeof (version) + 4, total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array (zero, buffer + 1, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_version_with_data (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[6] = {0};
	uint8_t version = 0x24;
	size_t length = sizeof (buffer);
	size_t total_len;
	size_t offset = 1;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (data), status);
	CuAssertIntEquals (test, sizeof (version) + 4, total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data), sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_version_with_data_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[7] = {0};
	uint8_t version = 0x24;
	size_t length = sizeof (buffer);
	size_t total_len;
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (data) - 1, status);
	CuAssertIntEquals (test, sizeof (version) + 4, total_len);

	status = testing_validate_array ((uint8_t*) &data + 1, buffer, sizeof (data) - 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data) - 1, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_version_with_data_small_buffer (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[7] = {0};
	uint8_t version = 0x24;
	size_t offset = 1;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 3, &total_len);
	CuAssertIntEquals (test, 3, status);
	CuAssertIntEquals (test, sizeof (version) + 4, total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, sizeof (data) - 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data) - 1, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_version_with_data_small_buffer_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[8] = {0};
	uint8_t version = 0x24;
	size_t offset = 2;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 2, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, sizeof (version) + 4, total_len);

	status = testing_validate_array ((uint8_t*) &data + 1, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_version_invalid_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10];
	uint8_t version = 0x24;
	size_t length = sizeof (buffer);
	size_t total_len;
	size_t offset = 5;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (version) + 4, total_len);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_event_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10];
	size_t length = sizeof (buffer);
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, 9, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (event) + 4, total_len);
	CuAssertIntEquals (test, version, buffer[4]);

	status = testing_validate_array ((uint8_t*) &event, buffer, 4);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + 5, 4);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_event_version_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10];
	size_t length = sizeof (buffer);
	size_t total_len;
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, 7, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (event) + 4, total_len);
	CuAssertIntEquals (test, version, buffer[2]);

	status = testing_validate_array ((uint8_t*) &event + 2, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + 3, 4);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_event_version_small_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[3] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, 7, &total_len);
	CuAssertIntEquals (test, 7, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (event) + 4, total_len);
	CuAssertIntEquals (test, version, buffer[4]);

	status = testing_validate_array ((uint8_t*) &event, buffer, 4);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + 5, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 7, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_event_version_small_buffer_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[5] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 5, &total_len);
	CuAssertIntEquals (test, 5, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (event) + 4, total_len);
	CuAssertIntEquals (test, version, buffer[2]);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + 3, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 5, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_event_version_with_event_version (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[5] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, 5, &total_len);
	CuAssertIntEquals (test, 5, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (event) + 4, total_len);
	CuAssertIntEquals (test, version, buffer[4]);

	status = testing_validate_array ((uint8_t*) &event, buffer, 4);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 5, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_event_version_with_event_version_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[7] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 3, &total_len);
	CuAssertIntEquals (test, 3, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (event) + 4, total_len);
	CuAssertIntEquals (test, version, buffer[2]);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 3, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_event_version_with_version_data (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[5] = {0};
	size_t length = sizeof (buffer);
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 4;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, 5, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (event) + 4, total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array ((uint8_t*) &data, buffer + 1, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 5, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_event_version_with_version_data_small_buffer (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[7] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 4;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 3, &total_len);
	CuAssertIntEquals (test, 3, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (event) + 4, total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array ((uint8_t*) &data, buffer + 1, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 3, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_event_version_with_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[6] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, 4, &total_len);
	CuAssertIntEquals (test, 4, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (event) + 4, total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, 4);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 4, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_event_version_with_event_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[8] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 2, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (event) + 4, total_len);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_event_version_with_event_small_buffer (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[7] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, 3, &total_len);
	CuAssertIntEquals (test, 3, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (event) + 4, total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, 3);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 3, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_event_version_with_event_small_buffer_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[9] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 1, &total_len);
	CuAssertIntEquals (test, 1, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (event) + 4, total_len);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 1, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_event_version_with_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[9] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 4;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 1, &total_len);
	CuAssertIntEquals (test, 1, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (event) + 4, total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array (zero, buffer + 1, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_event_version_with_data (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[6] = {0};
	size_t length = sizeof (buffer);
	size_t total_len;
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t offset = 5;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (data), status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (event) + 4, total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data), sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_event_version_with_data_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[7] = {0};
	size_t length = sizeof (buffer);
	size_t total_len;
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t offset = 6;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, 3, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (event) + 4, total_len);

	status = testing_validate_array ((uint8_t*) &data + 1, buffer, 3);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 3, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_event_version_with_data_small_buffer (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[8] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 5;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 2, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (event) + 4, total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_event_version_with_data_small_buffer_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[8] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 6;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 2, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (event) + 4, total_len);

	status = testing_validate_array ((uint8_t*) &data + 1, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_4byte_include_event_version_invalid_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10];
	size_t length = sizeof (buffer);
	size_t total_len;
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t offset = 9;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (event) + 4, total_len);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[8];
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, 8, status);
	CuAssertIntEquals (test, 8, total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, 8);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_zero_length (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[8];
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, 0, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 8, total_len);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[8];
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 2, buffer, length, &total_len);
	CuAssertIntEquals (test, 6, status);
	CuAssertIntEquals (test, 8, total_len);

	status = testing_validate_array ((uint8_t*) &data + 2, buffer, 6);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_small_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[5];
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, 8, total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, length);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_small_buffer_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[5];
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, 8, total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, length);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_invalid_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[8];
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 8, buffer, length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 8, total_len);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[15];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (event) + sizeof (data), status);
	CuAssertIntEquals (test, 8 + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, sizeof (event));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + sizeof (event), sizeof (data));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_event_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[15] = {0};
	size_t length = sizeof (buffer);
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (event) + sizeof (data) - offset, status);
	CuAssertIntEquals (test, 8 + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, sizeof (event) - offset);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + (sizeof (event) - offset),
		sizeof (data));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_event_small_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[15] = {0};
	uint8_t zero[2] = {0};
	size_t length = sizeof (data) + sizeof (event) - 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, 8 + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, sizeof (event));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + sizeof (event),
		length - sizeof (event));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + length, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_event_small_buffer_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[15] = {0};
	uint8_t zero[7] = {0};
	size_t offset = 2;
	size_t length = sizeof (data) + sizeof (event) - offset - 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, 8 + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, sizeof (event) - 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + offset, sizeof (data) - 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + length, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_event_with_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[15] = {0};
	uint8_t zero[11] = {0};
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, sizeof (event), &total_len);
	CuAssertIntEquals (test, sizeof (event), status);
	CuAssertIntEquals (test, 8 + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, sizeof (event));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (event), sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_event_with_event_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[15] = {0};
	uint8_t zero[13] = {0};
	size_t offset = 2;
	size_t length = sizeof (event) - offset;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, 8 + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, sizeof (event) - offset);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + offset, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_event_with_event_small_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[15] = {0};
	uint8_t zero[13] = {0};
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, 2, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, 8 + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_event_with_event_small_buffer_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[15] = {0};
	uint8_t zero[13] = {0};
	size_t offset = 1;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 2, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, 8 + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_event_with_data (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[15] = {0};
	uint8_t zero[7] = {0};
	size_t length = sizeof (buffer);
	size_t offset = 4;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (data), status);
	CuAssertIntEquals (test, 8 + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data), sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_event_with_data_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[15] = {0};
	uint8_t zero[8] = {0};
	size_t length = sizeof (buffer);
	size_t offset = 5;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (data) - 1, status);
	CuAssertIntEquals (test, 8 + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &data + 1, buffer, sizeof (data) - 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data) - 1, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_event_with_data_small_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[15] = {0};
	uint8_t zero[8] = {0};
	size_t offset = 4;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, sizeof (data) - 1, &total_len);
	CuAssertIntEquals (test, sizeof (data) - 1, status);
	CuAssertIntEquals (test, 8 + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, sizeof (data) - 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data) - 1, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_event_with_data_small_buffer_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[15] = {0};
	uint8_t zero[9] = {0};
	size_t offset = 5;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, sizeof (data) - 2, &total_len);
	CuAssertIntEquals (test, sizeof (data) - 2, status);
	CuAssertIntEquals (test, 8 + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &data + 1, buffer, sizeof (data) - 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data) - 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_event_invalid_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[15] = {0};
	uint8_t zero[15] = {0};
	size_t length = sizeof (buffer);
	size_t offset = 13;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 8 + sizeof (event), total_len);

	status = testing_validate_array (zero, buffer, length);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[15];
	uint8_t version = 0x24;
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (version) + sizeof (data), status);
	CuAssertIntEquals (test, 8 + sizeof (version), total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array ((uint8_t*) &data, buffer + 1, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_version_small_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[15] = {0};
	uint8_t zero[7] = {0};
	uint8_t version = 0x24;
	size_t length = sizeof (version) + sizeof (data) - 1;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, 8 + sizeof (version), total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array ((uint8_t*) &data, buffer + 1, sizeof (data) - 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + length, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_version_with_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[15] = {0};
	uint8_t zero[14] = {0};
	uint8_t version = 0x24;
	size_t length = sizeof (version);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, 8 + sizeof (version), total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array (zero, buffer + length, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_version_with_data (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[15] = {0};
	uint8_t zero[7] = {0};
	uint8_t version = 0x24;
	size_t length = sizeof (buffer);
	size_t total_len;
	size_t offset = 1;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (data), status);
	CuAssertIntEquals (test, 8 + sizeof (version), total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data), sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_version_with_data_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[15] = {0};
	uint8_t zero[8] = {0};
	uint8_t version = 0x24;
	size_t length = sizeof (buffer);
	size_t total_len;
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (data) - 1, status);
	CuAssertIntEquals (test, 8 + sizeof (version), total_len);

	status = testing_validate_array ((uint8_t*) &data + 1, buffer, sizeof (data) - 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data) - 1, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_version_with_data_small_buffer (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[15] = {0};
	uint8_t zero[8] = {0};
	uint8_t version = 0x24;
	size_t offset = 1;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, sizeof (data) - 1, &total_len);
	CuAssertIntEquals (test, sizeof (data) - 1, status);
	CuAssertIntEquals (test, 8 + sizeof (version), total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, sizeof (data) - 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data) - 1, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_version_with_data_small_buffer_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[15] = {0};
	uint8_t zero[9] = {0};
	uint8_t version = 0x24;
	size_t offset = 2;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, sizeof (data) - 2, &total_len);
	CuAssertIntEquals (test, sizeof (data) - 2, status);
	CuAssertIntEquals (test, 8 + sizeof (version), total_len);

	status = testing_validate_array ((uint8_t*) &data + 1, buffer, sizeof (data) - 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data) - 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_version_invalid_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[15];
	uint8_t version = 0x24;
	size_t length = sizeof (buffer);
	size_t total_len;
	size_t offset = 9;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 8 + sizeof (version), total_len);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_event_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[15];
	size_t length = sizeof (buffer);
	size_t total_len;
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (event) + sizeof (version) + sizeof (data), status);
	CuAssertIntEquals (test, 8 + sizeof (version) + sizeof (event), total_len);
	CuAssertIntEquals (test, version, buffer[4]);

	status = testing_validate_array ((uint8_t*) &event, buffer, sizeof (event));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + 5, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_event_version_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[15];
	size_t length = sizeof (buffer);
	size_t total_len;
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (data) + sizeof (version) + sizeof (event) - offset, status);
	CuAssertIntEquals (test, 8 + sizeof (version) + sizeof (event), total_len);
	CuAssertIntEquals (test, version, buffer[2]);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + 3, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_event_version_small_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[15] = {0};
	uint8_t zero[4] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t length = sizeof (data) + sizeof (event) + sizeof (version) - 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, 8 + sizeof (version) + sizeof (event), total_len);
	CuAssertIntEquals (test, version, buffer[4]);

	status = testing_validate_array ((uint8_t*) &event, buffer, sizeof (event));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + 5, sizeof (data) - 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + length, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_event_version_small_buffer_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[15] = {0};
	uint8_t zero[6] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 2;
	size_t length = sizeof (data) + sizeof (event) + sizeof (version) - offset - 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, 8 + sizeof (version) + sizeof (event), total_len);
	CuAssertIntEquals (test, version, buffer[2]);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + 3, sizeof (data) - 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + length, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_event_version_with_event_version (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[15] = {0};
	uint8_t zero[10] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t length = sizeof (event) + sizeof (version);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, 8 + sizeof (version) + sizeof (event), total_len);
	CuAssertIntEquals (test, version, buffer[4]);

	status = testing_validate_array ((uint8_t*) &event, buffer, sizeof (event));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + length, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_event_version_with_event_version_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[15] = {0};
	uint8_t zero[12] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 2;
	size_t length = sizeof (event) + sizeof (version);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length - offset, &total_len);
	CuAssertIntEquals (test, length - offset, status);
	CuAssertIntEquals (test, 8 + sizeof (version) + sizeof (event), total_len);
	CuAssertIntEquals (test, version, buffer[2]);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + length - offset, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_event_version_with_version_data (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[15] = {0};
	uint8_t zero[6] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 4;
	size_t length = sizeof (version) + sizeof (data);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, sizeof (buffer), &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, 8 + sizeof (version) + sizeof (event), total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array ((uint8_t*) &data, buffer + 1, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + length, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_event_version_with_version_data_small_buffer (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[15] = {0};
	uint8_t zero[7] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 4;
	size_t length = sizeof (data) + sizeof (version) - 1;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, 8 + sizeof (version) + sizeof (event), total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array ((uint8_t*) &data, buffer + 1, sizeof (data) - 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + length, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_event_version_with_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[15] = {0};
	uint8_t zero[11] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, sizeof (event), &total_len);
	CuAssertIntEquals (test, sizeof (event), status);
	CuAssertIntEquals (test, 8 + sizeof (version) + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, sizeof (event));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (event), sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_event_version_with_event_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[15] = {0};
	uint8_t zero[13] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 2, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, 8 + sizeof (version) + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_event_version_with_event_small_buffer (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[15] = {0};
	uint8_t zero[12] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t length = sizeof (event) -1;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, 8 + sizeof (version) + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + length, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_event_version_with_event_small_buffer_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[15] = {0};
	uint8_t zero[14] = {0};
	size_t length = 1;
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, 8 + sizeof (version) + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + length, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_event_version_with_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[15] = {0};
	uint8_t zero[14] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 4;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 1, &total_len);
	CuAssertIntEquals (test, 1, status);
	CuAssertIntEquals (test, 8 + sizeof (version) + sizeof (event), total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array (zero, buffer + 1, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_event_version_with_data (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[15] = {0};
	uint8_t zero[7] = {0};
	size_t length = sizeof (buffer);
	size_t total_len;
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t offset = 5;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (data), status);
	CuAssertIntEquals (test, 8 + sizeof (version) + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data), sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_event_version_with_data_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[15] = {0};
	uint8_t zero[8] = {0};
	size_t length = sizeof (buffer);
	size_t total_len;
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t offset = 6;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (data) - 1, status);
	CuAssertIntEquals (test, 8 + sizeof (version) + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &data + 1, buffer, sizeof (data) - 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data) - 1, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_event_version_with_data_small_buffer (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[15] = {0};
	uint8_t zero[9] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 5;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, sizeof (data) - 2, &total_len);
	CuAssertIntEquals (test, sizeof (data) - 2, status);
	CuAssertIntEquals (test, 8 + sizeof (version) + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, sizeof (data) - 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data) - 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_event_version_with_data_small_buffer_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[15] = {0};
	uint8_t zero[9] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 6;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, sizeof (data) - 2, &total_len);
	CuAssertIntEquals (test, sizeof (data) - 2, status);
	CuAssertIntEquals (test, 8 + sizeof (version) + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &data + 1, buffer, sizeof (data) - 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data) - 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_8byte_include_event_version_invalid_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint64_t data = 0x1122334455667788;
	uint8_t buffer[15];
	size_t length = sizeof (buffer);
	size_t total_len;
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t offset = 13;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 8 + sizeof (version) + sizeof (event), total_len);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[50];
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (data), status);
	CuAssertIntEquals (test, sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, sizeof(data));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_zero_length (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[50];
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, 0, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (data), total_len);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[50];
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 10, buffer, length, &total_len);
	CuAssertIntEquals (test, (sizeof (data) - 10), status);
	CuAssertIntEquals (test, sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &data + 10, buffer, (sizeof (data) - 10));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_small_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[20];
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, length);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_small_buffer_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[20];
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 12, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &data + 12, buffer, length);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_invalid_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[50];
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, sizeof (data), buffer, length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (data), total_len);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[40];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (event) + sizeof (data), status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, sizeof (event));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + sizeof (event), sizeof (data));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_event_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[40] = {0};
	size_t length = sizeof (buffer);
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (event) + sizeof (data) - offset, status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, sizeof (event) - offset);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + (sizeof (event) - offset),
		sizeof (data));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_event_small_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[40] = {0};
	uint8_t zero[6] = {0};
	size_t length = sizeof (data) + sizeof (event) - 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, sizeof (event));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + sizeof (event),
		length - sizeof (event));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + length, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_event_small_buffer_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[40] = {0};
	uint8_t zero[8] = {0};
	size_t offset = 2;
	size_t length = sizeof (data) + sizeof (event) - offset - 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, sizeof (event) - 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + offset, sizeof (data) - 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + length, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_event_with_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[40] = {0};
	uint8_t zero[36] = {0};
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, sizeof (event), &total_len);
	CuAssertIntEquals (test, sizeof (event), status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, sizeof (event));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (event), sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_event_with_event_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[40] = {0};
	uint8_t zero[38] = {0};
	size_t offset = 2;
	size_t length = sizeof (event) - offset;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, sizeof (event) - offset);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + offset, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_event_with_event_small_buffer (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[40] = {0};
	uint8_t zero[38] = {0};
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, 2, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_event_with_event_small_buffer_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[40] = {0};
	uint8_t zero[38] = {0};
	size_t offset = 1;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 2, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_event_with_data (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[40] = {0};
	uint8_t zero[8] = {0};
	size_t length = sizeof (buffer);
	size_t offset = 4;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (data), status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data), sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_event_with_data_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[40] = {0};
	uint8_t zero[9] = {0};
	size_t length = sizeof (buffer);
	size_t offset = 5;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (data) - 1, status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &data + 1, buffer, sizeof (data) - 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data) - 1, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_event_with_data_small_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[40] = {0};
	uint8_t zero[9] = {0};
	size_t offset = 4;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, sizeof (data) - 1, &total_len);
	CuAssertIntEquals (test, sizeof (data) - 1, status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, sizeof (data) - 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data) - 1, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_event_with_data_small_buffer_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[40] = {0};
	uint8_t zero[10] = {0};
	size_t offset = 5;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, sizeof (data) - 2, &total_len);
	CuAssertIntEquals (test, sizeof (data) - 2, status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &data + 1, buffer, sizeof (data) - 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data) - 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_event_invalid_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[40] = {0};
	uint8_t zero[40] = {0};
	size_t length = sizeof (buffer);
	size_t offset = 36;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (event), total_len);

	status = testing_validate_array (zero, buffer, length);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40];
	uint8_t version = 0x24;
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), false,
		version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (version) + sizeof (data), status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (version), total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array ((uint8_t*) &data, buffer + 1, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_version_small_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[8] = {0};
	uint8_t version = 0x24;
	size_t length = sizeof (version) + sizeof (data) - 1;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), false,
		version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (version), total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array ((uint8_t*) &data, buffer + 1, sizeof (data) - 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + length, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_version_with_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[39] = {0};
	uint8_t version = 0x24;
	size_t length = sizeof (version);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), false,
		version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (version), total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array (zero, buffer + length, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_version_with_data (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[8] = {0};
	uint8_t version = 0x24;
	size_t length = sizeof (buffer);
	size_t total_len;
	size_t offset = 1;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), false,
		version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (data), status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (version), total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data), sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_version_with_data_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[9] = {0};
	uint8_t version = 0x24;
	size_t length = sizeof (buffer);
	size_t total_len;
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), false,
		version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (data) - 1, status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (version), total_len);

	status = testing_validate_array ((uint8_t*) &data + 1, buffer, sizeof (data) - 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data) - 1, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_version_with_data_small_buffer (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[9] = {0};
	uint8_t version = 0x24;
	size_t total_len;
	size_t offset = 1;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), false,
		version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, sizeof (data) - 1, &total_len);
	CuAssertIntEquals (test, sizeof (data) - 1, status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (version), total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, sizeof (data) - 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data) - 1, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_version_with_data_small_buffer_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[10] = {0};
	uint8_t version = 0x24;
	size_t offset = 2;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), false,
		version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, sizeof (data) - 2, &total_len);
	CuAssertIntEquals (test, sizeof (data) - 2, status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (version), total_len);

	status = testing_validate_array ((uint8_t*) &data + 1, buffer, sizeof (data) - 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data) - 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_version_invalid_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40];
	uint8_t version = 0x24;
	size_t length = sizeof (buffer);
	size_t total_len;
	size_t offset = 33;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), false,
		version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (version), total_len);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_event_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40];
	size_t length = sizeof (buffer);
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (event) + sizeof (version) + sizeof (data), status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (event) + sizeof (version), total_len);
	CuAssertIntEquals (test, version, buffer[4]);

	status = testing_validate_array ((uint8_t*) &event, buffer, sizeof (event));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + 5, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_event_version_no_data (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t buffer[40];
	size_t length = sizeof (buffer);
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = NULL;
	measurement_data.data.memory.length = 0;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, NULL, 0, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (event) + sizeof (version), status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (version), total_len);
	CuAssertIntEquals (test, version, buffer[4]);

	status = testing_validate_array ((uint8_t*) &event, buffer, sizeof (event));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_event_version_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40];
	size_t length = sizeof (buffer);
	size_t total_len;
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (data) + sizeof (version) + sizeof (event) - offset, status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (event) + sizeof (version), total_len);
	CuAssertIntEquals (test, version, buffer[2]);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + 3, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_event_version_small_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[5] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t length = sizeof (data) + sizeof (event) + sizeof (version) - 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (event) + sizeof (version), total_len);
	CuAssertIntEquals (test, version, buffer[4]);

	status = testing_validate_array ((uint8_t*) &event, buffer, sizeof (event));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + 5, sizeof (data) - 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + length, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_event_version_small_buffer_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[7] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 2;
	size_t length = sizeof (data) + sizeof (event) + sizeof (version) - offset - 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (event) + sizeof (version), total_len);
	CuAssertIntEquals (test, version, buffer[2]);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + 3, sizeof (data) - 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + length, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_event_version_with_event_version (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[35] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t length = sizeof (event) + sizeof (version);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (event) + sizeof (version), total_len);
	CuAssertIntEquals (test, version, buffer[4]);

	status = testing_validate_array ((uint8_t*) &event, buffer, sizeof (event));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + length, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_event_version_with_event_version_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[37] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 2;
	size_t length = sizeof (event) + sizeof (version);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length - offset, &total_len);
	CuAssertIntEquals (test, length - offset, status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (event) + sizeof (version), total_len);
	CuAssertIntEquals (test, version, buffer[2]);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + length - offset, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_event_version_with_version_data (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[7] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 4;
	size_t length = sizeof (version) + sizeof (data);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, sizeof (buffer), &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (event) + sizeof (version), total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array ((uint8_t*) &data, buffer + 1, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + length, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_event_version_with_version_data_small_buffer (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[8] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 4;
	size_t length = sizeof (data) + sizeof (version) - 1;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (event) + sizeof (version), total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array ((uint8_t*) &data, buffer + 1, sizeof (data) - 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + length, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_event_version_with_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[36] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, sizeof (event), &total_len);
	CuAssertIntEquals (test, sizeof (event), status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (event) + sizeof (version), total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, sizeof (event));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (event), sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_event_version_with_event_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[38] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 2, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (event) + sizeof (version), total_len);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_event_version_with_event_small_buffer (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[37] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t length = sizeof (event) - 1;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (event) + sizeof (version), total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + length, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_event_version_with_event_small_buffer_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[39] = {0};
	size_t length = 1;
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (event) + sizeof (version), total_len);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + length, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_event_version_with_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[39] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 4;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 1, &total_len);
	CuAssertIntEquals (test, 1, status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (event) + sizeof (version), total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array (zero, buffer + 1, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_event_version_with_data (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[8] = {0};
	size_t length = sizeof (buffer);
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 5;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (data), status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (event) + sizeof (version), total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data), sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_event_version_with_data_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[9] = {0};
	size_t length = sizeof (buffer);
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 6;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (data) - 1, status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (event) + sizeof (version), total_len);

	status = testing_validate_array ((uint8_t*) &data + 1, buffer, sizeof (data) - 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data) - 1, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_event_version_with_data_small_buffer (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[10] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 5;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, sizeof (data) - 2, &total_len);
	CuAssertIntEquals (test, sizeof (data) - 2, status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (event) + sizeof (version), total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, sizeof (data) - 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data) - 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_event_version_with_data_small_buffer_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[10] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 6;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, sizeof (data) - 2, &total_len);
	CuAssertIntEquals (test, sizeof (data) - 2, status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (event) + sizeof (version), total_len);

	status = testing_validate_array ((uint8_t*) &data + 1, buffer, sizeof (data) - 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data) - 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_memory_include_event_version_invalid_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40];
	size_t length = sizeof (buffer);
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 37;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = data;
	measurement_data.data.memory.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (data) + sizeof (event) + sizeof (version), total_len);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[32];
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&pcr.flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (data), status);
	CuAssertIntEquals (test, sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_zero_length (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t buffer[32];
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = 32;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, 0, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 32, total_len);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[50];
	size_t length = sizeof (buffer);
	size_t total_len;
	size_t offset = 15;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344 + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data) - offset));
	status |= mock_expect_output (&pcr.flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (data) - offset, status);
	CuAssertIntEquals (test, sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &data + offset, buffer, sizeof (data) - offset);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_small_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[22];
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (length));
	status |= mock_expect_output (&pcr.flash.mock, 1, data, length, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, length);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_small_buffer_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[22];
	size_t length = sizeof (buffer);
	size_t total_len;
	size_t offset = 5;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344 + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (length));
	status |= mock_expect_output (&pcr.flash.mock, 1, data + offset, length, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &data + offset, buffer, length);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}
static void pcr_test_get_measurement_data_flash_invalid_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t buffer[50];
	size_t length = sizeof (buffer);
	size_t total_len;
	size_t offset = 32;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = 32;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 32, total_len);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_read_fail (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t buffer[50];
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = 32;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, FLASH_READ_FAILED,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[40];
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&pcr.flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (event) + sizeof (data), status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, sizeof (event));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + sizeof (event), sizeof (data));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_event_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[40] = {0};
	size_t length = sizeof (buffer);
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&pcr.flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (event) + sizeof (data) - offset, status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, sizeof (event) - offset);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + (sizeof (event) - offset),
		sizeof (data));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_event_small_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[40] = {0};
	uint8_t zero[6] = {0};
	size_t length = sizeof (data) + sizeof (event) - 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data) - 2));
	status |= mock_expect_output (&pcr.flash.mock, 1, data, sizeof (data) - 2, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, sizeof (event));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + sizeof (event),
		length - sizeof (event));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + length, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_event_small_buffer_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[40] = {0};
	uint8_t zero[8] = {0};
	size_t offset = 2;
	size_t length = sizeof (data) + sizeof (event) - offset - 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data) - 2));
	status |= mock_expect_output (&pcr.flash.mock, 1, data, sizeof (data) - 2, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, sizeof (event) - 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + offset, sizeof (data) - 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + length, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_event_with_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[40] = {0};
	uint8_t zero[36] = {0};
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = 0;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, sizeof (event), &total_len);
	CuAssertIntEquals (test, sizeof (event), status);
	CuAssertIntEquals (test, sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, sizeof (event));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (event), sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_event_with_event_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[40] = {0};
	uint8_t zero[38] = {0};
	size_t offset = 2;
	size_t length = sizeof (event) - offset;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = 0;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, sizeof (event) - offset);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + offset, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_event_with_event_small_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[40] = {0};
	uint8_t zero[38] = {0};
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = 0;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, 2, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_event_with_event_small_buffer_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[40] = {0};
	uint8_t zero[38] = {0};
	size_t offset = 1;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = 0;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 2, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, sizeof (event), total_len);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_event_with_data (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[40] = {0};
	uint8_t zero[8] = {0};
	size_t length = sizeof (buffer);
	size_t offset = 4;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&pcr.flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (data), status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data), sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_event_with_data_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[40] = {0};
	uint8_t zero[9] = {0};
	size_t length = sizeof (buffer);
	size_t offset = 5;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344 + 1), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data) - 1));
	status |= mock_expect_output (&pcr.flash.mock, 1, data + 1, sizeof (data) - 1, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (data) - 1, status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &data + 1, buffer, sizeof (data) - 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data) - 1, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_event_with_data_small_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[40] = {0};
	uint8_t zero[9] = {0};
	size_t offset = 4;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data) - 1));
	status |= mock_expect_output (&pcr.flash.mock, 1, data, sizeof (data) - 1, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, sizeof (data) - 1, &total_len);
	CuAssertIntEquals (test, sizeof (data) - 1, status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, sizeof (data) - 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data) - 1, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_event_with_data_small_buffer_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[40] = {0};
	uint8_t zero[10] = {0};
	size_t offset = 5;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344 + 1), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data) - 2));
	status |= mock_expect_output (&pcr.flash.mock, 1, data + 1, sizeof (data) - 2, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, sizeof (data) - 2, &total_len);
	CuAssertIntEquals (test, sizeof (data) - 2, status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &data + 1, buffer, sizeof (data) - 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data) - 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_event_with_data_read_fail (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[40] = {0};
	uint8_t zero[40] = {0};
	size_t length = sizeof (buffer);
	size_t offset = 4;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = 1;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, FLASH_READ_FAILED,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = testing_validate_array (zero, buffer, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_event_read_fail (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[40] = {0};
	size_t length = sizeof (buffer);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = 1;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, FLASH_READ_FAILED,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_event_invalid_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[40] = {0};
	uint8_t zero[40] = {0};
	size_t length = sizeof (buffer);
	size_t offset = 36;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = 1;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (event) + 1, total_len);

	status = testing_validate_array (zero, buffer, length);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40];
	uint8_t version = 0x24;
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), false,
		version);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&pcr.flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (version) + sizeof (data), status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (data), total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array ((uint8_t*) &data, buffer + 1, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_version_small_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[8] = {0};
	uint8_t version = 0x24;
	size_t length = sizeof (version) + sizeof (data) - 1;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), false,
		version);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data) - 1));
	status |= mock_expect_output (&pcr.flash.mock, 1, data, sizeof (data) - 1, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (data), total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array ((uint8_t*) &data, buffer + 1, sizeof (data) - 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + length, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_version_with_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[39] = {0};
	uint8_t version = 0x24;
	size_t length = sizeof (version);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = 0;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), false,
		version);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, sizeof (version), total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array (zero, buffer + length, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_version_with_data (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[8] = {0};
	uint8_t version = 0x24;
	size_t length = sizeof (buffer);
	size_t total_len;
	size_t offset = 1;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), false,
		version);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&pcr.flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (data), status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data), sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_version_with_data_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[9] = {0};
	uint8_t version = 0x24;
	size_t length = sizeof (buffer);
	size_t total_len;
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), false,
		version);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344 + 1), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data) - 1));
	status |= mock_expect_output (&pcr.flash.mock, 1, data + 1, sizeof (data) - 1, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (data) - 1, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &data + 1, buffer, sizeof (data) - 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data) - 1, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_version_with_data_small_buffer (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[9] = {0};
	uint8_t version = 0x24;
	size_t total_len;
	size_t offset = 1;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), false,
		version);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data) - 1));
	status |= mock_expect_output (&pcr.flash.mock, 1, data, sizeof (data) - 1, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, sizeof (data) - 1, &total_len);
	CuAssertIntEquals (test, sizeof (data) - 1, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, sizeof (data) - 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data) - 1, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_version_with_data_small_buffer_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[10] = {0};
	uint8_t version = 0x24;
	size_t offset = 2;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), false,
		version);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344 + 1), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data) - 2));
	status |= mock_expect_output (&pcr.flash.mock, 1, data + 1, sizeof (data) - 2, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, sizeof (data) - 2, &total_len);
	CuAssertIntEquals (test, sizeof (data) - 2, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &data + 1, buffer, sizeof (data) - 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data) - 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_version_with_data_read_fail (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[40] = {0};
	uint8_t version = 0x24;
	size_t length = sizeof (buffer);
	size_t total_len;
	size_t offset = 1;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = 1;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), false,
		version);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, FLASH_READ_FAILED,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = testing_validate_array (zero, buffer, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_version_read_fail (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t version = 0x24;
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = 1;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), false,
		version);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, FLASH_READ_FAILED,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_version_invalid_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40];
	uint8_t version = 0x24;
	size_t length = sizeof (buffer);
	size_t offset = 33;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = 1;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), false,
		version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (version) + 1, total_len);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_event_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40];
	size_t length = sizeof (buffer);
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&pcr.flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (event) + sizeof (version) + sizeof (data), status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (version) + sizeof (data), total_len);
	CuAssertIntEquals (test, version, buffer[4]);

	status = testing_validate_array ((uint8_t*) &event, buffer, sizeof (event));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + 5, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_event_version_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40];
	size_t length = sizeof (buffer);
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&pcr.flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (data) + sizeof (version) + sizeof (event) - offset, status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (version) + sizeof (data), total_len);
	CuAssertIntEquals (test, version, buffer[2]);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + 3, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_event_version_small_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[5] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t length = sizeof (data) + sizeof (event) + sizeof (version) - 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data) - 2));
	status |= mock_expect_output (&pcr.flash.mock, 1, data, sizeof (data) - 2, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (version) + sizeof (data), total_len);
	CuAssertIntEquals (test, version, buffer[4]);

	status = testing_validate_array ((uint8_t*) &event, buffer, sizeof (event));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + 5, sizeof (data) - 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + length, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_event_version_small_buffer_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[7] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 2;
	size_t length = sizeof (data) + sizeof (event) + sizeof (version) - offset - 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data) - 2));
	status |= mock_expect_output (&pcr.flash.mock, 1, data, sizeof (data) - 2, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (version) + sizeof (data), total_len);
	CuAssertIntEquals (test, version, buffer[2]);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + 3, sizeof (data) - 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + length, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_event_version_with_event_version (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[35] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t length = sizeof (event) + sizeof (version);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = 0;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (version), total_len);
	CuAssertIntEquals (test, version, buffer[4]);

	status = testing_validate_array ((uint8_t*) &event, buffer, sizeof (event));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + length, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_event_version_with_event_version_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[37] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 2;
	size_t length = sizeof (event) + sizeof (version);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = 0;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length - offset, &total_len);
	CuAssertIntEquals (test, length - offset, status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (version), total_len);
	CuAssertIntEquals (test, version, buffer[2]);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + length - offset, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_event_version_with_version_data (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[7] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 4;
	size_t length = sizeof (version) + sizeof (data);
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&pcr.flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, sizeof (buffer), &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (version) + sizeof (data), total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array ((uint8_t*) &data, buffer + 1, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + length, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_event_version_with_version_data_small_buffer (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[8] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 4;
	size_t length = sizeof (data) + sizeof (version) - 1;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data) - 1));
	status |= mock_expect_output (&pcr.flash.mock, 1, data, sizeof (data) - 1, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (version) + sizeof (data), total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array ((uint8_t*) &data, buffer + 1, sizeof (data) - 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + length, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_event_version_with_version_data_read_fail (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 4;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = 1;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, FLASH_READ_FAILED,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, sizeof (buffer), &total_len);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_event_version_with_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[36] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = 0;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, sizeof (event), &total_len);
	CuAssertIntEquals (test, sizeof (event), status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (version), total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, sizeof (event));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (event), sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_event_version_with_event_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[38] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = 0;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 2, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (version), total_len);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_event_version_with_event_small_buffer (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[37] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t length = sizeof (event) - 1;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = 0;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (version), total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + length, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_event_version_with_event_small_buffer_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[39] = {0};
	size_t length = 1;
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = 0;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (version), total_len);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + length, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_event_version_with_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[39] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 4;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = 0;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 1, &total_len);
	CuAssertIntEquals (test, 1, status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (version), total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array (zero, buffer + 1, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_event_version_with_data (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[8] = {0};
	size_t length = sizeof (buffer);
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 5;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&pcr.flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (data), status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (version) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data), sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_event_version_with_data_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[9] = {0};
	size_t length = sizeof (buffer);
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 6;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344 + 1), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data) - 1));
	status |= mock_expect_output (&pcr.flash.mock, 1, data + 1, sizeof (data) - 1, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (data) - 1, status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (version) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &data + 1, buffer, sizeof (data) - 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data) - 1, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_event_version_with_data_small_buffer (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[10] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 5;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data) - 2));
	status |= mock_expect_output (&pcr.flash.mock, 1, data, sizeof (data) -2, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, sizeof (data) - 2, &total_len);
	CuAssertIntEquals (test, sizeof (data) - 2, status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (version) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, sizeof (data) - 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data) - 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_event_version_with_data_small_buffer_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[10] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 6;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = sizeof (data);

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344 + 1), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data) - 2));
	status |= mock_expect_output (&pcr.flash.mock, 1, data + 1, sizeof (data) - 2, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, sizeof (data) - 2, &total_len);
	CuAssertIntEquals (test, sizeof (data) - 2, status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (version) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &data + 1, buffer, sizeof (data) - 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data) - 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_event_version_with_data_read_fail (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	uint8_t zero[40] = {0};
	size_t length = sizeof (buffer);
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 5;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = 1;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, FLASH_READ_FAILED,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = testing_validate_array (zero, buffer, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_event_version_read_fail (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40] = {0};
	size_t length = sizeof (buffer);
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = 1;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, FLASH_READ_FAILED,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_flash_include_event_version_invalid_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[40];
	size_t length = sizeof (buffer);
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 37;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = 1;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, data, sizeof (data), true,
		version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (version) + 1, total_len);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x12345678;
	uint8_t buffer[5];
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (data), status);
	CuAssertIntEquals (test, sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_zero_length (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x12345678;
	size_t total_len;
	uint8_t buffer[5];
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, 0, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (data), total_len);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x12345678;
	uint8_t *data_addr = (uint8_t*) &data;
	uint8_t buffer[5];
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 2, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (data) - 2, status);
	CuAssertIntEquals (test, sizeof (data), total_len);

	status = testing_validate_array (data_addr + 2, buffer, sizeof (data) - 2);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_fail (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t buffer[5];
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = NULL;

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, PCR_NO_MEMORY, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint32_t event = 0xaabbccdd;
	uint8_t buffer[10];
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data, sizeof (data),
		true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (event) + sizeof (data), status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, sizeof (event));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + sizeof (event), sizeof (data));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_event_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint32_t event = 0xaabbccdd;
	uint8_t buffer[10] = {0};
	size_t length = sizeof (buffer);
	size_t total_len;
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data, sizeof (data),
		true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (event) + sizeof (data) - offset, status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, sizeof (event) - offset);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + (sizeof (event) - offset),
		sizeof (data));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_event_small_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint32_t event = 0xaabbccdd;
	uint8_t buffer[10] = {0};
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data, sizeof (data),
		true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length - 2, &total_len);
	CuAssertIntEquals (test, length - 2, status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, sizeof (event));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + sizeof (event),	sizeof (data) - 2);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_event_small_buffer_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[10] = {0};
	uint8_t zero[6] = {0};
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data, sizeof (data),
		true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 4, &total_len);
	CuAssertIntEquals (test, 4, status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + 2, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 4, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_event_with_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[10] = {0};
	uint8_t zero[6] = {0};
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data, sizeof (data),
		true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, sizeof (event), &total_len);
	CuAssertIntEquals (test, sizeof (event), status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, sizeof (event));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (event), sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_event_with_event_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[10] = {0};
	uint8_t zero[8] = {0};
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data, sizeof (data),
		true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 2, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + offset, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_event_with_event_small_buffer (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[10] = {0};
	uint8_t zero[8] = {0};
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data, sizeof (data),
		true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, 2, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_event_with_event_small_buffer_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[10] = {0};
	uint8_t zero[8] = {0};
	size_t offset = 1;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data, sizeof (data),
		true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 2, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_event_with_data (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[10] = {0};
	uint8_t zero[6] = {0};
	size_t offset = 4;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data, sizeof (data),
		true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, sizeof (data), &total_len);
	CuAssertIntEquals (test, sizeof (data), status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data), sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_event_with_data_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[10] = {0};
	uint8_t zero[7] = {0};
	size_t offset = 5;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data, sizeof (data),
		true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 3, &total_len);
	CuAssertIntEquals (test, 3, status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &data + 1, buffer, sizeof (data) - 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 3, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_event_with_data_small_buffer (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[10] = {0};
	uint8_t zero[7] = {0};
	size_t offset = 4;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data, sizeof (data),
		true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 3, &total_len);
	CuAssertIntEquals (test, 3, status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, 3);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 3, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_event_with_data_small_buffer_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	uint8_t buffer[10] = {0};
	uint8_t zero[8] = {0};
	size_t offset = 5;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data, sizeof (data),
		true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 2, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, sizeof (event) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &data + 1, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_event_with_data_fail (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint32_t event = 0xaabbccdd;
	uint8_t buffer[10] = {0};
	uint8_t zero[10] = {0};
	size_t length = sizeof (buffer);
	size_t total_len;
	size_t offset = 4;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = NULL;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data, sizeof (data),
		true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, PCR_NO_MEMORY, status);

	status = testing_validate_array (zero, buffer, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_event_fail (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint32_t event = 0xaabbccdd;
	uint8_t buffer[10] = {0};
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = NULL;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data, sizeof (data),
		true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, PCR_NO_MEMORY, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10];
	uint8_t version = 0x24;
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data,
		sizeof (data), false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (version) + sizeof (data), status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (data), total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array ((uint8_t*) &data, buffer + 1, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_version_small_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	size_t total_len;
	uint8_t buffer[10] = {0};
	uint8_t zero[6] = {0};
	uint8_t version = 0x24;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data,
		sizeof (data), false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, 4, &total_len);
	CuAssertIntEquals (test, 4, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (data), total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array ((uint8_t*) &data, buffer + 1, 3);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 4, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_version_with_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	size_t total_len;
	uint8_t buffer[10] = {0};
	uint8_t zero[9] = {0};
	uint8_t version = 0x24;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data,
		sizeof (data), false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, 1, &total_len);
	CuAssertIntEquals (test, 1, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (data), total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array (zero, buffer + 1, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_version_with_data (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[6] = {0};
	uint8_t version = 0x24;
	size_t length = sizeof (buffer);
	size_t offset = 1;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data,
		sizeof (data), false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (data), status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data), sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_version_with_data_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[7] = {0};
	uint8_t version = 0x24;
	size_t length = sizeof (buffer);
	size_t offset = 2;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data,
		sizeof (data), false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (data) - 1, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &data + 1, buffer, sizeof (data) - 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data) - 1, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_version_with_data_small_buffer (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	size_t total_len;
	uint8_t buffer[10] = {0};
	uint8_t zero[7] = {0};
	uint8_t version = 0x24;
	size_t offset = 1;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data,
		sizeof (data), false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 3, &total_len);
	CuAssertIntEquals (test, 3, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, sizeof (data) - 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data) - 1, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_version_with_data_small_buffer_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	size_t total_len;
	uint8_t buffer[10] = {0};
	uint8_t zero[8] = {0};
	uint8_t version = 0x24;
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data,
		sizeof (data), false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 2, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &data + 1, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_version_with_data_fail (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[10] = {0};
	uint8_t version = 0x24;
	size_t length = sizeof (buffer);
	size_t offset = 1;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = NULL;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data,
		sizeof (data), false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, PCR_NO_MEMORY, status);

	status = testing_validate_array (zero, buffer, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_version_fail (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t version = 0x24;
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = NULL;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data,
		sizeof (data), false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, PCR_NO_MEMORY, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_event_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10];
	size_t length = sizeof (buffer);
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data,
		sizeof (data), true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, 9, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (event) + sizeof (data), total_len);
	CuAssertIntEquals (test, version, buffer[4]);

	status = testing_validate_array ((uint8_t*) &event, buffer, 4);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + 5, 4);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_event_version_offset (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10];
	size_t length = sizeof (buffer);
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data,
		sizeof (data), true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, 7, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (event) + sizeof (data), total_len);
	CuAssertIntEquals (test, version, buffer[2]);

	status = testing_validate_array ((uint8_t*) &event + 2, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + 3, 4);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_event_version_small_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[3] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data,
		sizeof (data), true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, 7, &total_len);
	CuAssertIntEquals (test, 7, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (event) + sizeof (data), total_len);
	CuAssertIntEquals (test, version, buffer[4]);

	status = testing_validate_array ((uint8_t*) &event, buffer, 4);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + 5, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 7, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_event_version_small_buffer_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[5] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data,
		sizeof (data), true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 5, &total_len);
	CuAssertIntEquals (test, 5, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (event) + sizeof (data), total_len);
	CuAssertIntEquals (test, version, buffer[2]);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &data, buffer + 3, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 5, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_event_version_with_event_version (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[5] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data,
		sizeof (data), true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, 5, &total_len);
	CuAssertIntEquals (test, 5, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (event) + sizeof (data), total_len);
	CuAssertIntEquals (test, version, buffer[4]);

	status = testing_validate_array ((uint8_t*) &event, buffer, 4);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 5, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_event_version_with_event_version_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[7] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data,
		sizeof (data), true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 3, &total_len);
	CuAssertIntEquals (test, 3, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (event) + sizeof (data), total_len);
	CuAssertIntEquals (test, version, buffer[2]);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 3, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_event_version_with_version_data (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[5] = {0};
	size_t length = sizeof (buffer);
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 4;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data,
		sizeof (data), true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, 5, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (event) + sizeof (data), total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array ((uint8_t*) &data, buffer + 1, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 5, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_event_version_with_version_data_small_buffer (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[7] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 4;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data,
		sizeof (data), true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 3, &total_len);
	CuAssertIntEquals (test, 3, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (event) + sizeof (data), total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array ((uint8_t*) &data, buffer + 1, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 3, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_event_version_with_version_data_fail (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	size_t length = sizeof (buffer);
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 4;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = NULL;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data,
		sizeof (data), true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, PCR_NO_MEMORY, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_event_version_with_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[6] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data,
		sizeof (data), true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, 4, &total_len);
	CuAssertIntEquals (test, 4, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (event) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, 4);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 4, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_event_version_with_event_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[8] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data,
		sizeof (data), true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 2, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (event) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_event_version_with_event_small_buffer (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[7] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data,
		sizeof (data), true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, 3, &total_len);
	CuAssertIntEquals (test, 3, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (event) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &event, buffer, 3);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 3, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_event_version_with_event_small_buffer_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[9] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 2;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data,
		sizeof (data), true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 1, &total_len);
	CuAssertIntEquals (test, 1, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (event) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &event + offset, buffer, 1);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 1, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_event_version_with_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[9] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 4;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data,
		sizeof (data), true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 1, &total_len);
	CuAssertIntEquals (test, 1, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (event) + sizeof (data), total_len);
	CuAssertIntEquals (test, version, buffer[0]);

	status = testing_validate_array (zero, buffer + 1, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_event_version_with_data (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[6] = {0};
	size_t length = sizeof (buffer);
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 5;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data,
		sizeof (data), true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, sizeof (data), status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (event) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + sizeof (data), sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_event_version_with_data_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[7] = {0};
	size_t length = sizeof (buffer);
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 6;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data,
		sizeof (data), true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, 3, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (event) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &data + 1, buffer, 3);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 3, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_event_version_with_data_small_buffer (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[8] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 5;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data,
		sizeof (data), true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 2, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (event) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &data, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_event_version_with_data_small_buffer_offset (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[8] = {0};
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 6;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data,
		sizeof (data), true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, 2, &total_len);
	CuAssertIntEquals (test, 2, status);
	CuAssertIntEquals (test, sizeof (version) + sizeof (event) + sizeof (data), total_len);

	status = testing_validate_array ((uint8_t*) &data + 1, buffer, 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer + 2, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_event_version_with_data_fail (
	CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	uint8_t zero[10] = {0};
	size_t length = sizeof (buffer);
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	size_t offset = 5;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = NULL;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data,
		sizeof (data), true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, offset, buffer, length, &total_len);
	CuAssertIntEquals (test, PCR_NO_MEMORY, status);

	status = testing_validate_array (zero, buffer, sizeof (zero));
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_callback_include_event_version_fail (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[10] = {0};
	size_t length = sizeof (buffer);
	uint8_t version = 0x24;
	uint32_t event = 0xaabbccdd;
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.context = NULL;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 2, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 2, (uint8_t*) &data,
		sizeof (data), true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, PCR_NO_MEMORY, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_no_measured_data (
	CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[40];
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, total_len);

	pcr_testing_release (test, &pcr);
}


static void pcr_test_get_measurement_data_null (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[5];
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_get_measurement_data (NULL, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, NULL, length, &total_len);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, NULL);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_bad_measurement_index (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[1];
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_get_measurement_data (&pcr.test, 6, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_no_data (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[1];
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, total_len);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_measurement_data_bad_measurement_data_type (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	uint8_t buffer[4];
	size_t length = sizeof (buffer);
	size_t total_len;
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	/* This is a contrived test that is not possible using the APIs, so need to change the value
	 * after setting the measured data. */
	measurement_data.type = NUM_PCR_DATA_TYPE;

	status = pcr_get_measurement_data (&pcr.test, 2, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, PCR_INVALID_DATA_TYPE, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha256_matches_pcr (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_FULL_BLOCK_512_HASH, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha256_matches_pcr_include_event (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_tcg_event_type (&pcr.test, 1, 0xaabbccdd);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 1, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 1, &pcr.hash.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_FULL_BLOCK_512_HASH_WITH_EVENT, buffer,
		status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha256_matches_pcr_include_version (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 3, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false, 0x24);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 3, &pcr.hash.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_FULL_BLOCK_512_HASH_VERSIONED, buffer,
		status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha256_matches_pcr_include_event_version (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_tcg_event_type (&pcr.test, 0, 0xaabbccdd);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 0, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, true, 0x24);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 0, &pcr.hash.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_FULL_BLOCK_512_HASH_VERSIONED_WITH_EVENT,
		buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
static void pcr_test_hash_measurement_data_sha384_matches_pcr (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash.base, HASH_TYPE_SHA384, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (SHA384_FULL_BLOCK_512_HASH, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha384_matches_pcr_include_event (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_tcg_event_type (&pcr.test, 1, 0xaabbccdd);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 1, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 1, &pcr.hash.base, HASH_TYPE_SHA384, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA384_FULL_BLOCK_512_HASH_WITH_EVENT, buffer,
		status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha384_matches_pcr_include_version (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 3, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false, 0x24);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 3, &pcr.hash.base, HASH_TYPE_SHA384, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA384_FULL_BLOCK_512_HASH_VERSIONED, buffer,
		status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha384_matches_pcr_include_event_version (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_tcg_event_type (&pcr.test, 0, 0xaabbccdd);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 0, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, true, 0x24);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 0, &pcr.hash.base, HASH_TYPE_SHA384, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA384_FULL_BLOCK_512_HASH_VERSIONED_WITH_EVENT,
		buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}
#endif

#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
static void pcr_test_hash_measurement_data_sha512_matches_pcr (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA512);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 2, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash.base, HASH_TYPE_SHA512, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (SHA512_FULL_BLOCK_512_HASH, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha512_matches_pcr_include_event (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA512);

	status = pcr_set_tcg_event_type (&pcr.test, 1, 0xaabbccdd);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 1, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 1, &pcr.hash.base, HASH_TYPE_SHA512, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA512_FULL_BLOCK_512_HASH_WITH_EVENT, buffer,
		status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha512_matches_pcr_include_version (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA512);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 3, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, false, 0x24);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 3, &pcr.hash.base, HASH_TYPE_SHA512, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA512_FULL_BLOCK_512_HASH_VERSIONED, buffer,
		status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha512_matches_pcr_include_event_version (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA512);

	status = pcr_set_tcg_event_type (&pcr.test, 0, 0xaabbccdd);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 0, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, true, 0x24);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 0, &pcr.hash.base, HASH_TYPE_SHA512, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA512_FULL_BLOCK_512_HASH_VERSIONED_WITH_EVENT,
		buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}
#endif

#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
static void pcr_test_hash_measurement_data_sha256_1byte (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint8_t data = 0x11;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_1BYTE_DATA, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha256_1byte_include_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint8_t data = 0x11;
	const uint32_t event = 0xaabbccdd;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 1, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 1, &measurement_data.data.value_1byte, 1,
		true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 1, &pcr.hash.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_1BYTE_DATA_WITH_EVENT, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha256_1byte_include_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint8_t data = 0x11;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 3, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 3,
		&measurement_data.data.value_1byte, 1, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 3, &pcr.hash.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_1BYTE_DATA_VERSIONED, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha256_1byte_include_event_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint8_t data = 0x11;
	const uint32_t event = 0xaabbccdd;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 0, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 0, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 0,
		&measurement_data.data.value_1byte, 1, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 0, &pcr.hash.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_1BYTE_DATA_VERSIONED_WITH_EVENT, buffer,
		status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha256_2byte (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint16_t data = 0x1122;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_2BYTE_DATA, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha256_2byte_include_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint16_t data = 0x1122;
	const uint32_t event = 0xaabbccdd;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 1, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 1,
		(uint8_t*) &measurement_data.data.value_2byte, 2, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 1, &pcr.hash.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_2BYTE_DATA_WITH_EVENT, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha256_2byte_include_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint16_t data = 0x1122;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 3, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 3,
		(uint8_t*) &measurement_data.data.value_2byte, 2, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 3, &pcr.hash.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_2BYTE_DATA_VERSIONED, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha256_2byte_include_event_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint16_t data = 0x1122;
	const uint32_t event = 0xaabbccdd;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 0, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 0, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 0,
		(uint8_t*) &measurement_data.data.value_2byte, 2, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 0, &pcr.hash.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_2BYTE_DATA_VERSIONED_WITH_EVENT, buffer,
		status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha256_4byte (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint32_t data = 0x11223344;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_4BYTE_DATA, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha256_4byte_include_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint32_t data = 0x11223344;
	const uint32_t event = 0xaabbccdd;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 1, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 1,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 1, &pcr.hash.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_4BYTE_DATA_WITH_EVENT, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha256_4byte_include_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint32_t data = 0x11223344;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 3, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 3,
		(uint8_t*) &measurement_data.data.value_4byte, 4, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 3, &pcr.hash.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_4BYTE_DATA_VERSIONED, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha256_4byte_include_event_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint32_t data = 0x11223344;
	const uint32_t event = 0xaabbccdd;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 0, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 0, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 0,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 0, &pcr.hash.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_4BYTE_DATA_VERSIONED_WITH_EVENT, buffer,
		status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha256_8byte (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint64_t data = 0x1122334455667788;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_8BYTE_DATA, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha256_8byte_include_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint64_t data = 0x1122334455667788;
	const uint32_t event = 0xaabbccdd;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 1, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 1,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 1, &pcr.hash.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_8BYTE_DATA_WITH_EVENT, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha256_8byte_include_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint64_t data = 0x1122334455667788;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 3, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 3,
		(uint8_t*) &measurement_data.data.value_8byte, 8, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 3, &pcr.hash.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_8BYTE_DATA_VERSIONED, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha256_8byte_include_event_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint64_t data = 0x1122334455667788;
	const uint32_t event = 0xaabbccdd;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 0, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 0, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 0,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 0, &pcr.hash.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_8BYTE_DATA_VERSIONED_WITH_EVENT, buffer,
		status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha256_memory (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = HASH_TESTING_FULL_BLOCK_512;
	measurement_data.data.memory.length = HASH_TESTING_FULL_BLOCK_512_LEN;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_FULL_BLOCK_512_HASH, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha256_memory_include_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint32_t event = 0xaabbccdd;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = HASH_TESTING_FULL_BLOCK_512;
	measurement_data.data.memory.length = HASH_TESTING_FULL_BLOCK_512_LEN;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 1, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 1,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 1, &pcr.hash.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_FULL_BLOCK_512_HASH_WITH_EVENT, buffer,
		status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha256_memory_include_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = HASH_TESTING_FULL_BLOCK_512;
	measurement_data.data.memory.length = HASH_TESTING_FULL_BLOCK_512_LEN;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 3, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 3,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 3, &pcr.hash.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_FULL_BLOCK_512_HASH_VERSIONED, buffer,
		status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha256_memory_include_event_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint32_t event = 0xaabbccdd;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = HASH_TESTING_FULL_BLOCK_512;
	measurement_data.data.memory.length = HASH_TESTING_FULL_BLOCK_512_LEN;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 0, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 0, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 0,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 0, &pcr.hash.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_FULL_BLOCK_512_HASH_VERSIONED_WITH_EVENT,
		buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha256_flash (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = HASH_TESTING_FULL_BLOCK_1024_LEN;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (HASH_TESTING_FULL_BLOCK_1024_LEN));
	status |= mock_expect_output (&pcr.flash.mock, 1, HASH_TESTING_FULL_BLOCK_1024,
		HASH_TESTING_FULL_BLOCK_1024_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (SHA256_FULL_BLOCK_1024_HASH, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha256_flash_include_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint32_t event = 0xaabbccdd;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x44332211;
	measurement_data.data.flash.length = HASH_TESTING_FULL_BLOCK_512_LEN;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 1, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 1,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x44332211), MOCK_ARG_NOT_NULL, MOCK_ARG (HASH_TESTING_FULL_BLOCK_512_LEN));
	status |= mock_expect_output (&pcr.flash.mock, 1, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 1, &pcr.hash.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_FULL_BLOCK_512_HASH_WITH_EVENT, buffer,
		status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha256_flash_include_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = HASH_TESTING_FULL_BLOCK_512_LEN;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 3, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 3,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (HASH_TESTING_FULL_BLOCK_512_LEN));
	status |= mock_expect_output (&pcr.flash.mock, 1, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 3, &pcr.hash.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_FULL_BLOCK_512_HASH_VERSIONED, buffer,
		status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha256_flash_include_event_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint32_t event = 0xaabbccdd;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = HASH_TESTING_FULL_BLOCK_512_LEN;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 0, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 0, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 0,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true, version);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (HASH_TESTING_FULL_BLOCK_512_LEN));
	status |= mock_expect_output (&pcr.flash.mock, 1, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 0, &pcr.hash.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_FULL_BLOCK_512_HASH_VERSIONED_WITH_EVENT,
		buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha256_callback (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.hash_data = pcr_testing_measurement_hash_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_4BYTE_DATA, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha256_callback_include_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	const uint32_t event = 0xaabbccdd;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.hash_data = pcr_testing_measurement_hash_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 1, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 1, (uint8_t*) &data, sizeof (data),
		true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 1, &pcr.hash.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_4BYTE_DATA_WITH_EVENT, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha256_callback_include_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.hash_data = pcr_testing_measurement_hash_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 3, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 3, (uint8_t*) &data,
		sizeof (data), false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 3, &pcr.hash.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_4BYTE_DATA_VERSIONED, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha256_callback_include_event_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	const uint32_t event = 0xaabbccdd;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.hash_data = pcr_testing_measurement_hash_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 0, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 0, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 0, (uint8_t*) &data,
		sizeof (data), true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 0, &pcr.hash.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA256_4BYTE_DATA_VERSIONED_WITH_EVENT,
		buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha384_1byte (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint8_t data = 0x11;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash.base, HASH_TYPE_SHA384, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA384_1BYTE_DATA, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha384_1byte_include_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint8_t data = 0x11;
	const uint32_t event = 0xaabbccdd;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 1, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 1, &measurement_data.data.value_1byte, 1,
		true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 1, &pcr.hash.base, HASH_TYPE_SHA384, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA384_1BYTE_DATA_WITH_EVENT, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha384_1byte_include_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint8_t data = 0x11;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 3, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 3,
		&measurement_data.data.value_1byte, 1, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 3, &pcr.hash.base, HASH_TYPE_SHA384, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA384_1BYTE_DATA_VERSIONED, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha384_1byte_include_event_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint8_t data = 0x11;
	const uint32_t event = 0xaabbccdd;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 0, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 0, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 0,
		&measurement_data.data.value_1byte, 1, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 0, &pcr.hash.base, HASH_TYPE_SHA384, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA384_1BYTE_DATA_VERSIONED_WITH_EVENT, buffer,
		status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha384_2byte (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint16_t data = 0x1122;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash.base, HASH_TYPE_SHA384, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA384_2BYTE_DATA, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha384_2byte_include_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint16_t data = 0x1122;
	const uint32_t event = 0xaabbccdd;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 1, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 1,
		(uint8_t*) &measurement_data.data.value_2byte, 2, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 1, &pcr.hash.base, HASH_TYPE_SHA384, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA384_2BYTE_DATA_WITH_EVENT, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha384_2byte_include_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint16_t data = 0x1122;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 3, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 3,
		(uint8_t*) &measurement_data.data.value_2byte, 2, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 3, &pcr.hash.base, HASH_TYPE_SHA384, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA384_2BYTE_DATA_VERSIONED, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha384_2byte_include_event_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint16_t data = 0x1122;
	const uint32_t event = 0xaabbccdd;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 0, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 0, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 0,
		(uint8_t*) &measurement_data.data.value_2byte, 2, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 0, &pcr.hash.base, HASH_TYPE_SHA384, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA384_2BYTE_DATA_VERSIONED_WITH_EVENT, buffer,
		status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha384_4byte (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint32_t data = 0x11223344;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash.base, HASH_TYPE_SHA384, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA384_4BYTE_DATA, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha384_4byte_include_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint32_t data = 0x11223344;
	const uint32_t event = 0xaabbccdd;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 1, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 1,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 1, &pcr.hash.base, HASH_TYPE_SHA384, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA384_4BYTE_DATA_WITH_EVENT, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha384_4byte_include_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint32_t data = 0x11223344;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 3, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 3,
		(uint8_t*) &measurement_data.data.value_4byte, 4, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 3, &pcr.hash.base, HASH_TYPE_SHA384, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA384_4BYTE_DATA_VERSIONED, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha384_4byte_include_event_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint32_t data = 0x11223344;
	const uint32_t event = 0xaabbccdd;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 0, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 0, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 0,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 0, &pcr.hash.base, HASH_TYPE_SHA384, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA384_4BYTE_DATA_VERSIONED_WITH_EVENT, buffer,
		status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha384_8byte (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint64_t data = 0x1122334455667788;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash.base, HASH_TYPE_SHA384, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA384_8BYTE_DATA, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha384_8byte_include_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint64_t data = 0x1122334455667788;
	const uint32_t event = 0xaabbccdd;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 1, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 1,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 1, &pcr.hash.base, HASH_TYPE_SHA384, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA384_8BYTE_DATA_WITH_EVENT, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha384_8byte_include_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint64_t data = 0x1122334455667788;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 3, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 3,
		(uint8_t*) &measurement_data.data.value_8byte, 8, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 3, &pcr.hash.base, HASH_TYPE_SHA384, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA384_8BYTE_DATA_VERSIONED, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha384_8byte_include_event_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint64_t data = 0x1122334455667788;
	const uint32_t event = 0xaabbccdd;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 0, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 0, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 0,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 0, &pcr.hash.base, HASH_TYPE_SHA384, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA384_8BYTE_DATA_VERSIONED_WITH_EVENT, buffer,
		status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha384_memory (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = HASH_TESTING_FULL_BLOCK_512;
	measurement_data.data.memory.length = HASH_TESTING_FULL_BLOCK_512_LEN;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash.base, HASH_TYPE_SHA384, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (SHA384_FULL_BLOCK_512_HASH, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha384_memory_include_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint32_t event = 0xaabbccdd;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = HASH_TESTING_FULL_BLOCK_512;
	measurement_data.data.memory.length = HASH_TESTING_FULL_BLOCK_512_LEN;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 1, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 1,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 1, &pcr.hash.base, HASH_TYPE_SHA384, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA384_FULL_BLOCK_512_HASH_WITH_EVENT, buffer,
		status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha384_memory_include_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = HASH_TESTING_FULL_BLOCK_512;
	measurement_data.data.memory.length = HASH_TESTING_FULL_BLOCK_512_LEN;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 3, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 3,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 3, &pcr.hash.base, HASH_TYPE_SHA384, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA384_FULL_BLOCK_512_HASH_VERSIONED, buffer,
		status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha384_memory_include_event_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint32_t event = 0xaabbccdd;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = HASH_TESTING_FULL_BLOCK_512;
	measurement_data.data.memory.length = HASH_TESTING_FULL_BLOCK_512_LEN;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 0, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 0, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 0,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 0, &pcr.hash.base, HASH_TYPE_SHA384, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA384_FULL_BLOCK_512_HASH_VERSIONED_WITH_EVENT,
		buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha384_flash (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = HASH_TESTING_FULL_BLOCK_1024_LEN;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (HASH_TESTING_FULL_BLOCK_1024_LEN));
	status |= mock_expect_output (&pcr.flash.mock, 1, HASH_TESTING_FULL_BLOCK_1024,
		HASH_TESTING_FULL_BLOCK_1024_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash.base, HASH_TYPE_SHA384, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (SHA384_FULL_BLOCK_1024_HASH, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha384_flash_include_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint32_t event = 0xaabbccdd;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x44332211;
	measurement_data.data.flash.length = HASH_TESTING_FULL_BLOCK_512_LEN;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 1, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 1,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x44332211), MOCK_ARG_NOT_NULL, MOCK_ARG (HASH_TESTING_FULL_BLOCK_512_LEN));
	status |= mock_expect_output (&pcr.flash.mock, 1, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 1, &pcr.hash.base, HASH_TYPE_SHA384, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA384_FULL_BLOCK_512_HASH_WITH_EVENT, buffer,
		status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha384_flash_include_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = HASH_TESTING_FULL_BLOCK_512_LEN;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 3, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 3,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (HASH_TESTING_FULL_BLOCK_512_LEN));
	status |= mock_expect_output (&pcr.flash.mock, 1, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 3, &pcr.hash.base, HASH_TYPE_SHA384, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA384_FULL_BLOCK_512_HASH_VERSIONED, buffer,
		status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha384_flash_include_event_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint32_t event = 0xaabbccdd;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = HASH_TESTING_FULL_BLOCK_512_LEN;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 0, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 0, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 0,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true, version);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (HASH_TESTING_FULL_BLOCK_512_LEN));
	status |= mock_expect_output (&pcr.flash.mock, 1, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 0, &pcr.hash.base, HASH_TYPE_SHA384, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA384_FULL_BLOCK_512_HASH_VERSIONED_WITH_EVENT,
		buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha384_callback (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.hash_data = pcr_testing_measurement_hash_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash.base, HASH_TYPE_SHA384, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA384_4BYTE_DATA, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha384_callback_include_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	const uint32_t event = 0xaabbccdd;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.hash_data = pcr_testing_measurement_hash_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 1, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 1, (uint8_t*) &data, sizeof (data),
		true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 1, &pcr.hash.base, HASH_TYPE_SHA384, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA384_4BYTE_DATA_WITH_EVENT, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha384_callback_include_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.hash_data = pcr_testing_measurement_hash_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 3, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 3, (uint8_t*) &data,
		sizeof (data), false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 3, &pcr.hash.base, HASH_TYPE_SHA384, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA384_4BYTE_DATA_VERSIONED, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha384_callback_include_event_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	const uint32_t event = 0xaabbccdd;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.hash_data = pcr_testing_measurement_hash_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 0, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 0, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 0, (uint8_t*) &data,
		sizeof (data), true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 0, &pcr.hash.base, HASH_TYPE_SHA384, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA384_4BYTE_DATA_VERSIONED_WITH_EVENT,
		buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}
#endif

#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
static void pcr_test_hash_measurement_data_sha512_1byte (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint8_t data = 0x11;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash.base, HASH_TYPE_SHA512, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA512_1BYTE_DATA, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha512_1byte_include_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint8_t data = 0x11;
	const uint32_t event = 0xaabbccdd;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 1, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 1, &measurement_data.data.value_1byte, 1,
		true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 1, &pcr.hash.base, HASH_TYPE_SHA512, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA512_1BYTE_DATA_WITH_EVENT, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha512_1byte_include_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint8_t data = 0x11;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 3, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 3,
		&measurement_data.data.value_1byte, 1, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 3, &pcr.hash.base, HASH_TYPE_SHA512, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA512_1BYTE_DATA_VERSIONED, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha512_1byte_include_event_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint8_t data = 0x11;
	const uint32_t event = 0xaabbccdd;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 0, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 0, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 0,
		&measurement_data.data.value_1byte, 1, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 0, &pcr.hash.base, HASH_TYPE_SHA512, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA512_1BYTE_DATA_VERSIONED_WITH_EVENT, buffer,
		status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha512_2byte (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint16_t data = 0x1122;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash.base, HASH_TYPE_SHA512, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA512_2BYTE_DATA, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha512_2byte_include_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint16_t data = 0x1122;
	const uint32_t event = 0xaabbccdd;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 1, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 1,
		(uint8_t*) &measurement_data.data.value_2byte, 2, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 1, &pcr.hash.base, HASH_TYPE_SHA512, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA512_2BYTE_DATA_WITH_EVENT, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha512_2byte_include_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint16_t data = 0x1122;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 3, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 3,
		(uint8_t*) &measurement_data.data.value_2byte, 2, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 3, &pcr.hash.base, HASH_TYPE_SHA512, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA512_2BYTE_DATA_VERSIONED, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha512_2byte_include_event_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint16_t data = 0x1122;
	const uint32_t event = 0xaabbccdd;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 0, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 0, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 0,
		(uint8_t*) &measurement_data.data.value_2byte, 2, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 0, &pcr.hash.base, HASH_TYPE_SHA512, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA512_2BYTE_DATA_VERSIONED_WITH_EVENT, buffer,
		status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha512_4byte (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint32_t data = 0x11223344;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash.base, HASH_TYPE_SHA512, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA512_4BYTE_DATA, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha512_4byte_include_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint32_t data = 0x11223344;
	const uint32_t event = 0xaabbccdd;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 1, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 1,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 1, &pcr.hash.base, HASH_TYPE_SHA512, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA512_4BYTE_DATA_WITH_EVENT, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha512_4byte_include_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint32_t data = 0x11223344;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 3, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 3,
		(uint8_t*) &measurement_data.data.value_4byte, 4, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 3, &pcr.hash.base, HASH_TYPE_SHA512, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA512_4BYTE_DATA_VERSIONED, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha512_4byte_include_event_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint32_t data = 0x11223344;
	const uint32_t event = 0xaabbccdd;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 0, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 0, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 0,
		(uint8_t*) &measurement_data.data.value_4byte, 4, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 0, &pcr.hash.base, HASH_TYPE_SHA512, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA512_4BYTE_DATA_VERSIONED_WITH_EVENT, buffer,
		status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha512_8byte (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint64_t data = 0x1122334455667788;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash.base, HASH_TYPE_SHA512, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA512_8BYTE_DATA, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha512_8byte_include_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint64_t data = 0x1122334455667788;
	const uint32_t event = 0xaabbccdd;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 1, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 1,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 1, &pcr.hash.base, HASH_TYPE_SHA512, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA512_8BYTE_DATA_WITH_EVENT, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha512_8byte_include_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint64_t data = 0x1122334455667788;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 3, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 3,
		(uint8_t*) &measurement_data.data.value_8byte, 8, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 3, &pcr.hash.base, HASH_TYPE_SHA512, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA512_8BYTE_DATA_VERSIONED, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha512_8byte_include_event_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint64_t data = 0x1122334455667788;
	const uint32_t event = 0xaabbccdd;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 0, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 0, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 0,
		(uint8_t*) &measurement_data.data.value_8byte, 8, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 0, &pcr.hash.base, HASH_TYPE_SHA512, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA512_8BYTE_DATA_VERSIONED_WITH_EVENT, buffer,
		status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha512_memory (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = HASH_TESTING_FULL_BLOCK_512;
	measurement_data.data.memory.length = HASH_TESTING_FULL_BLOCK_512_LEN;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash.base, HASH_TYPE_SHA512, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (SHA512_FULL_BLOCK_512_HASH, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha512_memory_include_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint32_t event = 0xaabbccdd;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = HASH_TESTING_FULL_BLOCK_512;
	measurement_data.data.memory.length = HASH_TESTING_FULL_BLOCK_512_LEN;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 1, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 1,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 1, &pcr.hash.base, HASH_TYPE_SHA512, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA512_FULL_BLOCK_512_HASH_WITH_EVENT, buffer,
		status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha512_memory_include_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = HASH_TESTING_FULL_BLOCK_512;
	measurement_data.data.memory.length = HASH_TESTING_FULL_BLOCK_512_LEN;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 3, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 3,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 3, &pcr.hash.base, HASH_TYPE_SHA512, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA512_FULL_BLOCK_512_HASH_VERSIONED, buffer,
		status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha512_memory_include_event_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint32_t event = 0xaabbccdd;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = HASH_TESTING_FULL_BLOCK_512;
	measurement_data.data.memory.length = HASH_TESTING_FULL_BLOCK_512_LEN;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 0, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 0, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 0,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 0, &pcr.hash.base, HASH_TYPE_SHA512, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA512_FULL_BLOCK_512_HASH_VERSIONED_WITH_EVENT,
		buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha512_flash (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = HASH_TESTING_FULL_BLOCK_1024_LEN;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (HASH_TESTING_FULL_BLOCK_1024_LEN));
	status |= mock_expect_output (&pcr.flash.mock, 1, HASH_TESTING_FULL_BLOCK_1024,
		HASH_TESTING_FULL_BLOCK_1024_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash.base, HASH_TYPE_SHA512, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (SHA512_FULL_BLOCK_1024_HASH, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha512_flash_include_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint32_t event = 0xaabbccdd;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x44332211;
	measurement_data.data.flash.length = HASH_TESTING_FULL_BLOCK_512_LEN;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 1, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 1,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x44332211), MOCK_ARG_NOT_NULL, MOCK_ARG (HASH_TESTING_FULL_BLOCK_512_LEN));
	status |= mock_expect_output (&pcr.flash.mock, 1, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 1, &pcr.hash.base, HASH_TYPE_SHA512, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA512_FULL_BLOCK_512_HASH_WITH_EVENT, buffer,
		status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha512_flash_include_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = HASH_TESTING_FULL_BLOCK_512_LEN;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 3, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 3,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (HASH_TESTING_FULL_BLOCK_512_LEN));
	status |= mock_expect_output (&pcr.flash.mock, 1, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 3, &pcr.hash.base, HASH_TYPE_SHA512, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA512_FULL_BLOCK_512_HASH_VERSIONED, buffer,
		status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha512_flash_include_event_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint32_t event = 0xaabbccdd;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = HASH_TESTING_FULL_BLOCK_512_LEN;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 0, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 0, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 0,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true, version);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, 0,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (HASH_TESTING_FULL_BLOCK_512_LEN));
	status |= mock_expect_output (&pcr.flash.mock, 1, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 0, &pcr.hash.base, HASH_TYPE_SHA512, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA512_FULL_BLOCK_512_HASH_VERSIONED_WITH_EVENT,
		buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha512_callback (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.hash_data = pcr_testing_measurement_hash_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash.base, HASH_TYPE_SHA512, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA512_4BYTE_DATA, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha512_callback_include_event (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	const uint32_t event = 0xaabbccdd;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.hash_data = pcr_testing_measurement_hash_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 1, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 1, (uint8_t*) &data, sizeof (data),
		true);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 1, &pcr.hash.base, HASH_TYPE_SHA512, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA512_4BYTE_DATA_WITH_EVENT, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha512_callback_include_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.hash_data = pcr_testing_measurement_hash_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 3, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 3, (uint8_t*) &data,
		sizeof (data), false, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 3, &pcr.hash.base, HASH_TYPE_SHA512, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA512_4BYTE_DATA_VERSIONED, buffer, status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha512_callback_include_event_version (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	const uint32_t event = 0xaabbccdd;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.hash_data = pcr_testing_measurement_hash_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 0, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 0, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 0, (uint8_t*) &data,
		sizeof (data), true, version);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 0, &pcr.hash.base, HASH_TYPE_SHA512, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (PCR_TESTING_SHA512_4BYTE_DATA_VERSIONED_WITH_EVENT, buffer,
		status);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}
#endif

static void pcr_test_hash_measurement_data_null (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_hash_measurement_data (NULL, 2, &pcr.hash.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, NULL, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash.base, HASH_TYPE_SHA256, NULL,
		sizeof (buffer));
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_bad_measurement_index (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_hash_measurement_data (&pcr.test, 5, &pcr.hash.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, PCR_INVALID_INDEX, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_unknown_hash (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_hash_measurement_data (&pcr.test, 3, &pcr.hash.base, HASH_TYPE_INVALID, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, HASH_ENGINE_UNKNOWN_HASH, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha256_small_output_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash.base, HASH_TYPE_SHA256, buffer,
		SHA256_HASH_LENGTH - 1);
	CuAssertIntEquals (test, PCR_SMALL_OUTPUT_BUFFER, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha384_small_output_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash.base, HASH_TYPE_SHA384, buffer,
		SHA384_HASH_LENGTH - 1);
	CuAssertIntEquals (test, PCR_SMALL_OUTPUT_BUFFER, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha512_small_output_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash.base, HASH_TYPE_SHA512, buffer,
		SHA512_HASH_LENGTH - 1);
	CuAssertIntEquals (test, PCR_SMALL_OUTPUT_BUFFER, status);

	pcr_testing_release (test, &pcr);
}

#ifdef HASH_ENABLE_SHA384
static void pcr_test_hash_measurement_data_sha384_start_hash_error (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = HASH_TESTING_FULL_BLOCK_512;
	measurement_data.data.memory.length = HASH_TESTING_FULL_BLOCK_512_LEN;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha384, &pcr.hash_mock,
		HASH_ENGINE_START_SHA384_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash_mock.base, HASH_TYPE_SHA384, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA384_FAILED, status);

	pcr_testing_release (test, &pcr);
}
#endif

#ifdef HASH_ENABLE_SHA512
static void pcr_test_hash_measurement_data_sha512_start_hash_error (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = HASH_TESTING_FULL_BLOCK_512;
	measurement_data.data.memory.length = HASH_TESTING_FULL_BLOCK_512_LEN;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha512, &pcr.hash_mock,
		HASH_ENGINE_START_SHA512_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash_mock.base, HASH_TYPE_SHA512, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA512_FAILED, status);

	pcr_testing_release (test, &pcr);
}
#endif

#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
static void pcr_test_hash_measurement_data_no_measured_data (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, PCR_MEASURED_DATA_NOT_AVIALABLE, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_sha256_start_hash_error (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = HASH_TESTING_FULL_BLOCK_512;
	measurement_data.data.memory.length = HASH_TESTING_FULL_BLOCK_512_LEN;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock,
		HASH_ENGINE_START_SHA256_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash_mock.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_event_hash_error (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint32_t event = 0xaabbccdd;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = HASH_TESTING_FULL_BLOCK_512;
	measurement_data.data.memory.length = HASH_TESTING_FULL_BLOCK_512_LEN;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 1, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_tcg_event_type (&pcr.test, 1, event);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_buffer (&pcr.test, &pcr.hash.base, 1,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, true);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock, 0);
	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock,
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_PTR_CONTAINS (&event, sizeof (event)),
		MOCK_ARG (sizeof (event)));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.cancel, &pcr.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 1, &pcr.hash_mock.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_version_hash_error (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint8_t version = 0x24;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = HASH_TESTING_FULL_BLOCK_512;
	measurement_data.data.memory.length = HASH_TESTING_FULL_BLOCK_512_LEN;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 3, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = pcr_update_versioned_buffer (&pcr.test, &pcr.hash.base, 3,
		HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN, false, version);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock, 0);
	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock,
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_PTR_CONTAINS (&version, sizeof (version)),
		MOCK_ARG (sizeof (version)));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.cancel, &pcr.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 3, &pcr.hash_mock.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_1byte_hash_error (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint8_t data = 0x11;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock, 0);
	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock,
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)),
		MOCK_ARG (sizeof (data)));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.cancel, &pcr.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash_mock.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_2byte_hash_error (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint16_t data = 0x1122;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_2BYTE;
	measurement_data.data.value_2byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock, 0);
	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock,
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)),
		MOCK_ARG (sizeof (data)));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.cancel, &pcr.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash_mock.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_4byte_hash_error (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint32_t data = 0x11223344;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_4BYTE;
	measurement_data.data.value_4byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock, 0);
	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock,
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)),
		MOCK_ARG (sizeof (data)));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.cancel, &pcr.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash_mock.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_8byte_hash_error (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	const uint64_t data = 0x1122334455667788;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_8BYTE;
	measurement_data.data.value_8byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock, 0);
	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock,
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)),
		MOCK_ARG (sizeof (data)));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.cancel, &pcr.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash_mock.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_memory_hash_error (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = HASH_TESTING_FULL_BLOCK_512;
	measurement_data.data.memory.length = HASH_TESTING_FULL_BLOCK_512_LEN;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock, 0);
	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock,
		HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_512_LEN));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.cancel, &pcr.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash_mock.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_flash_error (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_FLASH;
	measurement_data.data.flash.flash = &pcr.flash.base;
	measurement_data.data.flash.addr = 0x11223344;
	measurement_data.data.flash.length = HASH_TESTING_FULL_BLOCK_1024_LEN;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock, 0);

	status |= mock_expect (&pcr.flash.mock, pcr.flash.base.read, &pcr.flash, FLASH_READ_FAILED,
		MOCK_ARG (0x11223344), MOCK_ARG_NOT_NULL, MOCK_ARG (HASH_TESTING_FULL_BLOCK_1024_LEN));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.cancel, &pcr.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash_mock.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_callback_error (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.hash_data = pcr_testing_measurement_hash_callback;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock, 0);
	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock,
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_PTR_CONTAINS (&data, sizeof (data)),
		MOCK_ARG (sizeof (data)));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.cancel, &pcr.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash_mock.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_no_hash_callback (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint32_t data = 0x11223344;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_CALLBACK;
	measurement_data.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement_data.data.callback.hash_data = NULL;
	measurement_data.data.callback.context = &data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock, 0);

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.cancel, &pcr.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash_mock.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, PCR_MEASURED_DATA_NO_HASH_CALLBACK, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_bad_measurement_data_type (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t data = 0x11;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_1BYTE;
	measurement_data.data.value_1byte = data;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	/* This is a contrived test that is not possible using the APIs, so need to change the value
	 * after setting the measured data. */
	measurement_data.type = NUM_PCR_DATA_TYPE;

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock, 0);

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.cancel, &pcr.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash_mock.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, PCR_INVALID_DATA_TYPE, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_hash_measurement_data_finish_error (CuTest *test)
{
	struct pcr_testing pcr;
	struct pcr_measured_data measurement_data;
	uint8_t buffer[HASH_MAX_HASH_LEN];
	int status;

	TEST_START;

	measurement_data.type = PCR_DATA_TYPE_MEMORY;
	measurement_data.data.memory.buffer = HASH_TESTING_FULL_BLOCK_512;
	measurement_data.data.memory.length = HASH_TESTING_FULL_BLOCK_512_LEN;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	status = pcr_set_measurement_data (&pcr.test, 2, &measurement_data);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.start_sha256, &pcr.hash_mock, 0);
	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.update, &pcr.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN),
		MOCK_ARG (HASH_TESTING_FULL_BLOCK_512_LEN));
	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.finish, &pcr.hash_mock,
		HASH_ENGINE_FINISH_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));

	status |= mock_expect (&pcr.hash_mock.mock, pcr.hash_mock.base.cancel, &pcr.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = pcr_hash_measurement_data (&pcr.test, 2, &pcr.hash_mock.base, HASH_TYPE_SHA256, buffer,
		sizeof (buffer));
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	pcr_testing_release (test, &pcr);
}
#endif

static void pcr_test_get_tcg_log_sha256 (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[512];
	uint8_t digests[5][SHA256_HASH_LENGTH] = {
		{
			0xab,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xcd,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xef,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x12,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x23,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
	};
	struct pcr_tcg_event2_sha256 *event = (struct pcr_tcg_event2_sha256*) buffer;
	struct pcr_measured_data measurement[5];
	size_t total_len;
	int i_measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	for (i_measurement = 0; i_measurement < 5; ++i_measurement) {
		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;

		status = pcr_update_digest (&pcr.test, i_measurement, digests[i_measurement],
			SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_set_tcg_event_type (&pcr.test, i_measurement, 0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		status = pcr_set_measurement_data (&pcr.test, i_measurement, &measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcr_get_tcg_log (&pcr.test, 0, 0, buffer, sizeof (buffer), &total_len);
	CuAssertIntEquals (test, (sizeof (struct pcr_tcg_event2_sha256) * 5) + (sizeof (uint8_t) * 5),
		status);

	for (i_measurement = 0; i_measurement < 5; ++i_measurement) {
		CuAssertIntEquals (test, 0, event->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event->header.event_type);
		CuAssertIntEquals (test, 1, event->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, event->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha256))[0]);

		status = testing_validate_array (digests[i_measurement], event->digest, SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event = (struct pcr_tcg_event2_sha256*) ((uint8_t*) (event + 1) + 1);
	}

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_tcg_log_sha256_explicit (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t digest[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t buffer[512];
	size_t total_len;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 0, HASH_TYPE_SHA256);

	status = pcr_update_digest (&pcr.test, 0, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_tcg_log (&pcr.test, 0, 0, buffer, sizeof (buffer), &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, total_len);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_tcg_log_sha256_offset_beginning_of_event (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[512];
	uint8_t digests[5][SHA256_HASH_LENGTH] = {
		{
			0xab,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xcd,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xef,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x12,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x23,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
	};
	struct pcr_tcg_event2_sha256 *event = (struct pcr_tcg_event2_sha256*) buffer;
	struct pcr_measured_data measurement[5];
	size_t total_len;
	int i_measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	for (i_measurement = 0; i_measurement < 5; ++i_measurement) {
		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;

		status = pcr_update_digest (&pcr.test, i_measurement, digests[i_measurement],
			SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_set_tcg_event_type (&pcr.test, i_measurement, 0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		status = pcr_set_measurement_data (&pcr.test, i_measurement, &measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcr_get_tcg_log (&pcr.test, 0,
		(sizeof (struct pcr_tcg_event2_sha256) * 2) + (sizeof (uint8_t) * 2), buffer,
		sizeof (buffer), &total_len);
	CuAssertIntEquals (test, (sizeof (struct pcr_tcg_event2_sha256) * 3) + (sizeof (uint8_t) * 3),
		status);

	for (i_measurement = 2; i_measurement < 5; ++i_measurement) {
		CuAssertIntEquals (test, 0, event->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event->header.event_type);
		CuAssertIntEquals (test, 1, event->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, event->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha256))[0]);

		status = testing_validate_array (digests[i_measurement], event->digest, SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event = (struct pcr_tcg_event2_sha256*) ((uint8_t*) (event + 1) + 1);
	}

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_tcg_log_sha256_offset_middle_of_event (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[512];
	uint8_t digests[5][SHA256_HASH_LENGTH] = {
		{
			0xab,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xcd,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xef,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x12,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x23,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
	};
	struct pcr_tcg_event2_sha256 *event = (struct pcr_tcg_event2_sha256*) (buffer + 1);
	struct pcr_measured_data measurement[5];
	size_t total_len;
	int i_measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	for (i_measurement = 0; i_measurement < 5; ++i_measurement) {
		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;

		status = pcr_update_digest (&pcr.test, i_measurement, digests[i_measurement],
			SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_set_tcg_event_type (&pcr.test, i_measurement, 0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		status = pcr_set_measurement_data (&pcr.test, i_measurement, &measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcr_get_tcg_log (&pcr.test, 0, sizeof (struct pcr_tcg_event2_sha256), buffer,
		sizeof (buffer), &total_len);
	CuAssertIntEquals (test, (sizeof (struct pcr_tcg_event2_sha256) * 4) + (sizeof (uint8_t) * 5),
		status);

	CuAssertIntEquals (test, 0xAA, buffer[0]);

	for (i_measurement = 1; i_measurement < 5; ++i_measurement) {
		CuAssertIntEquals (test, 0, event->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event->header.event_type);
		CuAssertIntEquals (test, 1, event->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, event->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha256))[0]);

		status = testing_validate_array (digests[i_measurement], event->digest, SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event = (struct pcr_tcg_event2_sha256*) ((uint8_t*) (event + 1) + 1);
	}

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_tcg_log_sha256_offset_middle_of_event_header (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[512];
	uint8_t digests[5][SHA256_HASH_LENGTH] = {
		{
			0xab,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xcd,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xef,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x12,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x23,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
	};
	struct pcr_tcg_event2_sha256 *event;
	struct pcr_measured_data measurement[5];
	size_t total_len;
	int i_measurement;
	int status;
	int offset = sizeof (struct pcr_tcg_event2_sha256) / 2;
	uint8_t first_event[sizeof (struct pcr_tcg_event2_sha256) + 1];
	uint8_t zero[sizeof (buffer)] = {0};

	TEST_START;

	memset (buffer, 0, sizeof (buffer));

	memset (first_event, 0, sizeof (first_event));
	event = (struct pcr_tcg_event2_sha256*) first_event;
	event->header.pcr_index = 1;
	event->header.event_type = 0x0A;
	event->header.digest_count = 1;
	event->header.digest_algorithm_id = PCR_TCG_SHA256_ALG_ID;
	memcpy (event->digest, digests[0], SHA256_HASH_LENGTH);
	event->event_size = 1;
	first_event[sizeof (first_event) - 1] = 0xAA;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	for (i_measurement = 0; i_measurement < 5; ++i_measurement) {
		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;

		status = pcr_update_digest (&pcr.test, i_measurement, digests[i_measurement],
			SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_set_tcg_event_type (&pcr.test, i_measurement, 0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		status = pcr_set_measurement_data (&pcr.test, i_measurement, &measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcr_get_tcg_log (&pcr.test, 1, offset, &buffer[offset], sizeof (buffer) - offset,
		&total_len);
	CuAssertIntEquals (test,
		(sizeof (struct pcr_tcg_event2_sha256) * 5) + (sizeof (uint8_t) * 5) - offset, status);

	status = testing_validate_array (zero, &buffer[offset + status],
		sizeof (buffer) - (offset + status));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer, offset);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (&((uint8_t*) &first_event)[offset], &buffer[offset],
		sizeof (first_event) - offset);
	CuAssertIntEquals (test, 0, status);

	event = (struct pcr_tcg_event2_sha256*) &buffer[sizeof (struct pcr_tcg_event2_sha256) + 1];
	for (i_measurement = 1; i_measurement < 5; ++i_measurement) {
		CuAssertIntEquals (test, 1, event->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event->header.event_type);
		CuAssertIntEquals (test, 1, event->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, event->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha256))[0]);

		status = testing_validate_array (digests[i_measurement], event->digest, SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event = (struct pcr_tcg_event2_sha256*) ((uint8_t*) (event + 1) + 1);
	}

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_tcg_log_sha256_zero_bytes_read (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[512];
	uint8_t digests[5][SHA256_HASH_LENGTH] = {
		{
			0xab,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xcd,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xef,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x12,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x23,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
	};
	struct pcr_measured_data measurement[5];
	size_t total_len;
	int i_measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	for (i_measurement = 0; i_measurement < 5; ++i_measurement) {
		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;

		status = pcr_update_digest (&pcr.test, i_measurement, digests[i_measurement],
			SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_set_tcg_event_type (&pcr.test, i_measurement, 0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		status = pcr_set_measurement_data (&pcr.test, i_measurement, &measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcr_get_tcg_log (&pcr.test, 0,
		(sizeof (struct pcr_tcg_event2_sha256) * 5) + (sizeof (uint8_t) * 5), buffer,
		sizeof (buffer), &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, (sizeof (struct pcr_tcg_event2_sha256) * 5) + (sizeof (uint8_t) * 5),
		total_len);

	pcr_testing_release (test, &pcr);
}

#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
static void pcr_test_get_tcg_log_sha384 (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[512];
	uint8_t digests[5][SHA384_HASH_LENGTH] = {
		{
			0xd6,0xe5,0x99,0xca,0x03,0xb6,0xf5,0xf9,0x1c,0x8a,0xbe,0xa9,0x97,0x05,0x1b,0xbb,
			0xd5,0xdb,0xde,0x47,0xbc,0x98,0x8b,0x29,0x38,0x11,0xec,0xa2,0x23,0x91,0xf4,0x62,
			0x37,0x82,0x16,0xd9,0x8d,0x08,0x43,0x64,0x46,0x72,0x33,0xa4,0xd7,0xaf,0xe8,0x68
		},
		{
			0x62,0x27,0x99,0xa6,0x03,0xd0,0x15,0x56,0xfa,0x02,0x85,0x56,0x31,0xee,0x52,0x20,
			0x7b,0xad,0xc6,0x30,0xfb,0xf0,0x74,0xb4,0xc1,0x7f,0xa8,0x69,0x73,0xc8,0x3b,0xa2,
			0x6d,0xbe,0x84,0x3e,0x4e,0x0a,0x47,0x67,0x10,0x0c,0xed,0x1c,0x2e,0x24,0xe0,0xd5
		},
		{
			0x08,0x64,0x33,0xc7,0x9f,0x49,0x12,0x83,0xc7,0x01,0x20,0xd7,0x8c,0xb6,0x7d,0x2d,
			0x4f,0x84,0x7d,0x44,0x57,0xfd,0x07,0xf8,0xb6,0xf6,0x8d,0xc6,0xc6,0x15,0xe9,0x62,
			0x97,0x02,0x33,0xb4,0xd4,0xec,0x3f,0x2e,0xa7,0xa2,0x3f,0x8d,0xf7,0x6d,0x42,0xd6
		},
		{
			0x3e,0x64,0x01,0x6f,0xdf,0x7f,0x68,0x59,0x05,0xf4,0x1e,0xb0,0xf5,0x67,0xcf,0x9c,
			0xb3,0xfb,0xab,0x6c,0xab,0xc7,0xbb,0x34,0x99,0x40,0x70,0x51,0xd5,0xe6,0x2f,0xa3,
			0x7d,0xe7,0x2b,0x3b,0xc5,0xb6,0xd9,0x12,0xd6,0xb8,0x2d,0x28,0xe8,0x24,0xf3,0x16
		},
		{
			0x1a,0xf9,0x84,0x98,0x0b,0x8e,0x4e,0xca,0x05,0x49,0x3e,0xbe,0x19,0x5f,0xd2,0xce,
			0x19,0xf3,0x7d,0x4a,0xcd,0xcf,0x09,0xe2,0xf1,0x40,0x49,0xa0,0xa2,0xbc,0x78,0xe3,
			0x16,0xf7,0x60,0xef,0x4f,0x9e,0x88,0x5f,0xd3,0x76,0x06,0xc7,0x6d,0xdd,0xdb,0x99
		},
	};
	struct pcr_tcg_event2_sha384 *event = (struct pcr_tcg_event2_sha384*) buffer;
	struct pcr_measured_data measurement[5];
	size_t total_len;
	int i_measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	for (i_measurement = 0; i_measurement < 5; ++i_measurement) {
		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;

		status = pcr_update_digest (&pcr.test, i_measurement, digests[i_measurement],
			SHA384_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_set_tcg_event_type (&pcr.test, i_measurement, 0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		status = pcr_set_measurement_data (&pcr.test, i_measurement, &measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcr_get_tcg_log (&pcr.test, 0, 0, buffer, sizeof (buffer), &total_len);
	CuAssertIntEquals (test, (sizeof (struct pcr_tcg_event2_sha384) * 5) + (sizeof (uint8_t) * 5),
		status);

	for (i_measurement = 0; i_measurement < 5; ++i_measurement) {
		CuAssertIntEquals (test, 0, event->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event->header.event_type);
		CuAssertIntEquals (test, 1, event->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA384_ALG_ID, event->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha384))[0]);

		status = testing_validate_array (digests[i_measurement], event->digest, SHA384_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event = (struct pcr_tcg_event2_sha384*) ((uint8_t*) (event + 1) + 1);
	}

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_tcg_log_sha384_explicit (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t digest[] = {
		0x40,0xfd,0x7a,0xd6,0x44,0x91,0xe6,0x54,0x4b,0x08,0xe1,0x30,0xcd,0x2a,0xca,0xb9,
		0x26,0x29,0xc3,0xfb,0xf3,0x26,0x84,0x3c,0x2c,0x25,0x3f,0xb4,0x49,0x5d,0xfc,0xe1,
		0x48,0x88,0xb6,0xca,0x53,0xd2,0xa0,0xdf,0x84,0x3f,0x52,0x08,0xff,0xfb,0x00,0x8a
	};
	uint8_t buffer[512];
	size_t total_len;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 0, HASH_TYPE_SHA384);

	status = pcr_update_digest (&pcr.test, 0, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_tcg_log (&pcr.test, 0, 0, buffer, sizeof (buffer), &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, total_len);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_tcg_log_sha384_offset_beginning_of_event (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[512];
	uint8_t digests[5][SHA384_HASH_LENGTH] = {
		{
			0xd6,0xe5,0x99,0xca,0x03,0xb6,0xf5,0xf9,0x1c,0x8a,0xbe,0xa9,0x97,0x05,0x1b,0xbb,
			0xd5,0xdb,0xde,0x47,0xbc,0x98,0x8b,0x29,0x38,0x11,0xec,0xa2,0x23,0x91,0xf4,0x62,
			0x37,0x82,0x16,0xd9,0x8d,0x08,0x43,0x64,0x46,0x72,0x33,0xa4,0xd7,0xaf,0xe8,0x68
		},
		{
			0x62,0x27,0x99,0xa6,0x03,0xd0,0x15,0x56,0xfa,0x02,0x85,0x56,0x31,0xee,0x52,0x20,
			0x7b,0xad,0xc6,0x30,0xfb,0xf0,0x74,0xb4,0xc1,0x7f,0xa8,0x69,0x73,0xc8,0x3b,0xa2,
			0x6d,0xbe,0x84,0x3e,0x4e,0x0a,0x47,0x67,0x10,0x0c,0xed,0x1c,0x2e,0x24,0xe0,0xd5
		},
		{
			0x08,0x64,0x33,0xc7,0x9f,0x49,0x12,0x83,0xc7,0x01,0x20,0xd7,0x8c,0xb6,0x7d,0x2d,
			0x4f,0x84,0x7d,0x44,0x57,0xfd,0x07,0xf8,0xb6,0xf6,0x8d,0xc6,0xc6,0x15,0xe9,0x62,
			0x97,0x02,0x33,0xb4,0xd4,0xec,0x3f,0x2e,0xa7,0xa2,0x3f,0x8d,0xf7,0x6d,0x42,0xd6
		},
		{
			0x3e,0x64,0x01,0x6f,0xdf,0x7f,0x68,0x59,0x05,0xf4,0x1e,0xb0,0xf5,0x67,0xcf,0x9c,
			0xb3,0xfb,0xab,0x6c,0xab,0xc7,0xbb,0x34,0x99,0x40,0x70,0x51,0xd5,0xe6,0x2f,0xa3,
			0x7d,0xe7,0x2b,0x3b,0xc5,0xb6,0xd9,0x12,0xd6,0xb8,0x2d,0x28,0xe8,0x24,0xf3,0x16
		},
		{
			0x1a,0xf9,0x84,0x98,0x0b,0x8e,0x4e,0xca,0x05,0x49,0x3e,0xbe,0x19,0x5f,0xd2,0xce,
			0x19,0xf3,0x7d,0x4a,0xcd,0xcf,0x09,0xe2,0xf1,0x40,0x49,0xa0,0xa2,0xbc,0x78,0xe3,
			0x16,0xf7,0x60,0xef,0x4f,0x9e,0x88,0x5f,0xd3,0x76,0x06,0xc7,0x6d,0xdd,0xdb,0x99
		},
	};
	struct pcr_tcg_event2_sha384 *event = (struct pcr_tcg_event2_sha384*) buffer;
	struct pcr_measured_data measurement[5];
	size_t total_len;
	int i_measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	for (i_measurement = 0; i_measurement < 5; ++i_measurement) {
		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;

		status = pcr_update_digest (&pcr.test, i_measurement, digests[i_measurement],
			SHA384_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_set_tcg_event_type (&pcr.test, i_measurement, 0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		status = pcr_set_measurement_data (&pcr.test, i_measurement, &measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcr_get_tcg_log (&pcr.test, 0,
		(sizeof (struct pcr_tcg_event2_sha384) * 2) + (sizeof (uint8_t) * 2), buffer,
		sizeof (buffer), &total_len);
	CuAssertIntEquals (test, (sizeof (struct pcr_tcg_event2_sha384) * 3) + (sizeof (uint8_t) * 3),
		status);

	for (i_measurement = 2; i_measurement < 5; ++i_measurement) {
		CuAssertIntEquals (test, 0, event->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event->header.event_type);
		CuAssertIntEquals (test, 1, event->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA384_ALG_ID, event->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha384))[0]);

		status = testing_validate_array (digests[i_measurement], event->digest, SHA384_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event = (struct pcr_tcg_event2_sha384*) ((uint8_t*) (event + 1) + 1);
	}

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_tcg_log_sha384_offset_middle_of_event (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[512];
	uint8_t digests[5][SHA384_HASH_LENGTH] = {
		{
			0xd6,0xe5,0x99,0xca,0x03,0xb6,0xf5,0xf9,0x1c,0x8a,0xbe,0xa9,0x97,0x05,0x1b,0xbb,
			0xd5,0xdb,0xde,0x47,0xbc,0x98,0x8b,0x29,0x38,0x11,0xec,0xa2,0x23,0x91,0xf4,0x62,
			0x37,0x82,0x16,0xd9,0x8d,0x08,0x43,0x64,0x46,0x72,0x33,0xa4,0xd7,0xaf,0xe8,0x68
		},
		{
			0x62,0x27,0x99,0xa6,0x03,0xd0,0x15,0x56,0xfa,0x02,0x85,0x56,0x31,0xee,0x52,0x20,
			0x7b,0xad,0xc6,0x30,0xfb,0xf0,0x74,0xb4,0xc1,0x7f,0xa8,0x69,0x73,0xc8,0x3b,0xa2,
			0x6d,0xbe,0x84,0x3e,0x4e,0x0a,0x47,0x67,0x10,0x0c,0xed,0x1c,0x2e,0x24,0xe0,0xd5
		},
		{
			0x08,0x64,0x33,0xc7,0x9f,0x49,0x12,0x83,0xc7,0x01,0x20,0xd7,0x8c,0xb6,0x7d,0x2d,
			0x4f,0x84,0x7d,0x44,0x57,0xfd,0x07,0xf8,0xb6,0xf6,0x8d,0xc6,0xc6,0x15,0xe9,0x62,
			0x97,0x02,0x33,0xb4,0xd4,0xec,0x3f,0x2e,0xa7,0xa2,0x3f,0x8d,0xf7,0x6d,0x42,0xd6
		},
		{
			0x3e,0x64,0x01,0x6f,0xdf,0x7f,0x68,0x59,0x05,0xf4,0x1e,0xb0,0xf5,0x67,0xcf,0x9c,
			0xb3,0xfb,0xab,0x6c,0xab,0xc7,0xbb,0x34,0x99,0x40,0x70,0x51,0xd5,0xe6,0x2f,0xa3,
			0x7d,0xe7,0x2b,0x3b,0xc5,0xb6,0xd9,0x12,0xd6,0xb8,0x2d,0x28,0xe8,0x24,0xf3,0x16
		},
		{
			0x1a,0xf9,0x84,0x98,0x0b,0x8e,0x4e,0xca,0x05,0x49,0x3e,0xbe,0x19,0x5f,0xd2,0xce,
			0x19,0xf3,0x7d,0x4a,0xcd,0xcf,0x09,0xe2,0xf1,0x40,0x49,0xa0,0xa2,0xbc,0x78,0xe3,
			0x16,0xf7,0x60,0xef,0x4f,0x9e,0x88,0x5f,0xd3,0x76,0x06,0xc7,0x6d,0xdd,0xdb,0x99
		},
	};
	struct pcr_tcg_event2_sha384 *event = (struct pcr_tcg_event2_sha384*) (buffer + 1);
	struct pcr_measured_data measurement[5];
	size_t total_len;
	int i_measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	for (i_measurement = 0; i_measurement < 5; ++i_measurement) {
		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;

		status = pcr_update_digest (&pcr.test, i_measurement, digests[i_measurement],
			SHA384_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_set_tcg_event_type (&pcr.test, i_measurement, 0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		status = pcr_set_measurement_data (&pcr.test, i_measurement, &measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcr_get_tcg_log (&pcr.test, 0, sizeof (struct pcr_tcg_event2_sha384), buffer,
		sizeof (buffer), &total_len);
	CuAssertIntEquals (test, (sizeof (struct pcr_tcg_event2_sha384) * 4) + (sizeof (uint8_t) * 5),
		status);

	CuAssertIntEquals (test, 0xAA, buffer[0]);

	for (i_measurement = 1; i_measurement < 5; ++i_measurement) {
		CuAssertIntEquals (test, 0, event->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event->header.event_type);
		CuAssertIntEquals (test, 1, event->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA384_ALG_ID, event->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha384))[0]);

		status = testing_validate_array (digests[i_measurement], event->digest, SHA384_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event = (struct pcr_tcg_event2_sha384*) ((uint8_t*) (event + 1) + 1);
	}

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_tcg_log_sha384_offset_middle_of_event_header (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[512];
	uint8_t digests[5][SHA384_HASH_LENGTH] = {
		{
			0xd6,0xe5,0x99,0xca,0x03,0xb6,0xf5,0xf9,0x1c,0x8a,0xbe,0xa9,0x97,0x05,0x1b,0xbb,
			0xd5,0xdb,0xde,0x47,0xbc,0x98,0x8b,0x29,0x38,0x11,0xec,0xa2,0x23,0x91,0xf4,0x62,
			0x37,0x82,0x16,0xd9,0x8d,0x08,0x43,0x64,0x46,0x72,0x33,0xa4,0xd7,0xaf,0xe8,0x68
		},
		{
			0x62,0x27,0x99,0xa6,0x03,0xd0,0x15,0x56,0xfa,0x02,0x85,0x56,0x31,0xee,0x52,0x20,
			0x7b,0xad,0xc6,0x30,0xfb,0xf0,0x74,0xb4,0xc1,0x7f,0xa8,0x69,0x73,0xc8,0x3b,0xa2,
			0x6d,0xbe,0x84,0x3e,0x4e,0x0a,0x47,0x67,0x10,0x0c,0xed,0x1c,0x2e,0x24,0xe0,0xd5
		},
		{
			0x08,0x64,0x33,0xc7,0x9f,0x49,0x12,0x83,0xc7,0x01,0x20,0xd7,0x8c,0xb6,0x7d,0x2d,
			0x4f,0x84,0x7d,0x44,0x57,0xfd,0x07,0xf8,0xb6,0xf6,0x8d,0xc6,0xc6,0x15,0xe9,0x62,
			0x97,0x02,0x33,0xb4,0xd4,0xec,0x3f,0x2e,0xa7,0xa2,0x3f,0x8d,0xf7,0x6d,0x42,0xd6
		},
		{
			0x3e,0x64,0x01,0x6f,0xdf,0x7f,0x68,0x59,0x05,0xf4,0x1e,0xb0,0xf5,0x67,0xcf,0x9c,
			0xb3,0xfb,0xab,0x6c,0xab,0xc7,0xbb,0x34,0x99,0x40,0x70,0x51,0xd5,0xe6,0x2f,0xa3,
			0x7d,0xe7,0x2b,0x3b,0xc5,0xb6,0xd9,0x12,0xd6,0xb8,0x2d,0x28,0xe8,0x24,0xf3,0x16
		},
		{
			0x1a,0xf9,0x84,0x98,0x0b,0x8e,0x4e,0xca,0x05,0x49,0x3e,0xbe,0x19,0x5f,0xd2,0xce,
			0x19,0xf3,0x7d,0x4a,0xcd,0xcf,0x09,0xe2,0xf1,0x40,0x49,0xa0,0xa2,0xbc,0x78,0xe3,
			0x16,0xf7,0x60,0xef,0x4f,0x9e,0x88,0x5f,0xd3,0x76,0x06,0xc7,0x6d,0xdd,0xdb,0x99
		},
	};
	struct pcr_tcg_event2_sha384 *event;
	struct pcr_measured_data measurement[5];
	size_t total_len;
	int i_measurement;
	int status;
	int offset = sizeof (struct pcr_tcg_event2_sha384) / 2;
	uint8_t first_event[sizeof (struct pcr_tcg_event2_sha384) + 1];
	uint8_t zero[sizeof (buffer)] = {0};

	TEST_START;

	memset (buffer, 0, sizeof (buffer));

	memset (first_event, 0, sizeof (first_event));
	event = (struct pcr_tcg_event2_sha384*) first_event;
	event->header.pcr_index = 1;
	event->header.event_type = 0x0A;
	event->header.digest_count = 1;
	event->header.digest_algorithm_id = PCR_TCG_SHA384_ALG_ID;
	memcpy (event->digest, digests[0], SHA384_HASH_LENGTH);
	event->event_size = 1;
	first_event[sizeof (first_event) - 1] = 0xAA;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	for (i_measurement = 0; i_measurement < 5; ++i_measurement) {
		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;

		status = pcr_update_digest (&pcr.test, i_measurement, digests[i_measurement],
			SHA384_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_set_tcg_event_type (&pcr.test, i_measurement, 0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		status = pcr_set_measurement_data (&pcr.test, i_measurement, &measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcr_get_tcg_log (&pcr.test, 1, offset, &buffer[offset], sizeof (buffer) - offset,
		&total_len);
	CuAssertIntEquals (test,
		(sizeof (struct pcr_tcg_event2_sha384) * 5) + (sizeof (uint8_t) * 5) - offset, status);

	status = testing_validate_array (zero, &buffer[offset + status],
		sizeof (buffer) - (offset + status));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer, offset);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (&((uint8_t*) &first_event)[offset], &buffer[offset],
		sizeof (first_event) - offset);
	CuAssertIntEquals (test, 0, status);

	event = (struct pcr_tcg_event2_sha384*) &buffer[sizeof (struct pcr_tcg_event2_sha384) + 1];
	for (i_measurement = 1; i_measurement < 5; ++i_measurement) {
		CuAssertIntEquals (test, 1, event->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event->header.event_type);
		CuAssertIntEquals (test, 1, event->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA384_ALG_ID, event->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha384))[0]);

		status = testing_validate_array (digests[i_measurement], event->digest, SHA384_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event = (struct pcr_tcg_event2_sha384*) ((uint8_t*) (event + 1) + 1);
	}

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_tcg_log_sha384_zero_bytes_read (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[512];
	uint8_t digests[5][SHA384_HASH_LENGTH] = {
		{
			0xd6,0xe5,0x99,0xca,0x03,0xb6,0xf5,0xf9,0x1c,0x8a,0xbe,0xa9,0x97,0x05,0x1b,0xbb,
			0xd5,0xdb,0xde,0x47,0xbc,0x98,0x8b,0x29,0x38,0x11,0xec,0xa2,0x23,0x91,0xf4,0x62,
			0x37,0x82,0x16,0xd9,0x8d,0x08,0x43,0x64,0x46,0x72,0x33,0xa4,0xd7,0xaf,0xe8,0x68
		},
		{
			0x62,0x27,0x99,0xa6,0x03,0xd0,0x15,0x56,0xfa,0x02,0x85,0x56,0x31,0xee,0x52,0x20,
			0x7b,0xad,0xc6,0x30,0xfb,0xf0,0x74,0xb4,0xc1,0x7f,0xa8,0x69,0x73,0xc8,0x3b,0xa2,
			0x6d,0xbe,0x84,0x3e,0x4e,0x0a,0x47,0x67,0x10,0x0c,0xed,0x1c,0x2e,0x24,0xe0,0xd5
		},
		{
			0x08,0x64,0x33,0xc7,0x9f,0x49,0x12,0x83,0xc7,0x01,0x20,0xd7,0x8c,0xb6,0x7d,0x2d,
			0x4f,0x84,0x7d,0x44,0x57,0xfd,0x07,0xf8,0xb6,0xf6,0x8d,0xc6,0xc6,0x15,0xe9,0x62,
			0x97,0x02,0x33,0xb4,0xd4,0xec,0x3f,0x2e,0xa7,0xa2,0x3f,0x8d,0xf7,0x6d,0x42,0xd6
		},
		{
			0x3e,0x64,0x01,0x6f,0xdf,0x7f,0x68,0x59,0x05,0xf4,0x1e,0xb0,0xf5,0x67,0xcf,0x9c,
			0xb3,0xfb,0xab,0x6c,0xab,0xc7,0xbb,0x34,0x99,0x40,0x70,0x51,0xd5,0xe6,0x2f,0xa3,
			0x7d,0xe7,0x2b,0x3b,0xc5,0xb6,0xd9,0x12,0xd6,0xb8,0x2d,0x28,0xe8,0x24,0xf3,0x16
		},
		{
			0x1a,0xf9,0x84,0x98,0x0b,0x8e,0x4e,0xca,0x05,0x49,0x3e,0xbe,0x19,0x5f,0xd2,0xce,
			0x19,0xf3,0x7d,0x4a,0xcd,0xcf,0x09,0xe2,0xf1,0x40,0x49,0xa0,0xa2,0xbc,0x78,0xe3,
			0x16,0xf7,0x60,0xef,0x4f,0x9e,0x88,0x5f,0xd3,0x76,0x06,0xc7,0x6d,0xdd,0xdb,0x99
		},
	};
	struct pcr_measured_data measurement[5];
	size_t total_len;
	int i_measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA384);

	for (i_measurement = 0; i_measurement < 5; ++i_measurement) {
		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;

		status = pcr_update_digest (&pcr.test, i_measurement, digests[i_measurement],
			SHA384_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_set_tcg_event_type (&pcr.test, i_measurement, 0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		status = pcr_set_measurement_data (&pcr.test, i_measurement, &measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcr_get_tcg_log (&pcr.test, 0,
		(sizeof (struct pcr_tcg_event2_sha384) * 5) + (sizeof (uint8_t) * 5), buffer,
		sizeof (buffer), &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, (sizeof (struct pcr_tcg_event2_sha384) * 5) + (sizeof (uint8_t) * 5),
		total_len);

	pcr_testing_release (test, &pcr);
}
#endif

#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
static void pcr_test_get_tcg_log_sha512 (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[512];
	uint8_t digests[5][SHA512_HASH_LENGTH] = {
		{
			0x99,0x1b,0x75,0x7d,0x33,0x0d,0x0e,0x77,0x02,0x8c,0xb1,0x40,0x37,0x8d,0x60,0xd2,
			0xff,0xc0,0x09,0x5b,0x42,0xb6,0x3a,0x3b,0x5b,0xf8,0x6d,0xb4,0x1b,0xc3,0x09,0x11,
			0xc1,0x04,0x51,0x82,0x0d,0x68,0x34,0x5a,0xad,0x6f,0xa4,0xb6,0x9c,0x8e,0x6c,0x7a,
			0x91,0x29,0xf5,0x52,0x50,0x35,0x3e,0x97,0x49,0x5f,0x18,0x51,0x90,0x10,0x13,0x88
		},
		{
			0x33,0x8f,0x2d,0xab,0xde,0x1a,0xbc,0x9d,0x4a,0x88,0x6b,0x96,0x0f,0x27,0x69,0xa7,
			0x17,0xfe,0xf6,0x1b,0xf2,0x05,0x08,0x5d,0xef,0x4d,0x06,0x20,0x5e,0x69,0xc9,0xb8,
			0x3e,0x62,0x0f,0x60,0xfb,0xd7,0xd3,0x57,0xea,0x02,0xaa,0x63,0x5f,0x14,0x5c,0x24,
			0xd8,0x91,0x54,0x48,0x3c,0x40,0xe8,0xba,0x9e,0x2b,0x31,0x81,0x53,0x30,0xb9,0xc5
		},
		{
			0x7c,0x0e,0xe4,0x42,0x4d,0x23,0xa6,0x21,0x1a,0xd7,0xc3,0xe8,0x6f,0x6b,0x70,0x05,
			0x16,0xd7,0x6b,0x64,0xca,0xa1,0xa0,0xec,0x03,0x57,0x73,0x98,0x8e,0x94,0x04,0x3a,
			0x2e,0xd7,0x96,0x73,0xf7,0x0e,0x34,0xdb,0xa7,0x79,0xb6,0x8e,0xb6,0x55,0x3b,0xa2,
			0x02,0xb8,0xcd,0x73,0x3c,0xf6,0x38,0xf1,0xed,0xc4,0x5f,0x2b,0x8b,0xef,0xc9,0xd3
		},
		{
			0x71,0x13,0xec,0x29,0xfd,0x15,0xd2,0x70,0x6f,0xf1,0xc1,0x51,0x81,0x94,0xce,0xf2,
			0x3e,0xa5,0x88,0x72,0xa1,0xee,0xf8,0xe4,0x3e,0xd7,0x66,0x37,0x37,0xf0,0xd9,0x87,
			0xc5,0x20,0x65,0xd9,0x9a,0x43,0xcc,0xad,0x01,0xcc,0xba,0x03,0x9f,0xd0,0x41,0x1e,
			0xbf,0x56,0xe3,0xd9,0xae,0xed,0x42,0xdd,0x3e,0xfe,0xfd,0x2e,0x71,0xd1,0xac,0x63
		},
		{
			0x6e,0xbb,0xf8,0x3c,0x69,0xc5,0x3c,0xa6,0xbf,0xa1,0xe1,0xcb,0x43,0x25,0xd8,0x70,
			0xa0,0x56,0xba,0xbc,0xef,0x56,0xb4,0xb0,0x25,0x8d,0xc7,0x77,0x65,0x4a,0x51,0x93,
			0x0c,0x30,0x54,0x98,0x1d,0xe3,0xdd,0x74,0xa4,0xde,0x82,0xbe,0x9e,0xf5,0x68,0x14,
			0xfd,0x04,0x9d,0x25,0x5a,0xb7,0xb1,0x3a,0x20,0x48,0x3b,0x5a,0x53,0x6a,0x41,0xdf
		},
	};
	struct pcr_tcg_event2_sha512 *event = (struct pcr_tcg_event2_sha512*) buffer;
	struct pcr_measured_data measurement[5];
	size_t total_len;
	int i_measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA512);

	for (i_measurement = 0; i_measurement < 5; ++i_measurement) {
		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;

		status = pcr_update_digest (&pcr.test, i_measurement, digests[i_measurement],
			SHA512_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_set_tcg_event_type (&pcr.test, i_measurement, 0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		status = pcr_set_measurement_data (&pcr.test, i_measurement, &measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcr_get_tcg_log (&pcr.test, 0, 0, buffer, sizeof (buffer), &total_len);
	CuAssertIntEquals (test, (sizeof (struct pcr_tcg_event2_sha512) * 5) + (sizeof (uint8_t) * 5),
		status);

	for (i_measurement = 0; i_measurement < 5; ++i_measurement) {
		CuAssertIntEquals (test, 0, event->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event->header.event_type);
		CuAssertIntEquals (test, 1, event->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA512_ALG_ID, event->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha512))[0]);

		status = testing_validate_array (digests[i_measurement], event->digest, SHA512_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event = (struct pcr_tcg_event2_sha512*) ((uint8_t*) (event + 1) + 1);
	}

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_tcg_log_sha512_explicit (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t digest[] = {
		0x0b,0x45,0x5c,0xc4,0x94,0x84,0x1f,0x70,0xcb,0xa0,0xae,0x3f,0xf6,0xf8,0x89,0xed,
		0xfa,0xb6,0xc8,0x2e,0xcb,0x75,0xf3,0x66,0x3d,0xb4,0xbd,0xdb,0x65,0xb1,0xac,0x50,
		0x29,0xbb,0x4e,0x21,0x4d,0xe5,0xbf,0xde,0xc3,0xc4,0xc3,0x92,0x35,0xe5,0x68,0xef,
		0x97,0x04,0xee,0x64,0x40,0xda,0x06,0xb8,0x10,0xed,0x75,0xa4,0x37,0xd2,0x7b,0xf0
	};
	uint8_t buffer[512];
	size_t total_len;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 0, HASH_TYPE_SHA512);

	status = pcr_update_digest (&pcr.test, 0, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_tcg_log (&pcr.test, 0, 0, buffer, sizeof (buffer), &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, total_len);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_tcg_log_sha512_offset_beginning_of_event (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[512];
	uint8_t digests[5][SHA512_HASH_LENGTH] = {
		{
			0x99,0x1b,0x75,0x7d,0x33,0x0d,0x0e,0x77,0x02,0x8c,0xb1,0x40,0x37,0x8d,0x60,0xd2,
			0xff,0xc0,0x09,0x5b,0x42,0xb6,0x3a,0x3b,0x5b,0xf8,0x6d,0xb4,0x1b,0xc3,0x09,0x11,
			0xc1,0x04,0x51,0x82,0x0d,0x68,0x34,0x5a,0xad,0x6f,0xa4,0xb6,0x9c,0x8e,0x6c,0x7a,
			0x91,0x29,0xf5,0x52,0x50,0x35,0x3e,0x97,0x49,0x5f,0x18,0x51,0x90,0x10,0x13,0x88
		},
		{
			0x33,0x8f,0x2d,0xab,0xde,0x1a,0xbc,0x9d,0x4a,0x88,0x6b,0x96,0x0f,0x27,0x69,0xa7,
			0x17,0xfe,0xf6,0x1b,0xf2,0x05,0x08,0x5d,0xef,0x4d,0x06,0x20,0x5e,0x69,0xc9,0xb8,
			0x3e,0x62,0x0f,0x60,0xfb,0xd7,0xd3,0x57,0xea,0x02,0xaa,0x63,0x5f,0x14,0x5c,0x24,
			0xd8,0x91,0x54,0x48,0x3c,0x40,0xe8,0xba,0x9e,0x2b,0x31,0x81,0x53,0x30,0xb9,0xc5
		},
		{
			0x7c,0x0e,0xe4,0x42,0x4d,0x23,0xa6,0x21,0x1a,0xd7,0xc3,0xe8,0x6f,0x6b,0x70,0x05,
			0x16,0xd7,0x6b,0x64,0xca,0xa1,0xa0,0xec,0x03,0x57,0x73,0x98,0x8e,0x94,0x04,0x3a,
			0x2e,0xd7,0x96,0x73,0xf7,0x0e,0x34,0xdb,0xa7,0x79,0xb6,0x8e,0xb6,0x55,0x3b,0xa2,
			0x02,0xb8,0xcd,0x73,0x3c,0xf6,0x38,0xf1,0xed,0xc4,0x5f,0x2b,0x8b,0xef,0xc9,0xd3
		},
		{
			0x71,0x13,0xec,0x29,0xfd,0x15,0xd2,0x70,0x6f,0xf1,0xc1,0x51,0x81,0x94,0xce,0xf2,
			0x3e,0xa5,0x88,0x72,0xa1,0xee,0xf8,0xe4,0x3e,0xd7,0x66,0x37,0x37,0xf0,0xd9,0x87,
			0xc5,0x20,0x65,0xd9,0x9a,0x43,0xcc,0xad,0x01,0xcc,0xba,0x03,0x9f,0xd0,0x41,0x1e,
			0xbf,0x56,0xe3,0xd9,0xae,0xed,0x42,0xdd,0x3e,0xfe,0xfd,0x2e,0x71,0xd1,0xac,0x63
		},
		{
			0x6e,0xbb,0xf8,0x3c,0x69,0xc5,0x3c,0xa6,0xbf,0xa1,0xe1,0xcb,0x43,0x25,0xd8,0x70,
			0xa0,0x56,0xba,0xbc,0xef,0x56,0xb4,0xb0,0x25,0x8d,0xc7,0x77,0x65,0x4a,0x51,0x93,
			0x0c,0x30,0x54,0x98,0x1d,0xe3,0xdd,0x74,0xa4,0xde,0x82,0xbe,0x9e,0xf5,0x68,0x14,
			0xfd,0x04,0x9d,0x25,0x5a,0xb7,0xb1,0x3a,0x20,0x48,0x3b,0x5a,0x53,0x6a,0x41,0xdf
		},
	};
	struct pcr_tcg_event2_sha512 *event = (struct pcr_tcg_event2_sha512*) buffer;
	struct pcr_measured_data measurement[5];
	size_t total_len;
	int i_measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA512);

	for (i_measurement = 0; i_measurement < 5; ++i_measurement) {
		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;

		status = pcr_update_digest (&pcr.test, i_measurement, digests[i_measurement],
			SHA512_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_set_tcg_event_type (&pcr.test, i_measurement, 0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		status = pcr_set_measurement_data (&pcr.test, i_measurement, &measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcr_get_tcg_log (&pcr.test, 0,
		(sizeof (struct pcr_tcg_event2_sha512) * 2) + (sizeof (uint8_t) * 2), buffer,
		sizeof (buffer), &total_len);
	CuAssertIntEquals (test, (sizeof (struct pcr_tcg_event2_sha512) * 3) + (sizeof (uint8_t) * 3),
		status);

	for (i_measurement = 2; i_measurement < 5; ++i_measurement) {
		CuAssertIntEquals (test, 0, event->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event->header.event_type);
		CuAssertIntEquals (test, 1, event->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA512_ALG_ID, event->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha512))[0]);

		status = testing_validate_array (digests[i_measurement], event->digest, SHA512_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event = (struct pcr_tcg_event2_sha512*) ((uint8_t*) (event + 1) + 1);
	}

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_tcg_log_sha512_offset_middle_of_event (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[512];
	uint8_t digests[5][SHA512_HASH_LENGTH] = {
		{
			0x99,0x1b,0x75,0x7d,0x33,0x0d,0x0e,0x77,0x02,0x8c,0xb1,0x40,0x37,0x8d,0x60,0xd2,
			0xff,0xc0,0x09,0x5b,0x42,0xb6,0x3a,0x3b,0x5b,0xf8,0x6d,0xb4,0x1b,0xc3,0x09,0x11,
			0xc1,0x04,0x51,0x82,0x0d,0x68,0x34,0x5a,0xad,0x6f,0xa4,0xb6,0x9c,0x8e,0x6c,0x7a,
			0x91,0x29,0xf5,0x52,0x50,0x35,0x3e,0x97,0x49,0x5f,0x18,0x51,0x90,0x10,0x13,0x88
		},
		{
			0x33,0x8f,0x2d,0xab,0xde,0x1a,0xbc,0x9d,0x4a,0x88,0x6b,0x96,0x0f,0x27,0x69,0xa7,
			0x17,0xfe,0xf6,0x1b,0xf2,0x05,0x08,0x5d,0xef,0x4d,0x06,0x20,0x5e,0x69,0xc9,0xb8,
			0x3e,0x62,0x0f,0x60,0xfb,0xd7,0xd3,0x57,0xea,0x02,0xaa,0x63,0x5f,0x14,0x5c,0x24,
			0xd8,0x91,0x54,0x48,0x3c,0x40,0xe8,0xba,0x9e,0x2b,0x31,0x81,0x53,0x30,0xb9,0xc5
		},
		{
			0x7c,0x0e,0xe4,0x42,0x4d,0x23,0xa6,0x21,0x1a,0xd7,0xc3,0xe8,0x6f,0x6b,0x70,0x05,
			0x16,0xd7,0x6b,0x64,0xca,0xa1,0xa0,0xec,0x03,0x57,0x73,0x98,0x8e,0x94,0x04,0x3a,
			0x2e,0xd7,0x96,0x73,0xf7,0x0e,0x34,0xdb,0xa7,0x79,0xb6,0x8e,0xb6,0x55,0x3b,0xa2,
			0x02,0xb8,0xcd,0x73,0x3c,0xf6,0x38,0xf1,0xed,0xc4,0x5f,0x2b,0x8b,0xef,0xc9,0xd3
		},
		{
			0x71,0x13,0xec,0x29,0xfd,0x15,0xd2,0x70,0x6f,0xf1,0xc1,0x51,0x81,0x94,0xce,0xf2,
			0x3e,0xa5,0x88,0x72,0xa1,0xee,0xf8,0xe4,0x3e,0xd7,0x66,0x37,0x37,0xf0,0xd9,0x87,
			0xc5,0x20,0x65,0xd9,0x9a,0x43,0xcc,0xad,0x01,0xcc,0xba,0x03,0x9f,0xd0,0x41,0x1e,
			0xbf,0x56,0xe3,0xd9,0xae,0xed,0x42,0xdd,0x3e,0xfe,0xfd,0x2e,0x71,0xd1,0xac,0x63
		},
		{
			0x6e,0xbb,0xf8,0x3c,0x69,0xc5,0x3c,0xa6,0xbf,0xa1,0xe1,0xcb,0x43,0x25,0xd8,0x70,
			0xa0,0x56,0xba,0xbc,0xef,0x56,0xb4,0xb0,0x25,0x8d,0xc7,0x77,0x65,0x4a,0x51,0x93,
			0x0c,0x30,0x54,0x98,0x1d,0xe3,0xdd,0x74,0xa4,0xde,0x82,0xbe,0x9e,0xf5,0x68,0x14,
			0xfd,0x04,0x9d,0x25,0x5a,0xb7,0xb1,0x3a,0x20,0x48,0x3b,0x5a,0x53,0x6a,0x41,0xdf
		},
	};
	struct pcr_tcg_event2_sha512 *event = (struct pcr_tcg_event2_sha512*) (buffer + 1);
	struct pcr_measured_data measurement[5];
	size_t total_len;
	int i_measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA512);

	for (i_measurement = 0; i_measurement < 5; ++i_measurement) {
		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;

		status = pcr_update_digest (&pcr.test, i_measurement, digests[i_measurement],
			SHA512_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_set_tcg_event_type (&pcr.test, i_measurement, 0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		status = pcr_set_measurement_data (&pcr.test, i_measurement, &measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcr_get_tcg_log (&pcr.test, 0, sizeof (struct pcr_tcg_event2_sha512), buffer,
		sizeof (buffer), &total_len);
	CuAssertIntEquals (test, (sizeof (struct pcr_tcg_event2_sha512) * 4) + (sizeof (uint8_t) * 5),
		status);

	CuAssertIntEquals (test, 0xAA, buffer[0]);

	for (i_measurement = 1; i_measurement < 5; ++i_measurement) {
		CuAssertIntEquals (test, 0, event->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event->header.event_type);
		CuAssertIntEquals (test, 1, event->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA512_ALG_ID, event->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha512))[0]);

		status = testing_validate_array (digests[i_measurement], event->digest, SHA512_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event = (struct pcr_tcg_event2_sha512*) ((uint8_t*) (event + 1) + 1);
	}

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_tcg_log_sha512_offset_middle_of_event_header (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[512];
	uint8_t digests[5][SHA512_HASH_LENGTH] = {
		{
			0x99,0x1b,0x75,0x7d,0x33,0x0d,0x0e,0x77,0x02,0x8c,0xb1,0x40,0x37,0x8d,0x60,0xd2,
			0xff,0xc0,0x09,0x5b,0x42,0xb6,0x3a,0x3b,0x5b,0xf8,0x6d,0xb4,0x1b,0xc3,0x09,0x11,
			0xc1,0x04,0x51,0x82,0x0d,0x68,0x34,0x5a,0xad,0x6f,0xa4,0xb6,0x9c,0x8e,0x6c,0x7a,
			0x91,0x29,0xf5,0x52,0x50,0x35,0x3e,0x97,0x49,0x5f,0x18,0x51,0x90,0x10,0x13,0x88
		},
		{
			0x33,0x8f,0x2d,0xab,0xde,0x1a,0xbc,0x9d,0x4a,0x88,0x6b,0x96,0x0f,0x27,0x69,0xa7,
			0x17,0xfe,0xf6,0x1b,0xf2,0x05,0x08,0x5d,0xef,0x4d,0x06,0x20,0x5e,0x69,0xc9,0xb8,
			0x3e,0x62,0x0f,0x60,0xfb,0xd7,0xd3,0x57,0xea,0x02,0xaa,0x63,0x5f,0x14,0x5c,0x24,
			0xd8,0x91,0x54,0x48,0x3c,0x40,0xe8,0xba,0x9e,0x2b,0x31,0x81,0x53,0x30,0xb9,0xc5
		},
		{
			0x7c,0x0e,0xe4,0x42,0x4d,0x23,0xa6,0x21,0x1a,0xd7,0xc3,0xe8,0x6f,0x6b,0x70,0x05,
			0x16,0xd7,0x6b,0x64,0xca,0xa1,0xa0,0xec,0x03,0x57,0x73,0x98,0x8e,0x94,0x04,0x3a,
			0x2e,0xd7,0x96,0x73,0xf7,0x0e,0x34,0xdb,0xa7,0x79,0xb6,0x8e,0xb6,0x55,0x3b,0xa2,
			0x02,0xb8,0xcd,0x73,0x3c,0xf6,0x38,0xf1,0xed,0xc4,0x5f,0x2b,0x8b,0xef,0xc9,0xd3
		},
		{
			0x71,0x13,0xec,0x29,0xfd,0x15,0xd2,0x70,0x6f,0xf1,0xc1,0x51,0x81,0x94,0xce,0xf2,
			0x3e,0xa5,0x88,0x72,0xa1,0xee,0xf8,0xe4,0x3e,0xd7,0x66,0x37,0x37,0xf0,0xd9,0x87,
			0xc5,0x20,0x65,0xd9,0x9a,0x43,0xcc,0xad,0x01,0xcc,0xba,0x03,0x9f,0xd0,0x41,0x1e,
			0xbf,0x56,0xe3,0xd9,0xae,0xed,0x42,0xdd,0x3e,0xfe,0xfd,0x2e,0x71,0xd1,0xac,0x63
		},
		{
			0x6e,0xbb,0xf8,0x3c,0x69,0xc5,0x3c,0xa6,0xbf,0xa1,0xe1,0xcb,0x43,0x25,0xd8,0x70,
			0xa0,0x56,0xba,0xbc,0xef,0x56,0xb4,0xb0,0x25,0x8d,0xc7,0x77,0x65,0x4a,0x51,0x93,
			0x0c,0x30,0x54,0x98,0x1d,0xe3,0xdd,0x74,0xa4,0xde,0x82,0xbe,0x9e,0xf5,0x68,0x14,
			0xfd,0x04,0x9d,0x25,0x5a,0xb7,0xb1,0x3a,0x20,0x48,0x3b,0x5a,0x53,0x6a,0x41,0xdf
		},
	};
	struct pcr_tcg_event2_sha512 *event;
	struct pcr_measured_data measurement[5];
	size_t total_len;
	int i_measurement;
	int status;
	int offset = sizeof (struct pcr_tcg_event2_sha512) / 2;
	uint8_t first_event[sizeof (struct pcr_tcg_event2_sha512) + 1];
	uint8_t zero[sizeof (buffer)] = {0};

	TEST_START;

	memset (buffer, 0, sizeof (buffer));

	memset (first_event, 0, sizeof (first_event));
	event = (struct pcr_tcg_event2_sha512*) first_event;
	event->header.pcr_index = 1;
	event->header.event_type = 0x0A;
	event->header.digest_count = 1;
	event->header.digest_algorithm_id = PCR_TCG_SHA512_ALG_ID;
	memcpy (event->digest, digests[0], SHA512_HASH_LENGTH);
	event->event_size = 1;
	first_event[sizeof (first_event) - 1] = 0xAA;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA512);

	for (i_measurement = 0; i_measurement < 5; ++i_measurement) {
		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;

		status = pcr_update_digest (&pcr.test, i_measurement, digests[i_measurement],
			SHA512_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_set_tcg_event_type (&pcr.test, i_measurement, 0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		status = pcr_set_measurement_data (&pcr.test, i_measurement, &measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcr_get_tcg_log (&pcr.test, 1, offset, &buffer[offset], sizeof (buffer) - offset,
		&total_len);
	CuAssertIntEquals (test,
		(sizeof (struct pcr_tcg_event2_sha512) * 5) + (sizeof (uint8_t) * 5) - offset, status);

	status = testing_validate_array (zero, &buffer[offset + status],
		sizeof (buffer) - (offset + status));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer, offset);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (&((uint8_t*) &first_event)[offset], &buffer[offset],
		sizeof (first_event) - offset);
	CuAssertIntEquals (test, 0, status);

	event = (struct pcr_tcg_event2_sha512*) &buffer[sizeof (struct pcr_tcg_event2_sha512) + 1];
	for (i_measurement = 1; i_measurement < 5; ++i_measurement) {
		CuAssertIntEquals (test, 1, event->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event->header.event_type);
		CuAssertIntEquals (test, 1, event->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA512_ALG_ID, event->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha512))[0]);

		status = testing_validate_array (digests[i_measurement], event->digest, SHA512_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event = (struct pcr_tcg_event2_sha512*) ((uint8_t*) (event + 1) + 1);
	}

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_tcg_log_sha512_zero_bytes_read (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[512];
	uint8_t digests[5][SHA512_HASH_LENGTH] = {
		{
			0x99,0x1b,0x75,0x7d,0x33,0x0d,0x0e,0x77,0x02,0x8c,0xb1,0x40,0x37,0x8d,0x60,0xd2,
			0xff,0xc0,0x09,0x5b,0x42,0xb6,0x3a,0x3b,0x5b,0xf8,0x6d,0xb4,0x1b,0xc3,0x09,0x11,
			0xc1,0x04,0x51,0x82,0x0d,0x68,0x34,0x5a,0xad,0x6f,0xa4,0xb6,0x9c,0x8e,0x6c,0x7a,
			0x91,0x29,0xf5,0x52,0x50,0x35,0x3e,0x97,0x49,0x5f,0x18,0x51,0x90,0x10,0x13,0x88
		},
		{
			0x33,0x8f,0x2d,0xab,0xde,0x1a,0xbc,0x9d,0x4a,0x88,0x6b,0x96,0x0f,0x27,0x69,0xa7,
			0x17,0xfe,0xf6,0x1b,0xf2,0x05,0x08,0x5d,0xef,0x4d,0x06,0x20,0x5e,0x69,0xc9,0xb8,
			0x3e,0x62,0x0f,0x60,0xfb,0xd7,0xd3,0x57,0xea,0x02,0xaa,0x63,0x5f,0x14,0x5c,0x24,
			0xd8,0x91,0x54,0x48,0x3c,0x40,0xe8,0xba,0x9e,0x2b,0x31,0x81,0x53,0x30,0xb9,0xc5
		},
		{
			0x7c,0x0e,0xe4,0x42,0x4d,0x23,0xa6,0x21,0x1a,0xd7,0xc3,0xe8,0x6f,0x6b,0x70,0x05,
			0x16,0xd7,0x6b,0x64,0xca,0xa1,0xa0,0xec,0x03,0x57,0x73,0x98,0x8e,0x94,0x04,0x3a,
			0x2e,0xd7,0x96,0x73,0xf7,0x0e,0x34,0xdb,0xa7,0x79,0xb6,0x8e,0xb6,0x55,0x3b,0xa2,
			0x02,0xb8,0xcd,0x73,0x3c,0xf6,0x38,0xf1,0xed,0xc4,0x5f,0x2b,0x8b,0xef,0xc9,0xd3
		},
		{
			0x71,0x13,0xec,0x29,0xfd,0x15,0xd2,0x70,0x6f,0xf1,0xc1,0x51,0x81,0x94,0xce,0xf2,
			0x3e,0xa5,0x88,0x72,0xa1,0xee,0xf8,0xe4,0x3e,0xd7,0x66,0x37,0x37,0xf0,0xd9,0x87,
			0xc5,0x20,0x65,0xd9,0x9a,0x43,0xcc,0xad,0x01,0xcc,0xba,0x03,0x9f,0xd0,0x41,0x1e,
			0xbf,0x56,0xe3,0xd9,0xae,0xed,0x42,0xdd,0x3e,0xfe,0xfd,0x2e,0x71,0xd1,0xac,0x63
		},
		{
			0x6e,0xbb,0xf8,0x3c,0x69,0xc5,0x3c,0xa6,0xbf,0xa1,0xe1,0xcb,0x43,0x25,0xd8,0x70,
			0xa0,0x56,0xba,0xbc,0xef,0x56,0xb4,0xb0,0x25,0x8d,0xc7,0x77,0x65,0x4a,0x51,0x93,
			0x0c,0x30,0x54,0x98,0x1d,0xe3,0xdd,0x74,0xa4,0xde,0x82,0xbe,0x9e,0xf5,0x68,0x14,
			0xfd,0x04,0x9d,0x25,0x5a,0xb7,0xb1,0x3a,0x20,0x48,0x3b,0x5a,0x53,0x6a,0x41,0xdf
		},
	};
	struct pcr_measured_data measurement[5];
	size_t total_len;
	int i_measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA512);

	for (i_measurement = 0; i_measurement < 5; ++i_measurement) {
		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;

		status = pcr_update_digest (&pcr.test, i_measurement, digests[i_measurement],
			SHA512_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_set_tcg_event_type (&pcr.test, i_measurement, 0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		status = pcr_set_measurement_data (&pcr.test, i_measurement, &measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcr_get_tcg_log (&pcr.test, 0,
		(sizeof (struct pcr_tcg_event2_sha512) * 5) + (sizeof (uint8_t) * 5), buffer,
		sizeof (buffer), &total_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, (sizeof (struct pcr_tcg_event2_sha512) * 5) + (sizeof (uint8_t) * 5),
		total_len);

	pcr_testing_release (test, &pcr);
}
#endif

static void pcr_test_get_tcg_log_small_buffer (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[512];
	uint8_t digests[5][SHA256_HASH_LENGTH] = {
		{
			0xab,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xcd,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xef,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x12,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x23,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
	};
	struct pcr_tcg_event2_sha256 *event = (struct pcr_tcg_event2_sha256*) buffer;
	struct pcr_measured_data measurement[5];
	size_t total_len;
	int i_measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	for (i_measurement = 0; i_measurement < 5; ++i_measurement) {
		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;

		status = pcr_update_digest (&pcr.test, i_measurement, digests[i_measurement],
			SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_set_tcg_event_type (&pcr.test, i_measurement, 0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		status = pcr_set_measurement_data (&pcr.test, i_measurement, &measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcr_get_tcg_log (&pcr.test, 0, 0, buffer,
		(sizeof (struct pcr_tcg_event2_sha256) * 2) + (sizeof (uint8_t) * 2), &total_len);
	CuAssertIntEquals (test, (sizeof (struct pcr_tcg_event2_sha256) * 2) + (sizeof (uint8_t) * 2),
		status);

	for (i_measurement = 0; i_measurement < 2; ++i_measurement) {
		CuAssertIntEquals (test, 0, event->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event->header.event_type);
		CuAssertIntEquals (test, 1, event->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, event->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha256))[0]);

		status = testing_validate_array (digests[i_measurement], event->digest, SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event = (struct pcr_tcg_event2_sha256*) ((uint8_t*) (event + 1) + 1);
	}

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_tcg_log_small_buffer_with_offset (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[512];
	uint8_t digests[5][SHA256_HASH_LENGTH] = {
		{
			0xab,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xcd,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xef,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x12,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x23,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
	};
	struct pcr_tcg_event2_sha256 *event = (struct pcr_tcg_event2_sha256*) buffer;
	struct pcr_measured_data measurement[5];
	size_t total_len;
	int i_measurement;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	for (i_measurement = 0; i_measurement < 5; ++i_measurement) {
		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;

		status = pcr_update_digest (&pcr.test, i_measurement, digests[i_measurement],
			SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_set_tcg_event_type (&pcr.test, i_measurement, 0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		status = pcr_set_measurement_data (&pcr.test, i_measurement, &measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcr_get_tcg_log (&pcr.test, 0,
		sizeof (struct pcr_tcg_event2_sha256) + sizeof (uint8_t), buffer,
		(sizeof (struct pcr_tcg_event2_sha256) * 2) + (sizeof (uint8_t) * 2), &total_len);
	CuAssertIntEquals (test, (sizeof (struct pcr_tcg_event2_sha256) * 2) + (sizeof (uint8_t) * 2),
		status);

	for (i_measurement = 1; i_measurement < 3; ++i_measurement) {
		CuAssertIntEquals (test, 0, event->header.pcr_index);
		CuAssertIntEquals (test, 0x0A + i_measurement, event->header.event_type);
		CuAssertIntEquals (test, 1, event->header.digest_count);
		CuAssertIntEquals (test, PCR_TCG_SHA256_ALG_ID, event->header.digest_algorithm_id);
		CuAssertIntEquals (test, 1, event->event_size);
		CuAssertIntEquals (test, 0xAA + i_measurement,
			(((uint8_t*) event) + sizeof (struct pcr_tcg_event2_sha256))[0]);

		status = testing_validate_array (digests[i_measurement], event->digest, SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		event = (struct pcr_tcg_event2_sha256*) ((uint8_t*) (event + 1) + 1);
	}

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_tcg_log_short_buffer_middle_of_event_header (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[512];
	uint8_t digests[5][SHA256_HASH_LENGTH] = {
		{
			0xab,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xcd,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0xef,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x12,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
		{
			0x23,0xe6,0xe6,0x4f,0x38,0x13,0x4f,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
			0x7f,0xe6,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x7f,0x6e
		},
	};
	struct pcr_tcg_event2_sha256 *event;
	struct pcr_measured_data measurement[5];
	size_t total_len;
	int i_measurement;
	int status;
	int length = sizeof (struct pcr_tcg_event2_sha256) / 2;
	uint8_t first_event[sizeof (struct pcr_tcg_event2_sha256) + 1];
	uint8_t zero[sizeof (buffer)] = {0};

	TEST_START;

	memset (buffer, 0, sizeof (buffer));

	memset (first_event, 0, sizeof (first_event));
	event = (struct pcr_tcg_event2_sha256*) first_event;
	event->header.pcr_index = 1;
	event->header.event_type = 0x0A;
	event->header.digest_count = 1;
	event->header.digest_algorithm_id = PCR_TCG_SHA256_ALG_ID;
	memcpy (event->digest, digests[0], SHA256_HASH_LENGTH);
	event->event_size = 1;
	first_event[sizeof (first_event) - 1] = 0xAA;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	for (i_measurement = 0; i_measurement < 5; ++i_measurement) {
		measurement[i_measurement].type = PCR_DATA_TYPE_1BYTE;
		measurement[i_measurement].data.value_1byte = 0xAA + i_measurement;

		status = pcr_update_digest (&pcr.test, i_measurement, digests[i_measurement],
			SHA256_HASH_LENGTH);
		CuAssertIntEquals (test, 0, status);

		status = pcr_set_tcg_event_type (&pcr.test, i_measurement, 0x0A + i_measurement);
		CuAssertIntEquals (test, 0, status);

		status = pcr_set_measurement_data (&pcr.test, i_measurement, &measurement[i_measurement]);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcr_get_tcg_log (&pcr.test, 1, 0, buffer, length, &total_len);
	CuAssertIntEquals (test, length, status);

	status = testing_validate_array (zero, &buffer[length], sizeof (buffer) - length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array ((uint8_t*) &first_event, buffer, length);
	CuAssertIntEquals (test, 0, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_tcg_log_null (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[512];
	size_t total_len;
	int status;

	TEST_START;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_get_tcg_log (NULL, 0, 0, buffer, sizeof (buffer), &total_len);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_get_tcg_log (&pcr.test, 0, 0, NULL, sizeof (buffer), &total_len);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	status = pcr_get_tcg_log (&pcr.test, 0, 0, buffer, sizeof (buffer), NULL);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	pcr_testing_release (test, &pcr);
}

static void pcr_test_get_tcg_log_get_measured_data_fail (CuTest *test)
{
	struct pcr_testing pcr;
	uint8_t buffer[512];
	struct pcr_measured_data measurement;
	size_t total_len;
	int status;

	TEST_START;

	measurement.type = PCR_DATA_TYPE_CALLBACK;
	measurement.data.callback.get_data = pcr_testing_measurement_data_callback;
	measurement.data.callback.context = NULL;

	pcr_testing_init (test, &pcr, 5, HASH_TYPE_SHA256);

	status = pcr_set_tcg_event_type (&pcr.test, 0, 0x0A + 0);
	CuAssertIntEquals (test, 0, status);

	status = pcr_set_measurement_data (&pcr.test, 0, &measurement);
	CuAssertIntEquals (test, 0, status);

	status = pcr_get_tcg_log (&pcr.test, 0, 0, buffer, sizeof (buffer), &total_len);
	CuAssertIntEquals (test, PCR_NO_MEMORY, status);

	pcr_testing_release (test, &pcr);
}


TEST_SUITE_START (pcr);

TEST (pcr_test_init_sha256);
TEST (pcr_test_init_sha384);
TEST (pcr_test_init_sha512);
TEST (pcr_test_init_explicit);
TEST (pcr_test_init_null);
TEST (pcr_test_init_sha1);
TEST (pcr_test_init_unknown_hash_algorithm);
TEST (pcr_test_release_null);
TEST (pcr_test_get_num_measurements_null);
TEST (pcr_test_get_hash_algorithm_null);
TEST (pcr_test_get_digest_length_null);
TEST (pcr_test_check_measurement_index);
TEST (pcr_test_check_measurement_index_explicit);
TEST (pcr_test_check_measurement_index_bad_index);
TEST (pcr_test_check_measurement_index_bad_index_explicit);
TEST (pcr_test_check_measurement_index_null);
TEST (pcr_test_update_digest_sha256);
TEST (pcr_test_update_digest_sha256_explicit);
#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
TEST (pcr_test_update_digest_sha384);
TEST (pcr_test_update_digest_sha384_explicit);
#endif
#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
TEST (pcr_test_update_digest_sha512);
TEST (pcr_test_update_digest_sha512_explicit);
#endif
TEST (pcr_test_update_digest_twice);
TEST (pcr_test_update_digest_null);
TEST (pcr_test_update_digest_wrong_digest_length);
#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
TEST (pcr_test_update_digest_sha384_with_sha256);
#endif
TEST (pcr_test_update_digest_invalid_index);
TEST (pcr_test_get_measurement_null);
TEST (pcr_test_get_measurement_invalid_index);
TEST (pcr_test_update_buffer_sha256);
TEST (pcr_test_update_buffer_sha256_explicit);
TEST (pcr_test_update_buffer_sha256_with_event);
TEST (pcr_test_update_buffer_sha256_with_event_no_data);
#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
TEST (pcr_test_update_buffer_sha384);
TEST (pcr_test_update_buffer_sha384_explicit);
TEST (pcr_test_update_buffer_sha384_with_event);
TEST (pcr_test_update_buffer_sha384_with_event_no_data);
#endif
#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
TEST (pcr_test_update_buffer_sha512);
TEST (pcr_test_update_buffer_sha512_explicit);
TEST (pcr_test_update_buffer_sha512_with_event);
TEST (pcr_test_update_buffer_sha512_with_event_no_data);
#endif
TEST (pcr_test_update_buffer_twice);
TEST (pcr_test_update_buffer_with_event_then_update_digest);
TEST (pcr_test_update_buffer_null);
TEST (pcr_test_update_buffer_sha256_start_hash_fail);
#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
TEST (pcr_test_update_buffer_sha384_start_hash_fail);
#endif
#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
TEST (pcr_test_update_buffer_sha512_start_hash_fail);
#endif
TEST (pcr_test_update_buffer_update_hash_fail);
TEST (pcr_test_update_buffer_finish_hash_fail);
TEST (pcr_test_update_buffer_with_event_sha256_start_hash_fail);
TEST (pcr_test_update_buffer_with_event_event_hash_fail);
TEST (pcr_test_update_buffer_with_event_update_buffer_hash_fail);
TEST (pcr_test_update_buffer_with_event_finish_hash_fail);
TEST (pcr_test_update_buffer_update_digest_fail);
TEST (pcr_test_update_versioned_buffer_sha256);
TEST (pcr_test_update_versioned_buffer_sha256_explicit);
TEST (pcr_test_update_versioned_buffer_sha256_no_data);
TEST (pcr_test_update_versioned_buffer_sha256_with_event);
#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
TEST (pcr_test_update_versioned_buffer_sha384);
TEST (pcr_test_update_versioned_buffer_sha384_explicit);
TEST (pcr_test_update_versioned_buffer_sha384_no_data);
TEST (pcr_test_update_versioned_buffer_sha384_with_event);
#endif
#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
TEST (pcr_test_update_versioned_buffer_sha512);
TEST (pcr_test_update_versioned_buffer_sha512_explicit);
TEST (pcr_test_update_versioned_buffer_sha512_no_data);
TEST (pcr_test_update_versioned_buffer_sha512_with_event);
#endif
TEST (pcr_test_update_versioned_buffer_twice);
TEST (pcr_test_update_versioned_buffer_with_event_then_update_digest);
TEST (pcr_test_update_versioned_buffer_null);
TEST (pcr_test_update_versioned_buffer_sha256_start_hash_fail);
#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
TEST (pcr_test_update_versioned_buffer_sha384_start_hash_fail);
#endif
#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
TEST (pcr_test_update_versioned_buffer_sha512_start_hash_fail);
#endif
TEST (pcr_test_update_versioned_buffer_with_event_update_hash_fail);
TEST (pcr_test_update_versioned_buffer_update_version_hash_fail);
TEST (pcr_test_update_versioned_buffer_update_buffer_hash_fail);
TEST (pcr_test_update_versioned_buffer_finish_hash_fail);
TEST (pcr_test_update_versioned_buffer_update_digest_fail);
TEST (pcr_test_set_tcg_event_type_null);
TEST (pcr_test_set_tcg_event_type_invalid_index);
TEST (pcr_test_const_update_digest_sha256);
TEST (pcr_test_const_update_digest_sha256_explicit);
#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
TEST (pcr_test_const_update_digest_sha384);
TEST (pcr_test_const_update_digest_sha384_explicit);
#endif
#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
TEST (pcr_test_const_update_digest_sha512);
TEST (pcr_test_const_update_digest_sha512_explicit);
#endif
TEST (pcr_test_const_update_digest_then_update_different_measurement);
TEST (pcr_test_const_update_digest_null);
TEST (pcr_test_const_update_digest_twice);
TEST (pcr_test_const_update_digest_then_update_with_other_calls);
TEST (pcr_test_const_update_digest_wrong_digest_length);
#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
TEST (pcr_test_const_update_digest_sha384_with_sha256);
#endif
TEST (pcr_test_const_update_digest_invalid_index);
TEST (pcr_test_const_update_buffer_sha256);
TEST (pcr_test_const_update_buffer_sha256_explicit);
TEST (pcr_test_const_update_buffer_sha256_with_event);
TEST (pcr_test_const_update_buffer_sha256_with_event_no_data);
#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
TEST (pcr_test_const_update_buffer_sha384);
TEST (pcr_test_const_update_buffer_sha384_explicit);
TEST (pcr_test_const_update_buffer_sha384_with_event);
TEST (pcr_test_const_update_buffer_sha384_with_event_no_data);
#endif
#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
TEST (pcr_test_const_update_buffer_sha512);
TEST (pcr_test_const_update_buffer_sha512_explicit);
TEST (pcr_test_const_update_buffer_sha512_with_event);
TEST (pcr_test_const_update_buffer_sha512_with_event_no_data);
#endif
TEST (pcr_test_const_update_buffer_then_update_different_measurement);
TEST (pcr_test_const_update_buffer_null);
TEST (pcr_test_const_update_buffer_twice);
TEST (pcr_test_const_update_buffer_then_update_with_other_calls);
TEST (pcr_test_const_update_buffer_sha256_start_hash_fail);
#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
TEST (pcr_test_const_update_buffer_sha384_start_hash_fail);
#endif
#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
TEST (pcr_test_const_update_buffer_sha512_start_hash_fail);
#endif
TEST (pcr_test_const_update_buffer_update_hash_fail);
TEST (pcr_test_const_update_buffer_finish_hash_fail);
TEST (pcr_test_const_update_buffer_with_event_sha256_start_hash_fail);
TEST (pcr_test_const_update_buffer_with_event_event_hash_fail);
TEST (pcr_test_const_update_buffer_with_event_update_buffer_hash_fail);
TEST (pcr_test_const_update_buffer_with_event_finish_hash_fail);
TEST (pcr_test_const_update_buffer_update_digest_fail);
TEST (pcr_test_const_update_versioned_buffer_sha256);
TEST (pcr_test_const_update_versioned_buffer_sha256_explicit);
TEST (pcr_test_const_update_versioned_buffer_sha256_no_data);
TEST (pcr_test_const_update_versioned_buffer_sha256_with_event);
#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
TEST (pcr_test_const_update_versioned_buffer_sha384);
TEST (pcr_test_const_update_versioned_buffer_sha384_explicit);
TEST (pcr_test_const_update_versioned_buffer_sha384_no_data);
TEST (pcr_test_const_update_versioned_buffer_sha384_with_event);
#endif
#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
TEST (pcr_test_const_update_versioned_buffer_sha512);
TEST (pcr_test_const_update_versioned_buffer_sha512_explicit);
TEST (pcr_test_const_update_versioned_buffer_sha512_no_data);
TEST (pcr_test_const_update_versioned_buffer_sha512_with_event);
#endif
TEST (pcr_test_const_update_versioned_buffer_then_update_different_measurement);
TEST (pcr_test_const_update_versioned_buffer_null);
TEST (pcr_test_const_update_versioned_buffer_twice);
TEST (pcr_test_const_update_versioned_buffer_then_update_with_other_calls);
TEST (pcr_test_const_update_versioned_buffer_sha256_start_hash_fail);
#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
TEST (pcr_test_const_update_versioned_buffer_sha384_start_hash_fail);
#endif
#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
TEST (pcr_test_const_update_versioned_buffer_sha512_start_hash_fail);
#endif
TEST (pcr_test_const_update_versioned_buffer_with_event_update_hash_fail);
TEST (pcr_test_const_update_versioned_buffer_update_version_hash_fail);
TEST (pcr_test_const_update_versioned_buffer_update_buffer_hash_fail);
TEST (pcr_test_const_update_versioned_buffer_finish_hash_fail);
TEST (pcr_test_const_update_versioned_buffer_update_digest_fail);
TEST (pcr_test_get_tcg_event_type);
TEST (pcr_test_get_tcg_event_type_explicit);
TEST (pcr_test_get_tcg_event_type_null);
TEST (pcr_test_get_tcg_event_type_invalid_index);
TEST (pcr_test_set_dmtf_value_type);
TEST (pcr_test_set_dmtf_value_type_change_type);
TEST (pcr_test_set_dmtf_value_type_null);
TEST (pcr_test_set_dmtf_value_type_invalid_index);
TEST (pcr_test_set_dmtf_value_type_invalid_type);
TEST (pcr_test_get_dmtf_value_type_unset);
TEST (pcr_test_get_dmtf_value_type_null);
TEST (pcr_test_get_dmtf_value_type_invalid_index);
TEST (pcr_test_is_measurement_in_tcb_unset);
TEST (pcr_test_is_measurement_in_tcb_null);
TEST (pcr_test_is_measurement_in_tcb_invalid_index);
TEST (pcr_test_get_all_measurements_sha256);
TEST (pcr_test_get_all_measurements_sha256_explicit);
#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
TEST (pcr_test_get_all_measurements_sha384);
TEST (pcr_test_get_all_measurements_sha384_explicit);
#endif
#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
TEST (pcr_test_get_all_measurements_sha512);
TEST (pcr_test_get_all_measurements_sha512_explicit);
#endif
TEST (pcr_test_get_all_measurements_null);
TEST (pcr_test_invalidate_measurement);
TEST (pcr_test_invalidate_measurement_explicit);
TEST (pcr_test_invalidate_measurement_constant);
TEST (pcr_test_invalidate_measurement_null);
TEST (pcr_test_invalidate_measurement_bad_index);
TEST (pcr_test_compute_sha256);
TEST (pcr_test_compute_sha256_explicit);
TEST (pcr_test_compute_sha256_no_valid_measurements);
TEST (pcr_test_compute_sha256_no_valid_measurements_explicit);
#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
TEST (pcr_test_compute_sha384);
TEST (pcr_test_compute_sha384_explicit);
TEST (pcr_test_compute_sha384_no_valid_measurements);
TEST (pcr_test_compute_sha384_no_valid_measurements_explicit);
#endif
#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
TEST (pcr_test_compute_sha512);
TEST (pcr_test_compute_sha512_explicit);
TEST (pcr_test_compute_sha512_no_valid_measurements);
TEST (pcr_test_compute_sha512_no_valid_measurements_explicit);
#endif
TEST (pcr_test_compute_no_lock);
TEST (pcr_test_compute_no_out);
TEST (pcr_test_compute_no_out_explicit);
TEST (pcr_test_compute_null);
TEST (pcr_test_compute_sha256_small_output_buffer);
TEST (pcr_test_compute_sha256_start_hash_fail);
#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
TEST (pcr_test_compute_sha384_small_output_buffer);
TEST (pcr_test_compute_sha384_start_hash_fail);
#endif
#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
TEST (pcr_test_compute_sha512_small_output_buffer);
TEST (pcr_test_compute_sha512_start_hash_fail);
#endif
TEST (pcr_test_compute_hash_fail);
TEST (pcr_test_compute_extend_hash_fail);
TEST (pcr_test_compute_finish_hash_fail);
TEST (pcr_test_lock_then_unlock);
TEST (pcr_test_lock_null);
TEST (pcr_test_unlock_null);
TEST (pcr_test_set_measurement_data);
TEST (pcr_test_set_measurement_data_memory_no_data);
TEST (pcr_test_set_measurement_data_remove);
TEST (pcr_test_set_measurement_data_null);
TEST (pcr_test_set_measurement_data_bad_measurement_index);
TEST (pcr_test_set_measurement_data_bad_measurement_data_type);
TEST (pcr_test_is_measurement_data_available_null);
TEST (pcr_test_is_measurement_data_available_bad_measurement_index);
TEST (pcr_test_get_measurement_data_1byte);
TEST (pcr_test_get_measurement_data_1byte_zero_length);
TEST (pcr_test_get_measurement_data_1byte_invalid_offset);
TEST (pcr_test_get_measurement_data_1byte_include_event);
TEST (pcr_test_get_measurement_data_1byte_include_event_offset);
TEST (pcr_test_get_measurement_data_1byte_include_event_with_event);
TEST (pcr_test_get_measurement_data_1byte_include_event_with_event_offset);
TEST (pcr_test_get_measurement_data_1byte_include_event_with_event_small_buffer);
TEST (pcr_test_get_measurement_data_1byte_include_event_with_event_small_buffer_offset);
TEST (pcr_test_get_measurement_data_1byte_include_event_offset_with_data);
TEST (pcr_test_get_measurement_data_1byte_include_event_invalid_offset);
TEST (pcr_test_get_measurement_data_1byte_include_version);
TEST (pcr_test_get_measurement_data_1byte_include_version_offset);
TEST (pcr_test_get_measurement_data_1byte_include_version_with_version);
TEST (pcr_test_get_measurement_data_1byte_include_version_invalid_offset);
TEST (pcr_test_get_measurement_data_1byte_include_event_version);
TEST (pcr_test_get_measurement_data_1byte_include_event_version_offset);
TEST (pcr_test_get_measurement_data_1byte_include_event_version_with_event_version);
TEST (pcr_test_get_measurement_data_1byte_include_event_version_with_event_version_offset);
TEST (pcr_test_get_measurement_data_1byte_include_event_version_with_version_data);
TEST (pcr_test_get_measurement_data_1byte_include_event_version_with_event);
TEST (pcr_test_get_measurement_data_1byte_include_event_version_with_event_offset);
TEST (pcr_test_get_measurement_data_1byte_include_event_version_with_event_small_buffer);
TEST (pcr_test_get_measurement_data_1byte_include_event_version_with_event_small_buffer_offset);
TEST (pcr_test_get_measurement_data_1byte_include_event_version_with_version);
TEST (pcr_test_get_measurement_data_1byte_include_event_version_with_data);
TEST (pcr_test_get_measurement_data_1byte_include_event_version_invalid_offset);
TEST (pcr_test_get_measurement_data_2byte);
TEST (pcr_test_get_measurement_data_2byte_zero_length);
TEST (pcr_test_get_measurement_data_2byte_with_offset);
TEST (pcr_test_get_measurement_data_2byte_small_buffer);
TEST (pcr_test_get_measurement_data_2byte_small_buffer_offset);
TEST (pcr_test_get_measurement_data_2byte_invalid_offset);
TEST (pcr_test_get_measurement_data_2byte_include_event);
TEST (pcr_test_get_measurement_data_2byte_include_event_offset);
TEST (pcr_test_get_measurement_data_2byte_include_event_small_buffer);
TEST (pcr_test_get_measurement_data_2byte_include_event_small_buffer_offset);
TEST (pcr_test_get_measurement_data_2byte_include_event_with_event);
TEST (pcr_test_get_measurement_data_2byte_include_event_with_event_offset);
TEST (pcr_test_get_measurement_data_2byte_include_event_with_event_small_buffer);
TEST (pcr_test_get_measurement_data_2byte_include_event_with_event_small_buffer_offset);
TEST (pcr_test_get_measurement_data_2byte_include_event_with_data);
TEST (pcr_test_get_measurement_data_2byte_include_event_with_data_offset);
TEST (pcr_test_get_measurement_data_2byte_include_event_with_data_small_buffer);
TEST (pcr_test_get_measurement_data_2byte_include_event_invalid_offset);
TEST (pcr_test_get_measurement_data_2byte_include_version);
TEST (pcr_test_get_measurement_data_2byte_include_version_offset);
TEST (pcr_test_get_measurement_data_2byte_include_version_small_buffer);
TEST (pcr_test_get_measurement_data_2byte_include_version_small_buffer_offset);
TEST (pcr_test_get_measurement_data_2byte_include_version_invalid_offset);
TEST (pcr_test_get_measurement_data_2byte_include_event_version);
TEST (pcr_test_get_measurement_data_2byte_include_event_version_offset);
TEST (pcr_test_get_measurement_data_2byte_include_event_version_small_buffer);
TEST (pcr_test_get_measurement_data_2byte_include_event_version_small_buffer_offset);
TEST (pcr_test_get_measurement_data_2byte_include_event_version_with_event_version);
TEST (pcr_test_get_measurement_data_2byte_include_event_version_with_event_version_offset);
TEST (pcr_test_get_measurement_data_2byte_include_event_version_with_version_data);
TEST (pcr_test_get_measurement_data_2byte_include_event_version_with_version_data_small_buffer);
TEST (pcr_test_get_measurement_data_2byte_include_event_version_with_event);
TEST (pcr_test_get_measurement_data_2byte_include_event_version_with_event_offset);
TEST (pcr_test_get_measurement_data_2byte_include_event_version_with_event_small_buffer);
TEST (pcr_test_get_measurement_data_2byte_include_event_version_with_event_small_buffer_offset);
TEST (pcr_test_get_measurement_data_2byte_include_event_version_with_version);
TEST (pcr_test_get_measurement_data_2byte_include_event_version_with_data);
TEST (pcr_test_get_measurement_data_2byte_include_event_version_with_data_offset);
TEST (pcr_test_get_measurement_data_2byte_include_event_version_with_data_small_buffer);
TEST (pcr_test_get_measurement_data_2byte_include_event_version_invalid_offset);
TEST (pcr_test_get_measurement_data_4byte);
TEST (pcr_test_get_measurement_data_4byte_zero_length);
TEST (pcr_test_get_measurement_data_4byte_offset);
TEST (pcr_test_get_measurement_data_4byte_small_buffer);
TEST (pcr_test_get_measurement_data_4byte_small_buffer_offset);
TEST (pcr_test_get_measurement_data_4byte_invalid_offset);
TEST (pcr_test_get_measurement_data_4byte_include_event);
TEST (pcr_test_get_measurement_data_4byte_include_event_offset);
TEST (pcr_test_get_measurement_data_4byte_include_event_small_buffer);
TEST (pcr_test_get_measurement_data_4byte_include_event_small_buffer_offset);
TEST (pcr_test_get_measurement_data_4byte_include_event_with_event);
TEST (pcr_test_get_measurement_data_4byte_include_event_with_event_offset);
TEST (pcr_test_get_measurement_data_4byte_include_event_with_event_small_buffer);
TEST (pcr_test_get_measurement_data_4byte_include_event_with_event_small_buffer_offset);
TEST (pcr_test_get_measurement_data_4byte_include_event_with_data);
TEST (pcr_test_get_measurement_data_4byte_include_event_with_data_offset);
TEST (pcr_test_get_measurement_data_4byte_include_event_with_data_small_buffer);
TEST (pcr_test_get_measurement_data_4byte_include_event_with_data_small_buffer_offset);
TEST (pcr_test_get_measurement_data_4byte_include_event_invalid_offset);
TEST (pcr_test_get_measurement_data_4byte_include_version);
TEST (pcr_test_get_measurement_data_4byte_include_version_small_buffer);
TEST (pcr_test_get_measurement_data_4byte_include_version_with_version);
TEST (pcr_test_get_measurement_data_4byte_include_version_with_data);
TEST (pcr_test_get_measurement_data_4byte_include_version_with_data_offset);
TEST (pcr_test_get_measurement_data_4byte_include_version_with_data_small_buffer);
TEST (pcr_test_get_measurement_data_4byte_include_version_with_data_small_buffer_offset);
TEST (pcr_test_get_measurement_data_4byte_include_version_invalid_offset);
TEST (pcr_test_get_measurement_data_4byte_include_event_version);
TEST (pcr_test_get_measurement_data_4byte_include_event_version_offset);
TEST (pcr_test_get_measurement_data_4byte_include_event_version_small_buffer);
TEST (pcr_test_get_measurement_data_4byte_include_event_version_small_buffer_offset);
TEST (pcr_test_get_measurement_data_4byte_include_event_version_with_event_version);
TEST (pcr_test_get_measurement_data_4byte_include_event_version_with_event_version_offset);
TEST (pcr_test_get_measurement_data_4byte_include_event_version_with_version_data);
TEST (pcr_test_get_measurement_data_4byte_include_event_version_with_version_data_small_buffer);
TEST (pcr_test_get_measurement_data_4byte_include_event_version_with_event);
TEST (pcr_test_get_measurement_data_4byte_include_event_version_with_event_offset);
TEST (pcr_test_get_measurement_data_4byte_include_event_version_with_event_small_buffer);
TEST (pcr_test_get_measurement_data_4byte_include_event_version_with_event_small_buffer_offset);
TEST (pcr_test_get_measurement_data_4byte_include_event_version_with_version);
TEST (pcr_test_get_measurement_data_4byte_include_event_version_with_data);
TEST (pcr_test_get_measurement_data_4byte_include_event_version_with_data_offset);
TEST (pcr_test_get_measurement_data_4byte_include_event_version_with_data_small_buffer);
TEST (pcr_test_get_measurement_data_4byte_include_event_version_with_data_small_buffer_offset);
TEST (pcr_test_get_measurement_data_4byte_include_event_version_invalid_offset);
TEST (pcr_test_get_measurement_data_8byte);
TEST (pcr_test_get_measurement_data_8byte_zero_length);
TEST (pcr_test_get_measurement_data_8byte_offset);
TEST (pcr_test_get_measurement_data_8byte_small_buffer);
TEST (pcr_test_get_measurement_data_8byte_small_buffer_offset);
TEST (pcr_test_get_measurement_data_8byte_invalid_offset);
TEST (pcr_test_get_measurement_data_8byte_include_event);
TEST (pcr_test_get_measurement_data_8byte_include_event_offset);
TEST (pcr_test_get_measurement_data_8byte_include_event_small_buffer);
TEST (pcr_test_get_measurement_data_8byte_include_event_small_buffer_offset);
TEST (pcr_test_get_measurement_data_8byte_include_event_with_event);
TEST (pcr_test_get_measurement_data_8byte_include_event_with_event_offset);
TEST (pcr_test_get_measurement_data_8byte_include_event_with_event_small_buffer);
TEST (pcr_test_get_measurement_data_8byte_include_event_with_event_small_buffer_offset);
TEST (pcr_test_get_measurement_data_8byte_include_event_with_data);
TEST (pcr_test_get_measurement_data_8byte_include_event_with_data_offset);
TEST (pcr_test_get_measurement_data_8byte_include_event_with_data_small_buffer);
TEST (pcr_test_get_measurement_data_8byte_include_event_with_data_small_buffer_offset);
TEST (pcr_test_get_measurement_data_8byte_include_event_invalid_offset);
TEST (pcr_test_get_measurement_data_8byte_include_version);
TEST (pcr_test_get_measurement_data_8byte_include_version_small_buffer);
TEST (pcr_test_get_measurement_data_8byte_include_version_with_version);
TEST (pcr_test_get_measurement_data_8byte_include_version_with_data);
TEST (pcr_test_get_measurement_data_8byte_include_version_with_data_offset);
TEST (pcr_test_get_measurement_data_8byte_include_version_with_data_small_buffer);
TEST (pcr_test_get_measurement_data_8byte_include_version_with_data_small_buffer_offset);
TEST (pcr_test_get_measurement_data_8byte_include_version_invalid_offset);
TEST (pcr_test_get_measurement_data_8byte_include_event_version);
TEST (pcr_test_get_measurement_data_8byte_include_event_version_offset);
TEST (pcr_test_get_measurement_data_8byte_include_event_version_small_buffer);
TEST (pcr_test_get_measurement_data_8byte_include_event_version_small_buffer_offset);
TEST (pcr_test_get_measurement_data_8byte_include_event_version_with_event_version);
TEST (pcr_test_get_measurement_data_8byte_include_event_version_with_event_version_offset);
TEST (pcr_test_get_measurement_data_8byte_include_event_version_with_version_data);
TEST (pcr_test_get_measurement_data_8byte_include_event_version_with_version_data_small_buffer);
TEST (pcr_test_get_measurement_data_8byte_include_event_version_with_event);
TEST (pcr_test_get_measurement_data_8byte_include_event_version_with_event_offset);
TEST (pcr_test_get_measurement_data_8byte_include_event_version_with_event_small_buffer);
TEST (pcr_test_get_measurement_data_8byte_include_event_version_with_event_small_buffer_offset);
TEST (pcr_test_get_measurement_data_8byte_include_event_version_with_version);
TEST (pcr_test_get_measurement_data_8byte_include_event_version_with_data);
TEST (pcr_test_get_measurement_data_8byte_include_event_version_with_data_offset);
TEST (pcr_test_get_measurement_data_8byte_include_event_version_with_data_small_buffer);
TEST (pcr_test_get_measurement_data_8byte_include_event_version_with_data_small_buffer_offset);
TEST (pcr_test_get_measurement_data_8byte_include_event_version_invalid_offset);
TEST (pcr_test_get_measurement_data_memory);
TEST (pcr_test_get_measurement_data_memory_zero_length);
TEST (pcr_test_get_measurement_data_memory_offset);
TEST (pcr_test_get_measurement_data_memory_small_buffer);
TEST (pcr_test_get_measurement_data_memory_small_buffer_offset);
TEST (pcr_test_get_measurement_data_memory_invalid_offset);
TEST (pcr_test_get_measurement_data_memory_include_event);
TEST (pcr_test_get_measurement_data_memory_include_event_offset);
TEST (pcr_test_get_measurement_data_memory_include_event_small_buffer);
TEST (pcr_test_get_measurement_data_memory_include_event_small_buffer_offset);
TEST (pcr_test_get_measurement_data_memory_include_event_with_event);
TEST (pcr_test_get_measurement_data_memory_include_event_with_event_offset);
TEST (pcr_test_get_measurement_data_memory_include_event_with_event_small_buffer);
TEST (pcr_test_get_measurement_data_memory_include_event_with_event_small_buffer_offset);
TEST (pcr_test_get_measurement_data_memory_include_event_with_data);
TEST (pcr_test_get_measurement_data_memory_include_event_with_data_offset);
TEST (pcr_test_get_measurement_data_memory_include_event_with_data_small_buffer);
TEST (pcr_test_get_measurement_data_memory_include_event_with_data_small_buffer_offset);
TEST (pcr_test_get_measurement_data_memory_include_event_invalid_offset);
TEST (pcr_test_get_measurement_data_memory_include_version);
TEST (pcr_test_get_measurement_data_memory_include_version_small_buffer);
TEST (pcr_test_get_measurement_data_memory_include_version_with_version);
TEST (pcr_test_get_measurement_data_memory_include_version_with_data);
TEST (pcr_test_get_measurement_data_memory_include_version_with_data_offset);
TEST (pcr_test_get_measurement_data_memory_include_version_with_data_small_buffer);
TEST (pcr_test_get_measurement_data_memory_include_version_with_data_small_buffer_offset);
TEST (pcr_test_get_measurement_data_memory_include_version_invalid_offset);
TEST (pcr_test_get_measurement_data_memory_include_event_version);
TEST (pcr_test_get_measurement_data_memory_include_event_version_no_data);
TEST (pcr_test_get_measurement_data_memory_include_event_version_offset);
TEST (pcr_test_get_measurement_data_memory_include_event_version_small_buffer);
TEST (pcr_test_get_measurement_data_memory_include_event_version_small_buffer_offset);
TEST (pcr_test_get_measurement_data_memory_include_event_version_with_event_version);
TEST (pcr_test_get_measurement_data_memory_include_event_version_with_event_version_offset);
TEST (pcr_test_get_measurement_data_memory_include_event_version_with_version_data);
TEST (pcr_test_get_measurement_data_memory_include_event_version_with_version_data_small_buffer);
TEST (pcr_test_get_measurement_data_memory_include_event_version_with_event);
TEST (pcr_test_get_measurement_data_memory_include_event_version_with_event_offset);
TEST (pcr_test_get_measurement_data_memory_include_event_version_with_event_small_buffer);
TEST (pcr_test_get_measurement_data_memory_include_event_version_with_event_small_buffer_offset);
TEST (pcr_test_get_measurement_data_memory_include_event_version_with_version);
TEST (pcr_test_get_measurement_data_memory_include_event_version_with_data);
TEST (pcr_test_get_measurement_data_memory_include_event_version_with_data_offset);
TEST (pcr_test_get_measurement_data_memory_include_event_version_with_data_small_buffer);
TEST (pcr_test_get_measurement_data_memory_include_event_version_with_data_small_buffer_offset);
TEST (pcr_test_get_measurement_data_memory_include_event_version_invalid_offset);
TEST (pcr_test_get_measurement_data_flash);
TEST (pcr_test_get_measurement_data_flash_zero_length);
TEST (pcr_test_get_measurement_data_flash_offset);
TEST (pcr_test_get_measurement_data_flash_small_buffer);
TEST (pcr_test_get_measurement_data_flash_small_buffer_offset);
TEST (pcr_test_get_measurement_data_flash_invalid_offset);
TEST (pcr_test_get_measurement_data_flash_read_fail);
TEST (pcr_test_get_measurement_data_flash_include_event);
TEST (pcr_test_get_measurement_data_flash_include_event_offset);
TEST (pcr_test_get_measurement_data_flash_include_event_small_buffer);
TEST (pcr_test_get_measurement_data_flash_include_event_small_buffer_offset);
TEST (pcr_test_get_measurement_data_flash_include_event_with_event);
TEST (pcr_test_get_measurement_data_flash_include_event_with_event_offset);
TEST (pcr_test_get_measurement_data_flash_include_event_with_event_small_buffer);
TEST (pcr_test_get_measurement_data_flash_include_event_with_event_small_buffer_offset);
TEST (pcr_test_get_measurement_data_flash_include_event_with_data);
TEST (pcr_test_get_measurement_data_flash_include_event_with_data_offset);
TEST (pcr_test_get_measurement_data_flash_include_event_with_data_small_buffer);
TEST (pcr_test_get_measurement_data_flash_include_event_with_data_small_buffer_offset);
TEST (pcr_test_get_measurement_data_flash_include_event_with_data_read_fail);
TEST (pcr_test_get_measurement_data_flash_include_event_read_fail);
TEST (pcr_test_get_measurement_data_flash_include_event_invalid_offset);
TEST (pcr_test_get_measurement_data_flash_include_version);
TEST (pcr_test_get_measurement_data_flash_include_version_small_buffer);
TEST (pcr_test_get_measurement_data_flash_include_version_with_version);
TEST (pcr_test_get_measurement_data_flash_include_version_with_data);
TEST (pcr_test_get_measurement_data_flash_include_version_with_data_offset);
TEST (pcr_test_get_measurement_data_flash_include_version_with_data_small_buffer);
TEST (pcr_test_get_measurement_data_flash_include_version_with_data_small_buffer_offset);
TEST (pcr_test_get_measurement_data_flash_include_version_with_data_read_fail);
TEST (pcr_test_get_measurement_data_flash_include_version_read_fail);
TEST (pcr_test_get_measurement_data_flash_include_version_invalid_offset);
TEST (pcr_test_get_measurement_data_flash_include_event_version);
TEST (pcr_test_get_measurement_data_flash_include_event_version_offset);
TEST (pcr_test_get_measurement_data_flash_include_event_version_small_buffer);
TEST (pcr_test_get_measurement_data_flash_include_event_version_small_buffer_offset);
TEST (pcr_test_get_measurement_data_flash_include_event_version_with_event_version);
TEST (pcr_test_get_measurement_data_flash_include_event_version_with_event_version_offset);
TEST (pcr_test_get_measurement_data_flash_include_event_version_with_version_data);
TEST (pcr_test_get_measurement_data_flash_include_event_version_with_version_data_small_buffer);
TEST (pcr_test_get_measurement_data_flash_include_event_version_with_version_data_read_fail);
TEST (pcr_test_get_measurement_data_flash_include_event_version_with_event);
TEST (pcr_test_get_measurement_data_flash_include_event_version_with_event_offset);
TEST (pcr_test_get_measurement_data_flash_include_event_version_with_event_small_buffer);
TEST (pcr_test_get_measurement_data_flash_include_event_version_with_event_small_buffer_offset);
TEST (pcr_test_get_measurement_data_flash_include_event_version_with_version);
TEST (pcr_test_get_measurement_data_flash_include_event_version_with_data);
TEST (pcr_test_get_measurement_data_flash_include_event_version_with_data_offset);
TEST (pcr_test_get_measurement_data_flash_include_event_version_with_data_small_buffer);
TEST (pcr_test_get_measurement_data_flash_include_event_version_with_data_small_buffer_offset);
TEST (pcr_test_get_measurement_data_flash_include_event_version_with_data_read_fail);
TEST (pcr_test_get_measurement_data_flash_include_event_version_read_fail);
TEST (pcr_test_get_measurement_data_flash_include_event_version_invalid_offset);
TEST (pcr_test_get_measurement_data_callback);
TEST (pcr_test_get_measurement_data_callback_zero_length);
TEST (pcr_test_get_measurement_data_callback_offset);
TEST (pcr_test_get_measurement_data_callback_fail);
TEST (pcr_test_get_measurement_data_callback_include_event);
TEST (pcr_test_get_measurement_data_callback_include_event_offset);
TEST (pcr_test_get_measurement_data_callback_include_event_small_buffer);
TEST (pcr_test_get_measurement_data_callback_include_event_small_buffer_offset);
TEST (pcr_test_get_measurement_data_callback_include_event_with_event);
TEST (pcr_test_get_measurement_data_callback_include_event_with_event_offset);
TEST (pcr_test_get_measurement_data_callback_include_event_with_event_small_buffer);
TEST (pcr_test_get_measurement_data_callback_include_event_with_event_small_buffer_offset);
TEST (pcr_test_get_measurement_data_callback_include_event_with_data);
TEST (pcr_test_get_measurement_data_callback_include_event_with_data_offset);
TEST (pcr_test_get_measurement_data_callback_include_event_with_data_small_buffer);
TEST (pcr_test_get_measurement_data_callback_include_event_with_data_small_buffer_offset);
TEST (pcr_test_get_measurement_data_callback_include_event_with_data_fail);
TEST (pcr_test_get_measurement_data_callback_include_event_fail);
TEST (pcr_test_get_measurement_data_callback_include_version);
TEST (pcr_test_get_measurement_data_callback_include_version_small_buffer);
TEST (pcr_test_get_measurement_data_callback_include_version_with_version);
TEST (pcr_test_get_measurement_data_callback_include_version_with_data);
TEST (pcr_test_get_measurement_data_callback_include_version_with_data_offset);
TEST (pcr_test_get_measurement_data_callback_include_version_with_data_small_buffer);
TEST (pcr_test_get_measurement_data_callback_include_version_with_data_small_buffer_offset);
TEST (pcr_test_get_measurement_data_callback_include_version_with_data_fail);
TEST (pcr_test_get_measurement_data_callback_include_version_fail);
TEST (pcr_test_get_measurement_data_callback_include_event_version);
TEST (pcr_test_get_measurement_data_callback_include_event_version_offset);
TEST (pcr_test_get_measurement_data_callback_include_event_version_small_buffer);
TEST (pcr_test_get_measurement_data_callback_include_event_version_small_buffer_offset);
TEST (pcr_test_get_measurement_data_callback_include_event_version_with_event_version);
TEST (pcr_test_get_measurement_data_callback_include_event_version_with_event_version_offset);
TEST (pcr_test_get_measurement_data_callback_include_event_version_with_version_data);
TEST (pcr_test_get_measurement_data_callback_include_event_version_with_version_data_small_buffer);
TEST (pcr_test_get_measurement_data_callback_include_event_version_with_version_data_fail);
TEST (pcr_test_get_measurement_data_callback_include_event_version_with_event);
TEST (pcr_test_get_measurement_data_callback_include_event_version_with_event_offset);
TEST (pcr_test_get_measurement_data_callback_include_event_version_with_event_small_buffer);
TEST (pcr_test_get_measurement_data_callback_include_event_version_with_event_small_buffer_offset);
TEST (pcr_test_get_measurement_data_callback_include_event_version_with_version);
TEST (pcr_test_get_measurement_data_callback_include_event_version_with_data);
TEST (pcr_test_get_measurement_data_callback_include_event_version_with_data_offset);
TEST (pcr_test_get_measurement_data_callback_include_event_version_with_data_small_buffer);
TEST (pcr_test_get_measurement_data_callback_include_event_version_with_data_small_buffer_offset);
TEST (pcr_test_get_measurement_data_callback_include_event_version_with_data_fail);
TEST (pcr_test_get_measurement_data_callback_include_event_version_fail);
TEST (pcr_test_get_measurement_data_no_measured_data);
TEST (pcr_test_get_measurement_data_null);
TEST (pcr_test_get_measurement_data_bad_measurement_index);
TEST (pcr_test_get_measurement_data_no_data);
TEST (pcr_test_get_measurement_data_bad_measurement_data_type);
TEST (pcr_test_hash_measurement_data_sha256_matches_pcr);
TEST (pcr_test_hash_measurement_data_sha256_matches_pcr_include_event);
TEST (pcr_test_hash_measurement_data_sha256_matches_pcr_include_version);
TEST (pcr_test_hash_measurement_data_sha256_matches_pcr_include_event_version);
#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
TEST (pcr_test_hash_measurement_data_sha384_matches_pcr);
TEST (pcr_test_hash_measurement_data_sha384_matches_pcr_include_event);
TEST (pcr_test_hash_measurement_data_sha384_matches_pcr_include_version);
TEST (pcr_test_hash_measurement_data_sha384_matches_pcr_include_event_version);
#endif
#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
TEST (pcr_test_hash_measurement_data_sha512_matches_pcr);
TEST (pcr_test_hash_measurement_data_sha512_matches_pcr_include_event);
TEST (pcr_test_hash_measurement_data_sha512_matches_pcr_include_version);
TEST (pcr_test_hash_measurement_data_sha512_matches_pcr_include_event_version);
#endif
#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
TEST (pcr_test_hash_measurement_data_sha256_1byte);
TEST (pcr_test_hash_measurement_data_sha256_1byte_include_event);
TEST (pcr_test_hash_measurement_data_sha256_1byte_include_version);
TEST (pcr_test_hash_measurement_data_sha256_1byte_include_event_version);
TEST (pcr_test_hash_measurement_data_sha256_2byte);
TEST (pcr_test_hash_measurement_data_sha256_2byte_include_event);
TEST (pcr_test_hash_measurement_data_sha256_2byte_include_version);
TEST (pcr_test_hash_measurement_data_sha256_2byte_include_event_version);
TEST (pcr_test_hash_measurement_data_sha256_4byte);
TEST (pcr_test_hash_measurement_data_sha256_4byte_include_event);
TEST (pcr_test_hash_measurement_data_sha256_4byte_include_version);
TEST (pcr_test_hash_measurement_data_sha256_4byte_include_event_version);
TEST (pcr_test_hash_measurement_data_sha256_8byte);
TEST (pcr_test_hash_measurement_data_sha256_8byte_include_event);
TEST (pcr_test_hash_measurement_data_sha256_8byte_include_version);
TEST (pcr_test_hash_measurement_data_sha256_8byte_include_event_version);
TEST (pcr_test_hash_measurement_data_sha256_memory);
TEST (pcr_test_hash_measurement_data_sha256_memory_include_event);
TEST (pcr_test_hash_measurement_data_sha256_memory_include_version);
TEST (pcr_test_hash_measurement_data_sha256_memory_include_event_version);
TEST (pcr_test_hash_measurement_data_sha256_flash);
TEST (pcr_test_hash_measurement_data_sha256_flash_include_event);
TEST (pcr_test_hash_measurement_data_sha256_flash_include_version);
TEST (pcr_test_hash_measurement_data_sha256_flash_include_event_version);
TEST (pcr_test_hash_measurement_data_sha256_callback);
TEST (pcr_test_hash_measurement_data_sha256_callback_include_event);
TEST (pcr_test_hash_measurement_data_sha256_callback_include_version);
TEST (pcr_test_hash_measurement_data_sha256_callback_include_event_version);
TEST (pcr_test_hash_measurement_data_sha384_1byte);
TEST (pcr_test_hash_measurement_data_sha384_1byte_include_event);
TEST (pcr_test_hash_measurement_data_sha384_1byte_include_version);
TEST (pcr_test_hash_measurement_data_sha384_1byte_include_event_version);
TEST (pcr_test_hash_measurement_data_sha384_2byte);
TEST (pcr_test_hash_measurement_data_sha384_2byte_include_event);
TEST (pcr_test_hash_measurement_data_sha384_2byte_include_version);
TEST (pcr_test_hash_measurement_data_sha384_2byte_include_event_version);
TEST (pcr_test_hash_measurement_data_sha384_4byte);
TEST (pcr_test_hash_measurement_data_sha384_4byte_include_event);
TEST (pcr_test_hash_measurement_data_sha384_4byte_include_version);
TEST (pcr_test_hash_measurement_data_sha384_4byte_include_event_version);
TEST (pcr_test_hash_measurement_data_sha384_8byte);
TEST (pcr_test_hash_measurement_data_sha384_8byte_include_event);
TEST (pcr_test_hash_measurement_data_sha384_8byte_include_version);
TEST (pcr_test_hash_measurement_data_sha384_8byte_include_event_version);
TEST (pcr_test_hash_measurement_data_sha384_memory);
TEST (pcr_test_hash_measurement_data_sha384_memory_include_event);
TEST (pcr_test_hash_measurement_data_sha384_memory_include_version);
TEST (pcr_test_hash_measurement_data_sha384_memory_include_event_version);
TEST (pcr_test_hash_measurement_data_sha384_flash);
TEST (pcr_test_hash_measurement_data_sha384_flash_include_event);
TEST (pcr_test_hash_measurement_data_sha384_flash_include_version);
TEST (pcr_test_hash_measurement_data_sha384_flash_include_event_version);
TEST (pcr_test_hash_measurement_data_sha384_callback);
TEST (pcr_test_hash_measurement_data_sha384_callback_include_event);
TEST (pcr_test_hash_measurement_data_sha384_callback_include_version);
TEST (pcr_test_hash_measurement_data_sha384_callback_include_event_version);
#endif
#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
TEST (pcr_test_hash_measurement_data_sha512_1byte);
TEST (pcr_test_hash_measurement_data_sha512_1byte_include_event);
TEST (pcr_test_hash_measurement_data_sha512_1byte_include_version);
TEST (pcr_test_hash_measurement_data_sha512_1byte_include_event_version);
TEST (pcr_test_hash_measurement_data_sha512_2byte);
TEST (pcr_test_hash_measurement_data_sha512_2byte_include_event);
TEST (pcr_test_hash_measurement_data_sha512_2byte_include_version);
TEST (pcr_test_hash_measurement_data_sha512_2byte_include_event_version);
TEST (pcr_test_hash_measurement_data_sha512_4byte);
TEST (pcr_test_hash_measurement_data_sha512_4byte_include_event);
TEST (pcr_test_hash_measurement_data_sha512_4byte_include_version);
TEST (pcr_test_hash_measurement_data_sha512_4byte_include_event_version);
TEST (pcr_test_hash_measurement_data_sha512_8byte);
TEST (pcr_test_hash_measurement_data_sha512_8byte_include_event);
TEST (pcr_test_hash_measurement_data_sha512_8byte_include_version);
TEST (pcr_test_hash_measurement_data_sha512_8byte_include_event_version);
TEST (pcr_test_hash_measurement_data_sha512_memory);
TEST (pcr_test_hash_measurement_data_sha512_memory_include_event);
TEST (pcr_test_hash_measurement_data_sha512_memory_include_version);
TEST (pcr_test_hash_measurement_data_sha512_memory_include_event_version);
TEST (pcr_test_hash_measurement_data_sha512_flash);
TEST (pcr_test_hash_measurement_data_sha512_flash_include_event);
TEST (pcr_test_hash_measurement_data_sha512_flash_include_version);
TEST (pcr_test_hash_measurement_data_sha512_flash_include_event_version);
TEST (pcr_test_hash_measurement_data_sha512_callback);
TEST (pcr_test_hash_measurement_data_sha512_callback_include_event);
TEST (pcr_test_hash_measurement_data_sha512_callback_include_version);
TEST (pcr_test_hash_measurement_data_sha512_callback_include_event_version);
#endif
TEST (pcr_test_hash_measurement_data_null);
TEST (pcr_test_hash_measurement_data_bad_measurement_index);
TEST (pcr_test_hash_measurement_data_unknown_hash);
TEST (pcr_test_hash_measurement_data_sha256_small_output_buffer);
TEST (pcr_test_hash_measurement_data_sha384_small_output_buffer);
TEST (pcr_test_hash_measurement_data_sha512_small_output_buffer);
#ifdef HASH_ENABLE_SHA384
TEST (pcr_test_hash_measurement_data_sha384_start_hash_error);
#endif
#ifdef HASH_ENABLE_SHA512
TEST (pcr_test_hash_measurement_data_sha512_start_hash_error);
#endif
#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
TEST (pcr_test_hash_measurement_data_no_measured_data);
TEST (pcr_test_hash_measurement_data_sha256_start_hash_error);
TEST (pcr_test_hash_measurement_data_event_hash_error);
TEST (pcr_test_hash_measurement_data_version_hash_error);
TEST (pcr_test_hash_measurement_data_1byte_hash_error);
TEST (pcr_test_hash_measurement_data_2byte_hash_error);
TEST (pcr_test_hash_measurement_data_4byte_hash_error);
TEST (pcr_test_hash_measurement_data_8byte_hash_error);
TEST (pcr_test_hash_measurement_data_memory_hash_error);
TEST (pcr_test_hash_measurement_data_flash_error);
TEST (pcr_test_hash_measurement_data_callback_error);
TEST (pcr_test_hash_measurement_data_no_hash_callback);
TEST (pcr_test_hash_measurement_data_bad_measurement_data_type);
TEST (pcr_test_hash_measurement_data_finish_error);
#endif
TEST (pcr_test_get_tcg_log_sha256);
TEST (pcr_test_get_tcg_log_sha256_explicit);
TEST (pcr_test_get_tcg_log_sha256_offset_beginning_of_event);
TEST (pcr_test_get_tcg_log_sha256_offset_middle_of_event);
TEST (pcr_test_get_tcg_log_sha256_offset_middle_of_event_header);
TEST (pcr_test_get_tcg_log_sha256_zero_bytes_read);
#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
TEST (pcr_test_get_tcg_log_sha384);
TEST (pcr_test_get_tcg_log_sha384_explicit);
TEST (pcr_test_get_tcg_log_sha384_offset_beginning_of_event);
TEST (pcr_test_get_tcg_log_sha384_offset_middle_of_event);
TEST (pcr_test_get_tcg_log_sha384_offset_middle_of_event_header);
TEST (pcr_test_get_tcg_log_sha384_zero_bytes_read);
#endif
#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
TEST (pcr_test_get_tcg_log_sha512);
TEST (pcr_test_get_tcg_log_sha512_explicit);
TEST (pcr_test_get_tcg_log_sha512_offset_beginning_of_event);
TEST (pcr_test_get_tcg_log_sha512_offset_middle_of_event);
TEST (pcr_test_get_tcg_log_sha512_offset_middle_of_event_header);
TEST (pcr_test_get_tcg_log_sha512_zero_bytes_read);
#endif
TEST (pcr_test_get_tcg_log_small_buffer);
TEST (pcr_test_get_tcg_log_small_buffer_with_offset);
TEST (pcr_test_get_tcg_log_short_buffer_middle_of_event_header);
TEST (pcr_test_get_tcg_log_null);
TEST (pcr_test_get_tcg_log_get_measured_data_fail);

TEST_SUITE_END;
