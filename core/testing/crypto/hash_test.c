// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "platform_io.h"
#include "testing.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/crypto/hash_testing.h"


TEST_SUITE_LABEL ("hash");


/**
 * SHA1 hash of "Test".
 */
const uint8_t SHA1_TEST_HASH[] = {
	0x64,0x0a,0xb2,0xba,0xe0,0x7b,0xed,0xc4,0xc1,0x63,0xf6,0x79,0xa7,0x46,0xf7,0xab,
	0x7f,0xb5,0xd1,0xfa
};

/**
 * SHA1 hash of "Test2".
 */
const uint8_t SHA1_TEST2_HASH[] = {
	0x2b,0x84,0xf6,0x21,0xc0,0xfd,0x4b,0xa8,0xbd,0x51,0x4c,0x5c,0x43,0xab,0x9a,0x89,
	0x7c,0x8c,0x01,0x4e
};

/**
 * SHA1 hash of "Nope".
 */
const uint8_t SHA1_NOPE_HASH[] = {
	0x2f,0x35,0xce,0xbe,0xbc,0xa8,0xfe,0x85,0x91,0xe4,0x48,0x7f,0xac,0xe7,0xcc,0x9e,
	0x00,0x40,0x5a,0x9d
};

/**
 * SHA1 hash of "Bad".
 */
const uint8_t SHA1_BAD_HASH[] = {
	0xbe,0x7e,0x10,0xd1,0xc5,0xdd,0x2a,0xd7,0x7f,0x6d,0x5a,0x61,0x73,0x72,0xa7,0xbf,
	0x01,0x3c,0xb7,0xbf
};

/**
 * SHA1 hash for testing an empty buffer.
 */
const uint8_t SHA1_EMPTY_BUFFER_HASH[] = {
	0xda,0x39,0xa3,0xee,0x5e,0x6b,0x4b,0x0d,0x32,0x55,0xbf,0xef,0x95,0x60,0x18,0x90,
	0xaf,0xd8,0x07,0x09
};

/**
 * SHA1 hash for testing a 32 byte buffer filled with zeros.
 */
const uint8_t SHA1_ZERO_BUFFER_HASH[] = {
	0xde,0x8a,0x84,0x7b,0xff,0x8c,0x34,0x3d,0x69,0xb8,0x53,0xa2,0x15,0xe6,0xee,0x77,
	0x5e,0xf2,0xef,0x96
};

/**
 * Test key to use for SHA1 HMAC.  The key length is equal to SHA1_HASH_LENGTH.
 */
const uint8_t SHA1_HMAC_KEY[] = {
	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
	0x10,0x11,0x12,0x13
};

/**
 * SHA1 HMAC of "Test" using SHA1_HMAC_KEY.
 */
const uint8_t SHA1_TEST_HMAC[] = {
	0xcf,0xed,0x6f,0x69,0x6a,0xf6,0x9d,0x06,0xbc,0xe0,0xe7,0x1e,0x43,0xe6,0x69,0x29,
	0x71,0x7e,0x35,0x0f
};

/**
 * SHA256 hash of "Test"
 */
const uint8_t SHA256_TEST_HASH[] = {
	0x53,0x2e,0xaa,0xbd,0x95,0x74,0x88,0x0d,0xbf,0x76,0xb9,0xb8,0xcc,0x00,0x83,0x2c,
	0x20,0xa6,0xec,0x11,0x3d,0x68,0x22,0x99,0x55,0x0d,0x7a,0x6e,0x0f,0x34,0x5e,0x25
};

/**
 * SHA256 hash of "Test2"
 */
const uint8_t SHA256_TEST2_HASH[] = {
	0x32,0xe6,0xe1,0xe1,0x34,0xf9,0xcc,0x8f,0x14,0xb0,0x59,0x25,0x66,0x7c,0x11,0x8d,
	0x19,0x24,0x4a,0xeb,0xce,0x44,0x2d,0x6f,0xec,0xd2,0xac,0x38,0xcd,0xc9,0x76,0x49
};

/**
 * SHA256 hash of "Nope"
 */
const uint8_t SHA256_NOPE_HASH[] = {
	0x7b,0xf1,0x55,0x67,0x08,0xef,0xd0,0xd8,0xaf,0x60,0x50,0xf5,0x92,0xae,0x25,0xa5,
	0xb6,0xfd,0xd4,0xf7,0xd1,0x5a,0xe3,0xed,0x6d,0xeb,0x43,0xb5,0xa2,0x6c,0x6f,0xf8
};

/**
 * SHA256 hash of "Bad"
 */
const uint8_t SHA256_BAD_HASH[] = {
	0x6f,0xe7,0xd7,0x11,0x2c,0xaa,0xba,0x1b,0x1b,0xc7,0xbf,0xa6,0x56,0x97,0x4a,0xc4,
	0x01,0x6c,0xc5,0x25,0xa7,0x28,0x61,0x17,0x49,0x4f,0x5b,0x29,0xdf,0xec,0x1f,0x77
};

/**
 * SHA256 hash for testing an empty buffer.
 */
const uint8_t SHA256_EMPTY_BUFFER_HASH[] = {
	0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
	0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
};

/**
 * SHA256 hash for testing a 32 byte buffer filled with zeros.
 */
const uint8_t SHA256_ZERO_BUFFER_HASH[] = {
	0x66,0x68,0x7a,0xad,0xf8,0x62,0xbd,0x77,0x6c,0x8f,0xc1,0x8b,0x8e,0x9f,0x8e,0x20,
	0x08,0x97,0x14,0x85,0x6e,0xe2,0x33,0xb3,0x90,0x2a,0x59,0x1d,0x0d,0x5f,0x29,0x25
};

/**
 * Test key to use for SHA256 HMAC.  The key length is equal to SHA256_HASH_LENGTH.
 */
const uint8_t SHA256_HMAC_KEY[] = {
	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
	0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};

/**
 * SHA256 HMAC of "Test" using SHA256_HMAC_KEY.
 */
const uint8_t SHA256_TEST_HMAC[] = {
	0xbe,0xac,0xa5,0x36,0x3b,0xec,0xae,0x40,0xda,0x59,0x28,0x57,0x79,0x4e,0x38,0x79,
	0x6e,0x86,0xd2,0x9a,0x7a,0x23,0xdf,0x5e,0x1c,0x62,0xb5,0xd0,0xa5,0xba,0x2e,0x67
};

/**
 * SHA384 hash of "Test".
 */
const uint8_t SHA384_TEST_HASH[] = {
	0x7b,0x8f,0x46,0x54,0x07,0x6b,0x80,0xeb,0x96,0x39,0x11,0xf1,0x9c,0xfa,0xd1,0xaa,
	0xf4,0x28,0x5e,0xd4,0x8e,0x82,0x6f,0x6c,0xde,0x1b,0x01,0xa7,0x9a,0xa7,0x3f,0xad,
	0xb5,0x44,0x6e,0x66,0x7f,0xc4,0xf9,0x04,0x17,0x78,0x2c,0x91,0x27,0x05,0x40,0xf3
};

/**
 * SHA384 hash of "Test2".
 */
const uint8_t SHA384_TEST2_HASH[] = {
	0xc2,0x50,0x99,0x84,0x5d,0x75,0x16,0x74,0x51,0xbc,0xb2,0x40,0x46,0x9d,0x91,0xf0,
	0x83,0xe9,0xee,0xc8,0x19,0xf7,0x58,0xcd,0x42,0xcb,0x19,0xb7,0x33,0xf1,0xa0,0x22,
	0x25,0xdd,0xc8,0x33,0xcd,0x50,0x82,0x7e,0x87,0xf1,0x09,0x16,0x2d,0x92,0x24,0xb5
};

/**
 * SHA384 hash of "Nope".
 */
const uint8_t SHA384_NOPE_HASH[] = {
	0x64,0xe0,0xa5,0x50,0xe7,0x2a,0x1e,0xa8,0x0d,0xcd,0x8c,0xb0,0x8b,0xf5,0x69,0x50,
	0xfe,0x44,0x3d,0xb7,0x21,0x5a,0x6f,0xae,0xa7,0x4b,0x07,0x33,0x2c,0x29,0xda,0x1c,
	0x94,0xd6,0x83,0xbe,0x7d,0xc5,0x91,0x39,0x85,0x35,0x9b,0x6e,0x89,0xa5,0x90,0xbf
};

/**
 * SHA384 hash of "Bad".
 */
const uint8_t SHA384_BAD_HASH[] = {
	0x6c,0x21,0xde,0xea,0xa2,0xfb,0x6e,0xb7,0x17,0xc7,0xcc,0xe2,0x70,0xbc,0x14,0x07,
	0xf1,0x1c,0xb1,0x5a,0x1a,0x4e,0x23,0x43,0xb0,0x3b,0xb2,0xd0,0x4d,0x95,0x06,0x83,
	0xb2,0xc7,0x2e,0x22,0xf5,0x1f,0xac,0x87,0x04,0x17,0x38,0x93,0x3a,0xc7,0xc4,0x37
};

/**
 * SHA384 hash for testing an empty buffer.
 */
const uint8_t SHA384_EMPTY_BUFFER_HASH[] = {
	0x38,0xb0,0x60,0xa7,0x51,0xac,0x96,0x38,0x4c,0xd9,0x32,0x7e,0xb1,0xb1,0xe3,0x6a,
	0x21,0xfd,0xb7,0x11,0x14,0xbe,0x07,0x43,0x4c,0x0c,0xc7,0xbf,0x63,0xf6,0xe1,0xda,
	0x27,0x4e,0xde,0xbf,0xe7,0x6f,0x65,0xfb,0xd5,0x1a,0xd2,0xf1,0x48,0x98,0xb9,0x5b
};

/**
 * SHA384 hash for testing a 32 byte buffer filled with zeros.
 */
const uint8_t SHA384_ZERO_BUFFER_HASH[] = {
	0xa3,0x8f,0xff,0x4b,0xa2,0x6c,0x15,0xe4,0xac,0x9c,0xde,0x8c,0x03,0x10,0x3a,0xc8,
	0x90,0x80,0xfd,0x47,0x54,0x5f,0xde,0x94,0x46,0xc8,0xf1,0x92,0x72,0x9e,0xab,0x7b,
	0xd0,0x3a,0x4d,0x5c,0x31,0x87,0xf7,0x5f,0xe2,0xa7,0x1b,0x0e,0xe5,0x0a,0x4a,0x40
};

/**
 * Test key to use for SHA384 HMAC.  The key length is equal to SHA384_HASH_LENGTH.
 */
const uint8_t SHA384_HMAC_KEY[] = {
	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
	0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
	0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f
};

/**
 * SHA384 HMAC of "Test" using SHA384_HMAC_KEY.
 */
const uint8_t SHA384_TEST_HMAC[] = {
	0x59,0x38,0x2e,0xc3,0x89,0xf5,0x8f,0x5b,0x95,0x1b,0xad,0xed,0xd4,0xab,0x25,0x40,
	0xc3,0x49,0x7e,0x99,0x23,0xb5,0x08,0x84,0x6b,0x0a,0x68,0x62,0xf2,0xe5,0x7f,0x1c,
	0x86,0x3b,0x9b,0x81,0x4e,0xce,0x4a,0x91,0x6b,0x20,0x80,0x32,0x2b,0x86,0x2f,0xf1
};

/**
 * SHA512 hash of "Test".
 */
const uint8_t SHA512_TEST_HASH[] = {
	0xc6,0xee,0x9e,0x33,0xcf,0x5c,0x67,0x15,0xa1,0xd1,0x48,0xfd,0x73,0xf7,0x31,0x88,
	0x84,0xb4,0x1a,0xdc,0xb9,0x16,0x02,0x1e,0x2b,0xc0,0xe8,0x00,0xa5,0xc5,0xdd,0x97,
	0xf5,0x14,0x21,0x78,0xf6,0xae,0x88,0xc8,0xfd,0xd9,0x8e,0x1a,0xfb,0x0c,0xe4,0xc8,
	0xd2,0xc5,0x4b,0x5f,0x37,0xb3,0x0b,0x7d,0xa1,0x99,0x7b,0xb3,0x3b,0x0b,0x8a,0x31
};

/**
 * SHA512 hash of "Test2".
 */
const uint8_t SHA512_TEST2_HASH[] = {
	0x91,0x8d,0x11,0xb7,0xa7,0xf8,0x08,0x04,0x55,0x79,0x5c,0xb7,0x11,0x5d,0x13,0xf5,
	0x35,0x66,0xe9,0xe0,0xe6,0x0e,0x28,0x7d,0xc8,0xeb,0x39,0xc9,0x3c,0xb2,0xdb,0x0f,
	0xd1,0x3b,0xd7,0x4c,0xd2,0x8e,0x8e,0x49,0x99,0xed,0xfb,0xd9,0xd1,0xfd,0xdb,0x60,
	0xb5,0x87,0xe2,0x9c,0xc4,0xe3,0xb9,0x06,0x3a,0x03,0xed,0xde,0x29,0x13,0xb5,0xbd
};

/**
 * SHA512 hash of "Nope".
 */
const uint8_t SHA512_NOPE_HASH[] = {
	0xec,0x9e,0x04,0x5f,0x37,0xc1,0x79,0x94,0xaf,0xb4,0x5d,0x11,0x35,0x30,0x97,0x3f,
	0xf2,0xbe,0x46,0xcb,0xe9,0xff,0x56,0x2b,0x7e,0xa7,0x94,0x27,0xf8,0x29,0x61,0xb4,
	0x0e,0xf9,0xee,0xaa,0xe1,0x10,0x3b,0x16,0x3b,0xac,0xe5,0xaa,0xa3,0xf2,0xc8,0x9c,
	0xba,0xca,0x03,0x63,0xe9,0x1c,0x59,0x6e,0xa4,0x25,0xb0,0x3a,0x7c,0x0b,0x8c,0x72
};

/**
 * SHA512 hash of "Bad".
 */
const uint8_t SHA512_BAD_HASH[] = {
	0xc8,0x5f,0xb9,0x4f,0x63,0xc5,0xb9,0xf9,0x3e,0x49,0x5f,0xb5,0x75,0x89,0x65,0x6d,
	0x31,0xb4,0x41,0x1e,0x0c,0x79,0x3a,0x11,0xfd,0xe6,0x40,0x39,0xfd,0xaa,0x2d,0xa8,
	0x59,0xd1,0x4d,0x41,0x67,0x24,0x14,0x86,0x46,0x91,0x63,0x7f,0x82,0x06,0x50,0x72,
	0xf6,0x4e,0x23,0x8d,0x7c,0xe2,0x77,0x43,0x79,0x27,0xca,0x7c,0xcb,0xfa,0x86,0x9c
};

/**
 * SHA512 hash for testing an empty buffer.
 */
const uint8_t SHA512_EMPTY_BUFFER_HASH[] = {
	0xcf,0x83,0xe1,0x35,0x7e,0xef,0xb8,0xbd,0xf1,0x54,0x28,0x50,0xd6,0x6d,0x80,0x07,
	0xd6,0x20,0xe4,0x05,0x0b,0x57,0x15,0xdc,0x83,0xf4,0xa9,0x21,0xd3,0x6c,0xe9,0xce,
	0x47,0xd0,0xd1,0x3c,0x5d,0x85,0xf2,0xb0,0xff,0x83,0x18,0xd2,0x87,0x7e,0xec,0x2f,
	0x63,0xb9,0x31,0xbd,0x47,0x41,0x7a,0x81,0xa5,0x38,0x32,0x7a,0xf9,0x27,0xda,0x3e
};

/**
 * SHA512 hash for testing a 32 byte buffer filled with zeros.
 */
const uint8_t SHA512_ZERO_BUFFER_HASH[] = {
	0x50,0x46,0xad,0xc1,0xdb,0xa8,0x38,0x86,0x7b,0x2b,0xbb,0xfd,0xd0,0xc3,0x42,0x3e,
	0x58,0xb5,0x79,0x70,0xb5,0x26,0x7a,0x90,0xf5,0x79,0x60,0x92,0x4a,0x87,0xf1,0x96,
	0x0a,0x6a,0x85,0xea,0xa6,0x42,0xda,0xc8,0x35,0x42,0x4b,0x5d,0x7c,0x8d,0x63,0x7c,
	0x00,0x40,0x8c,0x7a,0x73,0xda,0x67,0x2b,0x7f,0x49,0x85,0x21,0x42,0x0b,0x6d,0xd3
};

/**
 * Test key to use for SHA512 HMAC.  The key length is equal to SHA512_HASH_LENGTH.
 */
const uint8_t SHA512_HMAC_KEY[] = {
	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
	0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
	0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
	0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f
};

/**
 * SHA512 HMAC of "Test" using SHA512_HMAC_KEY.
 */
const uint8_t SHA512_TEST_HMAC[] = {
	0xc3,0x25,0x2d,0x64,0x2a,0xf1,0x3e,0x37,0xd1,0xd1,0x2a,0x4d,0xd7,0x2e,0xae,0xac,
	0x28,0x8c,0x9b,0x40,0xbf,0xfd,0xad,0x91,0x05,0x4f,0xc5,0x79,0x7a,0x91,0x4b,0x94,
	0xbf,0x82,0xa9,0x21,0xac,0x41,0xba,0x92,0xed,0xae,0x05,0x70,0xc0,0xc6,0x5f,0xfd,
	0xf6,0x82,0x43,0xe7,0xed,0x79,0xa8,0xaa,0x9a,0xa5,0x40,0x1f,0x06,0x22,0xc0,0x46
};

/*******************
 * Test cases
 *******************/

static void hash_test_hmac_sha1_incremental (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA1_HASH_LENGTH];
	uint8_t expected[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f
	};
	struct hmac_engine hmac_engine;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA1, key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_update (&hmac_engine, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_finish (&hmac_engine, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_sha1_incremental_large_key (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[SHA1_BLOCK_SIZE + 1];
	uint8_t hmac[SHA1_HASH_LENGTH];
	uint8_t expected[] = {
		0x19,0x75,0xda,0x73,0x05,0xeb,0xd1,0x29,0x3a,0x90,0xc8,0x36,0xe1,0xed,0x76,0x7f,
		0xa3,0x67,0x51,0x31
	};
	struct hmac_engine hmac_engine;
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (key); i++) {
		key[i] = i;
	}

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA1, key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_update (&hmac_engine, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_finish (&hmac_engine, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_sha256_incremental (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA256_HASH_LENGTH];
	uint8_t expected[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	struct hmac_engine hmac_engine;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA256, key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_update (&hmac_engine, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_finish (&hmac_engine, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_sha256_incremental_large_key (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[SHA256_BLOCK_SIZE + 1];
	uint8_t hmac[SHA256_HASH_LENGTH];
	uint8_t expected[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	struct hmac_engine hmac_engine;
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (key); i++) {
		key[i] = i;
	}

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA256, key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_update (&hmac_engine, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_finish (&hmac_engine, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_sha384_incremental (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA384_HASH_LENGTH];
	uint8_t expected[] = {
		0xd3,0x31,0xf1,0x53,0x07,0x7e,0xfb,0xad,0x73,0x8e,0xea,0x4f,0x3e,0x0c,0x5d,0x3f,
		0x6b,0x60,0x4d,0x7b,0x32,0xb6,0xa2,0xe8,0xb0,0xeb,0x4e,0x4e,0x7f,0xc9,0x52,0x7b,
		0xc6,0x04,0x44,0xf2,0x04,0x7e,0xac,0xc1,0xec,0x88,0x0b,0xff,0xd0,0xb1,0xc1,0xf2
	};
	struct hmac_engine hmac_engine;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA384, key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_update (&hmac_engine, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_finish (&hmac_engine, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_sha384_incremental_large_key (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[SHA384_BLOCK_SIZE + 1];
	uint8_t hmac[SHA384_HASH_LENGTH];
	uint8_t expected[] = {
		0xf8,0xa1,0x45,0x7e,0x62,0xdf,0x77,0xff,0x48,0x98,0xf4,0xc6,0x3b,0xa3,0x45,0x29,
		0x3b,0x1e,0x50,0x5c,0x90,0x9c,0xd3,0x00,0x70,0xc9,0x90,0x18,0xe2,0xa1,0x3f,0xec,
		0x54,0xaf,0x70,0x65,0xc5,0x3b,0x97,0xf7,0x63,0x30,0x9e,0x28,0xd1,0xcf,0x1f,0x0f
	};
	struct hmac_engine hmac_engine;
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (key); i++) {
		key[i] = i;
	}

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA384, key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_update (&hmac_engine, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_finish (&hmac_engine, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_sha512_incremental (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA512_HASH_LENGTH];
	uint8_t expected[] = {
		0x39,0xb8,0x29,0x9b,0x43,0x30,0xcb,0x1e,0x8b,0x51,0xfa,0xcb,0x76,0x79,0xaf,0x47,
		0xea,0x35,0xbf,0xea,0xb9,0x1b,0x34,0xd0,0x9e,0x0a,0xac,0xc9,0xde,0x64,0x80,0x60,
		0x29,0x8d,0x86,0xd5,0x47,0x9d,0x4e,0xb5,0x68,0xdf,0xe0,0xea,0xb6,0x2c,0x0e,0x4a,
		0x47,0x90,0x7e,0x28,0x09,0xb8,0x4b,0x21,0xdd,0x6b,0xc7,0x41,0xca,0x09,0x00,0x3a
	};
	struct hmac_engine hmac_engine;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA512, key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_update (&hmac_engine, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_finish (&hmac_engine, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_sha512_incremental_large_key (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[SHA512_BLOCK_SIZE + 1];
	uint8_t hmac[SHA512_HASH_LENGTH];
	uint8_t expected[] = {
		0x4b,0xf9,0x6c,0x4d,0x3d,0x7f,0xac,0x2f,0x10,0x48,0xc2,0x96,0x78,0xe1,0x07,0x95,
		0x33,0xa1,0x47,0x37,0x5b,0x1e,0xdd,0x2d,0x5f,0xa4,0xbc,0xf6,0x22,0x40,0x9f,0x96,
		0x4b,0x54,0x59,0xab,0xaa,0x6f,0x7b,0x58,0x56,0x14,0xe1,0x78,0x6b,0x0e,0xd8,0xf7,
		0x75,0x45,0xcb,0x90,0x1d,0xd6,0xd6,0x12,0xc2,0x33,0xb2,0x53,0xb3,0x17,0x05,0x5d
	};
	struct hmac_engine hmac_engine;
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (key); i++) {
		key[i] = i;
	}

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA512, key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_update (&hmac_engine, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_finish (&hmac_engine, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_cancel (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA1_HASH_LENGTH];
	struct hmac_engine hmac_engine;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA1, key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	hash_hmac_cancel (&hmac_engine);

	status = hash_hmac_update (&hmac_engine, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	status = hash_hmac_finish (&hmac_engine, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_init_null (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	struct hmac_engine hmac_engine;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (NULL, &engine.base, HMAC_SHA1, key, sizeof (key));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = hash_hmac_init (&hmac_engine, NULL, HMAC_SHA1, key, sizeof (key));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA1, NULL, sizeof (key));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA1, key, 0);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_init_unknown (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	struct hmac_engine hmac_engine;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, (enum hmac_hash) 4, key, sizeof (key));
	CuAssertIntEquals (test, HASH_ENGINE_UNKNOWN_HASH, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_init_error (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	struct hmac_engine hmac_engine;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha1, &engine, 0);

	status |= mock_expect (&engine.mock, engine.base.update, &engine, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA1_BLOCK_SIZE));
	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA1, key, sizeof (key));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_test_hmac_init_sha1_large_key_error (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;
	uint8_t key[SHA1_BLOCK_SIZE + 1];
	struct hmac_engine hmac_engine;
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (key); i++) {
		key[i] = i;
	}

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.calculate_sha1, &engine,
		HASH_ENGINE_SHA1_FAILED, MOCK_ARG (key), MOCK_ARG (sizeof (key)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA1, key, sizeof (key));
	CuAssertIntEquals (test, HASH_ENGINE_SHA1_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_test_hmac_init_sha256_large_key_error (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;
	uint8_t key[SHA256_BLOCK_SIZE + 1];
	struct hmac_engine hmac_engine;
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (key); i++) {
		key[i] = i;
	}

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.calculate_sha256, &engine,
		HASH_ENGINE_SHA256_FAILED, MOCK_ARG (key), MOCK_ARG (sizeof (key)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA256, key, sizeof (key));
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_test_hmac_init_sha384_large_key_error (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;
	uint8_t key[SHA384_BLOCK_SIZE + 1];
	struct hmac_engine hmac_engine;
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (key); i++) {
		key[i] = i;
	}

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.calculate_sha384, &engine,
		HASH_ENGINE_SHA384_FAILED, MOCK_ARG (key), MOCK_ARG (sizeof (key)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA384, key, sizeof (key));
	CuAssertIntEquals (test, HASH_ENGINE_SHA384_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_test_hmac_init_sha512_large_key_error (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;
	uint8_t key[SHA512_BLOCK_SIZE + 1];
	struct hmac_engine hmac_engine;
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (key); i++) {
		key[i] = i;
	}

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.calculate_sha512, &engine,
		HASH_ENGINE_SHA512_FAILED, MOCK_ARG (key), MOCK_ARG (sizeof (key)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA512, key, sizeof (key));
	CuAssertIntEquals (test, HASH_ENGINE_SHA512_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_test_hmac_update_null (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	struct hmac_engine hmac_engine;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA1, key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_update (NULL, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = hash_hmac_update (&hmac_engine, NULL, strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_finish_null (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA1_HASH_LENGTH];
	struct hmac_engine hmac_engine;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA1, key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_update (&hmac_engine, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_finish (NULL, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = hash_hmac_finish (&hmac_engine, NULL, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_finish_sha1_small_buffer (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA1_HASH_LENGTH];
	uint8_t expected[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f
	};
	struct hmac_engine hmac_engine;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA1, key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_update (&hmac_engine, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_finish (&hmac_engine, hmac, sizeof (hmac) - 1);
	CuAssertIntEquals (test, HASH_ENGINE_HASH_BUFFER_TOO_SMALL, status);

	status = hash_hmac_finish (&hmac_engine, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_finish_sha256_small_buffer (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA256_HASH_LENGTH];
	uint8_t expected[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	struct hmac_engine hmac_engine;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA256, key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_update (&hmac_engine, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_finish (&hmac_engine, hmac, sizeof (hmac) - 1);
	CuAssertIntEquals (test, HASH_ENGINE_HASH_BUFFER_TOO_SMALL, status);

	status = hash_hmac_finish (&hmac_engine, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_finish_sha384_small_buffer (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA384_HASH_LENGTH];
	uint8_t expected[] = {
		0xd3,0x31,0xf1,0x53,0x07,0x7e,0xfb,0xad,0x73,0x8e,0xea,0x4f,0x3e,0x0c,0x5d,0x3f,
		0x6b,0x60,0x4d,0x7b,0x32,0xb6,0xa2,0xe8,0xb0,0xeb,0x4e,0x4e,0x7f,0xc9,0x52,0x7b,
		0xc6,0x04,0x44,0xf2,0x04,0x7e,0xac,0xc1,0xec,0x88,0x0b,0xff,0xd0,0xb1,0xc1,0xf2
	};
	struct hmac_engine hmac_engine;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA384, key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_update (&hmac_engine, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_finish (&hmac_engine, hmac, sizeof (hmac) - 1);
	CuAssertIntEquals (test, HASH_ENGINE_HASH_BUFFER_TOO_SMALL, status);

	status = hash_hmac_finish (&hmac_engine, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_finish_sha512_small_buffer (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA512_HASH_LENGTH];
	uint8_t expected[] = {
		0x39,0xb8,0x29,0x9b,0x43,0x30,0xcb,0x1e,0x8b,0x51,0xfa,0xcb,0x76,0x79,0xaf,0x47,
		0xea,0x35,0xbf,0xea,0xb9,0x1b,0x34,0xd0,0x9e,0x0a,0xac,0xc9,0xde,0x64,0x80,0x60,
		0x29,0x8d,0x86,0xd5,0x47,0x9d,0x4e,0xb5,0x68,0xdf,0xe0,0xea,0xb6,0x2c,0x0e,0x4a,
		0x47,0x90,0x7e,0x28,0x09,0xb8,0x4b,0x21,0xdd,0x6b,0xc7,0x41,0xca,0x09,0x00,0x3a
	};
	struct hmac_engine hmac_engine;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA512, key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_update (&hmac_engine, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_finish (&hmac_engine, hmac, sizeof (hmac) - 1);
	CuAssertIntEquals (test, HASH_ENGINE_HASH_BUFFER_TOO_SMALL, status);

	status = hash_hmac_finish (&hmac_engine, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_finish_inner_hash_error (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA1_HASH_LENGTH];
	struct hmac_engine hmac_engine;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha1, &engine, 0);
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA1_BLOCK_SIZE));

	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG (message),
		MOCK_ARG (strlen (message)));

	status |= mock_expect (&engine.mock, engine.base.finish, &engine, HASH_ENGINE_FINISH_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA1, key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_update (&hmac_engine, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_finish (&hmac_engine, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_test_hmac_finish_outer_init_error (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA1_HASH_LENGTH];
	struct hmac_engine hmac_engine;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha1, &engine, 0);
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA1_BLOCK_SIZE));

	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG (message),
		MOCK_ARG (strlen (message)));

	status |= mock_expect (&engine.mock, engine.base.finish, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));

	status |= mock_expect (&engine.mock, engine.base.start_sha1, &engine,
		HASH_ENGINE_START_SHA1_FAILED);
	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA1, key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_update (&hmac_engine, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_finish (&hmac_engine, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA1_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_test_hmac_finish_outer_key_error (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA1_HASH_LENGTH];
	struct hmac_engine hmac_engine;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha1, &engine, 0);
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA1_BLOCK_SIZE));

	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG (message),
		MOCK_ARG (strlen (message)));

	status |= mock_expect (&engine.mock, engine.base.finish, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));

	status |= mock_expect (&engine.mock, engine.base.start_sha1, &engine, 0);

	status |= mock_expect (&engine.mock, engine.base.update, &engine, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA1_BLOCK_SIZE));
	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA1, key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_update (&hmac_engine, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_finish (&hmac_engine, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_test_hmac_finish_outer_update_error (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA1_HASH_LENGTH];
	struct hmac_engine hmac_engine;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha1, &engine, 0);
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA1_BLOCK_SIZE));

	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG (message),
		MOCK_ARG (strlen (message)));

	status |= mock_expect (&engine.mock, engine.base.finish, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));

	status |= mock_expect (&engine.mock, engine.base.start_sha1, &engine, 0);

	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA1_BLOCK_SIZE));

	status |= mock_expect (&engine.mock, engine.base.update, &engine, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA1_HASH_LENGTH));
	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA1, key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_update (&hmac_engine, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_finish (&hmac_engine, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_test_hmac_finish_outer_hash_error (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA1_HASH_LENGTH];
	struct hmac_engine hmac_engine;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha1, &engine, 0);
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA1_BLOCK_SIZE));

	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG (message),
		MOCK_ARG (strlen (message)));

	status |= mock_expect (&engine.mock, engine.base.finish, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_HASH_LENGTH));

	status |= mock_expect (&engine.mock, engine.base.start_sha1, &engine, 0);

	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA1_BLOCK_SIZE));

	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA1_HASH_LENGTH));

	status |= mock_expect (&engine.mock, engine.base.finish, &engine, HASH_ENGINE_FINISH_FAILED,
		MOCK_ARG (hmac), MOCK_ARG (SHA1_HASH_LENGTH));
	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA1, key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_update (&hmac_engine, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_finish (&hmac_engine, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_test_hmac_cancel_null (CuTest *test)
{
	TEST_START;

	hash_hmac_cancel (NULL);
}

static void hash_test_hmac_sha1 (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA1_HASH_LENGTH];
	uint8_t expected[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f
	};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_generate_hmac (&engine.base, key, sizeof (key), (uint8_t*) message,
		strlen (message), HMAC_SHA1, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_sha1_large_key (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[SHA1_BLOCK_SIZE + 1];
	uint8_t hmac[SHA1_HASH_LENGTH];
	uint8_t expected[] = {
		0x19,0x75,0xda,0x73,0x05,0xeb,0xd1,0x29,0x3a,0x90,0xc8,0x36,0xe1,0xed,0x76,0x7f,
		0xa3,0x67,0x51,0x31
	};
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (key); i++) {
		key[i] = i;
	}

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_generate_hmac (&engine.base, key, sizeof (key), (uint8_t*) message,
		strlen (message), HMAC_SHA1, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_sha1_test_key (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t hmac[SHA1_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_generate_hmac (&engine.base, SHA1_HMAC_KEY, SHA1_HASH_LENGTH, (uint8_t*) message,
		strlen (message), HMAC_SHA1, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_TEST_HMAC, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_sha256 (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA256_HASH_LENGTH];
	uint8_t expected[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_generate_hmac (&engine.base, key, sizeof (key), (uint8_t*) message,
		strlen (message), HMAC_SHA256, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_sha256_large_key (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[SHA256_BLOCK_SIZE + 1];
	uint8_t hmac[SHA256_HASH_LENGTH];
	uint8_t expected[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (key); i++) {
		key[i] = i;
	}

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_generate_hmac (&engine.base, key, sizeof (key), (uint8_t*) message,
		strlen (message), HMAC_SHA256, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_sha256_test_key (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t hmac[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_generate_hmac (&engine.base, SHA256_HMAC_KEY, SHA256_HASH_LENGTH,
		(uint8_t*) message, strlen (message), HMAC_SHA256, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_TEST_HMAC, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_sha384 (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA384_HASH_LENGTH];
	uint8_t expected[] = {
		0xd3,0x31,0xf1,0x53,0x07,0x7e,0xfb,0xad,0x73,0x8e,0xea,0x4f,0x3e,0x0c,0x5d,0x3f,
		0x6b,0x60,0x4d,0x7b,0x32,0xb6,0xa2,0xe8,0xb0,0xeb,0x4e,0x4e,0x7f,0xc9,0x52,0x7b,
		0xc6,0x04,0x44,0xf2,0x04,0x7e,0xac,0xc1,0xec,0x88,0x0b,0xff,0xd0,0xb1,0xc1,0xf2
	};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_generate_hmac (&engine.base, key, sizeof (key), (uint8_t*) message,
		strlen (message), HMAC_SHA384, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_sha384_large_key (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[SHA384_BLOCK_SIZE + 1];
	uint8_t hmac[SHA384_HASH_LENGTH];
	uint8_t expected[] = {
		0xf8,0xa1,0x45,0x7e,0x62,0xdf,0x77,0xff,0x48,0x98,0xf4,0xc6,0x3b,0xa3,0x45,0x29,
		0x3b,0x1e,0x50,0x5c,0x90,0x9c,0xd3,0x00,0x70,0xc9,0x90,0x18,0xe2,0xa1,0x3f,0xec,
		0x54,0xaf,0x70,0x65,0xc5,0x3b,0x97,0xf7,0x63,0x30,0x9e,0x28,0xd1,0xcf,0x1f,0x0f
	};
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (key); i++) {
		key[i] = i;
	}

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_generate_hmac (&engine.base, key, sizeof (key), (uint8_t*) message,
		strlen (message), HMAC_SHA384, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_sha384_test_key (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t hmac[SHA384_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_generate_hmac (&engine.base, SHA384_HMAC_KEY, SHA384_HASH_LENGTH,
		(uint8_t*) message, strlen (message), HMAC_SHA384, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_TEST_HMAC, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_sha512 (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA512_HASH_LENGTH];
	uint8_t expected[] = {
		0x39,0xb8,0x29,0x9b,0x43,0x30,0xcb,0x1e,0x8b,0x51,0xfa,0xcb,0x76,0x79,0xaf,0x47,
		0xea,0x35,0xbf,0xea,0xb9,0x1b,0x34,0xd0,0x9e,0x0a,0xac,0xc9,0xde,0x64,0x80,0x60,
		0x29,0x8d,0x86,0xd5,0x47,0x9d,0x4e,0xb5,0x68,0xdf,0xe0,0xea,0xb6,0x2c,0x0e,0x4a,
		0x47,0x90,0x7e,0x28,0x09,0xb8,0x4b,0x21,0xdd,0x6b,0xc7,0x41,0xca,0x09,0x00,0x3a
	};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_generate_hmac (&engine.base, key, sizeof (key), (uint8_t*) message,
		strlen (message), HMAC_SHA512, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_sha512_large_key (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[SHA512_BLOCK_SIZE + 1];
	uint8_t hmac[SHA512_HASH_LENGTH];
	uint8_t expected[] = {
		0x4b,0xf9,0x6c,0x4d,0x3d,0x7f,0xac,0x2f,0x10,0x48,0xc2,0x96,0x78,0xe1,0x07,0x95,
		0x33,0xa1,0x47,0x37,0x5b,0x1e,0xdd,0x2d,0x5f,0xa4,0xbc,0xf6,0x22,0x40,0x9f,0x96,
		0x4b,0x54,0x59,0xab,0xaa,0x6f,0x7b,0x58,0x56,0x14,0xe1,0x78,0x6b,0x0e,0xd8,0xf7,
		0x75,0x45,0xcb,0x90,0x1d,0xd6,0xd6,0x12,0xc2,0x33,0xb2,0x53,0xb3,0x17,0x05,0x5d
	};
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (key); i++) {
		key[i] = i;
	}

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_generate_hmac (&engine.base, key, sizeof (key), (uint8_t*) message,
		strlen (message), HMAC_SHA512, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_sha512_test_key (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t hmac[SHA512_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_generate_hmac (&engine.base, SHA512_HMAC_KEY, SHA512_HASH_LENGTH,
		(uint8_t*) message, strlen (message), HMAC_SHA512, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_TEST_HMAC, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_unknown (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_generate_hmac (&engine.base, key, sizeof (key), (uint8_t*) message,
		strlen (message), (enum hmac_hash) 4, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_UNKNOWN_HASH, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_null (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_generate_hmac (NULL, key, sizeof (key), (uint8_t*) message, strlen (message),
		HMAC_SHA256, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = hash_generate_hmac (&engine.base, NULL, sizeof (key), (uint8_t*) message,
		strlen (message), HMAC_SHA256, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = hash_generate_hmac (&engine.base, key, 0, (uint8_t*) message, strlen (message),
		HMAC_SHA256, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = hash_generate_hmac (&engine.base, key, sizeof (key), NULL, strlen (message),
		HMAC_SHA256, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = hash_generate_hmac (&engine.base, key, sizeof (key), (uint8_t*) message,
		strlen (message), HMAC_SHA256, NULL, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hash_generate_hmac_start_error (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha1, &engine,
		HASH_ENGINE_START_SHA1_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = hash_generate_hmac (&engine.base, key, sizeof (key), (uint8_t*) message,
		strlen (message), HMAC_SHA1, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA1_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_test_hash_generate_hmac_init_error (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha1, &engine, 0);

	status |= mock_expect (&engine.mock, engine.base.update, &engine, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA1_BLOCK_SIZE));
	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	status = hash_generate_hmac (&engine.base, key, sizeof (key), (uint8_t*) message,
		strlen (message), HMAC_SHA1, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_test_hash_generate_hmac_update_error (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha1, &engine, 0);

	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA1_BLOCK_SIZE));

	status |= mock_expect (&engine.mock, engine.base.update, &engine, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG (message), MOCK_ARG (strlen (message)));
	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	status = hash_generate_hmac (&engine.base, key, sizeof (key), (uint8_t*) message,
		strlen (message), HMAC_SHA1, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_test_hash_generate_hmac_finish_error (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha1, &engine, 0);

	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA1_BLOCK_SIZE));

	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG (message),
		MOCK_ARG (strlen (message)));

	status |= mock_expect (&engine.mock, engine.base.finish, &engine, HASH_ENGINE_FINISH_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	status = hash_generate_hmac (&engine.base, key, sizeof (key), (uint8_t*) message,
		strlen (message), HMAC_SHA1, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_test_hash_generate_hmac_sha1_small_buffer (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA1_HASH_LENGTH - 1];

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha1, &engine, 0);

	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA1_BLOCK_SIZE));
	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	status = hash_generate_hmac (&engine.base, key, sizeof (key), (uint8_t*) message,
		strlen (message), HMAC_SHA1, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_HASH_BUFFER_TOO_SMALL, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_test_hash_generate_hmac_sha256_small_buffer (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA256_HASH_LENGTH - 1];

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha256, &engine, 0);

	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_BLOCK_SIZE));
	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	status = hash_generate_hmac (&engine.base, key, sizeof (key), (uint8_t*) message,
		strlen (message), HMAC_SHA256, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_HASH_BUFFER_TOO_SMALL, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_test_hash_generate_hmac_sha384_small_buffer (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA384_HASH_LENGTH - 1];

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha384, &engine, 0);

	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA384_BLOCK_SIZE));
	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	status = hash_generate_hmac (&engine.base, key, sizeof (key), (uint8_t*) message,
		strlen (message), HMAC_SHA384, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_HASH_BUFFER_TOO_SMALL, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_test_hash_generate_hmac_sha512_small_buffer (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA512_HASH_LENGTH - 1];

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha512, &engine, 0);

	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA512_BLOCK_SIZE));
	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	status = hash_generate_hmac (&engine.base, key, sizeof (key), (uint8_t*) message,
		strlen (message), HMAC_SHA512, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_HASH_BUFFER_TOO_SMALL, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_test_start_new_hash_sha1 (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];
	uint8_t expected[] = {
		0x64,0x0a,0xb2,0xba,0xe0,0x7b,0xed,0xc4,0xc1,0x63,0xf6,0x79,0xa7,0x46,0xf7,0xab,
		0x7f,0xb5,0xd1,0xfa
	};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_start_new_hash (&engine.base, HASH_TYPE_SHA1);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_start_new_hash_sha256 (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];
	uint8_t expected[] = {
		0x53,0x2e,0xaa,0xbd,0x95,0x74,0x88,0x0d,0xbf,0x76,0xb9,0xb8,0xcc,0x00,0x83,0x2c,
		0x20,0xa6,0xec,0x11,0x3d,0x68,0x22,0x99,0x55,0x0d,0x7a,0x6e,0x0f,0x34,0x5e,0x25
	};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_start_new_hash (&engine.base, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_start_new_hash_sha384 (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA384_HASH_LENGTH];
	uint8_t expected[] = {
		0x7b,0x8f,0x46,0x54,0x07,0x6b,0x80,0xeb,0x96,0x39,0x11,0xf1,0x9c,0xfa,0xd1,0xaa,
		0xf4,0x28,0x5e,0xd4,0x8e,0x82,0x6f,0x6c,0xde,0x1b,0x01,0xa7,0x9a,0xa7,0x3f,0xad,
		0xb5,0x44,0x6e,0x66,0x7f,0xc4,0xf9,0x04,0x17,0x78,0x2c,0x91,0x27,0x05,0x40,0xf3
	};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_start_new_hash (&engine.base, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_start_new_hash_sha512 (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA512_HASH_LENGTH];
	uint8_t expected[] = {
		0xc6,0xee,0x9e,0x33,0xcf,0x5c,0x67,0x15,0xa1,0xd1,0x48,0xfd,0x73,0xf7,0x31,0x88,
		0x84,0xb4,0x1a,0xdc,0xb9,0x16,0x02,0x1e,0x2b,0xc0,0xe8,0x00,0xa5,0xc5,0xdd,0x97,
		0xf5,0x14,0x21,0x78,0xf6,0xae,0x88,0xc8,0xfd,0xd9,0x8e,0x1a,0xfb,0x0c,0xe4,0xc8,
		0xd2,0xc5,0x4b,0x5f,0x37,0xb3,0x0b,0x7d,0xa1,0x99,0x7b,0xb3,0x3b,0x0b,0x8a,0x31
	};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_start_new_hash (&engine.base, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_start_new_hash_unknown (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_start_new_hash (&engine.base, (enum hash_type) 10);
	CuAssertIntEquals (test, HASH_ENGINE_UNKNOWN_HASH, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_start_new_hash_null (CuTest *test)
{
	int status;

	TEST_START;

	status = hash_start_new_hash (NULL, HASH_TYPE_SHA1);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);
}

static void hash_test_start_new_hash_sha1_error (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha1, &engine,
		HASH_ENGINE_START_SHA1_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = hash_start_new_hash (&engine.base, HASH_TYPE_SHA1);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA1_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_test_start_new_hash_sha256_error (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha256, &engine,
		HASH_ENGINE_START_SHA256_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = hash_start_new_hash (&engine.base, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_test_start_new_hash_sha384_error (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha384, &engine,
		HASH_ENGINE_START_SHA384_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = hash_start_new_hash (&engine.base, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA384_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_test_start_new_hash_sha512_error (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha512, &engine,
		HASH_ENGINE_START_SHA512_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = hash_start_new_hash (&engine.base, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA512_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_test_calculate_sha1 (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];
	uint8_t expected[] = {
		0x64,0x0a,0xb2,0xba,0xe0,0x7b,0xed,0xc4,0xc1,0x63,0xf6,0x79,0xa7,0x46,0xf7,0xab,
		0x7f,0xb5,0xd1,0xfa
	};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_calculate (&engine.base, HASH_TYPE_SHA1, (uint8_t*) message, strlen (message),
		hash, sizeof (hash));
	CuAssertIntEquals (test, SHA1_HASH_LENGTH, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_calculate_sha256 (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];
	uint8_t expected[] = {
		0x53,0x2e,0xaa,0xbd,0x95,0x74,0x88,0x0d,0xbf,0x76,0xb9,0xb8,0xcc,0x00,0x83,0x2c,
		0x20,0xa6,0xec,0x11,0x3d,0x68,0x22,0x99,0x55,0x0d,0x7a,0x6e,0x0f,0x34,0x5e,0x25
	};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_calculate (&engine.base, HASH_TYPE_SHA256, (uint8_t*) message, strlen (message),
		hash, sizeof (hash));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_calculate_sha384 (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA384_HASH_LENGTH];
	uint8_t expected[] = {
		0x7b,0x8f,0x46,0x54,0x07,0x6b,0x80,0xeb,0x96,0x39,0x11,0xf1,0x9c,0xfa,0xd1,0xaa,
		0xf4,0x28,0x5e,0xd4,0x8e,0x82,0x6f,0x6c,0xde,0x1b,0x01,0xa7,0x9a,0xa7,0x3f,0xad,
		0xb5,0x44,0x6e,0x66,0x7f,0xc4,0xf9,0x04,0x17,0x78,0x2c,0x91,0x27,0x05,0x40,0xf3
	};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_calculate (&engine.base, HASH_TYPE_SHA384, (uint8_t*) message, strlen (message),
		hash, sizeof (hash));
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_calculate_sha512 (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA512_HASH_LENGTH];
	uint8_t expected[] = {
		0xc6,0xee,0x9e,0x33,0xcf,0x5c,0x67,0x15,0xa1,0xd1,0x48,0xfd,0x73,0xf7,0x31,0x88,
		0x84,0xb4,0x1a,0xdc,0xb9,0x16,0x02,0x1e,0x2b,0xc0,0xe8,0x00,0xa5,0xc5,0xdd,0x97,
		0xf5,0x14,0x21,0x78,0xf6,0xae,0x88,0xc8,0xfd,0xd9,0x8e,0x1a,0xfb,0x0c,0xe4,0xc8,
		0xd2,0xc5,0x4b,0x5f,0x37,0xb3,0x0b,0x7d,0xa1,0x99,0x7b,0xb3,0x3b,0x0b,0x8a,0x31
	};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_calculate (&engine.base, HASH_TYPE_SHA512, (uint8_t*) message, strlen (message),
		hash, sizeof (hash));
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_calculate_unknown (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_calculate (&engine.base, (enum hash_type) 10, (uint8_t*) message,
		strlen (message), hash, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_UNKNOWN_HASH, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_calculate_null (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_calculate (NULL, HASH_TYPE_SHA1, (uint8_t*) message, strlen (message),
		hash, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = hash_calculate (&engine.base, HASH_TYPE_SHA1, NULL, strlen (message),
		hash, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = hash_calculate (&engine.base, HASH_TYPE_SHA1, (uint8_t*) message, strlen (message),
		NULL, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_calculate_sha1_small_buffer (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_calculate (&engine.base, HASH_TYPE_SHA1, (uint8_t*) message, strlen (message),
		hash, sizeof (hash) - 1);
	CuAssertIntEquals (test, HASH_ENGINE_HASH_BUFFER_TOO_SMALL, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_calculate_sha256_small_buffer (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_calculate (&engine.base, HASH_TYPE_SHA256, (uint8_t*) message, strlen (message),
		hash, sizeof (hash) - 1);
	CuAssertIntEquals (test, HASH_ENGINE_HASH_BUFFER_TOO_SMALL, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_calculate_sha384_small_buffer (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_calculate (&engine.base, HASH_TYPE_SHA384, (uint8_t*) message, strlen (message),
		hash, sizeof (hash) - 1);
	CuAssertIntEquals (test, HASH_ENGINE_HASH_BUFFER_TOO_SMALL, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_calculate_sha512_small_buffer (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_calculate (&engine.base, HASH_TYPE_SHA512, (uint8_t*) message, strlen (message),
		hash, sizeof (hash) - 1);
	CuAssertIntEquals (test, HASH_ENGINE_HASH_BUFFER_TOO_SMALL, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}


TEST_SUITE_START (hash);

TEST (hash_test_hmac_sha1_incremental);
TEST (hash_test_hmac_sha1_incremental_large_key);
TEST (hash_test_hmac_sha256_incremental);
TEST (hash_test_hmac_sha256_incremental_large_key);
TEST (hash_test_hmac_sha384_incremental);
TEST (hash_test_hmac_sha384_incremental_large_key);
TEST (hash_test_hmac_sha512_incremental);
TEST (hash_test_hmac_sha512_incremental_large_key);
TEST (hash_test_hmac_cancel);
TEST (hash_test_hmac_init_null);
TEST (hash_test_hmac_init_unknown);
TEST (hash_test_hmac_init_error);
TEST (hash_test_hmac_init_sha1_large_key_error);
TEST (hash_test_hmac_init_sha256_large_key_error);
TEST (hash_test_hmac_init_sha384_large_key_error);
TEST (hash_test_hmac_init_sha512_large_key_error);
TEST (hash_test_hmac_update_null);
TEST (hash_test_hmac_finish_null);
TEST (hash_test_hmac_finish_sha1_small_buffer);
TEST (hash_test_hmac_finish_sha256_small_buffer);
TEST (hash_test_hmac_finish_sha384_small_buffer);
TEST (hash_test_hmac_finish_sha512_small_buffer);
TEST (hash_test_hmac_finish_inner_hash_error);
TEST (hash_test_hmac_finish_outer_init_error);
TEST (hash_test_hmac_finish_outer_key_error);
TEST (hash_test_hmac_finish_outer_update_error);
TEST (hash_test_hmac_finish_outer_hash_error);
TEST (hash_test_hmac_cancel_null);
TEST (hash_test_hmac_sha1);
TEST (hash_test_hmac_sha1_large_key);
TEST (hash_test_hmac_sha1_test_key);
TEST (hash_test_hmac_sha256);
TEST (hash_test_hmac_sha256_large_key);
TEST (hash_test_hmac_sha256_test_key);
TEST (hash_test_hmac_sha384);
TEST (hash_test_hmac_sha384_large_key);
TEST (hash_test_hmac_sha384_test_key);
TEST (hash_test_hmac_sha512);
TEST (hash_test_hmac_sha512_large_key);
TEST (hash_test_hmac_sha512_test_key);
TEST (hash_test_hmac_unknown);
TEST (hash_test_hmac_null);
TEST (hash_test_hash_generate_hmac_start_error);
TEST (hash_test_hash_generate_hmac_init_error);
TEST (hash_test_hash_generate_hmac_update_error);
TEST (hash_test_hash_generate_hmac_finish_error);
TEST (hash_test_hash_generate_hmac_sha1_small_buffer);
TEST (hash_test_hash_generate_hmac_sha256_small_buffer);
TEST (hash_test_hash_generate_hmac_sha384_small_buffer);
TEST (hash_test_hash_generate_hmac_sha512_small_buffer);
TEST (hash_test_start_new_hash_sha1);
TEST (hash_test_start_new_hash_sha256);
TEST (hash_test_start_new_hash_sha384);
TEST (hash_test_start_new_hash_sha512);
TEST (hash_test_start_new_hash_unknown);
TEST (hash_test_start_new_hash_null);
TEST (hash_test_start_new_hash_sha1_error);
TEST (hash_test_start_new_hash_sha256_error);
TEST (hash_test_start_new_hash_sha384_error);
TEST (hash_test_start_new_hash_sha512_error);
TEST (hash_test_calculate_sha1);
TEST (hash_test_calculate_sha256);
TEST (hash_test_calculate_sha384);
TEST (hash_test_calculate_sha512);
TEST (hash_test_calculate_unknown);
TEST (hash_test_calculate_null);
TEST (hash_test_calculate_sha1_small_buffer);
TEST (hash_test_calculate_sha256_small_buffer);
TEST (hash_test_calculate_sha384_small_buffer);
TEST (hash_test_calculate_sha512_small_buffer);

TEST_SUITE_END;
