// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "attestation/aux_attestation.h"
#include "common/array_size.h"
#include "testing/mock/asn1/x509_mock.h"
#include "testing/mock/keystore/keystore_mock.h"
#include "testing/mock/crypto/rsa_mock.h"
#include "testing/mock/crypto/ecc_mock.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/crypto/rng_mock.h"
#include "testing/engines/rsa_testing_engine.h"
#include "testing/engines/ecc_testing_engine.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/engines/x509_testing_engine.h"
#include "testing/engines/rng_testing_engine.h"
#include "testing/asn1/x509_testing.h"
#include "testing/crypto/rsa_testing.h"
#include "testing/crypto/ecc_testing.h"
#include "testing/riot/riot_core_testing.h"


TEST_SUITE_LABEL ("aux_attestation");


/**
 * The random seed for key derivation.
 */
const uint8_t KEY_SEED[] = {
	0xf9,0xf6,0x4e,0xa9,0xe3,0xcb,0x5f,0x5b,0xb0,0x80,0x25,0x5e,0xfa,0xfd,0xa5,0x8a,
	0x9a,0x1c,0xe6,0xa3,0xb9,0x73,0x16,0xb5,0x9b,0x69,0xc3,0x36,0xf2,0x05,0x1e,0x4b
};

const size_t KEY_SEED_LEN = sizeof (KEY_SEED);

/**
 * The random seed encrypted with the RSA3k public key using OAEP SHA1 padding.
 */
const uint8_t KEY_SEED_ENCRYPT_OAEP[] = {
	0x62,0x41,0xfc,0x32,0x40,0x72,0x3d,0x7f,0x56,0xc5,0xb0,0xe2,0xe4,0x51,0x51,0xc3,
	0x34,0xb2,0x79,0x65,0xf6,0x79,0x44,0xe7,0x8f,0xb7,0x61,0xae,0x57,0xcc,0x83,0xa9,
	0x6b,0x77,0x8c,0xc0,0xd5,0x1a,0x5c,0x63,0x0c,0x91,0x00,0xfa,0x03,0xdb,0xde,0x0d,
	0xaa,0x64,0xb8,0xb5,0x24,0x00,0x67,0xbe,0xcf,0xf8,0x47,0x6b,0x7c,0x88,0xdb,0x5e,
	0x3a,0x1e,0xb9,0x7a,0x99,0xb5,0x6f,0xb2,0xe3,0x52,0x8e,0x4c,0x6a,0xd9,0x7d,0x1c,
	0x54,0x56,0x0d,0xf4,0xeb,0xf2,0xfa,0x98,0xa8,0xb5,0x66,0x2b,0x87,0xec,0xfb,0x86,
	0x45,0xf0,0xba,0xcc,0xbb,0x2b,0xbe,0x62,0xa4,0x1c,0xcd,0x5e,0xc1,0x6b,0xcf,0x9d,
	0x93,0xe4,0xc5,0x67,0xd3,0x2c,0x95,0x97,0x07,0xda,0x12,0xaf,0x5c,0x46,0x2f,0x43,
	0xba,0xa4,0x07,0x7f,0xa1,0x59,0x57,0x15,0x39,0xd4,0xec,0x2e,0x14,0xf1,0xc3,0x61,
	0x80,0xee,0x57,0x1e,0x99,0xc1,0xb0,0x1d,0x7f,0xf6,0xd8,0xf5,0xaf,0x26,0x36,0x22,
	0x40,0xae,0xf0,0x53,0x94,0x6d,0x66,0xbd,0xcd,0xf2,0xba,0x2a,0x5d,0x7b,0x6d,0xe0,
	0x32,0x94,0x16,0xf5,0xe7,0xc4,0xdc,0xc7,0x52,0x11,0x66,0xb5,0xc1,0x8c,0x74,0x9c,
	0x28,0x33,0x9d,0x6c,0x49,0x31,0x4d,0x99,0xf2,0xef,0x8d,0x2a,0x23,0x4b,0x1f,0xfb,
	0x30,0xd4,0x37,0x06,0xe3,0x2e,0x10,0xdd,0x2b,0xcf,0x85,0xf9,0xb2,0x43,0xde,0x83,
	0x75,0xac,0x8d,0xc4,0x53,0xa6,0xd5,0x62,0x3c,0x6f,0xbc,0x9b,0x88,0x14,0xef,0x0c,
	0x78,0x15,0x79,0xdd,0x31,0xae,0xc7,0x7b,0x90,0x2b,0xae,0x7f,0xb3,0xf0,0x24,0xe1,
	0xa0,0xd6,0x4e,0xc3,0x0b,0x0c,0xd4,0x4c,0xf1,0x4e,0x7b,0x6e,0x05,0x5c,0x49,0xc1,
	0x65,0x66,0x41,0xf7,0xab,0x8a,0xab,0x84,0xf3,0x5b,0x82,0xcd,0xcb,0x5d,0x24,0x11,
	0x3b,0x13,0xb0,0x2a,0x58,0x83,0x1f,0x0c,0xaf,0x7e,0x0b,0xcb,0x04,0x9b,0x66,0x25,
	0x91,0x7a,0xcb,0x38,0x44,0x40,0x2d,0x62,0x3a,0x37,0x4a,0x7a,0x0e,0x64,0x08,0x63,
	0x0f,0x47,0x89,0x13,0xfc,0x3a,0x83,0x3a,0xe2,0x18,0x45,0x9a,0x08,0x4c,0x97,0x8e,
	0x71,0x00,0x54,0x6f,0x86,0x62,0x8c,0xcd,0x1d,0xb1,0x27,0xfb,0xc7,0xf6,0xa8,0xbd,
	0xcf,0x9d,0xba,0xf2,0x09,0x55,0xf0,0x6b,0x77,0x62,0x03,0xf5,0x98,0x4e,0xf1,0xca,
	0xa0,0x3b,0x6f,0x47,0xca,0x17,0x77,0x68,0x5c,0xf7,0xae,0x8d,0x63,0xa9,0x78,0x84
};

const size_t KEY_SEED_ENCRYPT_OAEP_LEN = sizeof (KEY_SEED_ENCRYPT_OAEP);

/**
 * The random seed encrypted with the RSA3k public key using OAEP SHA256 padding.
 */
const uint8_t KEY_SEED_ENCRYPT_OAEP_SHA256[] = {
	0x71,0x6c,0x41,0xa3,0x5f,0xfa,0x51,0x7d,0x37,0x63,0x38,0x53,0xad,0x43,0x57,0x88,
	0x24,0x60,0x9f,0xbf,0xd1,0x58,0xd4,0x9f,0x9b,0x03,0x5b,0x21,0xf1,0xb8,0x3f,0x28,
	0x2c,0xc0,0x63,0x01,0x9f,0x45,0x91,0xe4,0x2a,0x67,0xb9,0x64,0xeb,0xaf,0x26,0x58,
	0xef,0x1f,0x43,0x1b,0x9d,0xcd,0xbf,0x3f,0x92,0xcb,0xa2,0xd3,0xda,0x4b,0x4c,0x02,
	0x30,0xa0,0x00,0x00,0xff,0xfd,0x23,0x99,0xa7,0x89,0xc2,0x6e,0x4f,0x60,0x42,0x68,
	0xa7,0x5d,0xd1,0x7a,0x51,0x1b,0xa7,0xc0,0x09,0x40,0x42,0x4e,0xb9,0xb9,0xad,0xde,
	0x04,0x35,0x97,0xcd,0xcc,0x5f,0x71,0x50,0xb3,0xc3,0x97,0x99,0x38,0x82,0x9b,0x94,
	0xf9,0x7d,0xb2,0x96,0xc0,0x72,0x6b,0xac,0xf0,0x73,0x7c,0xd0,0x33,0x0d,0x1c,0xd2,
	0xa2,0x77,0xf0,0x74,0xd9,0xce,0x40,0x2c,0xde,0x65,0x0a,0xec,0xf9,0xe7,0x43,0xa7,
	0xee,0x90,0x7b,0x47,0xa1,0xd9,0xf1,0x9a,0xa0,0x48,0x28,0x04,0xe4,0x48,0x6f,0xb8,
	0x38,0x01,0xc6,0x15,0xd9,0xd5,0xa5,0x0a,0xed,0xb3,0x3f,0xf0,0xbc,0x9c,0xa6,0x1f,
	0x94,0x0e,0x15,0x0e,0x68,0x41,0x1b,0xcc,0x6a,0x5c,0x82,0x07,0x54,0xc0,0x31,0xbf,
	0xd4,0xfb,0x3c,0x71,0xb2,0xb7,0x99,0x3b,0x1c,0x7f,0x14,0x11,0x76,0x27,0x0b,0x5f,
	0x51,0x98,0xca,0x60,0xf2,0xce,0xae,0x26,0x51,0xa7,0x00,0xc5,0x4a,0xb7,0xc2,0xa3,
	0x16,0x36,0xcc,0x42,0x23,0x16,0x3c,0x3f,0x14,0xb6,0x0d,0x27,0xa3,0x87,0x94,0x7a,
	0x2b,0xbb,0xd6,0x47,0xb6,0x37,0x81,0xd7,0xd6,0xbe,0x65,0xed,0xa6,0xd2,0xd9,0xa6,
	0xfe,0xf5,0x95,0xef,0xae,0x92,0xf4,0xa6,0xc1,0xda,0x86,0x98,0xe4,0xbb,0x01,0x4f,
	0xba,0x02,0xe8,0x8f,0xda,0x54,0xe0,0x07,0x1c,0x89,0x60,0xf9,0xb0,0x16,0xd3,0x4b,
	0xf5,0x67,0xc1,0x9e,0x56,0x7f,0xda,0x43,0x22,0x0b,0xb6,0x1f,0x11,0x13,0x76,0x87,
	0xe9,0x1f,0x76,0x5a,0xdd,0xd9,0x79,0xdc,0x4e,0x20,0x42,0xe3,0xbe,0x60,0x80,0x50,
	0xd8,0xbd,0x74,0x7f,0xe9,0xa2,0x8c,0x19,0xaa,0xb0,0x0a,0xe2,0x01,0xb9,0xfc,0x49,
	0x2e,0xc2,0xaa,0x72,0x74,0x28,0x6d,0x44,0xfd,0xa2,0x76,0x64,0xf6,0x22,0x9c,0xc4,
	0x72,0x4d,0xcb,0x18,0x8b,0xa8,0x0d,0x1a,0xc1,0x79,0x1b,0x8a,0xa7,0x00,0x15,0x92,
	0x61,0xb6,0xc1,0xd7,0xbd,0x08,0x0a,0x43,0x07,0x8b,0xfb,0xa9,0xcb,0x69,0xa1,0x1c
};

const size_t KEY_SEED_ENCRYPT_OAEP_SHA256_LEN = sizeof (KEY_SEED_ENCRYPT_OAEP_SHA256);

/**
 * SHA256 hash of the seed.
 */
const uint8_t KEY_SEED_HASH[] = {
	0x36,0xd3,0xc2,0x37,0x5d,0x53,0x61,0xfa,0xa7,0x6b,0x4e,0xb8,0x74,0xcf,0xbe,0x16,
	0x20,0x82,0x6e,0xef,0x1d,0xb1,0x9c,0x05,0x38,0x16,0x92,0xd3,0xdc,0x98,0xd2,0x6e
};

const size_t KEY_SEED_HASH_LEN = sizeof (KEY_SEED_HASH);

/**
 * The value of i in the NIST SP800-108 KDF algorithm.
 */
const uint8_t NIST_KEY_DERIVE_I[] = {
	0x00,0x00,0x00,0x01
};

const size_t NIST_KEY_DERIVE_I_LEN = sizeof (NIST_KEY_DERIVE_I);

/**
 * The label for deriving the encryption key.
 */
const char ENCRYPTION_KEY_LABEL[] = "encryption key";

const size_t ENCRYPTION_KEY_LABEL_LEN = sizeof (ENCRYPTION_KEY_LABEL);

/**
 * The label for deriving the signing key.
 */
const char SIGNING_KEY_LABEL[] = "signing key";

const size_t SIGNING_KEY_LABEL_LEN = sizeof (SIGNING_KEY_LABEL);

/**
 * The value of L in the NIST SP800-108 KDF algorithm.
 */
const uint8_t NIST_KEY_DERIVE_L[] = {
	0x00,0x00,0x01,0x00
};

const size_t NIST_KEY_DERIVE_L_LEN = sizeof (NIST_KEY_DERIVE_L);

/**
 * The encryption key derived from the seed.  (Label=encryption key, Context=empty).
 */
const uint8_t ENCRYPTION_KEY[] = {
	0xf3,0x38,0xfa,0x33,0xd0,0xe7,0x4a,0xa8,0xf0,0x68,0xa9,0x57,0xbb,0xf4,0x73,0xad,
	0x2e,0x67,0x3f,0xf6,0xc3,0x1c,0x73,0x2f,0x07,0x92,0x3c,0x3f,0xdf,0x51,0xf7,0xf0
};

const size_t ENCRYPTION_KEY_LEN = sizeof (ENCRYPTION_KEY);

/**
 * The encryption key derived from the seed hash.  (Label=encryption key, Context=empty).
 */
const uint8_t ENCRYPTION_KEY_SEED_HASH[] = {
	0x2f,0x41,0x73,0x39,0x3e,0xa8,0x1d,0x3e,0x16,0xe1,0x8c,0xc2,0x7c,0xa0,0x45,0x28,
	0xce,0x86,0xea,0x2c,0xe0,0x40,0xbd,0xd0,0xd7,0xa3,0xcb,0x10,0x2a,0x9a,0x53,0x14
};

const size_t ENCRYPTION_KEY_SEED_HASH_LEN = sizeof (ENCRYPTION_KEY_SEED_HASH);

/**
 * The signing key derived from the seed.  (Label=signing key, Context=empty).
 */
const uint8_t SIGNING_KEY[] = {
	0x30,0xf4,0x4a,0x77,0x7a,0xd1,0x3d,0x71,0x33,0xb7,0x45,0x1f,0x3e,0x12,0x85,0xb3,
	0x28,0x32,0x20,0x03,0xce,0x27,0x70,0x65,0x0d,0x82,0x30,0x80,0xd0,0x53,0x28,0xb6
};

const size_t SIGNING_KEY_LEN = sizeof (SIGNING_KEY);

/**
 * The signing key derived from the seed hash.  (Label=signing key, Context=empty).
 */
const uint8_t SIGNING_KEY_SEED_HASH[] = {
	0xf8,0x35,0xb9,0xa1,0x6b,0xcd,0xbe,0xb5,0xb2,0x9f,0x1d,0x11,0xcd,0xee,0x24,0xc2,
	0x15,0x5a,0x8d,0x86,0xb6,0x61,0xfc,0x32,0xd2,0x2d,0x49,0x31,0x13,0xa9,0x92,0x68
};

const size_t SIGNING_KEY_SEED_HASH_LEN = sizeof (SIGNING_KEY_SEED_HASH);

/**
 * Data provided as the cipher text, though not actually encrypted with the key.
 */
const uint8_t CIPHER_TEXT[] = {
	0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99
};

const size_t CIPHER_TEXT_LEN = sizeof (CIPHER_TEXT);

/**
 * 64-byte Sealing policy value.
 */
const uint8_t SEALING_POLICY[][64] = {
	{
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0xf7,0x0e,0x27,0xc8,0xf0,0x0d,0x40,0x34,0xad,0xab,0x82,0x40,0x17,0x3e,0xd7,0x74,
		0xe4,0x4a,0xcb,0xd7,0x4d,0x0b,0x24,0xad,0x3d,0x4b,0x75,0x29,0x11,0x57,0x98,0x1e
	}
};

const size_t SEALING_POLICY_LEN = sizeof (SEALING_POLICY);

/**
 * HMAC (SIGNING_KEY, CIPHER_TEXT || SEALING_POLICY).
 */
const uint8_t PAYLOAD_HMAC[] = {
	0x7e,0xf2,0x81,0xe6,0x52,0x2c,0x99,0x4b,0x59,0x43,0xbd,0xd7,0x73,0xf0,0x0f,0x0d,
	0x8b,0xa0,0xbf,0x06,0xa6,0x9a,0x1d,0xc2,0xab,0x6e,0x18,0x5f,0x77,0x30,0x63,0x98
};

const size_t PAYLOAD_HMAC_LEN = sizeof (PAYLOAD_HMAC);

/**
 * HMAC (SIGNING_KEY_SEED_HASH, CIPHER_TEXT || SEALING_POLICY).
 */
const uint8_t PAYLOAD_HMAC_SEED_HASH[] = {
	0xa9,0x7b,0x62,0xa3,0xfd,0x42,0x39,0xf8,0xbc,0xd5,0xca,0x9f,0x64,0xac,0xf9,0x5f,
	0xc0,0x34,0x3d,0x14,0x3c,0x8a,0x24,0xad,0x03,0x86,0x8b,0x37,0x34,0xec,0xe5,0x6b
};

const size_t PAYLOAD_HMAC_SEED_HASH_LEN = sizeof (PAYLOAD_HMAC_SEED_HASH);

/**
 * 64-byte Sealing policy value with a SHA-384 digest.
 */
const uint8_t SEALING_POLICY_SHA384[][64] = {
	{
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0xa2,0x5c,0x43,0x12,0x86,0x71,0xbd,0x4b,0x49,0xc9,0x94,0x81,0x4f,0xda,0x51,0x39,
		0x9c,0x08,0xec,0x5b,0xfa,0x38,0xeb,0x7e,0x7f,0xfd,0x8f,0x6f,0xd6,0x18,0xf3,0xe5,
		0x95,0x2d,0x20,0xa2,0x60,0x7d,0x1a,0x76,0xda,0x10,0xd3,0x9f,0x0f,0x89,0x47,0xdd
	}
};

const size_t SEALING_POLICY_SHA384_LEN = sizeof (SEALING_POLICY_SHA384);

/**
 * HMAC (SIGNING_KEY, CIPHER_TEXT || SEALING_POLICY_SHA384).
 */
const uint8_t PAYLOAD_SHA384_HMAC[] = {
	0x1e,0x9d,0x98,0x37,0x4d,0xa8,0xed,0xe6,0xb2,0x57,0x95,0xc4,0xc1,0x39,0xd7,0x31,
	0x27,0xd9,0x24,0x79,0x63,0x78,0x05,0xde,0xff,0x43,0xd6,0xd3,0xf9,0xce,0xdc,0xe3
};

const size_t PAYLOAD_SHA384_HMAC_LEN = sizeof (PAYLOAD_SHA384_HMAC);

/**
 * 64-byte Sealing policy value with a SHA-512 digest.
 */
const uint8_t SEALING_POLICY_SHA512[][64] = {
	{
		0x3d,0x35,0x8c,0x5c,0xc9,0xd7,0x21,0x80,0xe3,0x96,0x89,0xc4,0x61,0x42,0xf1,0x07,
		0x6b,0x8f,0x39,0x49,0x05,0x1b,0x2b,0xd7,0xc8,0x97,0x97,0x26,0xf2,0xf6,0x0a,0x46,
		0xd1,0x65,0xaa,0x09,0xf8,0x79,0x4d,0x66,0x82,0x07,0x94,0xd9,0xee,0xa5,0x4f,0x65,
		0x41,0x95,0xdb,0x21,0x18,0xdc,0xaa,0x22,0x47,0x26,0x14,0x7c,0x22,0xef,0xb6,0x92
	}
};

const size_t SEALING_POLICY_SHA512_LEN = sizeof (SEALING_POLICY_SHA512);

/**
 * HMAC (SIGNING_KEY, CIPHER_TEXT || SEALING_POLICY_SHA512).
 */
const uint8_t PAYLOAD_SHA512_HMAC[] = {
	0x29,0x13,0x4e,0x69,0xa0,0x5b,0x3e,0x19,0xfb,0xfd,0xdf,0x76,0x9e,0x91,0xaf,0x79,
	0x10,0x34,0x99,0xa0,0xc5,0xe8,0x60,0xfa,0x6e,0x9a,0xe6,0x6b,0x20,0xb9,0x43,0xc9
};

const size_t PAYLOAD_SHA512_HMAC_LEN = sizeof (PAYLOAD_SHA512_HMAC);

/**
 * Sealing policy value using multiple PCRs
 */
const uint8_t SEALING_POLICY_MULTIPLE[][64] = {
	{
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0xf7,0x0e,0x27,0xc8,0xf0,0x0d,0x40,0x34,0xad,0xab,0x82,0x40,0x17,0x3e,0xd7,0x74,
		0xe4,0x4a,0xcb,0xd7,0x4d,0x0b,0x24,0xad,0x3d,0x4b,0x75,0x29,0x11,0x57,0x98,0x1e
	},
	{
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	},
	{
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	}
};

const size_t SEALING_POLICY_MULTIPLE_LEN = sizeof (SEALING_POLICY_MULTIPLE);

/**
 * HMAC (SIGNING_KEY, CIPHER_TEXT || SEALING_POLICY_MULTIPLE).
 */
const uint8_t PAYLOAD_MULTIPLE_HMAC[] = {
	0x18,0x2b,0x0b,0x77,0xbc,0xb4,0x79,0xb2,0x86,0x92,0x39,0x48,0xf0,0x36,0xb9,0xe8,
	0x02,0x44,0x79,0x28,0x7e,0xc5,0xd6,0x7b,0x3c,0x45,0x23,0x5d,0x92,0x18,0x2e,0x64
};

const size_t PAYLOAD_MULTIPLE_HMAC_LEN = sizeof (PAYLOAD_MULTIPLE_HMAC);

/**
 * Sealing policy value using multiple PCRs with different hash algorithms.
 */
const uint8_t SEALING_POLICY_MULTIPLE_ALGOS[][64] = {
	{
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0xf7,0x0e,0x27,0xc8,0xf0,0x0d,0x40,0x34,0xad,0xab,0x82,0x40,0x17,0x3e,0xd7,0x74,
		0xe4,0x4a,0xcb,0xd7,0x4d,0x0b,0x24,0xad,0x3d,0x4b,0x75,0x29,0x11,0x57,0x98,0x1e
	},
	{
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0xa2,0x5c,0x43,0x12,0x86,0x71,0xbd,0x4b,0x49,0xc9,0x94,0x81,0x4f,0xda,0x51,0x39,
		0x9c,0x08,0xec,0x5b,0xfa,0x38,0xeb,0x7e,0x7f,0xfd,0x8f,0x6f,0xd6,0x18,0xf3,0xe5,
		0x95,0x2d,0x20,0xa2,0x60,0x7d,0x1a,0x76,0xda,0x10,0xd3,0x9f,0x0f,0x89,0x47,0xdd
	},
	{
		0x3d,0x35,0x8c,0x5c,0xc9,0xd7,0x21,0x80,0xe3,0x96,0x89,0xc4,0x61,0x42,0xf1,0x07,
		0x6b,0x8f,0x39,0x49,0x05,0x1b,0x2b,0xd7,0xc8,0x97,0x97,0x26,0xf2,0xf6,0x0a,0x46,
		0xd1,0x65,0xaa,0x09,0xf8,0x79,0x4d,0x66,0x82,0x07,0x94,0xd9,0xee,0xa5,0x4f,0x65,
		0x41,0x95,0xdb,0x21,0x18,0xdc,0xaa,0x22,0x47,0x26,0x14,0x7c,0x22,0xef,0xb6,0x92
	},
	{
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x74,0x2e,0x1b,0xcb,0x21,0xae,0xeb,0x30,0x01,0x55,0x24,0x7a,0x90,0x06,0xad,0x0a,
		0xbf,0xa2,0xec,0xfc,0xef,0x73,0x0c,0xfd,0xca,0xb8,0x37,0x23,0x8d,0x51,0x13,0xff,
		0x6c,0x27,0x58,0xee,0x24,0x67,0xda,0x88,0x5c,0xa8,0x95,0x4e,0x75,0x1b,0x0f,0xdb
	},
	{
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	},
	{
		0x0b,0x45,0x5c,0xc4,0x94,0x84,0x1f,0x70,0xcb,0xa0,0xae,0x3f,0xf6,0xf8,0x89,0xed,
		0xfa,0xb6,0xc8,0x2e,0xcb,0x75,0xf3,0x66,0x3d,0xb4,0xbd,0xdb,0x65,0xb1,0xac,0x50,
		0x29,0xbb,0x4e,0x21,0x4d,0xe5,0xbf,0xde,0xc3,0xc4,0xc3,0x92,0x35,0xe5,0x68,0xef,
		0x97,0x04,0xee,0x64,0x40,0xda,0x06,0xb8,0x10,0xed,0x75,0xa4,0x37,0xd2,0x7b,0xf0
	}
};

const size_t SEALING_POLICY_MULTIPLE_ALGOS_LEN = sizeof (SEALING_POLICY_MULTIPLE_ALGOS);

/**
 * HMAC (SIGNING_KEY, CIPHER_TEXT || SEALING_POLICY_MULTIPLE_ALGOS).
 */
const uint8_t PAYLOAD_MULTIPLE_ALGOS_HMAC[] = {
	0x36,0xb2,0xe4,0x2c,0xf8,0xc0,0xe9,0x9d,0xb5,0x21,0x46,0xf5,0xa3,0x09,0x3e,0xf0,
	0xc1,0x8a,0x50,0xca,0x16,0x18,0xf7,0x5d,0xf6,0x7f,0x99,0x8c,0x2c,0x5c,0x3f,0x96
};

const size_t PAYLOAD_MULTIPLE_ALGOS_HMAC_LEN = sizeof (PAYLOAD_MULTIPLE_ALGOS_HMAC);

/**
 * Sealing policy value skipping a PCR
 */
const uint8_t SEALING_POLICY_SKIP[][64] = {
	{
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0xf7,0x0e,0x27,0xc8,0xf0,0x0d,0x40,0x34,0xad,0xab,0x82,0x40,0x17,0x3e,0xd7,0x74,
		0xe4,0x4a,0xcb,0xd7,0x4d,0x0b,0x24,0xad,0x3d,0x4b,0x75,0x29,0x11,0x57,0x98,0x1e
	},
	{
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
	},
	{
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	}
};

const size_t SEALING_POLICY_SKIP_LEN = sizeof (SEALING_POLICY_SKIP);

/**
 * HMAC (SIGNING_KEY, CIPHER_TEXT || SEALING_POLICY_SKIP).
 */
const uint8_t PAYLOAD_SKIP_HMAC[] = {
	0xa7,0x64,0xee,0x44,0x1c,0x3a,0x63,0xd8,0xb7,0x84,0x97,0x71,0x3f,0xfe,0xfe,0x4d,
	0x70,0xa6,0x54,0xd7,0x20,0x12,0x1f,0x41,0x95,0x23,0x69,0x4d,0x1e,0xc2,0x3f,0xd0
};

const size_t PAYLOAD_SKIP_HMAC_LEN = sizeof (PAYLOAD_SKIP_HMAC);

/**
 * Sealing policy that bypasses PCR checks.
 */
static const uint8_t SEALING_POLICY_BYPASS[][64] = {
	{
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
	}
};

static const size_t SEALING_POLICY_BYPASS_LEN = sizeof (SEALING_POLICY_BYPASS);

/**
 * HMAC (SIGNING_KEY, CIPHER_TEXT || SEALING_POLICY_BYPASS).
 */
static const uint8_t PAYLOAD_BYPASS_HMAC[] = {
	0x19,0xdf,0x15,0x5c,0xa8,0x69,0x61,0xd4,0xb8,0x31,0x1d,0xcb,0xb4,0x68,0x08,0xf6,
	0x55,0xa7,0xee,0x77,0x22,0x92,0xa8,0x77,0x28,0xa1,0x9b,0xb7,0xa2,0xe7,0xaf,0x27
};

static const size_t PAYLOAD_BYPASS_HMAC_LEN = sizeof (PAYLOAD_BYPASS_HMAC);

/**
 * Sealing policy that bypasses multiple PCR checks.
 */
static const uint8_t SEALING_POLICY_BYPASS_MULTIPLE[][64] = {
	{
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
	},
	{
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
	},
	{
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
	}
};

static const size_t SEALING_POLICY_BYPASS_MULTIPLE_LEN = sizeof (SEALING_POLICY_BYPASS_MULTIPLE);

/**
 * HMAC (SIGNING_KEY, CIPHER_TEXT || SEALING_POLICY_BYPASS_MULTIPLE).
 */
static const uint8_t PAYLOAD_BYPASS_MULTIPLE_HMAC[] = {
	0xa9,0x30,0x64,0xd0,0x02,0x18,0xc0,0x17,0x40,0xd5,0xb5,0x1c,0xa9,0xcb,0x3f,0xd2,
	0x5d,0xe1,0xfa,0x7b,0x5a,0x3a,0xa6,0x61,0x52,0x0c,0x44,0xbe,0x96,0x52,0xf2,0x3b
};

static const size_t PAYLOAD_BYPASS_MULTIPLE_HMAC_LEN = sizeof (PAYLOAD_BYPASS_MULTIPLE_HMAC);

/**
 * The local PCR0 value.
 */
const uint8_t PCR0_VALUE[] = {
	0xf7,0x0e,0x27,0xc8,0xf0,0x0d,0x40,0x34,0xad,0xab,0x82,0x40,0x17,0x3e,0xd7,0x74,
	0xe4,0x4a,0xcb,0xd7,0x4d,0x0b,0x24,0xad,0x3d,0x4b,0x75,0x29,0x11,0x57,0x98,0x1e
};

const size_t PCR0_VALUE_LEN = sizeof (PCR0_VALUE);

/**
 * The local PCR1 value.
 */
const uint8_t PCR1_VALUE[] = {
	0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
	0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
};

const size_t PCR1_VALUE_LEN = sizeof (PCR1_VALUE);

/**
 * The local PCR2 value.
 */
const uint8_t PCR2_VALUE[] = {
	0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
	0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
};

const size_t PCR2_VALUE_LEN = sizeof (PCR2_VALUE);

/**
 * The local PCR0 value with a SHA-384 digest.
 */
const uint8_t PCR0_VALUE_SHA384[] = {
	0xa2,0x5c,0x43,0x12,0x86,0x71,0xbd,0x4b,0x49,0xc9,0x94,0x81,0x4f,0xda,0x51,0x39,
	0x9c,0x08,0xec,0x5b,0xfa,0x38,0xeb,0x7e,0x7f,0xfd,0x8f,0x6f,0xd6,0x18,0xf3,0xe5,
	0x95,0x2d,0x20,0xa2,0x60,0x7d,0x1a,0x76,0xda,0x10,0xd3,0x9f,0x0f,0x89,0x47,0xdd
};

const size_t PCR0_VALUE_SHA384_LEN = sizeof (PCR0_VALUE_SHA384);

/**
 * The local PCR1 value with a SHA-384 digest.
 */
const uint8_t PCR1_VALUE_SHA384[] = {
	0x84,0x7c,0x37,0xfc,0x0c,0x7a,0x6b,0x57,0xfd,0xb0,0x49,0xf6,0x9d,0x80,0x34,0x9c,
	0x7f,0x8b,0x7b,0xb3,0x1a,0x9e,0x04,0xcb,0xcb,0x21,0x97,0xf7,0x73,0x52,0x6f,0xe8,
	0x1d,0x27,0xdf,0xfa,0xee,0x28,0x4e,0xa3,0x5d,0xd4,0x86,0x66,0x64,0xda,0xd3,0xbf
};

const size_t PCR1_VALUE_SHA384_LEN = sizeof (PCR1_VALUE_SHA384);

/**
 * The local PCR2 value with a SHA-384 digest.
 */
const uint8_t PCR2_VALUE_SHA384[] = {
	0x74,0x2e,0x1b,0xcb,0x21,0xae,0xeb,0x30,0x01,0x55,0x24,0x7a,0x90,0x06,0xad,0x0a,
	0xbf,0xa2,0xec,0xfc,0xef,0x73,0x0c,0xfd,0xca,0xb8,0x37,0x23,0x8d,0x51,0x13,0xff,
	0x6c,0x27,0x58,0xee,0x24,0x67,0xda,0x88,0x5c,0xa8,0x95,0x4e,0x75,0x1b,0x0f,0xdb
};

const size_t PCR2_VALUE_SHA384_LEN = sizeof (PCR2_VALUE_SHA384);

/**
 * The local PCR0 value with a SHA-512 digest.
 */
const uint8_t PCR0_VALUE_SHA512[] = {
	0x3d,0x35,0x8c,0x5c,0xc9,0xd7,0x21,0x80,0xe3,0x96,0x89,0xc4,0x61,0x42,0xf1,0x07,
	0x6b,0x8f,0x39,0x49,0x05,0x1b,0x2b,0xd7,0xc8,0x97,0x97,0x26,0xf2,0xf6,0x0a,0x46,
	0xd1,0x65,0xaa,0x09,0xf8,0x79,0x4d,0x66,0x82,0x07,0x94,0xd9,0xee,0xa5,0x4f,0x65,
	0x41,0x95,0xdb,0x21,0x18,0xdc,0xaa,0x22,0x47,0x26,0x14,0x7c,0x22,0xef,0xb6,0x92
};

const size_t PCR0_VALUE_SHA512_LEN = sizeof (PCR0_VALUE_SHA512);

/**
 * The local PCR1 value with a SHA-512 digest.
 */
const uint8_t PCR1_VALUE_SHA512[] = {
	0x37,0x9c,0xf7,0x91,0x5c,0x70,0x89,0x6e,0xc3,0xb3,0x46,0x75,0xc7,0x05,0x60,0x6c,
	0x69,0xac,0xc4,0x11,0x3e,0x2b,0x07,0xf8,0x8d,0xca,0xfb,0x99,0x1b,0x4f,0xd9,0xd2,
	0xdd,0xd1,0x95,0x10,0xed,0x62,0x94,0xc1,0x89,0x61,0x17,0x0a,0xf6,0xb6,0x43,0xe2,
	0x8f,0x92,0xd7,0x43,0x16,0x0b,0x0f,0x9d,0x44,0x31,0x06,0xd8,0xe7,0x23,0xc7,0x18
};

const size_t PCR1_VALUE_SHA512_LEN = sizeof (PCR1_VALUE_SHA512);

/**
 * The local PCR2 value with a SHA-512 digest.
 */
const uint8_t PCR2_VALUE_SHA512[] = {
	0x0b,0x45,0x5c,0xc4,0x94,0x84,0x1f,0x70,0xcb,0xa0,0xae,0x3f,0xf6,0xf8,0x89,0xed,
	0xfa,0xb6,0xc8,0x2e,0xcb,0x75,0xf3,0x66,0x3d,0xb4,0xbd,0xdb,0x65,0xb1,0xac,0x50,
	0x29,0xbb,0x4e,0x21,0x4d,0xe5,0xbf,0xde,0xc3,0xc4,0xc3,0x92,0x35,0xe5,0x68,0xef,
	0x97,0x04,0xee,0x64,0x40,0xda,0x06,0xb8,0x10,0xed,0x75,0xa4,0x37,0xd2,0x7b,0xf0
};

const size_t PCR2_VALUE_SHA512_LEN = sizeof (PCR2_VALUE_SHA512);

/**
 * RIoT keys for testing.
 */
static struct riot_keys keys = {
	.devid_cert = RIOT_CORE_DEVID_CERT,
	.devid_cert_length = 0,
	.devid_csr = RIOT_CORE_DEVID_CSR,
	.devid_csr_length = 0,
	.alias_key = RIOT_CORE_ALIAS_KEY,
	.alias_key_length = 0,
	.alias_cert = RIOT_CORE_ALIAS_CERT,
	.alias_cert_length = 0
};

/**
 * Dependencies for testing auxiliary attestation flows.
 */
struct aux_attestation_testing {
	struct rsa_engine_mock rsa;					/**< Mock for RSA operations. */
	struct ecc_engine_mock ecc;					/**< Mock for ECC operations. */
	struct x509_engine_mock x509;				/**< Mock for X.509 operations. */
	struct rng_engine_mock rng;					/**< Mock for RNG operations. */
	struct hash_engine_mock hash;				/**< Mock for hash operations. */
	struct keystore_mock keystore;				/**< Mock for the attestation keystore. */
	struct riot_key_manager_state riot_state;	/**< Context for the RIoT key manager. */
	struct riot_key_manager riot;				/**< Key manager for RIoT keys. */
	struct aux_attestation test;				/**< Attestation instance being tested. */
};

/**
 * Initialize the key manager for RIoT keys.
 *
 * @param test The testing framework.
 * @param aux Testing dependencies containing the RIoT keys to initialize.
 */
static void aux_attestation_testing_init_riot_keys (CuTest *test,
	struct aux_attestation_testing *aux)
{
	uint8_t *dev_id_der = NULL;
	int status;

	status = x509_mock_init (&aux->x509);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&aux->keystore);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux->keystore.mock, aux->keystore.base.load_key, &aux->keystore,
		KEYSTORE_NO_KEY, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&aux->keystore.mock, 1, &dev_id_der, sizeof (dev_id_der), -1);
	CuAssertIntEquals (test, 0, status);

	status = riot_key_manager_init_static_keys (&aux->riot, &aux->riot_state, &aux->keystore.base,
		&keys, &aux->x509.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&aux->keystore.mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release the key manager for RIoT keys used for testing.
 *
 * @param test The testing framework.
 * @param aux Testing dependencies containing the RIoT keys to release.
 */
static void aux_attestation_testing_release_riot_keys (CuTest *test,
	struct aux_attestation_testing *aux)
{
	int status;

	status = keystore_mock_validate_and_release (&aux->keystore);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&aux->x509);
	CuAssertIntEquals (test, 0, status);

	riot_key_manager_release (&aux->riot);
}

/**
 * Initialize all dependencies for attestation testing.
 *
 * @param test The testing framework.
 * @param aux Dependencies to initialize.
 */
static void aux_attestation_testing_init_dependencies (CuTest *test,
	struct aux_attestation_testing *aux)
{
	int status;

	keys.devid_cert_length = RIOT_CORE_DEVID_CERT_LEN;
	keys.devid_csr_length = RIOT_CORE_DEVID_CSR_LEN;
	keys.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;
	keys.alias_cert_length = RIOT_CORE_ALIAS_CERT_LEN;

	aux_attestation_testing_init_riot_keys (test, aux);

	status = rsa_mock_init (&aux->rsa);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&aux->ecc);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&aux->rng);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&aux->hash);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release all testing dependencies and validate mocks.
 *
 * @param test The testing framework.
 * @param aux Dependencies to release.
 *
 */
static void aux_attestation_testing_validate_and_release_dependencies (CuTest *test,
	struct aux_attestation_testing *aux)
{
	int status;

	status = rsa_mock_validate_and_release (&aux->rsa);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&aux->ecc);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&aux->rng);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&aux->hash);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_release_riot_keys (test, aux);
}

/**
 * Initiaize the auxiliary attestation instance for testing.
 *
 * @param test The testing framework.
 * @param aux Components to initialize.
 *
 */
static void aux_attestation_testing_init (CuTest *test, struct aux_attestation_testing *aux)
{
	int status;

	aux_attestation_testing_init_dependencies (test, aux);

	status = aux_attestation_init (&aux->test, &aux->keystore.base, &aux->rsa.base, &aux->riot,
		&aux->ecc.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release the auxiliary attesation instance and all dependencies.  Mocks will be validated.
 *
 * @param test The testing framework.
 * @param aux Components to release.
 *
 */
static void aux_attestation_testing_validate_and_release (CuTest *test,
	struct aux_attestation_testing *aux)
{
	aux_attestation_release (&aux->test);
	aux_attestation_testing_validate_and_release_dependencies (test, aux);
}


/*******************
 * Test cases
 *******************/

static void aux_attestation_test_init (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	const struct der_cert *cert;

	TEST_START;

	aux_attestation_testing_init_dependencies (test, &aux);

	status = aux_attestation_init (&aux.test, &aux.keystore.base, &aux.rsa.base, &aux.riot,
		&aux.ecc.base);
	CuAssertIntEquals (test, 0, status);

	cert = aux_attestation_get_certificate (&aux.test);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	aux_attestation_testing_validate_and_release_dependencies (test, &aux);

	aux_attestation_release (&aux.test);
}

static void aux_attestation_test_init_null (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;

	TEST_START;

	aux_attestation_testing_init_dependencies (test, &aux);

	status = aux_attestation_init (NULL, &aux.keystore.base, &aux.rsa.base, &aux.riot,
		&aux.ecc.base);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_init (&aux.test, NULL, &aux.rsa.base, &aux.riot,
		&aux.ecc.base);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_init (&aux.test, &aux.keystore.base, &aux.rsa.base, NULL,
		&aux.ecc.base);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	aux_attestation_testing_validate_and_release_dependencies (test, &aux);
}

static void aux_attestation_test_release_null (CuTest *test)
{
	TEST_START;

	aux_attestation_release (NULL);
}

static void aux_attestation_test_generate_key (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	uint8_t *key_der = NULL;

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = mock_expect (&aux.rsa.mock, aux.rsa.base.generate_key, &aux.rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (3072));
	status |= mock_expect_save_arg (&aux.rsa.mock, 0, 0);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.get_private_key_der, &aux.rsa, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.rsa.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.rsa.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&aux.keystore.mock, aux.keystore.base.save_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN));

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.release_key, &aux.rsa, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_generate_key (&aux.test);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_generate_key_null (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = aux_attestation_generate_key (NULL);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_generate_key_generation_no_rsa_support (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;

	TEST_START;

	aux_attestation_testing_init_dependencies (test, &aux);

	status = aux_attestation_init (&aux.test, NULL, NULL, &aux.riot, &aux.ecc.base);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_generate_key (&aux.test);
	CuAssertIntEquals (test, AUX_ATTESTATION_UNSUPPORTED_CRYPTO, status);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_generate_key_generation_error (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = mock_expect (&aux.rsa.mock, aux.rsa.base.generate_key, &aux.rsa,
		RSA_ENGINE_GENERATE_KEY_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG (3072));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_generate_key (&aux.test);
	CuAssertIntEquals (test, RSA_ENGINE_GENERATE_KEY_FAILED, status);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_generate_key_der_error (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = mock_expect (&aux.rsa.mock, aux.rsa.base.generate_key, &aux.rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (3072));
	status |= mock_expect_save_arg (&aux.rsa.mock, 0, 0);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.get_private_key_der, &aux.rsa,
		RSA_ENGINE_PRIVATE_KEY_DER_FAILED, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.release_key, &aux.rsa, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_generate_key (&aux.test);
	CuAssertIntEquals (test, RSA_ENGINE_PRIVATE_KEY_DER_FAILED, status);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_generate_key_save_error (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	uint8_t *key_der = NULL;

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = mock_expect (&aux.rsa.mock, aux.rsa.base.generate_key, &aux.rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (3072));
	status |= mock_expect_save_arg (&aux.rsa.mock, 0, 0);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.get_private_key_der, &aux.rsa, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.rsa.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.rsa.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&aux.keystore.mock, aux.keystore.base.save_key, &aux.keystore,
		KEYSTORE_SAVE_FAILED, MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN));

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.release_key, &aux.rsa, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_generate_key (&aux.test);
	CuAssertIntEquals (test, KEYSTORE_SAVE_FAILED, status);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_create_certificate (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	const struct der_cert *cert;
	uint8_t *key_der;
	uint8_t *cert_der;

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	cert_der = platform_malloc (X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertPtrNotNull (test, cert_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);
	memcpy (cert_der, X509_CERTCA_RSA_EE_DER, X509_CERTCA_RSA_EE_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&aux.x509.mock, aux.x509.base.load_certificate, &aux.x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&aux.x509.mock, 0, 0);

	status |= mock_expect (&aux.rng.mock, aux.rng.base.generate_random_buffer, &aux.rng, 0,
		MOCK_ARG (8), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.rng.mock, 1, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN,
		0);

	status |= mock_expect (&aux.x509.mock, aux.x509.base.create_ca_signed_certificate, &aux.x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG_PTR_CONTAINS (X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN), MOCK_ARG (8),
		MOCK_ARG_PTR_CONTAINS ("AUX", 3), MOCK_ARG (X509_CERT_END_ENTITY),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG (HASH_TYPE_SHA256), MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));
	status |= mock_expect_save_arg (&aux.x509.mock, 0, 1);

	status |= mock_expect (&aux.x509.mock, aux.x509.base.get_certificate_der, &aux.x509, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.x509.mock, 1, &cert_der, sizeof (cert_der), -1);
	status |= mock_expect_output (&aux.x509.mock, 2, &X509_CERTCA_RSA_EE_DER_LEN,
		sizeof (X509_CERTCA_RSA_EE_DER_LEN), -1);

	status |= mock_expect (&aux.x509.mock, aux.x509.base.release_certificate, &aux.x509, 0,
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&aux.x509.mock, aux.x509.base.release_certificate, &aux.x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_create_certificate (&aux.test, &aux.x509.base, &aux.rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, 0, status);

	cert = aux_attestation_get_certificate (&aux.test);
	CuAssertPtrNotNull (test, cert);
	CuAssertIntEquals (test, X509_CERTCA_RSA_EE_DER_LEN, cert->length);

	status = testing_validate_array (X509_CERTCA_RSA_EE_DER, cert->cert, cert->length);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_create_certificate_authenticate (CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	X509_TESTING_ENGINE (x509);
	RNG_TESTING_ENGINE (rng);
	struct aux_attestation_testing aux;
	int status;
	const struct der_cert *cert;
	uint8_t *key_der;
	size_t key_length;
	struct x509_certificate aux_cert;
	struct x509_ca_certs ca_certs;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = X509_TESTING_ENGINE_INIT (&x509);
	CuAssertIntEquals (test, 0, status);

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_init_dependencies (test, &aux);

	status = aux_attestation_init (&aux.test, &aux.keystore.base, &rsa.base, &aux.riot,
		&aux.ecc.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_create_certificate (&aux.test, &x509.base, &rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, 0, status);

	cert = aux_attestation_get_certificate (&aux.test);
	CuAssertPtrNotNull (test, cert);

	status = x509.base.load_certificate (&x509.base, &aux_cert, cert->cert, cert->length);
	CuAssertIntEquals (test, 0, status);

	status = x509.base.init_ca_cert_store (&x509.base, &ca_certs);
	CuAssertIntEquals (test, 0, status);

	status = x509.base.add_root_ca (&x509.base, &ca_certs, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = x509.base.authenticate (&x509.base, &aux_cert, &ca_certs);
	CuAssertIntEquals (test, 0, status);

	status = x509.base.get_public_key (&x509.base, &aux_cert, &key_der, &key_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RSA_PUBKEY_DER_LEN, key_length);

	status = testing_validate_array (RSA_PUBKEY_DER, key_der, key_length);
	CuAssertIntEquals (test, 0, status);

	platform_free (key_der);
	x509.base.release_certificate (&x509.base, &aux_cert);
	x509.base.release_ca_cert_store (&x509.base, &ca_certs);

	aux_attestation_testing_validate_and_release (test, &aux);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	X509_TESTING_ENGINE_RELEASE (&x509);
	RNG_TESTING_ENGINE_RELEASE (&rng);
}

static void aux_attestation_test_create_certificate_twice (CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	X509_TESTING_ENGINE (x509);
	RNG_TESTING_ENGINE (rng);
	struct aux_attestation_testing aux;
	int status;
	const struct der_cert *cert;
	uint8_t *key_der;

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = X509_TESTING_ENGINE_INIT (&x509);
	CuAssertIntEquals (test, 0, status);

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_init_dependencies (test, &aux);

	status = aux_attestation_init (&aux.test, &aux.keystore.base, &rsa.base, &aux.riot,
		&aux.ecc.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_create_certificate (&aux.test, &x509.base, &rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, 0, status);

	cert = aux_attestation_get_certificate (&aux.test);
	CuAssertPtrNotNull (test, cert);

	status = mock_validate (&aux.keystore.mock);
	CuAssertIntEquals (test, 0, status);

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_create_certificate (&aux.test, &x509.base, &rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, 0, status);

	cert = aux_attestation_get_certificate (&aux.test);
	CuAssertPtrNotNull (test, cert);

	aux_attestation_testing_validate_and_release (test, &aux);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	X509_TESTING_ENGINE_RELEASE (&x509);
	RNG_TESTING_ENGINE_RELEASE (&rng);
}

static void aux_attestation_test_create_certificate_zero_serial_number (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	const struct der_cert *cert;
	uint8_t *key_der;
	uint8_t zero[8] = {0};

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&aux.x509.mock, aux.x509.base.load_certificate, &aux.x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&aux.x509.mock, 0, 0);

	status |= mock_expect (&aux.rng.mock, aux.rng.base.generate_random_buffer, &aux.rng, 0,
		MOCK_ARG (8), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.rng.mock, 1, zero, sizeof (zero), 0);

	status |= mock_expect (&aux.rng.mock, aux.rng.base.generate_random_buffer, &aux.rng, 0,
		MOCK_ARG (8), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.rng.mock, 1, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN,
		0);

	status |= mock_expect (&aux.x509.mock, aux.x509.base.create_ca_signed_certificate, &aux.x509,
		X509_ENGINE_CA_SIGNED_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG_PTR_CONTAINS (X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN), MOCK_ARG (8),
		MOCK_ARG_PTR_CONTAINS ("AUX", 3), MOCK_ARG (X509_CERT_END_ENTITY),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG (HASH_TYPE_SHA256), MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	status |= mock_expect (&aux.x509.mock, aux.x509.base.release_certificate, &aux.x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_create_certificate (&aux.test, &aux.x509.base, &aux.rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, X509_ENGINE_CA_SIGNED_FAILED, status);

	cert = aux_attestation_get_certificate (&aux.test);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_create_certificate_zero_serial_number_twice (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	const struct der_cert *cert;
	uint8_t *key_der;
	uint8_t zero[8] = {0};

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&aux.x509.mock, aux.x509.base.load_certificate, &aux.x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&aux.x509.mock, 0, 0);

	status |= mock_expect (&aux.rng.mock, aux.rng.base.generate_random_buffer, &aux.rng, 0,
		MOCK_ARG (8), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.rng.mock, 1, zero, sizeof (zero), 0);

	status |= mock_expect (&aux.rng.mock, aux.rng.base.generate_random_buffer, &aux.rng, 0,
		MOCK_ARG (8), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.rng.mock, 1, zero, sizeof (zero), 0);

	status |= mock_expect (&aux.rng.mock, aux.rng.base.generate_random_buffer, &aux.rng, 0,
		MOCK_ARG (8), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.rng.mock, 1, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN,
		0);

	status |= mock_expect (&aux.x509.mock, aux.x509.base.create_ca_signed_certificate, &aux.x509,
		X509_ENGINE_CA_SIGNED_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG_PTR_CONTAINS (X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN), MOCK_ARG (8),
		MOCK_ARG_PTR_CONTAINS ("AUX", 3), MOCK_ARG (X509_CERT_END_ENTITY),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG (HASH_TYPE_SHA256), MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	status |= mock_expect (&aux.x509.mock, aux.x509.base.release_certificate, &aux.x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_create_certificate (&aux.test, &aux.x509.base, &aux.rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, X509_ENGINE_CA_SIGNED_FAILED, status);

	cert = aux_attestation_get_certificate (&aux.test);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_create_certificate_null (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	const struct der_cert *cert;

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = aux_attestation_create_certificate (NULL, &aux.x509.base, &aux.rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_create_certificate (&aux.test, NULL, &aux.rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_create_certificate (&aux.test, &aux.x509.base, NULL,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_create_certificate (&aux.test, &aux.x509.base, &aux.rng.base,
		NULL, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_create_certificate (&aux.test, &aux.x509.base, &aux.rng.base,
		RIOT_CORE_DEVID_CERT, 0, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_create_certificate (&aux.test, &aux.x509.base, &aux.rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, NULL,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_create_certificate (&aux.test, &aux.x509.base, &aux.rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		0);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	cert = aux_attestation_get_certificate (&aux.test);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_create_certificate_no_rsa_support (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	const struct der_cert *cert;

	TEST_START;

	aux_attestation_testing_init_dependencies (test, &aux);

	status = aux_attestation_init (&aux.test, NULL, NULL, &aux.riot, &aux.ecc.base);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_create_certificate (&aux.test, &aux.x509.base, &aux.rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, AUX_ATTESTATION_UNSUPPORTED_CRYPTO, status);

	cert = aux_attestation_get_certificate (&aux.test);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_create_certificate_no_private_key (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	const struct der_cert *cert;
	uint8_t *null = NULL;

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore,
		KEYSTORE_NO_KEY, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &null, sizeof (null), -1);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_create_certificate (&aux.test, &aux.x509.base, &aux.rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, KEYSTORE_NO_KEY, status);

	cert = aux_attestation_get_certificate (&aux.test);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_create_certificate_bad_private_key (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	const struct der_cert *cert;
	uint8_t *null = NULL;

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore,
		KEYSTORE_BAD_KEY, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &null, sizeof (null), -1);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_create_certificate (&aux.test, &aux.x509.base, &aux.rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, KEYSTORE_BAD_KEY, status);

	cert = aux_attestation_get_certificate (&aux.test);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_create_certificate_load_key_error (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	const struct der_cert *cert;
	uint8_t *key_der = NULL;

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore,
		KEYSTORE_LOAD_FAILED, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_create_certificate (&aux.test, &aux.x509.base, &aux.rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, KEYSTORE_LOAD_FAILED, status);

	cert = aux_attestation_get_certificate (&aux.test);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_create_certificate_load_ca_error (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	const struct der_cert *cert;
	uint8_t *key_der;

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&aux.x509.mock, aux.x509.base.load_certificate, &aux.x509,
		X509_ENGINE_LOAD_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_create_certificate (&aux.test, &aux.x509.base, &aux.rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, X509_ENGINE_LOAD_FAILED, status);

	cert = aux_attestation_get_certificate (&aux.test);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_create_certificate_serial_number_error (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	const struct der_cert *cert;
	uint8_t *key_der;

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&aux.x509.mock, aux.x509.base.load_certificate, &aux.x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&aux.x509.mock, 0, 0);

	status |= mock_expect (&aux.rng.mock, aux.rng.base.generate_random_buffer, &aux.rng,
		RNG_ENGINE_RANDOM_FAILED, MOCK_ARG (8), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&aux.x509.mock, aux.x509.base.release_certificate, &aux.x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_create_certificate (&aux.test, &aux.x509.base, &aux.rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, RNG_ENGINE_RANDOM_FAILED, status);

	cert = aux_attestation_get_certificate (&aux.test);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_create_certificate_create_error (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	const struct der_cert *cert;
	uint8_t *key_der;

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&aux.x509.mock, aux.x509.base.load_certificate, &aux.x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&aux.x509.mock, 0, 0);

	status |= mock_expect (&aux.rng.mock, aux.rng.base.generate_random_buffer, &aux.rng, 0,
		MOCK_ARG (8), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.rng.mock, 1, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN,
		0);

	status |= mock_expect (&aux.x509.mock, aux.x509.base.create_ca_signed_certificate, &aux.x509,
		X509_ENGINE_CA_SIGNED_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG_PTR_CONTAINS (X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN), MOCK_ARG (8),
		MOCK_ARG_PTR_CONTAINS ("AUX", 3), MOCK_ARG (X509_CERT_END_ENTITY),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG (HASH_TYPE_SHA256), MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	status |= mock_expect (&aux.x509.mock, aux.x509.base.release_certificate, &aux.x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_create_certificate (&aux.test, &aux.x509.base, &aux.rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, X509_ENGINE_CA_SIGNED_FAILED, status);

	cert = aux_attestation_get_certificate (&aux.test);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_create_certificate_cert_der_error (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	const struct der_cert *cert;
	uint8_t *key_der;
	uint8_t *cert_der = NULL;

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&aux.x509.mock, aux.x509.base.load_certificate, &aux.x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&aux.x509.mock, 0, 0);

	status |= mock_expect (&aux.rng.mock, aux.rng.base.generate_random_buffer, &aux.rng, 0,
		MOCK_ARG (8), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.rng.mock, 1, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN,
		0);

	status |= mock_expect (&aux.x509.mock, aux.x509.base.create_ca_signed_certificate, &aux.x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG_PTR_CONTAINS (X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN), MOCK_ARG (8),
		MOCK_ARG_PTR_CONTAINS ("AUX", 3), MOCK_ARG (X509_CERT_END_ENTITY),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG (HASH_TYPE_SHA256), MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));
	status |= mock_expect_save_arg (&aux.x509.mock, 0, 1);

	status |= mock_expect (&aux.x509.mock, aux.x509.base.get_certificate_der, &aux.x509,
		X509_ENGINE_CERT_DER_FAILED, MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.x509.mock, 1, &cert_der, sizeof (cert_der), -1);

	status |= mock_expect (&aux.x509.mock, aux.x509.base.release_certificate, &aux.x509, 0,
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&aux.x509.mock, aux.x509.base.release_certificate, &aux.x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_create_certificate (&aux.test, &aux.x509.base, &aux.rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, X509_ENGINE_CERT_DER_FAILED, status);

	cert = aux_attestation_get_certificate (&aux.test);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_set_certificate (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	const struct der_cert *cert;
	uint8_t *cert_der;

	TEST_START;

	cert_der = platform_malloc (X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertPtrNotNull (test, cert_der);

	memcpy (cert_der, X509_CERTCA_RSA_EE_DER, X509_CERTCA_RSA_EE_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = aux_attestation_set_certificate (&aux.test, cert_der, X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	cert = aux_attestation_get_certificate (&aux.test);
	CuAssertPtrNotNull (test, cert);
	CuAssertPtrEquals (test, cert_der, (void*) cert->cert);
	CuAssertIntEquals (test, X509_CERTCA_RSA_EE_DER_LEN, cert->length);

	status = testing_validate_array (X509_CERTCA_RSA_EE_DER, cert->cert, cert->length);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_set_certificate_before_create (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	const struct der_cert *cert;
	uint8_t *key_der;
	uint8_t *cert_der;

	TEST_START;

	cert_der = platform_malloc (X509_CERTCA_ECC_EE_DER_LEN);
	CuAssertPtrNotNull (test, cert_der);

	memcpy (cert_der, X509_CERTCA_ECC_EE_DER, X509_CERTCA_ECC_EE_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = aux_attestation_set_certificate (&aux.test, cert_der, X509_CERTCA_ECC_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	cert_der = platform_malloc (X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertPtrNotNull (test, cert_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);
	memcpy (cert_der, X509_CERTCA_RSA_EE_DER, X509_CERTCA_RSA_EE_DER_LEN);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&aux.x509.mock, aux.x509.base.load_certificate, &aux.x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&aux.x509.mock, 0, 0);

	status |= mock_expect (&aux.rng.mock, aux.rng.base.generate_random_buffer, &aux.rng, 0,
		MOCK_ARG (8), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.rng.mock, 1, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN,
		0);

	status |= mock_expect (&aux.x509.mock, aux.x509.base.create_ca_signed_certificate, &aux.x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG_PTR_CONTAINS (X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN), MOCK_ARG (8),
		MOCK_ARG_PTR_CONTAINS ("AUX", 3), MOCK_ARG (X509_CERT_END_ENTITY),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG (HASH_TYPE_SHA256), MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));
	status |= mock_expect_save_arg (&aux.x509.mock, 0, 1);

	status |= mock_expect (&aux.x509.mock, aux.x509.base.get_certificate_der, &aux.x509, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.x509.mock, 1, &cert_der, sizeof (cert_der), -1);
	status |= mock_expect_output (&aux.x509.mock, 2, &X509_CERTCA_RSA_EE_DER_LEN,
		sizeof (X509_CERTCA_RSA_EE_DER_LEN), -1);

	status |= mock_expect (&aux.x509.mock, aux.x509.base.release_certificate, &aux.x509, 0,
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&aux.x509.mock, aux.x509.base.release_certificate, &aux.x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_create_certificate (&aux.test, &aux.x509.base, &aux.rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, 0, status);

	cert = aux_attestation_get_certificate (&aux.test);
	CuAssertPtrNotNull (test, cert);
	CuAssertIntEquals (test, X509_CERTCA_RSA_EE_DER_LEN, cert->length);

	status = testing_validate_array (X509_CERTCA_RSA_EE_DER, cert->cert, cert->length);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_set_certificate_null (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	const struct der_cert *cert;
	uint8_t *cert_der;

	TEST_START;

	cert_der = platform_malloc (X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertPtrNotNull (test, cert_der);

	memcpy (cert_der, X509_CERTCA_RSA_EE_DER, X509_CERTCA_RSA_EE_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = aux_attestation_set_certificate (NULL, cert_der, X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_set_certificate (&aux.test, NULL, X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_set_certificate (&aux.test, cert_der, 0);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	cert = aux_attestation_get_certificate (&aux.test);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	aux_attestation_testing_validate_and_release (test, &aux);

	platform_free (cert_der);
}

static void aux_attestation_test_set_certificate_no_rsa_support (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	const struct der_cert *cert;
	uint8_t *cert_der;

	TEST_START;

	cert_der = platform_malloc (X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertPtrNotNull (test, cert_der);

	memcpy (cert_der, X509_CERTCA_RSA_EE_DER, X509_CERTCA_RSA_EE_DER_LEN);

	aux_attestation_testing_init_dependencies (test, &aux);

	status = aux_attestation_init (&aux.test, NULL, NULL, &aux.riot, &aux.ecc.base);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_set_certificate (&aux.test, cert_der, X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertIntEquals (test, AUX_ATTESTATION_UNSUPPORTED_CRYPTO, status);

	cert = aux_attestation_get_certificate (&aux.test);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	aux_attestation_testing_validate_and_release (test, &aux);

	platform_free (cert_der);
}

static void aux_attestation_test_set_certificate_twice (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	const struct der_cert *cert;
	uint8_t *cert_der;

	TEST_START;

	cert_der = platform_malloc (X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertPtrNotNull (test, cert_der);

	memcpy (cert_der, X509_CERTCA_RSA_EE_DER, X509_CERTCA_RSA_EE_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = aux_attestation_set_certificate (&aux.test, cert_der, X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	cert_der = platform_malloc (X509_CERTCA_ECC_EE_DER_LEN);
	CuAssertPtrNotNull (test, cert_der);

	memcpy (cert_der, X509_CERTCA_ECC_EE_DER, X509_CERTCA_ECC_EE_DER_LEN);

	status = aux_attestation_set_certificate (&aux.test, cert_der, X509_CERTCA_ECC_EE_DER_LEN);
	CuAssertIntEquals (test, AUX_ATTESTATION_HAS_CERTIFICATE, status);

	cert = aux_attestation_get_certificate (&aux.test);
	CuAssertPtrNotNull (test, cert);
	CuAssertTrue (test, (cert_der != cert->cert));
	CuAssertIntEquals (test, X509_CERTCA_RSA_EE_DER_LEN, cert->length);

	status = testing_validate_array (X509_CERTCA_RSA_EE_DER, cert->cert, cert->length);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);

	platform_free (cert_der);
}

static void aux_attestation_test_set_certificate_after_create (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	const struct der_cert *cert;
	uint8_t *key_der;
	uint8_t *cert_der;

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	cert_der = platform_malloc (X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertPtrNotNull (test, cert_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);
	memcpy (cert_der, X509_CERTCA_RSA_EE_DER, X509_CERTCA_RSA_EE_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&aux.x509.mock, aux.x509.base.load_certificate, &aux.x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&aux.x509.mock, 0, 0);

	status |= mock_expect (&aux.rng.mock, aux.rng.base.generate_random_buffer, &aux.rng, 0,
		MOCK_ARG (8), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.rng.mock, 1, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN,
		0);

	status |= mock_expect (&aux.x509.mock, aux.x509.base.create_ca_signed_certificate, &aux.x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG_PTR_CONTAINS (X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN), MOCK_ARG (8),
		MOCK_ARG_PTR_CONTAINS ("AUX", 3), MOCK_ARG (X509_CERT_END_ENTITY),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG (HASH_TYPE_SHA256), MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));
	status |= mock_expect_save_arg (&aux.x509.mock, 0, 1);

	status |= mock_expect (&aux.x509.mock, aux.x509.base.get_certificate_der, &aux.x509, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.x509.mock, 1, &cert_der, sizeof (cert_der), -1);
	status |= mock_expect_output (&aux.x509.mock, 2, &X509_CERTCA_RSA_EE_DER_LEN,
		sizeof (X509_CERTCA_RSA_EE_DER_LEN), -1);

	status |= mock_expect (&aux.x509.mock, aux.x509.base.release_certificate, &aux.x509, 0,
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&aux.x509.mock, aux.x509.base.release_certificate, &aux.x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_create_certificate (&aux.test, &aux.x509.base, &aux.rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, 0, status);

	cert_der = platform_malloc (X509_CERTCA_ECC_EE_DER_LEN);
	CuAssertPtrNotNull (test, cert_der);

	memcpy (cert_der, X509_CERTCA_ECC_EE_DER, X509_CERTCA_ECC_EE_DER_LEN);

	status = aux_attestation_set_certificate (&aux.test, cert_der, X509_CERTCA_ECC_EE_DER_LEN);
	CuAssertIntEquals (test, AUX_ATTESTATION_HAS_CERTIFICATE, status);

	cert = aux_attestation_get_certificate (&aux.test);
	CuAssertPtrNotNull (test, cert);
	CuAssertTrue (test, (cert_der != cert->cert));
	CuAssertIntEquals (test, X509_CERTCA_RSA_EE_DER_LEN, cert->length);

	status = testing_validate_array (X509_CERTCA_RSA_EE_DER, cert->cert, cert->length);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);

	platform_free (cert_der);
}

static void aux_attestation_test_set_static_certificate (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	const struct der_cert *cert;

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = aux_attestation_set_static_certificate (&aux.test, X509_CERTCA_RSA_EE_DER,
		X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	cert = aux_attestation_get_certificate (&aux.test);
	CuAssertPtrNotNull (test, cert);
	CuAssertPtrEquals (test, (void*) X509_CERTCA_RSA_EE_DER, (void*) cert->cert);
	CuAssertIntEquals (test, X509_CERTCA_RSA_EE_DER_LEN, cert->length);

	status = testing_validate_array (X509_CERTCA_RSA_EE_DER, cert->cert, cert->length);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_set_static_certificate_before_create (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	const struct der_cert *cert;
	uint8_t *key_der;
	uint8_t *cert_der;

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = aux_attestation_set_static_certificate (&aux.test, X509_CERTCA_ECC_EE_DER,
		X509_CERTCA_ECC_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	cert_der = platform_malloc (X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertPtrNotNull (test, cert_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);
	memcpy (cert_der, X509_CERTCA_RSA_EE_DER, X509_CERTCA_RSA_EE_DER_LEN);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&aux.x509.mock, aux.x509.base.load_certificate, &aux.x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&aux.x509.mock, 0, 0);

	status |= mock_expect (&aux.rng.mock, aux.rng.base.generate_random_buffer, &aux.rng, 0,
		MOCK_ARG (8), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.rng.mock, 1, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN,
		0);

	status |= mock_expect (&aux.x509.mock, aux.x509.base.create_ca_signed_certificate, &aux.x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG_PTR_CONTAINS (X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN), MOCK_ARG (8),
		MOCK_ARG_PTR_CONTAINS ("AUX", 3), MOCK_ARG (X509_CERT_END_ENTITY),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG (HASH_TYPE_SHA256), MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));
	status |= mock_expect_save_arg (&aux.x509.mock, 0, 1);

	status |= mock_expect (&aux.x509.mock, aux.x509.base.get_certificate_der, &aux.x509, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.x509.mock, 1, &cert_der, sizeof (cert_der), -1);
	status |= mock_expect_output (&aux.x509.mock, 2, &X509_CERTCA_RSA_EE_DER_LEN,
		sizeof (X509_CERTCA_RSA_EE_DER_LEN), -1);

	status |= mock_expect (&aux.x509.mock, aux.x509.base.release_certificate, &aux.x509, 0,
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&aux.x509.mock, aux.x509.base.release_certificate, &aux.x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_create_certificate (&aux.test, &aux.x509.base, &aux.rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, 0, status);

	cert = aux_attestation_get_certificate (&aux.test);
	CuAssertPtrNotNull (test, cert);
	CuAssertIntEquals (test, X509_CERTCA_RSA_EE_DER_LEN, cert->length);

	status = testing_validate_array (X509_CERTCA_RSA_EE_DER, cert->cert, cert->length);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_set_static_certificate_null (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	const struct der_cert *cert;

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = aux_attestation_set_static_certificate (NULL, X509_CERTCA_RSA_EE_DER,
		X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_set_static_certificate (&aux.test, NULL,
		X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_set_static_certificate (&aux.test, X509_CERTCA_RSA_EE_DER,
		0);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	cert = aux_attestation_get_certificate (&aux.test);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_set_static_certificate_no_rsa_support (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	const struct der_cert *cert;

	TEST_START;

	aux_attestation_testing_init_dependencies (test, &aux);

	status = aux_attestation_init (&aux.test, NULL, NULL, &aux.riot, &aux.ecc.base);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_set_static_certificate (&aux.test, X509_CERTCA_RSA_EE_DER,
		X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertIntEquals (test, AUX_ATTESTATION_UNSUPPORTED_CRYPTO, status);

	cert = aux_attestation_get_certificate (&aux.test);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_set_static_certificate_twice (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	const struct der_cert *cert;

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = aux_attestation_set_static_certificate (&aux.test, X509_CERTCA_RSA_EE_DER,
		X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_set_static_certificate (&aux.test, X509_CERTCA_ECC_EE_DER,
		X509_CERTCA_ECC_EE_DER_LEN);
	CuAssertIntEquals (test, AUX_ATTESTATION_HAS_CERTIFICATE, status);

	cert = aux_attestation_get_certificate (&aux.test);
	CuAssertPtrNotNull (test, cert);
	CuAssertTrue (test, (X509_CERTCA_ECC_EE_DER != cert->cert));
	CuAssertIntEquals (test, X509_CERTCA_RSA_EE_DER_LEN, cert->length);

	status = testing_validate_array (X509_CERTCA_RSA_EE_DER, cert->cert, cert->length);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_set_static_certificate_after_create (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	const struct der_cert *cert;
	uint8_t *key_der;
	uint8_t *cert_der;

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	cert_der = platform_malloc (X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertPtrNotNull (test, cert_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);
	memcpy (cert_der, X509_CERTCA_RSA_EE_DER, X509_CERTCA_RSA_EE_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&aux.x509.mock, aux.x509.base.load_certificate, &aux.x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&aux.x509.mock, 0, 0);

	status |= mock_expect (&aux.rng.mock, aux.rng.base.generate_random_buffer, &aux.rng, 0,
		MOCK_ARG (8), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.rng.mock, 1, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN,
		0);

	status |= mock_expect (&aux.x509.mock, aux.x509.base.create_ca_signed_certificate, &aux.x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG_PTR_CONTAINS (X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN), MOCK_ARG (8),
		MOCK_ARG_PTR_CONTAINS ("AUX", 3), MOCK_ARG (X509_CERT_END_ENTITY),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG (HASH_TYPE_SHA256), MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));
	status |= mock_expect_save_arg (&aux.x509.mock, 0, 1);

	status |= mock_expect (&aux.x509.mock, aux.x509.base.get_certificate_der, &aux.x509, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.x509.mock, 1, &cert_der, sizeof (cert_der), -1);
	status |= mock_expect_output (&aux.x509.mock, 2, &X509_CERTCA_RSA_EE_DER_LEN,
		sizeof (X509_CERTCA_RSA_EE_DER_LEN), -1);

	status |= mock_expect (&aux.x509.mock, aux.x509.base.release_certificate, &aux.x509, 0,
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&aux.x509.mock, aux.x509.base.release_certificate, &aux.x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_create_certificate (&aux.test, &aux.x509.base, &aux.rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_set_static_certificate (&aux.test, X509_CERTCA_ECC_EE_DER,
		X509_CERTCA_ECC_EE_DER_LEN);
	CuAssertIntEquals (test, AUX_ATTESTATION_HAS_CERTIFICATE, status);

	cert = aux_attestation_get_certificate (&aux.test);
	CuAssertPtrNotNull (test, cert);
	CuAssertTrue (test, (X509_CERTCA_ECC_EE_DER != cert->cert));
	CuAssertIntEquals (test, X509_CERTCA_RSA_EE_DER_LEN, cert->length);

	status = testing_validate_array (X509_CERTCA_RSA_EE_DER, cert->cert, cert->length);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_get_certificate_null (CuTest *test)
{
	const struct der_cert *cert;

	TEST_START;

	cert = aux_attestation_get_certificate (NULL);
	CuAssertPtrEquals (test, NULL, (void*) cert);

}

static void aux_attestation_test_unseal_rsa_oaep_sha1 (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t *key_der;
	uint8_t attestation_key[32];
	uint8_t separator = 0;

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.init_private_key, &aux.rsa, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&aux.rsa.mock, 0, 0);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.decrypt, &aux.rsa, KEY_SEED_LEN,
		MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&aux.rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.release_key, &aux.rsa, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN,
		HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN), MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (SEALING_POLICY, SEALING_POLICY_LEN), MOCK_ARG (SEALING_POLICY_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);

	/* Derive encryption key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) ENCRYPTION_KEY_LABEL, ENCRYPTION_KEY_LABEL_LEN),
		MOCK_ARG (ENCRYPTION_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, ENCRYPTION_KEY, ENCRYPTION_KEY_LEN);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ENCRYPTION_KEY, attestation_key, ENCRYPTION_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_rsa_oaep_sha256 (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t *key_der;
	uint8_t attestation_key[32];
	uint8_t separator = 0;

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.init_private_key, &aux.rsa, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&aux.rsa.mock, 0, 0);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.decrypt, &aux.rsa, KEY_SEED_LEN,
		MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP_SHA256, KEY_SEED_ENCRYPT_OAEP_SHA256_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_SHA256_LEN), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA256), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&aux.rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.release_key, &aux.rsa, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN,
		HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN), MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (SEALING_POLICY, SEALING_POLICY_LEN), MOCK_ARG (SEALING_POLICY_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);

	/* Derive encryption key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) ENCRYPTION_KEY_LABEL, ENCRYPTION_KEY_LABEL_LEN),
		MOCK_ARG (ENCRYPTION_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, ENCRYPTION_KEY, ENCRYPTION_KEY_LEN);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP_SHA256, KEY_SEED_ENCRYPT_OAEP_SHA256_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA256, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT,
		CIPHER_TEXT_LEN, SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ENCRYPTION_KEY, attestation_key, ENCRYPTION_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_rsa_pkcs15 (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t attestation_key[32];

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_PKCS15, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, AUX_ATTESTATION_BAD_SEED_PARAM, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_ecdh_raw (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t attestation_key[32];
	uint8_t separator = 0;

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	/* Derive seed */
	status = mock_expect (&aux.ecc.mock, aux.ecc.base.init_public_key, &aux.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&aux.ecc.mock, 2, 0);

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.init_key_pair, &aux.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&aux.ecc.mock, 2, 1);

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.get_shared_secret_max_length, &aux.ecc, 32,
		MOCK_ARG_SAVED_ARG (1));

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.compute_shared_secret, &aux.ecc,
		KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (1), MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL,
		MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&aux.ecc.mock, 2, KEY_SEED, KEY_SEED_LEN, 3);

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.release_key_pair, &aux.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.release_key_pair, &aux.ecc, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN,
		HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN), MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (SEALING_POLICY, SEALING_POLICY_LEN), MOCK_ARG (SEALING_POLICY_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);

	/* Derive encryption key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) ENCRYPTION_KEY_LABEL, ENCRYPTION_KEY_LABEL_LEN),
		MOCK_ARG (ENCRYPTION_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, ENCRYPTION_KEY, ENCRYPTION_KEY_LEN);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, AUX_ATTESTATION_SEED_ECDH,
		AUX_ATTESTATION_PARAM_ECDH_RAW, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ENCRYPTION_KEY, attestation_key, ENCRYPTION_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_ecdh_sha256 (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t attestation_key[32];
	uint8_t separator = 0;

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	/* Derive seed */
	status = mock_expect (&aux.ecc.mock, aux.ecc.base.init_public_key, &aux.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&aux.ecc.mock, 2, 0);

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.init_key_pair, &aux.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&aux.ecc.mock, 2, 1);

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.get_shared_secret_max_length, &aux.ecc, 32,
		MOCK_ARG_SAVED_ARG (1));

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.compute_shared_secret, &aux.ecc,
		KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (1), MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL,
		MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&aux.ecc.mock, 2, KEY_SEED, KEY_SEED_LEN, 3);

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.release_key_pair, &aux.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.release_key_pair, &aux.ecc, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&aux.hash.mock, aux.hash.base.calculate_sha256, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (KEY_SEED, KEY_SEED_LEN), MOCK_ARG (KEY_SEED_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&aux.hash.mock, 2, KEY_SEED_HASH, KEY_SEED_HASH_LEN, 3);

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED_HASH, KEY_SEED_HASH_LEN,
		HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED_HASH, KEY_SEED_HASH_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, SIGNING_KEY_SEED_HASH, SIGNING_KEY_SEED_HASH_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&aux.hash, SIGNING_KEY_SEED_HASH,
		SIGNING_KEY_SEED_HASH_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN), MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (SEALING_POLICY, SEALING_POLICY_LEN), MOCK_ARG (SEALING_POLICY_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, SIGNING_KEY_SEED_HASH,
		SIGNING_KEY_SEED_HASH_LEN, NULL, SHA256_HASH_LENGTH, HASH_TYPE_SHA256,
		PAYLOAD_HMAC_SEED_HASH, PAYLOAD_HMAC_SEED_HASH_LEN);

	/* Derive encryption key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED_HASH, KEY_SEED_HASH_LEN,
		HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) ENCRYPTION_KEY_LABEL, ENCRYPTION_KEY_LABEL_LEN),
		MOCK_ARG (ENCRYPTION_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED_HASH, KEY_SEED_HASH_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, ENCRYPTION_KEY_SEED_HASH,
		ENCRYPTION_KEY_SEED_HASH_LEN);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, AUX_ATTESTATION_SEED_ECDH,
		AUX_ATTESTATION_PARAM_ECDH_SHA256, PAYLOAD_HMAC_SEED_HASH, HMAC_SHA256, CIPHER_TEXT,
		CIPHER_TEXT_LEN, SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ENCRYPTION_KEY_SEED_HASH, attestation_key,
		ENCRYPTION_KEY_SEED_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_pcr_sha256_unused_byte_nonzero (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t *key_der;
	uint8_t attestation_key[32];
	uint8_t bad_sealing[1][64];
	uint8_t separator = 0;

	TEST_START;

	memcpy (bad_sealing, SEALING_POLICY, sizeof (bad_sealing));
	bad_sealing[0][31] ^= 0x55;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.init_private_key, &aux.rsa, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&aux.rsa.mock, 0, 0);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.decrypt, &aux.rsa, KEY_SEED_LEN,
		MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&aux.rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.release_key, &aux.rsa, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN,
		HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN), MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (bad_sealing, sizeof (bad_sealing)), MOCK_ARG (sizeof (bad_sealing)));
	status |= hash_mock_expect_hmac_finish (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		(const uint8_t(*)[64]) bad_sealing, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, AUX_ATTESTATION_PCR_LENGTH_MISMATCH, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
static void aux_attestation_test_unseal_pcr_sha384 (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA384
		}
	};
	int status;
	uint8_t *key_der;
	uint8_t attestation_key[32];
	uint8_t separator = 0;

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE_SHA384,
		PCR0_VALUE_SHA384_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.init_private_key, &aux.rsa, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&aux.rsa.mock, 0, 0);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.decrypt, &aux.rsa, KEY_SEED_LEN,
		MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&aux.rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.release_key, &aux.rsa, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN,
		HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN), MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (SEALING_POLICY_SHA384, SEALING_POLICY_SHA384_LEN),
		MOCK_ARG (SEALING_POLICY_SHA384_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, PAYLOAD_SHA384_HMAC, PAYLOAD_SHA384_HMAC_LEN);

	/* Derive encryption key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) ENCRYPTION_KEY_LABEL, ENCRYPTION_KEY_LABEL_LEN),
		MOCK_ARG (ENCRYPTION_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, ENCRYPTION_KEY, ENCRYPTION_KEY_LEN);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_SHA384_HMAC, HMAC_SHA256, CIPHER_TEXT,
		CIPHER_TEXT_LEN, SEALING_POLICY_SHA384, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ENCRYPTION_KEY, attestation_key, ENCRYPTION_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_pcr_sha384_unused_byte_nonzero (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA384
		}
	};
	int status;
	uint8_t *key_der;
	uint8_t attestation_key[32];
	uint8_t bad_sealing[1][64];
	uint8_t separator = 0;

	TEST_START;

	memcpy (bad_sealing, SEALING_POLICY_SHA384, sizeof (bad_sealing));
	bad_sealing[0][15] ^= 0x55;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE_SHA384,
		PCR0_VALUE_SHA384_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.init_private_key, &aux.rsa, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&aux.rsa.mock, 0, 0);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.decrypt, &aux.rsa, KEY_SEED_LEN,
		MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&aux.rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.release_key, &aux.rsa, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN,
		HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN), MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (bad_sealing, sizeof (bad_sealing)), MOCK_ARG (sizeof (bad_sealing)));
	status |= hash_mock_expect_hmac_finish (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, PAYLOAD_SHA384_HMAC, PAYLOAD_SHA384_HMAC_LEN);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_SHA384_HMAC, HMAC_SHA256, CIPHER_TEXT,
		CIPHER_TEXT_LEN, (const uint8_t(*)[64]) bad_sealing, 1, attestation_key,
		sizeof (attestation_key));
	CuAssertIntEquals (test, AUX_ATTESTATION_PCR_LENGTH_MISMATCH, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}
#endif

#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
static void aux_attestation_test_unseal_pcr_sha512 (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA512
		}
	};
	int status;
	uint8_t *key_der;
	uint8_t attestation_key[32];
	uint8_t separator = 0;

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE_SHA512,
		PCR0_VALUE_SHA512_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.init_private_key, &aux.rsa, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&aux.rsa.mock, 0, 0);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.decrypt, &aux.rsa, KEY_SEED_LEN,
		MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&aux.rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.release_key, &aux.rsa, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN,
		HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN), MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (SEALING_POLICY_SHA512, SEALING_POLICY_SHA512_LEN),
		MOCK_ARG (SEALING_POLICY_SHA512_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, PAYLOAD_SHA512_HMAC, PAYLOAD_SHA512_HMAC_LEN);

	/* Derive encryption key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) ENCRYPTION_KEY_LABEL, ENCRYPTION_KEY_LABEL_LEN),
		MOCK_ARG (ENCRYPTION_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, ENCRYPTION_KEY, ENCRYPTION_KEY_LEN);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_SHA512_HMAC, HMAC_SHA256, CIPHER_TEXT,
		CIPHER_TEXT_LEN, SEALING_POLICY_SHA512, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ENCRYPTION_KEY, attestation_key, ENCRYPTION_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}
#endif

static void aux_attestation_test_unseal_pcr_mismatch (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t *key_der;
	uint8_t attestation_key[32];
	uint8_t bad_pcr[PCR0_VALUE_LEN];
	uint8_t separator = 0;

	TEST_START;

	memcpy (bad_pcr, PCR0_VALUE, PCR0_VALUE_LEN);
	bad_pcr[0] ^= 0x55;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), bad_pcr, sizeof (bad_pcr));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.init_private_key, &aux.rsa, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&aux.rsa.mock, 0, 0);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.decrypt, &aux.rsa, KEY_SEED_LEN,
		MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&aux.rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.release_key, &aux.rsa, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN,
		HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN), MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (SEALING_POLICY, SEALING_POLICY_LEN), MOCK_ARG (SEALING_POLICY_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, AUX_ATTESTATION_PCR_MISMATCH, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_bypass_pcr_check (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t *key_der;
	uint8_t attestation_key[32];
	uint8_t separator = 0;

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.init_private_key, &aux.rsa, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&aux.rsa.mock, 0, 0);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.decrypt, &aux.rsa, KEY_SEED_LEN,
		MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&aux.rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.release_key, &aux.rsa, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN,
		HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN), MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (SEALING_POLICY_BYPASS, SEALING_POLICY_BYPASS_LEN),
		MOCK_ARG (SEALING_POLICY_BYPASS_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, PAYLOAD_BYPASS_HMAC, PAYLOAD_BYPASS_HMAC_LEN);

	/* Derive encryption key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) ENCRYPTION_KEY_LABEL, ENCRYPTION_KEY_LABEL_LEN),
		MOCK_ARG (ENCRYPTION_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, ENCRYPTION_KEY, ENCRYPTION_KEY_LEN);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_BYPASS_HMAC, HMAC_SHA256, CIPHER_TEXT,
		CIPHER_TEXT_LEN, SEALING_POLICY_BYPASS, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ENCRYPTION_KEY, attestation_key, ENCRYPTION_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_multiple_pcr (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[3] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t *key_der;
	uint8_t attestation_key[32];
	uint8_t separator = 0;

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	status |= pcr_store_update_digest (&pcr, PCR_MEASUREMENT (1, 0), PCR1_VALUE, PCR1_VALUE_LEN);
	status |= pcr_store_update_digest (&pcr, PCR_MEASUREMENT (2, 0), PCR2_VALUE, PCR2_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.init_private_key, &aux.rsa, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&aux.rsa.mock, 0, 0);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.decrypt, &aux.rsa, KEY_SEED_LEN,
		MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&aux.rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.release_key, &aux.rsa, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN,
		HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN), MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (SEALING_POLICY_MULTIPLE, SEALING_POLICY_MULTIPLE_LEN),
		MOCK_ARG (SEALING_POLICY_MULTIPLE_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, PAYLOAD_MULTIPLE_HMAC, PAYLOAD_MULTIPLE_HMAC_LEN);

	/* Derive encryption key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) ENCRYPTION_KEY_LABEL, ENCRYPTION_KEY_LABEL_LEN),
		MOCK_ARG (ENCRYPTION_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, ENCRYPTION_KEY, ENCRYPTION_KEY_LEN);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_MULTIPLE_HMAC, HMAC_SHA256, CIPHER_TEXT,
		CIPHER_TEXT_LEN, SEALING_POLICY_MULTIPLE, 3, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ENCRYPTION_KEY, attestation_key, ENCRYPTION_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

#if defined HASH_ENABLE_SHA384 && defined HASH_ENABLE_SHA512 && \
	(PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
static void aux_attestation_test_unseal_multiple_pcr_different_lengths (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[6] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA384
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA512
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA384
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA512
		}
	};
	int status;
	uint8_t *key_der;
	uint8_t attestation_key[32];
	uint8_t separator = 0;

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	status |= pcr_store_update_digest (&pcr, PCR_MEASUREMENT (1, 0), PCR0_VALUE_SHA384,
		PCR0_VALUE_SHA384_LEN);
	status |= pcr_store_update_digest (&pcr, PCR_MEASUREMENT (2, 0), PCR0_VALUE_SHA512,
		PCR0_VALUE_SHA512_LEN);
	status |= pcr_store_update_digest (&pcr, PCR_MEASUREMENT (3, 0), PCR2_VALUE_SHA384,
		PCR2_VALUE_SHA384_LEN);
	status |= pcr_store_update_digest (&pcr, PCR_MEASUREMENT (4, 0), PCR1_VALUE, PCR1_VALUE_LEN);
	status |= pcr_store_update_digest (&pcr, PCR_MEASUREMENT (5, 0), PCR2_VALUE_SHA512,
		PCR2_VALUE_SHA512_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.init_private_key, &aux.rsa, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&aux.rsa.mock, 0, 0);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.decrypt, &aux.rsa, KEY_SEED_LEN,
		MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&aux.rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.release_key, &aux.rsa, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN,
		HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN), MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (SEALING_POLICY_MULTIPLE_ALGOS, SEALING_POLICY_MULTIPLE_ALGOS_LEN),
		MOCK_ARG (SEALING_POLICY_MULTIPLE_ALGOS_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, PAYLOAD_MULTIPLE_ALGOS_HMAC,
		PAYLOAD_MULTIPLE_ALGOS_HMAC_LEN);

	/* Derive encryption key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) ENCRYPTION_KEY_LABEL, ENCRYPTION_KEY_LABEL_LEN),
		MOCK_ARG (ENCRYPTION_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, ENCRYPTION_KEY, ENCRYPTION_KEY_LEN);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_MULTIPLE_ALGOS_HMAC, HMAC_SHA256, CIPHER_TEXT,
		CIPHER_TEXT_LEN, SEALING_POLICY_MULTIPLE_ALGOS, 6, attestation_key,
		sizeof (attestation_key));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ENCRYPTION_KEY, attestation_key, ENCRYPTION_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}
#endif

static void aux_attestation_test_unseal_multiple_pcr_mismatch (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[3] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t *key_der;
	uint8_t attestation_key[32];
	uint8_t bad_pcr[PCR0_VALUE_LEN];
	uint8_t separator = 0;

	TEST_START;

	memcpy (bad_pcr, PCR2_VALUE, PCR2_VALUE_LEN);
	bad_pcr[0] ^= 0x55;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	status |= pcr_store_update_digest (&pcr, PCR_MEASUREMENT (1, 0), PCR1_VALUE, PCR1_VALUE_LEN);
	status |= pcr_store_update_digest (&pcr, PCR_MEASUREMENT (2, 0), bad_pcr, sizeof (bad_pcr));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.init_private_key, &aux.rsa, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&aux.rsa.mock, 0, 0);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.decrypt, &aux.rsa, KEY_SEED_LEN,
		MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&aux.rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.release_key, &aux.rsa, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN,
		HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN), MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (SEALING_POLICY_MULTIPLE, SEALING_POLICY_MULTIPLE_LEN),
		MOCK_ARG (SEALING_POLICY_MULTIPLE_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, PAYLOAD_MULTIPLE_HMAC, PAYLOAD_MULTIPLE_HMAC_LEN);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_MULTIPLE_HMAC, HMAC_SHA256, CIPHER_TEXT,
		CIPHER_TEXT_LEN, SEALING_POLICY_MULTIPLE, 3, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, AUX_ATTESTATION_PCR_MISMATCH, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_multiple_pcr_unused_byte_nonzero (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[3] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t *key_der;
	uint8_t attestation_key[32];
	uint8_t bad_sealing[3][64];
	uint8_t separator = 0;

	TEST_START;

	memcpy (bad_sealing, SEALING_POLICY_MULTIPLE, sizeof (bad_sealing));
	bad_sealing[2][16] ^= 0x55;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	status |= pcr_store_update_digest (&pcr, PCR_MEASUREMENT (1, 0), PCR1_VALUE, PCR1_VALUE_LEN);
	status |= pcr_store_update_digest (&pcr, PCR_MEASUREMENT (2, 0), PCR2_VALUE, PCR2_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.init_private_key, &aux.rsa, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&aux.rsa.mock, 0, 0);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.decrypt, &aux.rsa, KEY_SEED_LEN,
		MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&aux.rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.release_key, &aux.rsa, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN,
		HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN), MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (bad_sealing, sizeof (bad_sealing)), MOCK_ARG (sizeof (bad_sealing)));
	status |= hash_mock_expect_hmac_finish (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, PAYLOAD_MULTIPLE_HMAC, PAYLOAD_MULTIPLE_HMAC_LEN);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_MULTIPLE_HMAC, HMAC_SHA256, CIPHER_TEXT,
		CIPHER_TEXT_LEN, (const uint8_t(*)[64]) bad_sealing, 3, attestation_key,
		sizeof (attestation_key));
	CuAssertIntEquals (test, AUX_ATTESTATION_PCR_LENGTH_MISMATCH, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_multiple_pcr_bypass_single (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[3] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t *key_der;
	uint8_t attestation_key[32];
	uint8_t separator = 0;

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	status |= pcr_store_update_digest (&pcr, PCR_MEASUREMENT (1, 0), PCR1_VALUE, PCR1_VALUE_LEN);
	status |= pcr_store_update_digest (&pcr, PCR_MEASUREMENT (2, 0), PCR2_VALUE, PCR2_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.init_private_key, &aux.rsa, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&aux.rsa.mock, 0, 0);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.decrypt, &aux.rsa, KEY_SEED_LEN,
		MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&aux.rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.release_key, &aux.rsa, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN,
		HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN), MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (SEALING_POLICY_SKIP, SEALING_POLICY_SKIP_LEN),
		MOCK_ARG (SEALING_POLICY_SKIP_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, PAYLOAD_SKIP_HMAC, PAYLOAD_SKIP_HMAC_LEN);

	/* Derive encryption key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) ENCRYPTION_KEY_LABEL, ENCRYPTION_KEY_LABEL_LEN),
		MOCK_ARG (ENCRYPTION_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, ENCRYPTION_KEY, ENCRYPTION_KEY_LEN);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_SKIP_HMAC, HMAC_SHA256, CIPHER_TEXT,
		CIPHER_TEXT_LEN, SEALING_POLICY_SKIP, 3, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ENCRYPTION_KEY, attestation_key, ENCRYPTION_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_multiple_pcr_bypass_multiple (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[3] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t *key_der;
	uint8_t attestation_key[32];
	uint8_t separator = 0;

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	status |= pcr_store_update_digest (&pcr, PCR_MEASUREMENT (1, 0), PCR1_VALUE, PCR1_VALUE_LEN);
	status |= pcr_store_update_digest (&pcr, PCR_MEASUREMENT (2, 0), PCR2_VALUE, PCR2_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.init_private_key, &aux.rsa, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&aux.rsa.mock, 0, 0);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.decrypt, &aux.rsa, KEY_SEED_LEN,
		MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&aux.rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.release_key, &aux.rsa, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN,
		HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN), MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (SEALING_POLICY_BYPASS_MULTIPLE, SEALING_POLICY_BYPASS_MULTIPLE_LEN),
		MOCK_ARG (SEALING_POLICY_BYPASS_MULTIPLE_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, PAYLOAD_BYPASS_MULTIPLE_HMAC,
		PAYLOAD_BYPASS_MULTIPLE_HMAC_LEN);

	/* Derive encryption key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) ENCRYPTION_KEY_LABEL, ENCRYPTION_KEY_LABEL_LEN),
		MOCK_ARG (ENCRYPTION_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, ENCRYPTION_KEY, ENCRYPTION_KEY_LEN);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_BYPASS_MULTIPLE_HMAC, HMAC_SHA256, CIPHER_TEXT,
		CIPHER_TEXT_LEN, SEALING_POLICY_BYPASS_MULTIPLE, 3, attestation_key,
		sizeof (attestation_key));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ENCRYPTION_KEY, attestation_key, ENCRYPTION_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_unused_pcrs (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[3] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t *key_der;
	uint8_t attestation_key[32];
	uint8_t separator = 0;

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	status |= pcr_store_update_digest (&pcr, PCR_MEASUREMENT (1, 0), PCR1_VALUE, PCR1_VALUE_LEN);
	status |= pcr_store_update_digest (&pcr, PCR_MEASUREMENT (2, 0), PCR2_VALUE, PCR2_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.init_private_key, &aux.rsa, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&aux.rsa.mock, 0, 0);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.decrypt, &aux.rsa, KEY_SEED_LEN,
		MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&aux.rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.release_key, &aux.rsa, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN,
		HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN), MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (SEALING_POLICY, SEALING_POLICY_LEN), MOCK_ARG (SEALING_POLICY_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);

	/* Derive encryption key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) ENCRYPTION_KEY_LABEL, ENCRYPTION_KEY_LABEL_LEN),
		MOCK_ARG (ENCRYPTION_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, ENCRYPTION_KEY, ENCRYPTION_KEY_LEN);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ENCRYPTION_KEY, attestation_key, ENCRYPTION_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_unsupported_pcr_bypassed (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[2] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t *key_der;
	uint8_t attestation_key[32];
	uint8_t separator = 0;

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	status |= pcr_store_update_digest (&pcr, PCR_MEASUREMENT (1, 0), PCR1_VALUE, PCR1_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.init_private_key, &aux.rsa, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&aux.rsa.mock, 0, 0);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.decrypt, &aux.rsa, KEY_SEED_LEN,
		MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&aux.rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.release_key, &aux.rsa, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN,
		HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN), MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (SEALING_POLICY_BYPASS_MULTIPLE, SEALING_POLICY_BYPASS_MULTIPLE_LEN),
		MOCK_ARG (SEALING_POLICY_BYPASS_MULTIPLE_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, PAYLOAD_BYPASS_MULTIPLE_HMAC,
		PAYLOAD_BYPASS_MULTIPLE_HMAC_LEN);

	/* Derive encryption key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) ENCRYPTION_KEY_LABEL, ENCRYPTION_KEY_LABEL_LEN),
		MOCK_ARG (ENCRYPTION_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, ENCRYPTION_KEY, ENCRYPTION_KEY_LEN);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_BYPASS_MULTIPLE_HMAC, HMAC_SHA256, CIPHER_TEXT,
		CIPHER_TEXT_LEN, SEALING_POLICY_BYPASS_MULTIPLE, 3, attestation_key,
		sizeof (attestation_key));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ENCRYPTION_KEY, attestation_key, ENCRYPTION_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_bad_hmac (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t *key_der;
	uint8_t attestation_key[32];
	uint8_t separator = 0;

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.init_private_key, &aux.rsa, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&aux.rsa.mock, 0, 0);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.decrypt, &aux.rsa, KEY_SEED_LEN,
		MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&aux.rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.release_key, &aux.rsa, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN,
		HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN), MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (SEALING_POLICY, SEALING_POLICY_LEN), MOCK_ARG (SEALING_POLICY_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_BYPASS_HMAC, HMAC_SHA256, CIPHER_TEXT,
		CIPHER_TEXT_LEN, SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, AUX_ATTESTATION_HMAC_MISMATCH, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_rsa_oaep_sha1_no_mock (CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t *key_der;
	uint8_t attestation_key[32];

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_init_dependencies (test, &aux);

	status = aux_attestation_init (&aux.test, &aux.keystore.base, &rsa.base, &aux.riot,
		&aux.ecc.base);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ENCRYPTION_KEY, attestation_key, ENCRYPTION_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_rsa_oaep_sha256_no_mock (CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t *key_der;
	uint8_t attestation_key[32];

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_init_dependencies (test, &aux);

	status = aux_attestation_init (&aux.test, &aux.keystore.base, &rsa.base, &aux.riot,
		&aux.ecc.base);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP_SHA256, KEY_SEED_ENCRYPT_OAEP_SHA256_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA256, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT,
		CIPHER_TEXT_LEN, SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ENCRYPTION_KEY, attestation_key, ENCRYPTION_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_ecdh_raw_no_mock (CuTest *test)
{
	ECC_TESTING_ENGINE (ecc);
	HASH_TESTING_ENGINE (hash);
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t attestation_key[32];

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_init_dependencies (test, &aux);

	status = aux_attestation_init (&aux.test, &aux.keystore.base, &aux.rsa.base, &aux.riot,
		&ecc.base);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, AUX_ATTESTATION_SEED_ECDH,
		AUX_ATTESTATION_PARAM_ECDH_RAW, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ENCRYPTION_KEY, attestation_key, ENCRYPTION_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_ecdh_sha256_no_mock (CuTest *test)
{
	ECC_TESTING_ENGINE (ecc);
	HASH_TESTING_ENGINE (hash);
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t attestation_key[32];

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_init_dependencies (test, &aux);

	status = aux_attestation_init (&aux.test, &aux.keystore.base, &aux.rsa.base, &aux.riot,
		&ecc.base);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, AUX_ATTESTATION_SEED_ECDH,
		AUX_ATTESTATION_PARAM_ECDH_SHA256, PAYLOAD_HMAC_SEED_HASH, HMAC_SHA256, CIPHER_TEXT,
		CIPHER_TEXT_LEN, SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ENCRYPTION_KEY_SEED_HASH, attestation_key,
		ENCRYPTION_KEY_SEED_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	pcr_store_release (&pcr);
}

#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
static void aux_attestation_test_unseal_pcr_sha384_no_mock (CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA384
		}
	};
	int status;
	uint8_t *key_der;
	uint8_t attestation_key[32];

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_init_dependencies (test, &aux);

	status = aux_attestation_init (&aux.test, &aux.keystore.base, &rsa.base, &aux.riot,
		&aux.ecc.base);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE_SHA384,
		PCR0_VALUE_SHA384_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_SHA384_HMAC, HMAC_SHA256, CIPHER_TEXT,
		CIPHER_TEXT_LEN, SEALING_POLICY_SHA384, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ENCRYPTION_KEY, attestation_key, ENCRYPTION_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	pcr_store_release (&pcr);
}
#endif

#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
static void aux_attestation_test_unseal_pcr_sha512_no_mock (CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA512
		}
	};
	int status;
	uint8_t *key_der;
	uint8_t attestation_key[32];

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_init_dependencies (test, &aux);

	status = aux_attestation_init (&aux.test, &aux.keystore.base, &rsa.base, &aux.riot,
		&aux.ecc.base);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE_SHA512,
		PCR0_VALUE_SHA512_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_SHA512_HMAC, HMAC_SHA256, CIPHER_TEXT,
		CIPHER_TEXT_LEN, SEALING_POLICY_SHA512, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ENCRYPTION_KEY, attestation_key, ENCRYPTION_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	pcr_store_release (&pcr);
}
#endif

static void aux_attestation_test_unseal_rsa_no_ecc (CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t *key_der;
	uint8_t attestation_key[32];

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_init_dependencies (test, &aux);

	status = aux_attestation_init (&aux.test, &aux.keystore.base, &rsa.base, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ENCRYPTION_KEY, attestation_key, ENCRYPTION_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_ecdh_no_rsa (CuTest *test)
{
	ECC_TESTING_ENGINE (ecc);
	HASH_TESTING_ENGINE (hash);
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t attestation_key[32];

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_init_dependencies (test, &aux);

	status = aux_attestation_init (&aux.test, NULL, NULL, &aux.riot, &ecc.base);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, AUX_ATTESTATION_SEED_ECDH,
		AUX_ATTESTATION_PARAM_ECDH_RAW, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ENCRYPTION_KEY, attestation_key, ENCRYPTION_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_null (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t attestation_key[32];

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (NULL, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_unseal (&aux.test, NULL, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, NULL, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		NULL, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, 0, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, NULL, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256, NULL, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, 0,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		NULL, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 0, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, NULL, sizeof (attestation_key));
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_invalid_key_length (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t attestation_key[48];

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr,
		(enum aux_attestation_key_length) 48, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		AUX_ATTESTATION_SEED_RSA, AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256,
		CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, AUX_ATTESTATION_UNSUPPORTED_KEY_LENGTH, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_invalid_hmac_type (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t attestation_key[32];

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA1, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, AUX_ATTESTATION_UNSUPPORTED_HMAC, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_buffer_too_small (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t attestation_key[32 - 1];

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, AUX_ATTESTATION_BUFFER_TOO_SMALL, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, 0);
	CuAssertIntEquals (test, AUX_ATTESTATION_BUFFER_TOO_SMALL, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_no_rsa_support (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t attestation_key[32];

	TEST_START;

	aux_attestation_testing_init_dependencies (test, &aux);

	status = aux_attestation_init (&aux.test, NULL, NULL, &aux.riot, &aux.ecc.base);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, AUX_ATTESTATION_UNSUPPORTED_CRYPTO, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_no_ecc_support (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t attestation_key[32];

	TEST_START;

	aux_attestation_testing_init_dependencies (test, &aux);

	status = aux_attestation_init (&aux.test, &aux.keystore.base, &aux.rsa.base, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, AUX_ATTESTATION_SEED_ECDH,
		AUX_ATTESTATION_PARAM_ECDH_RAW, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, AUX_ATTESTATION_UNSUPPORTED_CRYPTO, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_unknown_seed (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t attestation_key[32];

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, (enum aux_attestation_seed_type) 2,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, AUX_ATTESTATION_UNKNOWN_SEED, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_rsa_invalid_padding (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t attestation_key[32];

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		(enum aux_attestation_seed_param) 3, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT,
		CIPHER_TEXT_LEN, SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, AUX_ATTESTATION_BAD_SEED_PARAM, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_rsa_load_error (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t *key_der = NULL;
	uint8_t attestation_key[32];

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore,
		KEYSTORE_LOAD_FAILED, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, KEYSTORE_LOAD_FAILED, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_rsa_init_key_error (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t *key_der;
	uint8_t attestation_key[32];

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.init_private_key, &aux.rsa,
		RSA_ENGINE_KEY_PAIR_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, RSA_ENGINE_KEY_PAIR_FAILED, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_rsa_decrypt_error (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t *key_der;
	uint8_t attestation_key[32];

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.init_private_key, &aux.rsa, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&aux.rsa.mock, 0, 0);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.decrypt, &aux.rsa, RSA_ENGINE_DECRYPT_FAILED,
		MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.release_key, &aux.rsa, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, RSA_ENGINE_DECRYPT_FAILED, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_ecdh_invalid_padding (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t attestation_key[32];

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, AUX_ATTESTATION_SEED_ECDH,
		(enum aux_attestation_seed_param) 2, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT,
		CIPHER_TEXT_LEN, SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, AUX_ATTESTATION_BAD_SEED_PARAM, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_ecdh_public_key_error (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t attestation_key[32];

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	/* Derive seed */
	status = mock_expect (&aux.ecc.mock, aux.ecc.base.init_public_key, &aux.ecc,
		ECC_ENGINE_PUBLIC_KEY_FAILED, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, AUX_ATTESTATION_SEED_ECDH,
		AUX_ATTESTATION_PARAM_ECDH_RAW, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, ECC_ENGINE_PUBLIC_KEY_FAILED, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_ecdh_private_key_error (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t attestation_key[32];

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	/* Derive seed */
	status = mock_expect (&aux.ecc.mock, aux.ecc.base.init_public_key, &aux.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&aux.ecc.mock, 2, 0);

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.init_key_pair, &aux.ecc,
		ECC_ENGINE_KEY_PAIR_FAILED,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.release_key_pair, &aux.ecc, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, AUX_ATTESTATION_SEED_ECDH,
		AUX_ATTESTATION_PARAM_ECDH_RAW, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, ECC_ENGINE_KEY_PAIR_FAILED, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_ecdh_secret_length_error (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t attestation_key[32];

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	/* Derive seed */
	status = mock_expect (&aux.ecc.mock, aux.ecc.base.init_public_key, &aux.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&aux.ecc.mock, 2, 0);

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.init_key_pair, &aux.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&aux.ecc.mock, 2, 1);

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.get_shared_secret_max_length, &aux.ecc,
		ECC_ENGINE_SECRET_LENGTH_FAILED, MOCK_ARG_SAVED_ARG (1));

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.release_key_pair, &aux.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.release_key_pair, &aux.ecc, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, AUX_ATTESTATION_SEED_ECDH,
		AUX_ATTESTATION_PARAM_ECDH_RAW, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, ECC_ENGINE_SECRET_LENGTH_FAILED, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_ecdh_shared_secret_error (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t attestation_key[32];

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	/* Derive seed */
	status = mock_expect (&aux.ecc.mock, aux.ecc.base.init_public_key, &aux.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&aux.ecc.mock, 2, 0);

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.init_key_pair, &aux.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&aux.ecc.mock, 2, 1);

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.get_shared_secret_max_length, &aux.ecc, 32,
		MOCK_ARG_SAVED_ARG (1));

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.compute_shared_secret, &aux.ecc,
		ECC_ENGINE_SHARED_SECRET_FAILED, MOCK_ARG_SAVED_ARG (1), MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.release_key_pair, &aux.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.release_key_pair, &aux.ecc, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, AUX_ATTESTATION_SEED_ECDH,
		AUX_ATTESTATION_PARAM_ECDH_RAW, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, ECC_ENGINE_SHARED_SECRET_FAILED, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_ecdh_hash_error (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t attestation_key[32];

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	/* Derive seed */
	status = mock_expect (&aux.ecc.mock, aux.ecc.base.init_public_key, &aux.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&aux.ecc.mock, 2, 0);

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.init_key_pair, &aux.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&aux.ecc.mock, 2, 1);

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.get_shared_secret_max_length, &aux.ecc, 32,
		MOCK_ARG_SAVED_ARG (1));

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.compute_shared_secret, &aux.ecc,
		KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (1), MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL,
		MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&aux.ecc.mock, 2, KEY_SEED, KEY_SEED_LEN, 3);

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.release_key_pair, &aux.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.release_key_pair, &aux.ecc, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&aux.hash.mock, aux.hash.base.calculate_sha256, &aux.hash,
		HASH_ENGINE_SHA256_FAILED, MOCK_ARG_PTR_CONTAINS (KEY_SEED, KEY_SEED_LEN),
		MOCK_ARG (KEY_SEED_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, AUX_ATTESTATION_SEED_ECDH,
		AUX_ATTESTATION_PARAM_ECDH_SHA256, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_signing_key_kdf_error (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t *key_der;
	uint8_t attestation_key[32];

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.init_private_key, &aux.rsa, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&aux.rsa.mock, 0, 0);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.decrypt, &aux.rsa, KEY_SEED_LEN,
		MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&aux.rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.release_key, &aux.rsa, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= mock_expect (&aux.hash.mock, aux.hash.base.start_sha256, &aux.hash,
		HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_validate_init_error (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t *key_der;
	uint8_t attestation_key[32];
	uint8_t separator = 0;

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.init_private_key, &aux.rsa, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&aux.rsa.mock, 0, 0);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.decrypt, &aux.rsa, KEY_SEED_LEN,
		MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&aux.rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.release_key, &aux.rsa, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= mock_expect (&aux.hash.mock, aux.hash.base.start_sha256, &aux.hash,
		HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_validate_hash_cipher_error (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t *key_der;
	uint8_t attestation_key[32];
	uint8_t separator = 0;

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.init_private_key, &aux.rsa, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&aux.rsa.mock, 0, 0);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.decrypt, &aux.rsa, KEY_SEED_LEN,
		MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&aux.rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.release_key, &aux.rsa, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN,
		HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash,
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN),
		MOCK_ARG (CIPHER_TEXT_LEN));

	status |= mock_expect (&aux.hash.mock, aux.hash.base.cancel, &aux.hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_validate_hash_policy_error (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t *key_der;
	uint8_t attestation_key[32];
	uint8_t separator = 0;

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.init_private_key, &aux.rsa, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&aux.rsa.mock, 0, 0);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.decrypt, &aux.rsa, KEY_SEED_LEN,
		MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&aux.rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.release_key, &aux.rsa, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN,
		HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN), MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash,
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_PTR_CONTAINS (SEALING_POLICY, SEALING_POLICY_LEN),
		MOCK_ARG (SEALING_POLICY_LEN));

	status |= mock_expect (&aux.hash.mock, aux.hash.base.cancel, &aux.hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_validate_finish_error (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t *key_der;
	uint8_t attestation_key[32];
	uint8_t separator = 0;

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.init_private_key, &aux.rsa, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&aux.rsa.mock, 0, 0);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.decrypt, &aux.rsa, KEY_SEED_LEN,
		MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&aux.rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.release_key, &aux.rsa, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN,
		HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN), MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (SEALING_POLICY, SEALING_POLICY_LEN), MOCK_ARG (SEALING_POLICY_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.finish, &aux.hash,
		HASH_ENGINE_FINISH_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));

	status |= mock_expect (&aux.hash.mock, aux.hash.base.cancel, &aux.hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_unsupported_pcr (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[2] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		},
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t *key_der;
	uint8_t attestation_key[32];
	uint8_t separator = 0;

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	status |= pcr_store_update_digest (&pcr, PCR_MEASUREMENT (1, 0), PCR1_VALUE, PCR1_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.init_private_key, &aux.rsa, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&aux.rsa.mock, 0, 0);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.decrypt, &aux.rsa, KEY_SEED_LEN,
		MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&aux.rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.release_key, &aux.rsa, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN,
		HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN), MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (SEALING_POLICY_MULTIPLE, SEALING_POLICY_MULTIPLE_LEN),
		MOCK_ARG (SEALING_POLICY_MULTIPLE_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, PAYLOAD_MULTIPLE_HMAC, PAYLOAD_MULTIPLE_HMAC_LEN);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_MULTIPLE_HMAC, HMAC_SHA256, CIPHER_TEXT,
		CIPHER_TEXT_LEN, SEALING_POLICY_MULTIPLE, 3, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, PCR_INVALID_PCR, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_compute_pcr_error (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 1,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t *key_der;
	uint8_t attestation_key[32];
	uint8_t separator = 0;

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.init_private_key, &aux.rsa, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&aux.rsa.mock, 0, 0);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.decrypt, &aux.rsa, KEY_SEED_LEN,
		MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&aux.rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.release_key, &aux.rsa, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN,
		HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN), MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (SEALING_POLICY, SEALING_POLICY_LEN), MOCK_ARG (SEALING_POLICY_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);

	/* Compute the PCR. */
	status |= mock_expect (&aux.hash.mock, aux.hash.base.start_sha256, &aux.hash,
		HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_unseal_encryption_key_kdf_error (CuTest *test)
{
	struct aux_attestation_testing aux;
	struct pcr_store pcr;
	const struct pcr_config pcr_config[1] = {
		{
			.num_measurements = 0,
			.measurement_algo = HASH_TYPE_SHA256
		}
	};
	int status;
	uint8_t *key_der;
	uint8_t attestation_key[32];
	uint8_t separator = 0;

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = pcr_store_init (&pcr, pcr_config, ARRAY_SIZE (pcr_config));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&pcr, PCR_MEASUREMENT (0, 0), PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.init_private_key, &aux.rsa, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&aux.rsa.mock, 0, 0);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.decrypt, &aux.rsa, KEY_SEED_LEN,
		MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&aux.rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.release_key, &aux.rsa, 0,
		MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&aux.hash, KEY_SEED, KEY_SEED_LEN, HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN - 1));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN,
		HASH_TYPE_SHA256);
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN), MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&aux.hash.mock, aux.hash.base.update, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (SEALING_POLICY, SEALING_POLICY_LEN), MOCK_ARG (SEALING_POLICY_LEN));
	status |= hash_mock_expect_hmac_finish (&aux.hash, SIGNING_KEY, SIGNING_KEY_LEN, NULL,
		SHA256_HASH_LENGTH, HASH_TYPE_SHA256, PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);

	/* Derive encryption key */
	status |= mock_expect (&aux.hash.mock, aux.hash.base.start_sha256, &aux.hash,
		HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_unseal (&aux.test, &aux.hash.base, &pcr, AUX_ATTESTATION_KEY_256BIT,
		KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN, AUX_ATTESTATION_SEED_RSA,
		AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, 1, attestation_key, sizeof (attestation_key));
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	aux_attestation_testing_validate_and_release (test, &aux);
	pcr_store_release (&pcr);
}

static void aux_attestation_test_erase_key (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	const struct der_cert *cert;

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.erase_key, &aux.keystore, 0,
		MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_erase_key (&aux.test);
	CuAssertIntEquals (test, 0, status);

	cert = aux_attestation_get_certificate (&aux.test);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_erase_key_with_certificate (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	const struct der_cert *cert;
	uint8_t *cert_der;

	TEST_START;

	cert_der = platform_malloc (X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertPtrNotNull (test, cert_der);

	memcpy (cert_der, X509_CERTCA_RSA_EE_DER, X509_CERTCA_RSA_EE_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = aux_attestation_set_certificate (&aux.test, cert_der, X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.erase_key, &aux.keystore, 0,
		MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_erase_key (&aux.test);
	CuAssertIntEquals (test, 0, status);

	cert = aux_attestation_get_certificate (&aux.test);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_erase_key_with_static_certificate (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	const struct der_cert *cert;

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = aux_attestation_set_static_certificate (&aux.test, X509_CERTCA_RSA_EE_DER,
		X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.erase_key, &aux.keystore, 0,
		MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_erase_key (&aux.test);
	CuAssertIntEquals (test, 0, status);

	cert = aux_attestation_get_certificate (&aux.test);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_erase_key_null (CuTest *test)
{
	int status;

	TEST_START;

	status = aux_attestation_erase_key (NULL);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);
}

static void aux_attestation_test_erase_key_no_rsa_support (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;

	TEST_START;

	aux_attestation_testing_init_dependencies (test, &aux);

	status = aux_attestation_init (&aux.test, NULL, NULL, &aux.riot, &aux.ecc.base);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_erase_key (&aux.test);
	CuAssertIntEquals (test, AUX_ATTESTATION_UNSUPPORTED_CRYPTO, status);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_erase_key_erase_error (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	const struct der_cert *cert;
	uint8_t *cert_der;

	TEST_START;

	cert_der = platform_malloc (X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertPtrNotNull (test, cert_der);

	memcpy (cert_der, X509_CERTCA_RSA_EE_DER, X509_CERTCA_RSA_EE_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = aux_attestation_set_certificate (&aux.test, cert_der, X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.erase_key, &aux.keystore,
		KEYSTORE_ERASE_FAILED, MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_erase_key (&aux.test);
	CuAssertIntEquals (test, KEYSTORE_ERASE_FAILED, status);

	cert = aux_attestation_get_certificate (&aux.test);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_decrypt (CuTest *test)
{
	struct aux_attestation_testing aux;
	uint8_t decrypted[RSA_KEY_LENGTH_3K];
	uint8_t *key_der;
	int status;

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.init_private_key, &aux.rsa, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&aux.rsa.mock, 0, 0);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.decrypt, &aux.rsa, KEY_SEED_LEN,
		MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (decrypted)));
	status |= mock_expect_output (&aux.rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.release_key, &aux.rsa, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_decrypt (&aux.test, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		NULL, 0, HASH_TYPE_SHA1, decrypted, sizeof (decrypted));
	CuAssertIntEquals (test, KEY_SEED_LEN, status);

	status = testing_validate_array (KEY_SEED, decrypted, KEY_SEED_LEN);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_decrypt_with_label (CuTest *test)
{
	struct aux_attestation_testing aux;
	uint8_t decrypted[RSA_KEY_LENGTH_3K];
	uint8_t *key_der;
	int status;

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.init_private_key, &aux.rsa, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&aux.rsa.mock, 0, 0);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.decrypt, &aux.rsa, KEY_SEED_LEN,
		MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_ENCRYPT_LABEL, RSA_ENCRYPT_LABEL_LEN),
		MOCK_ARG (RSA_ENCRYPT_LABEL_LEN), MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (decrypted)));
	status |= mock_expect_output (&aux.rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.release_key, &aux.rsa, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_decrypt (&aux.test, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		(uint8_t*) RSA_ENCRYPT_LABEL, RSA_ENCRYPT_LABEL_LEN, HASH_TYPE_SHA1, decrypted,
		sizeof (decrypted));
	CuAssertIntEquals (test, KEY_SEED_LEN, status);

	status = testing_validate_array (KEY_SEED, decrypted, KEY_SEED_LEN);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_decrypt_sha256 (CuTest *test)
{
	struct aux_attestation_testing aux;
	uint8_t decrypted[RSA_KEY_LENGTH_3K];
	uint8_t *key_der;
	int status;

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.init_private_key, &aux.rsa, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&aux.rsa.mock, 0, 0);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.decrypt, &aux.rsa, KEY_SEED_LEN,
		MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA256), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (decrypted)));
	status |= mock_expect_output (&aux.rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.release_key, &aux.rsa, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_decrypt (&aux.test, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		NULL, 0, HASH_TYPE_SHA256, decrypted, sizeof (decrypted));
	CuAssertIntEquals (test, KEY_SEED_LEN, status);

	status = testing_validate_array (KEY_SEED, decrypted, KEY_SEED_LEN);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_decrypt_no_mock (CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	struct aux_attestation_testing aux;
	uint8_t decrypted[RSA_KEY_LENGTH_3K];
	uint8_t *key_der;
	int status;

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_init_dependencies (test, &aux);

	status = aux_attestation_init (&aux.test, &aux.keystore.base, &rsa.base, &aux.riot,
		&aux.ecc.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_decrypt (&aux.test, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		NULL, 0, HASH_TYPE_SHA1, decrypted, sizeof (decrypted));
	CuAssertIntEquals (test, KEY_SEED_LEN, status);

	status = testing_validate_array (KEY_SEED, decrypted, KEY_SEED_LEN);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void aux_attestation_test_decrypt_sha256_no_mock (CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	struct aux_attestation_testing aux;
	uint8_t decrypted[RSA_KEY_LENGTH_3K];
	uint8_t *key_der;
	int status;

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_init_dependencies (test, &aux);

	status = aux_attestation_init (&aux.test, &aux.keystore.base, &rsa.base, &aux.riot,
		&aux.ecc.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_decrypt (&aux.test, KEY_SEED_ENCRYPT_OAEP_SHA256,
		KEY_SEED_ENCRYPT_OAEP_SHA256_LEN, NULL, 0, HASH_TYPE_SHA256, decrypted, sizeof (decrypted));
	CuAssertIntEquals (test, KEY_SEED_LEN, status);

	status = testing_validate_array (KEY_SEED, decrypted, KEY_SEED_LEN);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void aux_attestation_test_decrypt_null (CuTest *test)
{
	struct aux_attestation_testing aux;
	uint8_t decrypted[RSA_KEY_LENGTH_3K];
	int status;

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = aux_attestation_decrypt (NULL, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		NULL, 0, HASH_TYPE_SHA1, decrypted, sizeof (decrypted));
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_decrypt (&aux.test, NULL, KEY_SEED_ENCRYPT_OAEP_LEN,
		NULL, 0, HASH_TYPE_SHA1, decrypted, sizeof (decrypted));
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_decrypt (&aux.test, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		NULL, 0, HASH_TYPE_SHA1, NULL, sizeof (decrypted));
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_decrypt_no_rsa_support (CuTest *test)
{
	struct aux_attestation_testing aux;
	uint8_t decrypted[RSA_KEY_LENGTH_3K];
	int status;

	TEST_START;

	aux_attestation_testing_init_dependencies (test, &aux);

	status = aux_attestation_init (&aux.test, NULL, NULL, &aux.riot, &aux.ecc.base);
	CuAssertIntEquals (test, 0, status);


	status = aux_attestation_decrypt (&aux.test, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		NULL, 0, HASH_TYPE_SHA1, decrypted, sizeof (decrypted));
	CuAssertIntEquals (test, AUX_ATTESTATION_UNSUPPORTED_CRYPTO, status);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_decrypt_load_error (CuTest *test)
{
	struct aux_attestation_testing aux;
	uint8_t decrypted[RSA_KEY_LENGTH_3K];
	int status;

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore,
		KEYSTORE_LOAD_FAILED, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_decrypt (&aux.test, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		NULL, 0, HASH_TYPE_SHA1, decrypted, sizeof (decrypted));
	CuAssertIntEquals (test, KEYSTORE_LOAD_FAILED, status);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_decrypt_init_key_error (CuTest *test)
{
	struct aux_attestation_testing aux;
	uint8_t decrypted[RSA_KEY_LENGTH_3K];
	uint8_t *key_der;
	int status;

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.init_private_key, &aux.rsa,
		RSA_ENGINE_KEY_PAIR_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_decrypt (&aux.test, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		NULL, 0, HASH_TYPE_SHA1, decrypted, sizeof (decrypted));
	CuAssertIntEquals (test, RSA_ENGINE_KEY_PAIR_FAILED, status);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_decrypt_error (CuTest *test)
{
	struct aux_attestation_testing aux;
	uint8_t decrypted[RSA_KEY_LENGTH_3K];
	uint8_t *key_der;
	int status;

	TEST_START;

	key_der = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	aux_attestation_testing_init (test, &aux);

	status = mock_expect (&aux.keystore.mock, aux.keystore.base.load_key, &aux.keystore, 0,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&aux.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&aux.keystore.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.init_private_key, &aux.rsa, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA3K_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&aux.rsa.mock, 0, 0);

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.decrypt, &aux.rsa, RSA_ENGINE_DECRYPT_FAILED,
		MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (decrypted)));

	status |= mock_expect (&aux.rsa.mock, aux.rsa.base.release_key, &aux.rsa, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_decrypt (&aux.test, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		NULL, 0, HASH_TYPE_SHA1, decrypted, sizeof (decrypted));
	CuAssertIntEquals (test, RSA_ENGINE_DECRYPT_FAILED, status);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_generate_ecdh_seed (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	uint8_t seed[32];

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = mock_expect (&aux.ecc.mock, aux.ecc.base.init_public_key, &aux.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&aux.ecc.mock, 2, 0);

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.init_key_pair, &aux.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&aux.ecc.mock, 2, 1);

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.get_shared_secret_max_length, &aux.ecc, 32,
		MOCK_ARG_SAVED_ARG (1));

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.compute_shared_secret, &aux.ecc,
		KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (1), MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&aux.ecc.mock, 2, KEY_SEED, KEY_SEED_LEN, 3);

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.release_key_pair, &aux.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.release_key_pair, &aux.ecc, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_generate_ecdh_seed (&aux.test, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		NULL, seed, sizeof (seed));
	CuAssertIntEquals (test, KEY_SEED_LEN, status);

	status = testing_validate_array (KEY_SEED, seed, KEY_SEED_LEN);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_generate_ecdh_seed_sha256 (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	uint8_t seed[32];

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = mock_expect (&aux.ecc.mock, aux.ecc.base.init_public_key, &aux.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&aux.ecc.mock, 2, 0);

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.init_key_pair, &aux.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&aux.ecc.mock, 2, 1);

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.get_shared_secret_max_length, &aux.ecc, 32,
		MOCK_ARG_SAVED_ARG (1));

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.compute_shared_secret, &aux.ecc,
		KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (1), MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&aux.ecc.mock, 2, KEY_SEED, KEY_SEED_LEN, 3);

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.release_key_pair, &aux.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.release_key_pair, &aux.ecc, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&aux.hash.mock, aux.hash.base.calculate_sha256, &aux.hash, 0,
		MOCK_ARG_PTR_CONTAINS (KEY_SEED, KEY_SEED_LEN), MOCK_ARG (KEY_SEED_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&aux.hash.mock, 2, KEY_SEED_HASH, KEY_SEED_HASH_LEN, 3);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_generate_ecdh_seed (&aux.test, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&aux.hash.base, seed, sizeof (seed));
	CuAssertIntEquals (test, KEY_SEED_HASH_LEN, status);

	status = testing_validate_array (KEY_SEED_HASH, seed, KEY_SEED_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_generate_ecdh_seed_no_mock (CuTest *test)
{
	ECC_TESTING_ENGINE (ecc);
	struct aux_attestation_testing aux;
	int status;
	uint8_t seed[32];

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_init_dependencies (test, &aux);

	status = aux_attestation_init (&aux.test, &aux.keystore.base, &aux.rsa.base, &aux.riot,
		&ecc.base);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_generate_ecdh_seed (&aux.test, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		NULL, seed, sizeof (seed));
	CuAssertIntEquals (test, KEY_SEED_LEN, status);

	status = testing_validate_array (KEY_SEED, seed, KEY_SEED_LEN);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void aux_attestation_test_generate_ecdh_seed_sha256_no_mock (CuTest *test)
{
	ECC_TESTING_ENGINE (ecc);
	HASH_TESTING_ENGINE (hash);
	struct aux_attestation_testing aux;
	int status;
	uint8_t seed[32];

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_init_dependencies (test, &aux);

	status = aux_attestation_init (&aux.test, &aux.keystore.base, &aux.rsa.base, &aux.riot,
		&ecc.base);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_generate_ecdh_seed (&aux.test, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&hash.base, seed, sizeof (seed));
	CuAssertIntEquals (test, KEY_SEED_HASH_LEN, status);

	status = testing_validate_array (KEY_SEED_HASH, seed, KEY_SEED_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_testing_validate_and_release (test, &aux);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void aux_attestation_test_generate_ecdh_seed_null (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	uint8_t seed[32];

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = aux_attestation_generate_ecdh_seed (NULL, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		NULL, seed, sizeof (seed));
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_generate_ecdh_seed (&aux.test, NULL, ECC_PUBKEY_DER_LEN,
		NULL, seed, sizeof (seed));
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_generate_ecdh_seed (&aux.test, ECC_PUBKEY_DER, 0,
		NULL, seed, sizeof (seed));
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_generate_ecdh_seed (&aux.test, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		NULL, NULL, sizeof (seed));
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_generate_ecdh_seed_no_ecc_support (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	uint8_t seed[32];

	TEST_START;

	aux_attestation_testing_init_dependencies (test, &aux);

	status = aux_attestation_init (&aux.test, &aux.keystore.base, &aux.rsa.base, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_generate_ecdh_seed (&aux.test, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		NULL, seed, sizeof (seed));
	CuAssertIntEquals (test, AUX_ATTESTATION_UNSUPPORTED_CRYPTO, status);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_generate_ecdh_seed_small_seed_buffer (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	uint8_t seed[20];

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = mock_expect (&aux.ecc.mock, aux.ecc.base.init_public_key, &aux.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&aux.ecc.mock, 2, 0);

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.init_key_pair, &aux.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&aux.ecc.mock, 2, 1);

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.get_shared_secret_max_length, &aux.ecc, 20,
		MOCK_ARG_SAVED_ARG (1));

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.release_key_pair, &aux.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.release_key_pair, &aux.ecc, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_generate_ecdh_seed (&aux.test, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		NULL, seed, sizeof (seed) - 1);
	CuAssertIntEquals (test, AUX_ATTESTATION_BUFFER_TOO_SMALL, status);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_generate_ecdh_seed_small_seed_buffer_sha256 (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	uint8_t seed[32];

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = mock_expect (&aux.ecc.mock, aux.ecc.base.init_public_key, &aux.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&aux.ecc.mock, 2, 0);

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.init_key_pair, &aux.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&aux.ecc.mock, 2, 1);

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.get_shared_secret_max_length, &aux.ecc, 20,
		MOCK_ARG_SAVED_ARG (1));

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.release_key_pair, &aux.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.release_key_pair, &aux.ecc, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_generate_ecdh_seed (&aux.test, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&aux.hash.base, seed, sizeof (seed) - 1);
	CuAssertIntEquals (test, AUX_ATTESTATION_BUFFER_TOO_SMALL, status);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_generate_ecdh_seed_small_seed_buffer_sha256_large_secret (
	CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	uint8_t seed[48];

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = mock_expect (&aux.ecc.mock, aux.ecc.base.init_public_key, &aux.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&aux.ecc.mock, 2, 0);

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.init_key_pair, &aux.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&aux.ecc.mock, 2, 1);

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.get_shared_secret_max_length, &aux.ecc, 48,
		MOCK_ARG_SAVED_ARG (1));

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.release_key_pair, &aux.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.release_key_pair, &aux.ecc, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_generate_ecdh_seed (&aux.test, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&aux.hash.base, seed, sizeof (seed) - 1);
	CuAssertIntEquals (test, AUX_ATTESTATION_BUFFER_TOO_SMALL, status);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_generate_ecdh_seed_public_key_error (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	uint8_t seed[32];

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = mock_expect (&aux.ecc.mock, aux.ecc.base.init_public_key, &aux.ecc,
		ECC_ENGINE_PUBLIC_KEY_FAILED, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_generate_ecdh_seed (&aux.test, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		NULL, seed, sizeof (seed));
	CuAssertIntEquals (test, ECC_ENGINE_PUBLIC_KEY_FAILED, status);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_generate_ecdh_seed_private_key_error (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	uint8_t seed[32];

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = mock_expect (&aux.ecc.mock, aux.ecc.base.init_public_key, &aux.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&aux.ecc.mock, 2, 0);

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.init_key_pair, &aux.ecc,
		ECC_ENGINE_KEY_PAIR_FAILED,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.release_key_pair, &aux.ecc, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_generate_ecdh_seed (&aux.test, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		NULL, seed, sizeof (seed));
	CuAssertIntEquals (test, ECC_ENGINE_KEY_PAIR_FAILED, status);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_generate_ecdh_seed_secret_length_error (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	uint8_t seed[32];

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = mock_expect (&aux.ecc.mock, aux.ecc.base.init_public_key, &aux.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&aux.ecc.mock, 2, 0);

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.init_key_pair, &aux.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&aux.ecc.mock, 2, 1);

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.get_shared_secret_max_length, &aux.ecc,
		ECC_ENGINE_SECRET_LENGTH_FAILED, MOCK_ARG_SAVED_ARG (1));

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.release_key_pair, &aux.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.release_key_pair, &aux.ecc, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_generate_ecdh_seed (&aux.test, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		NULL, seed, sizeof (seed));
	CuAssertIntEquals (test, ECC_ENGINE_SECRET_LENGTH_FAILED, status);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_generate_ecdh_seed_shared_secret_error (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	uint8_t seed[32];

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = mock_expect (&aux.ecc.mock, aux.ecc.base.init_public_key, &aux.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&aux.ecc.mock, 2, 0);

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.init_key_pair, &aux.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&aux.ecc.mock, 2, 1);

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.get_shared_secret_max_length, &aux.ecc, 32,
		MOCK_ARG_SAVED_ARG (1));

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.compute_shared_secret, &aux.ecc,
		ECC_ENGINE_SHARED_SECRET_FAILED, MOCK_ARG_SAVED_ARG (1), MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.release_key_pair, &aux.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.release_key_pair, &aux.ecc, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_generate_ecdh_seed (&aux.test, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		NULL, seed, sizeof (seed));
	CuAssertIntEquals (test, ECC_ENGINE_SHARED_SECRET_FAILED, status);

	aux_attestation_testing_validate_and_release (test, &aux);
}

static void aux_attestation_test_generate_ecdh_seed_hash_error (CuTest *test)
{
	struct aux_attestation_testing aux;
	int status;
	uint8_t seed[32];

	TEST_START;

	aux_attestation_testing_init (test, &aux);

	status = mock_expect (&aux.ecc.mock, aux.ecc.base.init_public_key, &aux.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&aux.ecc.mock, 2, 0);

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.init_key_pair, &aux.ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&aux.ecc.mock, 2, 1);

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.get_shared_secret_max_length, &aux.ecc, 32,
		MOCK_ARG_SAVED_ARG (1));

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.compute_shared_secret, &aux.ecc,
		KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (1), MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&aux.ecc.mock, 2, KEY_SEED, KEY_SEED_LEN, 3);

	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.release_key_pair, &aux.ecc, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&aux.ecc.mock, aux.ecc.base.release_key_pair, &aux.ecc, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&aux.hash.mock, aux.hash.base.calculate_sha256, &aux.hash,
		HASH_ENGINE_SHA256_FAILED, MOCK_ARG_PTR_CONTAINS (KEY_SEED, KEY_SEED_LEN),
		MOCK_ARG (KEY_SEED_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_generate_ecdh_seed (&aux.test, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&aux.hash.base, seed, sizeof (seed));
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	aux_attestation_testing_validate_and_release (test, &aux);
}


// *INDENT-OFF*
TEST_SUITE_START (aux_attestation);

TEST (aux_attestation_test_init);
TEST (aux_attestation_test_init_null);
TEST (aux_attestation_test_release_null);
TEST (aux_attestation_test_generate_key);
TEST (aux_attestation_test_generate_key_null);
TEST (aux_attestation_test_generate_key_generation_no_rsa_support);
TEST (aux_attestation_test_generate_key_generation_error);
TEST (aux_attestation_test_generate_key_der_error);
TEST (aux_attestation_test_generate_key_save_error);
TEST (aux_attestation_test_create_certificate);
TEST (aux_attestation_test_create_certificate_authenticate);
TEST (aux_attestation_test_create_certificate_twice);
TEST (aux_attestation_test_create_certificate_zero_serial_number);
TEST (aux_attestation_test_create_certificate_zero_serial_number_twice);
TEST (aux_attestation_test_create_certificate_null);
TEST (aux_attestation_test_create_certificate_no_rsa_support);
TEST (aux_attestation_test_create_certificate_no_private_key);
TEST (aux_attestation_test_create_certificate_bad_private_key);
TEST (aux_attestation_test_create_certificate_load_key_error);
TEST (aux_attestation_test_create_certificate_load_ca_error);
TEST (aux_attestation_test_create_certificate_serial_number_error);
TEST (aux_attestation_test_create_certificate_create_error);
TEST (aux_attestation_test_create_certificate_cert_der_error);
TEST (aux_attestation_test_set_certificate);
TEST (aux_attestation_test_set_certificate_before_create);
TEST (aux_attestation_test_set_certificate_null);
TEST (aux_attestation_test_set_certificate_no_rsa_support);
TEST (aux_attestation_test_set_certificate_twice);
TEST (aux_attestation_test_set_certificate_after_create);
TEST (aux_attestation_test_set_static_certificate);
TEST (aux_attestation_test_set_static_certificate_before_create);
TEST (aux_attestation_test_set_static_certificate_null);
TEST (aux_attestation_test_set_static_certificate_no_rsa_support);
TEST (aux_attestation_test_set_static_certificate_twice);
TEST (aux_attestation_test_set_static_certificate_after_create);
TEST (aux_attestation_test_get_certificate_null);
TEST (aux_attestation_test_unseal_rsa_oaep_sha1);
TEST (aux_attestation_test_unseal_rsa_oaep_sha256);
TEST (aux_attestation_test_unseal_rsa_pkcs15);
TEST (aux_attestation_test_unseal_ecdh_raw);
TEST (aux_attestation_test_unseal_ecdh_sha256);
TEST (aux_attestation_test_unseal_pcr_sha256_unused_byte_nonzero);
#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
TEST (aux_attestation_test_unseal_pcr_sha384);
TEST (aux_attestation_test_unseal_pcr_sha384_unused_byte_nonzero);
#endif
#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
TEST (aux_attestation_test_unseal_pcr_sha512);
#endif
TEST (aux_attestation_test_unseal_pcr_mismatch);
TEST (aux_attestation_test_unseal_bypass_pcr_check);
TEST (aux_attestation_test_unseal_multiple_pcr);
#if defined HASH_ENABLE_SHA384 && defined HASH_ENABLE_SHA512 && \
	(PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
TEST (aux_attestation_test_unseal_multiple_pcr_different_lengths);
#endif
TEST (aux_attestation_test_unseal_multiple_pcr_mismatch);
TEST (aux_attestation_test_unseal_multiple_pcr_unused_byte_nonzero);
TEST (aux_attestation_test_unseal_multiple_pcr_bypass_single);
TEST (aux_attestation_test_unseal_multiple_pcr_bypass_multiple);
TEST (aux_attestation_test_unseal_unused_pcrs);
TEST (aux_attestation_test_unseal_unsupported_pcr_bypassed);
TEST (aux_attestation_test_unseal_bad_hmac);
TEST (aux_attestation_test_unseal_rsa_oaep_sha1_no_mock);
TEST (aux_attestation_test_unseal_rsa_oaep_sha256_no_mock);
TEST (aux_attestation_test_unseal_ecdh_raw_no_mock);
TEST (aux_attestation_test_unseal_ecdh_sha256_no_mock);
#if defined HASH_ENABLE_SHA384 && (PCR_MAX_DIGEST_LENGTH >= SHA384_HASH_LENGTH)
TEST (aux_attestation_test_unseal_pcr_sha384_no_mock);
#endif
#if defined HASH_ENABLE_SHA512 && (PCR_MAX_DIGEST_LENGTH >= SHA512_HASH_LENGTH)
TEST (aux_attestation_test_unseal_pcr_sha512_no_mock);
#endif
TEST (aux_attestation_test_unseal_rsa_no_ecc);
TEST (aux_attestation_test_unseal_ecdh_no_rsa);
TEST (aux_attestation_test_unseal_null);
TEST (aux_attestation_test_unseal_invalid_key_length);
TEST (aux_attestation_test_unseal_invalid_hmac_type);
TEST (aux_attestation_test_unseal_buffer_too_small);
TEST (aux_attestation_test_unseal_no_rsa_support);
TEST (aux_attestation_test_unseal_no_ecc_support);
TEST (aux_attestation_test_unseal_unknown_seed);
TEST (aux_attestation_test_unseal_rsa_invalid_padding);
TEST (aux_attestation_test_unseal_rsa_load_error);
TEST (aux_attestation_test_unseal_rsa_init_key_error);
TEST (aux_attestation_test_unseal_rsa_decrypt_error);
TEST (aux_attestation_test_unseal_ecdh_invalid_padding);
TEST (aux_attestation_test_unseal_ecdh_public_key_error);
TEST (aux_attestation_test_unseal_ecdh_private_key_error);
TEST (aux_attestation_test_unseal_ecdh_secret_length_error);
TEST (aux_attestation_test_unseal_ecdh_shared_secret_error);
TEST (aux_attestation_test_unseal_ecdh_hash_error);
TEST (aux_attestation_test_unseal_signing_key_kdf_error);
TEST (aux_attestation_test_unseal_validate_init_error);
TEST (aux_attestation_test_unseal_validate_hash_cipher_error);
TEST (aux_attestation_test_unseal_validate_hash_policy_error);
TEST (aux_attestation_test_unseal_validate_finish_error);
TEST (aux_attestation_test_unseal_unsupported_pcr);
TEST (aux_attestation_test_unseal_compute_pcr_error);
TEST (aux_attestation_test_unseal_encryption_key_kdf_error);
TEST (aux_attestation_test_erase_key);
TEST (aux_attestation_test_erase_key_with_certificate);
TEST (aux_attestation_test_erase_key_with_static_certificate);
TEST (aux_attestation_test_erase_key_null);
TEST (aux_attestation_test_erase_key_no_rsa_support);
TEST (aux_attestation_test_erase_key_erase_error);
TEST (aux_attestation_test_decrypt);
TEST (aux_attestation_test_decrypt_with_label);
TEST (aux_attestation_test_decrypt_sha256);
TEST (aux_attestation_test_decrypt_no_mock);
TEST (aux_attestation_test_decrypt_sha256_no_mock);
TEST (aux_attestation_test_decrypt_null);
TEST (aux_attestation_test_decrypt_no_rsa_support);
TEST (aux_attestation_test_decrypt_load_error);
TEST (aux_attestation_test_decrypt_init_key_error);
TEST (aux_attestation_test_decrypt_error);
TEST (aux_attestation_test_generate_ecdh_seed);
TEST (aux_attestation_test_generate_ecdh_seed_sha256);
TEST (aux_attestation_test_generate_ecdh_seed_no_mock);
TEST (aux_attestation_test_generate_ecdh_seed_sha256_no_mock);
TEST (aux_attestation_test_generate_ecdh_seed_null);
TEST (aux_attestation_test_generate_ecdh_seed_no_ecc_support);
TEST (aux_attestation_test_generate_ecdh_seed_small_seed_buffer);
TEST (aux_attestation_test_generate_ecdh_seed_small_seed_buffer_sha256);
TEST (aux_attestation_test_generate_ecdh_seed_small_seed_buffer_sha256_large_secret);
TEST (aux_attestation_test_generate_ecdh_seed_public_key_error);
TEST (aux_attestation_test_generate_ecdh_seed_private_key_error);
TEST (aux_attestation_test_generate_ecdh_seed_secret_length_error);
TEST (aux_attestation_test_generate_ecdh_seed_shared_secret_error);
TEST (aux_attestation_test_generate_ecdh_seed_hash_error);

TEST_SUITE_END;
// *INDENT-ON*
