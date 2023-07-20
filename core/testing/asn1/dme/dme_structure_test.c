// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "testing/asn1/x509_testing.h"
#include "testing/asn1/dme/dme_structure_testing.h"
#include "testing/crypto/ecc_testing.h"


TEST_SUITE_LABEL ("dme_structure");


/**
 * Test OID for a DME structure format.  The test structure uses type 0, which is not a valid DME
 * structure type on real devices.
 */
const uint8_t DME_STRUCTURE_TESTING_OID_TYPE[] = {
	0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x66,0x03,0x02,0x00
};

const size_t DME_STRUCTURE_TESTING_OID_TYPE_LEN = sizeof (DME_STRUCTURE_TESTING_OID_TYPE);

/**
 * Test data for a DME structure.
 */
const uint8_t DME_STRUCTURE_TESTING_DATA[] = {
	0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
	0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f
};

const size_t DME_STRUCTURE_TESTING_DATA_LEN = sizeof (DME_STRUCTURE_TESTING_DATA);

/**
 * Test OID for the signature type.  ecdsa-with-SHA256
 */
const uint8_t DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA256[] = {
	0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x02
};

const size_t DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA256_LEN =
	sizeof (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA256);

/**
 * Signature of the test DME structure using ECC_PRIVKEY and SHA256.
 */
const uint8_t DME_STRUCTURE_TESTING_SIG_ECC256_SHA256[] = {
	0x30,0x45,0x02,0x20,0x1e,0x09,0xe8,0x51,0xb9,0x7d,0xf6,0xb0,0x44,0x63,0x4f,0x80,
	0x03,0x4f,0x7c,0xfe,0x79,0x15,0xfe,0x1b,0xcb,0xa3,0xb0,0x12,0x5e,0x92,0x98,0x99,
	0xa0,0xda,0x3f,0x50,0x02,0x21,0x00,0x84,0x90,0x4a,0x5c,0x5e,0x48,0x60,0x4d,0xa6,
	0x4b,0xc7,0x46,0xdc,0x7d,0x56,0x81,0x01,0x5d,0x5c,0xb4,0x0a,0x83,0x09,0xc7,0xcf,
	0x4d,0x04,0x52,0x96,0x41,0x2c,0x2e
};

const size_t DME_STRUCTURE_TESTING_SIG_ECC256_SHA256_LEN =
	sizeof (DME_STRUCTURE_TESTING_SIG_ECC256_SHA256);

/**
 * Test OID for the signature type.  ecdsa-with-SHA384
 */
const uint8_t DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA384[] = {
	0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x03
};

const size_t DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA384_LEN =
	sizeof (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA384);

/**
 * Signature of the test DME structure using ECC384_PRIVKEY and SHA384.
 */
const uint8_t DME_STRUCTURE_TESTING_SIG_ECC384_SHA384[] = {
	0x30,0x65,0x02,0x31,0x00,0xcb,0x6c,0x99,0x54,0xbe,0x7a,0xaf,0xd9,0x33,0xea,0x13,
	0xef,0xdb,0x1e,0x02,0xd3,0x66,0x3e,0x11,0xa7,0x36,0xeb,0x3f,0x58,0xd4,0xf8,0xe1,
	0xfd,0x61,0xea,0xca,0xa9,0xb0,0xf7,0x39,0xa1,0x9b,0x00,0x6e,0xfc,0xf0,0xb9,0xcc,
	0xbc,0x7d,0xa4,0x5a,0xb7,0x02,0x30,0x63,0x1b,0x1d,0x00,0x1d,0xf6,0x8c,0x7d,0x1a,
	0x65,0x2b,0xee,0xda,0xbd,0x45,0xeb,0x12,0xf4,0xa9,0xba,0xed,0xc6,0xc4,0x58,0x06,
	0xf4,0xa2,0x00,0x7c,0x2a,0x42,0x30,0x81,0x99,0xee,0x4c,0xd3,0x56,0xb6,0x26,0xbf,
	0x2f,0xd0,0x1d,0xb5,0x9a,0x81,0xb8
};

const size_t DME_STRUCTURE_TESTING_SIG_ECC384_SHA384_LEN =
	sizeof (DME_STRUCTURE_TESTING_SIG_ECC384_SHA384);

/**
 * Test OID for the signature type.  ecdsa-with-SHA512
 */
const uint8_t DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA512[] = {
	0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x04
};

const size_t DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA512_LEN =
	sizeof (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA512);

/**
 * Signature of the test DME structure using ECC521_PRIVKEY and SHA512.
 */
const uint8_t DME_STRUCTURE_TESTING_SIG_ECC521_SHA512[] = {
	0x30,0x81,0x87,0x02,0x41,0x6a,0xfc,0x35,0x6d,0x60,0x8f,0xde,0x91,0x9d,0x85,0xd9,
	0xc9,0xd0,0xf9,0x22,0x20,0x9b,0x41,0xd2,0xa9,0x60,0xf7,0xfa,0xef,0xb6,0xb5,0x2d,
	0x6d,0x57,0x0e,0xb2,0xa8,0x2e,0xb6,0x04,0x26,0x27,0x3f,0xaf,0xb5,0xdb,0x78,0x14,
	0xd5,0x7d,0x46,0x87,0xfb,0x2f,0x75,0xe3,0xdf,0x20,0x9f,0xab,0x31,0x22,0x21,0x06,
	0xfc,0x34,0x0f,0xa6,0x10,0x25,0x02,0x42,0x00,0xcb,0x59,0x60,0x77,0x4e,0xcb,0xc2,
	0xac,0xba,0x6d,0x8d,0x92,0x5c,0xc9,0xb4,0x6d,0x81,0xd8,0x6a,0x2e,0xf0,0x6b,0xed,
	0xe1,0x36,0xd0,0xa7,0xc9,0x35,0xc6,0xd6,0xf9,0xea,0xa7,0xcd,0x3b,0x1e,0xb8,0x5a,
	0xbf,0x85,0x32,0xe6,0x79,0xe8,0x13,0x45,0x21,0x89,0x5a,0xd3,0xdd,0xd4,0x2c,0x1f,
	0xf4,0x67,0x55,0x4e,0xf8,0x38,0x21,0x7f,0x2d,0x32
};

const size_t DME_STRUCTURE_TESTING_SIG_ECC521_SHA512_LEN =
	sizeof (DME_STRUCTURE_TESTING_SIG_ECC521_SHA512);

/**
 * Test data for the DME renewal counter.
 */
const uint8_t DME_STRUCTURE_TESTING_RENEWAL_COUNTER[] = {
	0x01,0x23,0x45,0x67
};

const size_t DME_STRUCTURE_TESTING_RENEWAL_COUNTER_LEN =
	sizeof (DME_STRUCTURE_TESTING_RENEWAL_COUNTER);

/**
 * Test OID for a DME structure format type 1.
 */
const uint8_t DME_STRUCTURE_TESTING_TYPE1_OID[] = {
	0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x66,0x03,0x02,0x01
};

const size_t DME_STRUCTURE_TESTING_TYPE1_OID_LEN = sizeof (DME_STRUCTURE_TESTING_TYPE1_OID);

/**
 * Test data for a DME structure type 1.
 */
const uint8_t DME_STRUCTURE_TESTING_TYPE1_DATA[] = {
	0x33,0x23,0xb4,0x74,0xa1,0xae,0x36,0xda,0x4b,0x43,0x48,0x61,0xb2,0xb3,0xa8,0xb7,
	0x45,0x30,0x9e,0x8b,0x3d,0xe7,0x88,0xf4,0xb6,0xae,0x46,0x5f,0x58,0x2b,0xb2,0xaf,
	0xb5,0x7a,0xb9,0x58,0xee,0x71,0x10,0x5b,0xa6,0xab,0xd7,0xbd,0x4b,0xd1,0x7d,0x5e,
	0x18,0x5e,0xf7,0x96,0x0d,0x16,0xef,0x42,0x3a,0xe3,0xb9,0x33,0x97,0x15,0xc6,0x2a,
	0xea,0x6c,0xf7,0x84,0x3d,0xe1,0xba,0x57,0x3e,0x3a,0x52,0x80,0xc2,0x8a,0xb4,0x2d,
	0x22,0x43,0x3d,0xea,0x0d,0xc6,0x33,0xf9,0xbd,0x65,0x75,0x6a,0xd7,0x30,0x30,0x6a
};

const size_t DME_STRUCTURE_TESTING_TYPE1_DATA_LEN = sizeof (DME_STRUCTURE_TESTING_TYPE1_DATA);

/**
 * Signature of the test type 1 DME structure using ECC_PRIVKEY and SHA256.
 */
const uint8_t DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256[] = {
	0x30,0x44,0x02,0x20,0x10,0xf8,0xa8,0x15,0xfd,0x20,0xe3,0x3e,0x7d,0xf2,0x6f,0x5f,
	0x24,0xea,0x9a,0x01,0xdc,0x3b,0xae,0x4b,0x4f,0xcc,0x34,0xe6,0xb4,0x89,0x61,0xfc,
	0xbc,0x15,0x26,0xea,0x02,0x20,0x68,0x37,0x07,0xc6,0xf7,0x49,0xe9,0x27,0x17,0x24,
	0x3b,0x02,0x45,0x04,0x21,0x5f,0x4c,0x1c,0x38,0x82,0xb0,0xd1,0xad,0xc7,0x28,0xdc,
	0xd6,0xb4,0x02,0x09,0xe5,0xc4
};

const size_t DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_LEN =
	sizeof (DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256);

const uint8_t DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_RAW_R[] = {
	0x10,0xf8,0xa8,0x15,0xfd,0x20,0xe3,0x3e,0x7d,0xf2,0x6f,0x5f,0x24,0xea,0x9a,0x01,
	0xdc,0x3b,0xae,0x4b,0x4f,0xcc,0x34,0xe6,0xb4,0x89,0x61,0xfc,0xbc,0x15,0x26,0xea
};

const uint8_t DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_RAW_S[] = {
	0x68,0x37,0x07,0xc6,0xf7,0x49,0xe9,0x27,0x17,0x24,0x3b,0x02,0x45,0x04,0x21,0x5f,
	0x4c,0x1c,0x38,0x82,0xb0,0xd1,0xad,0xc7,0x28,0xdc,0xd6,0xb4,0x02,0x09,0xe5,0xc4
};

/**
 * Signature of the test type 1 DME structure using ECC384_PRIVKEY and SHA384.
 */
const uint8_t DME_STRUCTURE_TESTING_TYPE1_SIG_ECC384_SHA384[] = {
	0x30,0x65,0x02,0x31,0x00,0xfc,0xbe,0x42,0x93,0x2b,0xe0,0xc9,0xa3,0x1c,0x08,0x8e,
	0x84,0xf7,0xa5,0x08,0x18,0x64,0x41,0xf7,0x6c,0x51,0xb1,0x89,0x24,0xe1,0x8f,0xed,
	0xbb,0xdd,0xb9,0xd0,0x0e,0xc1,0xcc,0x7e,0x6a,0xb0,0xa1,0x06,0xfd,0xff,0xcd,0x82,
	0xa2,0x43,0x98,0xcd,0x43,0x02,0x30,0x3f,0x77,0x60,0x14,0x4c,0x99,0x60,0x53,0x94,
	0x65,0xff,0xe6,0x70,0x65,0x45,0x56,0xea,0x7c,0xba,0x5f,0x48,0xe9,0xe4,0xa4,0xaf,
	0x74,0x4f,0xac,0xec,0xaf,0xa5,0x9b,0xa5,0xbb,0x28,0x06,0x91,0xfd,0xff,0x1d,0x76,
	0x86,0x75,0xa3,0x10,0xbd,0x4d,0x7f
};

const size_t DME_STRUCTURE_TESTING_TYPE1_SIG_ECC384_SHA384_LEN =
	sizeof (DME_STRUCTURE_TESTING_TYPE1_SIG_ECC384_SHA384);

const uint8_t DME_STRUCTURE_TESTING_TYPE1_SIG_ECC384_SHA384_RAW_R[] = {
	0xfc,0xbe,0x42,0x93,0x2b,0xe0,0xc9,0xa3,0x1c,0x08,0x8e,0x84,0xf7,0xa5,0x08,0x18,
	0x64,0x41,0xf7,0x6c,0x51,0xb1,0x89,0x24,0xe1,0x8f,0xed,0xbb,0xdd,0xb9,0xd0,0x0e,
	0xc1,0xcc,0x7e,0x6a,0xb0,0xa1,0x06,0xfd,0xff,0xcd,0x82,0xa2,0x43,0x98,0xcd,0x43
};

const uint8_t DME_STRUCTURE_TESTING_TYPE1_SIG_ECC384_SHA384_RAW_S[] = {
	0x3f,0x77,0x60,0x14,0x4c,0x99,0x60,0x53,0x94,0x65,0xff,0xe6,0x70,0x65,0x45,0x56,
	0xea,0x7c,0xba,0x5f,0x48,0xe9,0xe4,0xa4,0xaf,0x74,0x4f,0xac,0xec,0xaf,0xa5,0x9b,
	0xa5,0xbb,0x28,0x06,0x91,0xfd,0xff,0x1d,0x76,0x86,0x75,0xa3,0x10,0xbd,0x4d,0x7f
};

/**
 * Signature of the test type 1 DME structure using ECC521_PRIVKEY and SHA512.
 */
const uint8_t DME_STRUCTURE_TESTING_TYPE1_SIG_ECC521_SHA512[] = {
	0x30,0x81,0x88,0x02,0x42,0x00,0x9e,0x4b,0xaf,0xf0,0xf2,0x28,0x73,0x2c,0xa1,0x6f,
	0x6d,0xbe,0xa5,0x53,0x38,0x1d,0x3c,0x62,0x6d,0x0c,0x80,0xb9,0xf5,0x60,0xe9,0x3c,
	0x22,0x8d,0xb9,0x1f,0xad,0x1b,0x61,0x17,0x75,0xf8,0x9f,0xf5,0x82,0xb3,0xe2,0x2b,
	0xcc,0x62,0x61,0x2e,0x40,0x95,0x42,0x5f,0x7a,0x24,0x1f,0x3b,0x86,0xce,0x39,0x93,
	0xc1,0x5a,0x8c,0xac,0x53,0x7e,0x78,0x02,0x42,0x00,0xaf,0xc8,0x31,0x05,0x0b,0xda,
	0x4a,0xaf,0x6b,0x9a,0x5a,0xe8,0x5e,0x2a,0xc4,0x99,0xed,0x90,0x07,0xb1,0xd3,0xf5,
	0xf0,0x44,0x4e,0xfd,0xba,0x00,0xed,0xa3,0x84,0xc5,0x50,0x66,0xe9,0x89,0x78,0x80,
	0xf8,0xcf,0xae,0xfb,0xce,0x5b,0xb9,0x86,0x39,0x51,0xec,0xd1,0x18,0xbd,0xae,0x14,
	0xfb,0x5b,0xdb,0x5a,0x58,0x98,0x9d,0xc1,0x50,0xc9,0x8d
};

const size_t DME_STRUCTURE_TESTING_TYPE1_SIG_ECC521_SHA512_LEN =
	sizeof (DME_STRUCTURE_TESTING_TYPE1_SIG_ECC521_SHA512);

const uint8_t DME_STRUCTURE_TESTING_TYPE1_SIG_ECC521_SHA512_RAW_R[] = {
	0x00,0x9e,0x4b,0xaf,0xf0,0xf2,0x28,0x73,0x2c,0xa1,0x6f,0x6d,0xbe,0xa5,0x53,0x38,
	0x1d,0x3c,0x62,0x6d,0x0c,0x80,0xb9,0xf5,0x60,0xe9,0x3c,0x22,0x8d,0xb9,0x1f,0xad,
	0x1b,0x61,0x17,0x75,0xf8,0x9f,0xf5,0x82,0xb3,0xe2,0x2b,0xcc,0x62,0x61,0x2e,0x40,
	0x95,0x42,0x5f,0x7a,0x24,0x1f,0x3b,0x86,0xce,0x39,0x93,0xc1,0x5a,0x8c,0xac,0x53,
	0x7e,0x78
};

const uint8_t DME_STRUCTURE_TESTING_TYPE1_SIG_ECC521_SHA512_RAW_S[] = {
	0x00,0xaf,0xc8,0x31,0x05,0x0b,0xda,0x4a,0xaf,0x6b,0x9a,0x5a,0xe8,0x5e,0x2a,0xc4,
	0x99,0xed,0x90,0x07,0xb1,0xd3,0xf5,0xf0,0x44,0x4e,0xfd,0xba,0x00,0xed,0xa3,0x84,
	0xc5,0x50,0x66,0xe9,0x89,0x78,0x80,0xf8,0xcf,0xae,0xfb,0xce,0x5b,0xb9,0x86,0x39,
	0x51,0xec,0xd1,0x18,0xbd,0xae,0x14,0xfb,0x5b,0xdb,0x5a,0x58,0x98,0x9d,0xc1,0x50,
	0xc9,0x8d
};

/**
 * Test OID for a DME structure format type 2.
 */
const uint8_t DME_STRUCTURE_TESTING_TYPE2_OID[] = {
	0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x66,0x03,0x02,0x02
};

const size_t DME_STRUCTURE_TESTING_TYPE2_OID_LEN = sizeof (DME_STRUCTURE_TESTING_TYPE2_OID);

/**
 * Test data for a DME structure type 2.
 */
const uint8_t DME_STRUCTURE_TESTING_TYPE2_DATA[] = {
	0x88,0x14,0x8a,0x15,0x26,0xe1,0x64,0xf6,0xcc,0x61,0x6b,0x10,0x7e,0x22,0xb8,0xe2,
	0x8a,0x71,0x84,0x3d,0xf7,0xdb,0x1d,0x6c,0xd6,0x84,0xc1,0x17,0xa5,0x94,0xc5,0xb3,
	0xcc,0x01,0x5f,0x17,0x9d,0xf2,0x38,0xbd,0x2a,0xaa,0x44,0x85,0xeb,0xa5,0x61,0xed,
	0xea,0xfe,0xc8,0x0a,0xa9,0x28,0xe3,0x2b,0x99,0x30,0xe7,0x2a,0xd0,0x20,0x88,0xaf,
	0x3f,0xd4,0x48,0x49,0xd7,0x96,0x61,0x83,0x60,0x9f,0x29,0xba,0xa8,0xd4,0xe9,0xd1,
	0x07,0x73,0xae,0xb2,0x8b,0xdc,0xb6,0x28,0x49,0xac,0x39,0x80,0x2a,0x0e,0x88,0x40,
	0x9b,0xbb,0xfc,0x8f,0x50,0x65,0x55,0x3f,0x53,0x5b,0x5c,0xa4,0x47,0x2b,0x62,0xc2,
	0x2d,0xd2,0xcc,0xe8,0xbd,0xc2,0x3f,0x8e,0x6c,0xe8,0x59,0xc7,0x7d,0xdb,0xff,0xbf
};

const size_t DME_STRUCTURE_TESTING_TYPE2_DATA_LEN = sizeof (DME_STRUCTURE_TESTING_TYPE2_DATA);

/**
 * Signature of the test type 2 DME structure using ECC_PRIVKEY and SHA256.
 */
const uint8_t DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256[] = {
	0x30,0x45,0x02,0x21,0x00,0xdb,0x95,0xf9,0xf1,0x8b,0x60,0x2e,0xce,0xd2,0x74,0xd4,
	0xf6,0x51,0x1f,0x3a,0x34,0x4d,0x70,0xf7,0xc1,0xfa,0xb2,0x51,0x9d,0x9f,0x29,0x29,
	0xdc,0xc2,0x26,0x36,0x15,0x02,0x20,0x5a,0xd2,0xa8,0x7b,0xbc,0x64,0x02,0x3a,0x0c,
	0xfa,0xf2,0x82,0x58,0x11,0x9d,0xc5,0x8b,0xb4,0x45,0x3a,0x49,0x42,0x15,0x80,0x66,
	0xd2,0x64,0x7a,0x2c,0x62,0xbc,0x5e
};

const size_t DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_LEN =
	sizeof (DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256);

const uint8_t DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_RAW_R[] = {
	0xdb,0x95,0xf9,0xf1,0x8b,0x60,0x2e,0xce,0xd2,0x74,0xd4,0xf6,0x51,0x1f,0x3a,0x34,
	0x4d,0x70,0xf7,0xc1,0xfa,0xb2,0x51,0x9d,0x9f,0x29,0x29,0xdc,0xc2,0x26,0x36,0x15
};

const uint8_t DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_RAW_S[] = {
	0x5a,0xd2,0xa8,0x7b,0xbc,0x64,0x02,0x3a,0x0c,0xfa,0xf2,0x82,0x58,0x11,0x9d,0xc5,
	0x8b,0xb4,0x45,0x3a,0x49,0x42,0x15,0x80,0x66,0xd2,0x64,0x7a,0x2c,0x62,0xbc,0x5e
};

/**
 * Signature of the test type 2 DME structure using ECC384_PRIVKEY and SHA384.
 */
const uint8_t DME_STRUCTURE_TESTING_TYPE2_SIG_ECC384_SHA384[] = {
	0x30,0x64,0x02,0x30,0x4f,0x4d,0xf8,0x30,0x5d,0x3a,0xc7,0x99,0x6c,0x96,0x7f,0x00,
	0xb1,0x26,0xcd,0xb3,0x0a,0x8a,0x9b,0x3b,0xde,0xcd,0xe8,0xe1,0x97,0xa0,0xbd,0x67,
	0xab,0x6b,0x49,0x45,0xce,0x43,0xfa,0xd1,0xf6,0xb2,0x1d,0xf3,0x4f,0x49,0xe5,0x39,
	0xe5,0xf8,0xa3,0x0a,0x02,0x30,0x0f,0x6e,0x24,0x1a,0xcc,0xd8,0xeb,0xd7,0x7f,0xf1,
	0x92,0xe6,0x1b,0x14,0xb2,0xdc,0xae,0x37,0x0e,0xe8,0x19,0x85,0x13,0xd7,0xa9,0xf2,
	0xb0,0x11,0x2f,0xf2,0x16,0x7a,0x80,0x19,0xb8,0x23,0x9f,0xc3,0xb7,0xe2,0x38,0x14,
	0xa5,0x46,0x83,0xbe,0x85,0x0d
};

const size_t DME_STRUCTURE_TESTING_TYPE2_SIG_ECC384_SHA384_LEN =
	sizeof (DME_STRUCTURE_TESTING_TYPE2_SIG_ECC384_SHA384);

const uint8_t DME_STRUCTURE_TESTING_TYPE2_SIG_ECC384_SHA384_RAW_R[] = {
	0x4f,0x4d,0xf8,0x30,0x5d,0x3a,0xc7,0x99,0x6c,0x96,0x7f,0x00,0xb1,0x26,0xcd,0xb3,
	0x0a,0x8a,0x9b,0x3b,0xde,0xcd,0xe8,0xe1,0x97,0xa0,0xbd,0x67,0xab,0x6b,0x49,0x45,
	0xce,0x43,0xfa,0xd1,0xf6,0xb2,0x1d,0xf3,0x4f,0x49,0xe5,0x39,0xe5,0xf8,0xa3,0x0a
};

const uint8_t DME_STRUCTURE_TESTING_TYPE2_SIG_ECC384_SHA384_RAW_S[] = {
	0x0f,0x6e,0x24,0x1a,0xcc,0xd8,0xeb,0xd7,0x7f,0xf1,0x92,0xe6,0x1b,0x14,0xb2,0xdc,
	0xae,0x37,0x0e,0xe8,0x19,0x85,0x13,0xd7,0xa9,0xf2,0xb0,0x11,0x2f,0xf2,0x16,0x7a,
	0x80,0x19,0xb8,0x23,0x9f,0xc3,0xb7,0xe2,0x38,0x14,0xa5,0x46,0x83,0xbe,0x85,0x0d
};

/**
 * Signature of the test type 2 DME structure using ECC521_PRIVKEY and SHA512.
 */
const uint8_t DME_STRUCTURE_TESTING_TYPE2_SIG_ECC521_SHA512[] = {
	0x30,0x81,0x87,0x02,0x42,0x01,0xf0,0x5a,0x8c,0x00,0xa2,0x8f,0xb4,0xb0,0x99,0xd3,
	0xf1,0x75,0x23,0xad,0xec,0x9a,0xe2,0x64,0xf6,0x2e,0x37,0x31,0x38,0xa8,0x96,0xa6,
	0x78,0x8b,0x16,0x74,0x10,0xae,0x09,0x7c,0x7c,0x5b,0x31,0x71,0x13,0xba,0xeb,0xc1,
	0x30,0xe3,0x28,0xe2,0x1c,0xe5,0x38,0xee,0x23,0xa5,0x0c,0xc7,0x24,0x35,0x19,0x23,
	0xff,0x6b,0xce,0x24,0xbd,0x08,0xea,0x02,0x41,0x57,0xfe,0xc2,0x8b,0x0d,0x9d,0x7e,
	0xed,0xc7,0x9b,0xdf,0x34,0xb5,0x1e,0x9d,0xd1,0x75,0x62,0xd1,0x9a,0xfc,0xc1,0x6e,
	0x6e,0xe1,0x1a,0xce,0x29,0x52,0x39,0x26,0x39,0x8b,0x00,0x03,0x2a,0x0c,0x9e,0xcd,
	0xfc,0x8f,0x1c,0xe8,0x7c,0x55,0xff,0x63,0x7c,0x02,0xe1,0x9b,0x50,0xf6,0xd7,0xbe,
	0x4d,0x42,0x85,0x7b,0xac,0xbb,0x2e,0xf3,0x16,0x49
};

const size_t DME_STRUCTURE_TESTING_TYPE2_SIG_ECC521_SHA512_LEN =
	sizeof (DME_STRUCTURE_TESTING_TYPE2_SIG_ECC521_SHA512);

const uint8_t DME_STRUCTURE_TESTING_TYPE2_SIG_ECC521_SHA512_RAW_R[] = {
	0x01,0xf0,0x5a,0x8c,0x00,0xa2,0x8f,0xb4,0xb0,0x99,0xd3,0xf1,0x75,0x23,0xad,0xec,
	0x9a,0xe2,0x64,0xf6,0x2e,0x37,0x31,0x38,0xa8,0x96,0xa6,0x78,0x8b,0x16,0x74,0x10,
	0xae,0x09,0x7c,0x7c,0x5b,0x31,0x71,0x13,0xba,0xeb,0xc1,0x30,0xe3,0x28,0xe2,0x1c,
	0xe5,0x38,0xee,0x23,0xa5,0x0c,0xc7,0x24,0x35,0x19,0x23,0xff,0x6b,0xce,0x24,0xbd,
	0x08,0xea
};

const uint8_t DME_STRUCTURE_TESTING_TYPE2_SIG_ECC521_SHA512_RAW_S[] = {
	0x00,0x57,0xfe,0xc2,0x8b,0x0d,0x9d,0x7e,0xed,0xc7,0x9b,0xdf,0x34,0xb5,0x1e,0x9d,
	0xd1,0x75,0x62,0xd1,0x9a,0xfc,0xc1,0x6e,0x6e,0xe1,0x1a,0xce,0x29,0x52,0x39,0x26,
	0x39,0x8b,0x00,0x03,0x2a,0x0c,0x9e,0xcd,0xfc,0x8f,0x1c,0xe8,0x7c,0x55,0xff,0x63,
	0x7c,0x02,0xe1,0x9b,0x50,0xf6,0xd7,0xbe,0x4d,0x42,0x85,0x7b,0xac,0xbb,0x2e,0xf3,
	0x16,0x49
};

/**
 * Test OID for a DME structure format type 3.
 */
const uint8_t DME_STRUCTURE_TESTING_TYPE3_OID[] = {
	0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x66,0x03,0x02,0x03
};

const size_t DME_STRUCTURE_TESTING_TYPE3_OID_LEN = sizeof (DME_STRUCTURE_TESTING_TYPE3_OID);

/**
 * Test data for a DME structure type 3.
 */
const uint8_t DME_STRUCTURE_TESTING_TYPE3_DATA[] = {
	0xe8,0x22,0xbd,0x85,0x26,0x17,0xb7,0xf5,0x8f,0xa3,0x3c,0xc2,0x55,0x3e,0x7c,0xf7,
	0xff,0x3c,0x0e,0x5f,0x4e,0xfd,0x66,0x83,0x6e,0x7f,0x4a,0x32,0x83,0x51,0xf9,0x34,
	0xee,0x2f,0x21,0xb7,0x3c,0x50,0x79,0xf3,0x56,0x44,0x2a,0x74,0x75,0x7e,0x6b,0x98,
	0x60,0x3f,0x87,0x53,0x1d,0x59,0x28,0xea,0x25,0x86,0xf7,0x1a,0xfc,0x17,0xfb,0x05
};

const size_t DME_STRUCTURE_TESTING_TYPE3_DATA_LEN = sizeof (DME_STRUCTURE_TESTING_TYPE3_DATA);

/**
 * Signature of the test type 3 DME structure using ECC_PRIVKEY and SHA256.
 */
const uint8_t DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256[] = {
	0x30,0x45,0x02,0x20,0x33,0x5a,0xac,0x25,0xcf,0x95,0xe8,0x7d,0x1a,0x45,0x42,0xb9,
	0xd1,0x06,0x6d,0xbb,0x54,0xe8,0x7f,0x8d,0x35,0xf3,0xe2,0xe1,0xff,0x09,0x36,0x66,
	0xde,0xae,0xda,0x21,0x02,0x21,0x00,0xcc,0xa8,0x3e,0x02,0xae,0x34,0xa2,0xed,0xd3,
	0xeb,0x3a,0x61,0x01,0x8b,0xed,0xca,0x92,0x83,0x97,0x11,0x3d,0x7b,0x79,0x6b,0x93,
	0x76,0xaa,0xb9,0x8e,0x9c,0x74,0xea
};

const size_t DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_LEN =
	sizeof (DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256);

const uint8_t DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_RAW_R[] = {
	0x33,0x5a,0xac,0x25,0xcf,0x95,0xe8,0x7d,0x1a,0x45,0x42,0xb9,0xd1,0x06,0x6d,0xbb,
	0x54,0xe8,0x7f,0x8d,0x35,0xf3,0xe2,0xe1,0xff,0x09,0x36,0x66,0xde,0xae,0xda,0x21
};

const uint8_t DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_RAW_S[] = {
	0xcc,0xa8,0x3e,0x02,0xae,0x34,0xa2,0xed,0xd3,0xeb,0x3a,0x61,0x01,0x8b,0xed,0xca,
	0x92,0x83,0x97,0x11,0x3d,0x7b,0x79,0x6b,0x93,0x76,0xaa,0xb9,0x8e,0x9c,0x74,0xea
};

/**
 * Signature of the test type 3 DME structure using ECC384_PRIVKEY and SHA384.
 */
const uint8_t DME_STRUCTURE_TESTING_TYPE3_SIG_ECC384_SHA384[] = {
	0x30,0x65,0x02,0x30,0x44,0x41,0x8a,0x98,0xf8,0xf4,0x0c,0xbb,0x68,0x14,0x67,0xfc,
	0xba,0x31,0x08,0x3a,0xf8,0xa9,0x1b,0x93,0x24,0x7a,0xdf,0x55,0xbf,0x0c,0x2d,0xa8,
	0x57,0x68,0x7d,0x39,0xcc,0x3f,0xb0,0x68,0x8d,0xf7,0x57,0xf2,0x24,0xef,0xe8,0x96,
	0x75,0xfc,0xed,0xdd,0x02,0x31,0x00,0xf5,0xc0,0xc4,0x05,0x16,0x95,0x44,0x19,0x76,
	0x90,0x7f,0xb7,0x65,0x9e,0xf7,0xe1,0xbe,0x6d,0x9d,0x2a,0x03,0x72,0x77,0x02,0x8b,
	0x9b,0x76,0x3b,0xfa,0xb5,0x5e,0x7f,0x62,0x3f,0x14,0x19,0x40,0x0c,0xb1,0x53,0xaf,
	0x4b,0xd5,0xad,0xfa,0x66,0xa5,0xcc
};

const size_t DME_STRUCTURE_TESTING_TYPE3_SIG_ECC384_SHA384_LEN =
	sizeof (DME_STRUCTURE_TESTING_TYPE3_SIG_ECC384_SHA384);

const uint8_t DME_STRUCTURE_TESTING_TYPE3_SIG_ECC384_SHA384_RAW_R[] = {
	0x44,0x41,0x8a,0x98,0xf8,0xf4,0x0c,0xbb,0x68,0x14,0x67,0xfc,0xba,0x31,0x08,0x3a,
	0xf8,0xa9,0x1b,0x93,0x24,0x7a,0xdf,0x55,0xbf,0x0c,0x2d,0xa8,0x57,0x68,0x7d,0x39,
	0xcc,0x3f,0xb0,0x68,0x8d,0xf7,0x57,0xf2,0x24,0xef,0xe8,0x96,0x75,0xfc,0xed,0xdd
};

const uint8_t DME_STRUCTURE_TESTING_TYPE3_SIG_ECC384_SHA384_RAW_S[] = {
	0xf5,0xc0,0xc4,0x05,0x16,0x95,0x44,0x19,0x76,0x90,0x7f,0xb7,0x65,0x9e,0xf7,0xe1,
	0xbe,0x6d,0x9d,0x2a,0x03,0x72,0x77,0x02,0x8b,0x9b,0x76,0x3b,0xfa,0xb5,0x5e,0x7f,
	0x62,0x3f,0x14,0x19,0x40,0x0c,0xb1,0x53,0xaf,0x4b,0xd5,0xad,0xfa,0x66,0xa5,0xcc
};

/**
 * Signature of the test type 3 DME structure using ECC521_PRIVKEY and SHA512.
 */
const uint8_t DME_STRUCTURE_TESTING_TYPE3_SIG_ECC521_SHA512[] = {
	0x30,0x81,0x88,0x02,0x42,0x01,0xfb,0x7f,0x30,0xc2,0x39,0x47,0x61,0x25,0x3a,0x78,
	0x10,0x75,0x9f,0xfc,0xdc,0x77,0xc5,0x97,0x7b,0x6f,0xe2,0x6d,0xa5,0x49,0xf8,0x3d,
	0x2d,0x7b,0x4f,0x39,0x11,0x47,0x64,0x8c,0x6b,0x53,0x5e,0x86,0x8f,0x0d,0x2a,0x62,
	0x8d,0x9c,0x78,0x9f,0xee,0xcc,0x00,0xbe,0x4d,0x20,0x7b,0xf7,0xd6,0xf0,0xe7,0x8c,
	0x29,0x64,0x37,0x8d,0xc4,0x0c,0x4b,0x02,0x42,0x01,0x65,0xb1,0x1e,0x7f,0xea,0x76,
	0x6b,0x94,0x07,0x6c,0x9a,0xb5,0xd6,0x2b,0x33,0xe1,0xc9,0x0b,0xb1,0xbc,0x3d,0x3f,
	0x5a,0xde,0x80,0x9a,0xf0,0x7b,0x3b,0xe2,0xf5,0x59,0xa3,0x57,0x90,0xa2,0x60,0xc5,
	0xab,0x0a,0xbb,0x71,0xde,0x19,0xf7,0x68,0xee,0x05,0x29,0x73,0x62,0xdd,0x4c,0xc8,
	0x35,0x31,0x51,0x9b,0x33,0xaf,0xe5,0xb7,0x0f,0xea,0xfd
};

const size_t DME_STRUCTURE_TESTING_TYPE3_SIG_ECC521_SHA512_LEN =
	sizeof (DME_STRUCTURE_TESTING_TYPE3_SIG_ECC521_SHA512);

const uint8_t DME_STRUCTURE_TESTING_TYPE3_SIG_ECC521_SHA512_RAW_R[] = {
	0x01,0xfb,0x7f,0x30,0xc2,0x39,0x47,0x61,0x25,0x3a,0x78,0x10,0x75,0x9f,0xfc,0xdc,
	0x77,0xc5,0x97,0x7b,0x6f,0xe2,0x6d,0xa5,0x49,0xf8,0x3d,0x2d,0x7b,0x4f,0x39,0x11,
	0x47,0x64,0x8c,0x6b,0x53,0x5e,0x86,0x8f,0x0d,0x2a,0x62,0x8d,0x9c,0x78,0x9f,0xee,
	0xcc,0x00,0xbe,0x4d,0x20,0x7b,0xf7,0xd6,0xf0,0xe7,0x8c,0x29,0x64,0x37,0x8d,0xc4,
	0x0c,0x4b
};

const uint8_t DME_STRUCTURE_TESTING_TYPE3_SIG_ECC521_SHA512_RAW_S[] = {
	0x01,0x65,0xb1,0x1e,0x7f,0xea,0x76,0x6b,0x94,0x07,0x6c,0x9a,0xb5,0xd6,0x2b,0x33,
	0xe1,0xc9,0x0b,0xb1,0xbc,0x3d,0x3f,0x5a,0xde,0x80,0x9a,0xf0,0x7b,0x3b,0xe2,0xf5,
	0x59,0xa3,0x57,0x90,0xa2,0x60,0xc5,0xab,0x0a,0xbb,0x71,0xde,0x19,0xf7,0x68,0xee,
	0x05,0x29,0x73,0x62,0xdd,0x4c,0xc8,0x35,0x31,0x51,0x9b,0x33,0xaf,0xe5,0xb7,0x0f,
	0xea,0xfd
};

/**
 * Test OID for a DME structure format type 4.
 */
const uint8_t DME_STRUCTURE_TESTING_TYPE4_OID[] = {
	0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x66,0x03,0x02,0x04
};

const size_t DME_STRUCTURE_TESTING_TYPE4_OID_LEN = sizeof (DME_STRUCTURE_TESTING_TYPE4_OID);

/**
 * Test data for a DME structure type 4.
 */
const uint8_t DME_STRUCTURE_TESTING_TYPE4_DATA[] = {
	0x1b,0x08,0x15,0xe0,0xc2,0xb5,0x0b,0x2b,0x2d,0xef,0xaa,0xac,0xe9,0xbb,0xcf,0x63,
	0x9f,0xd4,0x6e,0x40,0x86,0x65,0x56,0x1b,0x72,0xe7,0xd9,0x43,0xc5,0x5a,0x5f,0x43,
	0x14,0x56,0x36,0x31,0x43,0x71,0x59,0xf1,0x85,0xf9,0x11,0xbb,0xa1,0xa6,0x5a,0xec,
	0xa0,0xe7,0x0b,0x5b,0xb6,0xb7,0x61,0xa6,0xbb,0x57,0x79,0xc5,0x46,0x36,0xe4,0xfc,
	0x0c,0x36,0xd9,0x27,0x60,0x9b,0x74,0x4f,0xd2,0x88,0xb8,0xef,0x16,0x2d,0x0a,0x50,
	0x03,0xc5,0x96,0x3b,0x75,0xdf,0xbd,0xcf,0x31,0xd8,0xaf,0xd6,0x25,0x05,0x05,0x56
};

const size_t DME_STRUCTURE_TESTING_TYPE4_DATA_LEN = sizeof (DME_STRUCTURE_TESTING_TYPE4_DATA);

/**
 * Signature of the test type 4 DME structure using ECC_PRIVKEY and SHA256.
 */
const uint8_t DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256[] = {
	0x30,0x45,0x02,0x21,0x00,0x84,0xe5,0xc5,0xe2,0xc9,0x0e,0xf9,0x9c,0xce,0x43,0xe0,
	0x1f,0x81,0x93,0x2b,0xe7,0x0e,0xfd,0x7e,0x9d,0xa2,0x60,0xb9,0x2c,0xda,0x33,0x11,
	0x5b,0xcc,0x62,0x59,0x18,0x02,0x20,0x60,0xc1,0x07,0x7b,0xe3,0x51,0x3a,0xe4,0x6f,
	0x90,0x7d,0xa5,0x49,0xdf,0xd7,0xd3,0x9a,0x46,0xd5,0x1b,0xe0,0x32,0xde,0xd4,0x9a,
	0x54,0x94,0x59,0xe3,0x03,0xb2,0x25
};

const size_t DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_LEN =
	sizeof (DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256);

const uint8_t DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_RAW_R[] = {
	0x84,0xe5,0xc5,0xe2,0xc9,0x0e,0xf9,0x9c,0xce,0x43,0xe0,0x1f,0x81,0x93,0x2b,0xe7,
	0x0e,0xfd,0x7e,0x9d,0xa2,0x60,0xb9,0x2c,0xda,0x33,0x11,0x5b,0xcc,0x62,0x59,0x18
};

const uint8_t DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_RAW_S[] = {
	0x60,0xc1,0x07,0x7b,0xe3,0x51,0x3a,0xe4,0x6f,0x90,0x7d,0xa5,0x49,0xdf,0xd7,0xd3,
	0x9a,0x46,0xd5,0x1b,0xe0,0x32,0xde,0xd4,0x9a,0x54,0x94,0x59,0xe3,0x03,0xb2,0x25
};

/**
 * Signature of the test type 4 DME structure using ECC384_PRIVKEY and SHA384.
 */
const uint8_t DME_STRUCTURE_TESTING_TYPE4_SIG_ECC384_SHA384[] = {
	0x30,0x64,0x02,0x30,0x2a,0x17,0x83,0x8e,0x6b,0x15,0x0a,0xdd,0x72,0x5f,0x22,0x8e,
	0xcc,0x72,0x3a,0x31,0xec,0x9e,0x24,0x15,0x50,0x72,0x22,0x5c,0xe2,0x55,0xa7,0x71,
	0x23,0x30,0x7f,0x4e,0xaf,0xdc,0x10,0x6a,0x89,0xb8,0xba,0xc8,0xa6,0xc4,0xa8,0x28,
	0x19,0x2c,0x4f,0xd1,0x02,0x30,0x55,0x26,0x95,0x36,0xe0,0x97,0x02,0x66,0x88,0x6a,
	0x40,0x99,0x7b,0x06,0x30,0x86,0x5d,0x35,0xca,0x09,0xa6,0x24,0x99,0x61,0x39,0xa4,
	0xb8,0xbf,0x6a,0x2d,0x15,0x75,0x9c,0xe0,0xdf,0xc0,0x3e,0xb2,0x7b,0xb7,0xb4,0xe0,
	0x56,0xff,0x35,0x54,0xc3,0x91
};

const size_t DME_STRUCTURE_TESTING_TYPE4_SIG_ECC384_SHA384_LEN =
	sizeof (DME_STRUCTURE_TESTING_TYPE4_SIG_ECC384_SHA384);

const uint8_t DME_STRUCTURE_TESTING_TYPE4_SIG_ECC384_SHA384_RAW_R[] = {
	0x2a,0x17,0x83,0x8e,0x6b,0x15,0x0a,0xdd,0x72,0x5f,0x22,0x8e,0xcc,0x72,0x3a,0x31,
	0xec,0x9e,0x24,0x15,0x50,0x72,0x22,0x5c,0xe2,0x55,0xa7,0x71,0x23,0x30,0x7f,0x4e,
	0xaf,0xdc,0x10,0x6a,0x89,0xb8,0xba,0xc8,0xa6,0xc4,0xa8,0x28,0x19,0x2c,0x4f,0xd1
};

const uint8_t DME_STRUCTURE_TESTING_TYPE4_SIG_ECC384_SHA384_RAW_S[] = {
	0x55,0x26,0x95,0x36,0xe0,0x97,0x02,0x66,0x88,0x6a,0x40,0x99,0x7b,0x06,0x30,0x86,
	0x5d,0x35,0xca,0x09,0xa6,0x24,0x99,0x61,0x39,0xa4,0xb8,0xbf,0x6a,0x2d,0x15,0x75,
	0x9c,0xe0,0xdf,0xc0,0x3e,0xb2,0x7b,0xb7,0xb4,0xe0,0x56,0xff,0x35,0x54,0xc3,0x91
};

/**
 * Signature of the test type 4 DME structure using ECC521_PRIVKEY and SHA512.
 */
const uint8_t DME_STRUCTURE_TESTING_TYPE4_SIG_ECC521_SHA512[] = {
	0x30,0x81,0x88,0x02,0x42,0x01,0xd9,0x77,0x8f,0x58,0x45,0x96,0x9d,0x14,0x96,0x07,
	0xb9,0x37,0x5d,0x44,0xc5,0xc0,0x25,0x05,0x9b,0x02,0x87,0xf5,0xb8,0xd8,0x21,0x9b,
	0xae,0x89,0xa9,0xc7,0x82,0xd6,0x57,0x95,0x54,0xae,0xd0,0x91,0x26,0x14,0x8c,0x34,
	0xe7,0x06,0xf7,0x27,0xa4,0x3e,0x7d,0xc4,0x77,0x78,0xf7,0xcb,0x8c,0x2c,0x90,0x49,
	0x77,0x80,0x32,0x9a,0x06,0x4b,0xc9,0x02,0x42,0x01,0xf9,0xf6,0xe0,0xa9,0x62,0xbd,
	0x13,0xb2,0xe6,0xee,0x6e,0x07,0xc5,0x5c,0xea,0xf1,0x5d,0x57,0xbc,0xbc,0xc8,0xc0,
	0x2d,0x86,0x73,0x1c,0x38,0x0c,0x1b,0x94,0xb8,0x32,0x11,0x32,0xab,0x76,0x5e,0x1a,
	0x55,0xdb,0xa8,0xd7,0xa9,0x8f,0x65,0x21,0x6d,0xea,0x11,0xef,0x33,0xd7,0xef,0x82,
	0xe2,0x69,0x80,0x2b,0x53,0xca,0x58,0x86,0x77,0x52,0xf0
};

const size_t DME_STRUCTURE_TESTING_TYPE4_SIG_ECC521_SHA512_LEN =
	sizeof (DME_STRUCTURE_TESTING_TYPE4_SIG_ECC521_SHA512);

const uint8_t DME_STRUCTURE_TESTING_TYPE4_SIG_ECC521_SHA512_RAW_R[] = {
	0x01,0xd9,0x77,0x8f,0x58,0x45,0x96,0x9d,0x14,0x96,0x07,0xb9,0x37,0x5d,0x44,0xc5,
	0xc0,0x25,0x05,0x9b,0x02,0x87,0xf5,0xb8,0xd8,0x21,0x9b,0xae,0x89,0xa9,0xc7,0x82,
	0xd6,0x57,0x95,0x54,0xae,0xd0,0x91,0x26,0x14,0x8c,0x34,0xe7,0x06,0xf7,0x27,0xa4,
	0x3e,0x7d,0xc4,0x77,0x78,0xf7,0xcb,0x8c,0x2c,0x90,0x49,0x77,0x80,0x32,0x9a,0x06,
	0x4b,0xc9
};

const uint8_t DME_STRUCTURE_TESTING_TYPE4_SIG_ECC521_SHA512_RAW_S[] = {
	0x01,0xf9,0xf6,0xe0,0xa9,0x62,0xbd,0x13,0xb2,0xe6,0xee,0x6e,0x07,0xc5,0x5c,0xea,
	0xf1,0x5d,0x57,0xbc,0xbc,0xc8,0xc0,0x2d,0x86,0x73,0x1c,0x38,0x0c,0x1b,0x94,0xb8,
	0x32,0x11,0x32,0xab,0x76,0x5e,0x1a,0x55,0xdb,0xa8,0xd7,0xa9,0x8f,0x65,0x21,0x6d,
	0xea,0x11,0xef,0x33,0xd7,0xef,0x82,0xe2,0x69,0x80,0x2b,0x53,0xca,0x58,0x86,0x77,
	0x52,0xf0
};

/**
 * Test OID for a DME structure format type 5.
 */
const uint8_t DME_STRUCTURE_TESTING_TYPE5_OID[] = {
	0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x66,0x03,0x02,0x05
};

const size_t DME_STRUCTURE_TESTING_TYPE5_OID_LEN = sizeof (DME_STRUCTURE_TESTING_TYPE5_OID);

/**
 * Test data for a DME structure type 5.
 */
const uint8_t DME_STRUCTURE_TESTING_TYPE5_DATA[] = {
	0xde,0xf8,0x45,0xb3,0xc0,0x40,0x40,0xdf,0xfc,0x67,0x94,0xc1,0x85,0x71,0x0e,0x35,
	0x79,0xab,0xc6,0x76,0xc8,0x46,0xd8,0x27,0x88,0x86,0x79,0x8f,0xc5,0xcd,0xf7,0x00,
	0x47,0xb3,0xa6,0x62,0xff,0xbf,0x10,0xa1,0xfd,0xfa,0x25,0xf5,0x91,0xfd,0xfd,0xd8,
	0xd5,0x9b,0xbc,0xc4,0x1a,0xf1,0xea,0xc7,0x06,0x11,0x41,0x35,0xc1,0x83,0xf4,0x75,
	0x3c,0x67,0xa7,0x36,0xa6,0xab,0x40,0xdb,0x21,0x69,0xf5,0xd7,0xf8,0x34,0x3d,0x32,
	0x3e,0xc3,0x64,0xbf,0xe7,0xe3,0x83,0xc4,0x56,0xed,0x7e,0x12,0x30,0x2f,0xc4,0x89,
	0xbc,0xfb,0x5f,0x0a,0x00,0x5b,0x87,0xd8,0xf4,0x92,0x05,0xd7,0x8a,0x39,0x7f,0x7b,
	0xbe,0x46,0xa3,0x8f,0xdd,0x27,0xa4,0x87,0x0a,0xae,0x7e,0xfa,0x6f,0x7e,0x36,0x52
};

const size_t DME_STRUCTURE_TESTING_TYPE5_DATA_LEN = sizeof (DME_STRUCTURE_TESTING_TYPE5_DATA);

/**
 * Signature of the test type 5 DME structure using ECC_PRIVKEY and SHA256.
 */
const uint8_t DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256[] = {
	0x30,0x44,0x02,0x20,0x2a,0x8d,0xe3,0x88,0x82,0xb3,0x4f,0x1f,0xbb,0x0d,0x8c,0xed,
	0xda,0x37,0x12,0x65,0xbd,0xa9,0xdf,0x3c,0x5d,0x70,0x76,0xc0,0xe1,0x80,0x7f,0x8a,
	0x10,0x36,0xa4,0x0b,0x02,0x20,0x21,0x0f,0xa6,0x87,0x6e,0x7c,0xa0,0x47,0xe0,0x53,
	0x4f,0x42,0x33,0x29,0xe0,0x53,0x8e,0x4b,0xe8,0xc2,0xc7,0x0d,0xef,0x56,0x9b,0x13,
	0xea,0xfa,0xf1,0xc5,0xbb,0xc7
};

const size_t DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_LEN =
	sizeof (DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256);

const uint8_t DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_RAW_R[] = {
	0x2a,0x8d,0xe3,0x88,0x82,0xb3,0x4f,0x1f,0xbb,0x0d,0x8c,0xed,0xda,0x37,0x12,0x65,
	0xbd,0xa9,0xdf,0x3c,0x5d,0x70,0x76,0xc0,0xe1,0x80,0x7f,0x8a,0x10,0x36,0xa4,0x0b
};

const uint8_t DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_RAW_S[] = {
	0x21,0x0f,0xa6,0x87,0x6e,0x7c,0xa0,0x47,0xe0,0x53,0x4f,0x42,0x33,0x29,0xe0,0x53,
	0x8e,0x4b,0xe8,0xc2,0xc7,0x0d,0xef,0x56,0x9b,0x13,0xea,0xfa,0xf1,0xc5,0xbb,0xc7
};

/**
 * Signature of the test type 5 DME structure using ECC384_PRIVKEY and SHA384.
 */
const uint8_t DME_STRUCTURE_TESTING_TYPE5_SIG_ECC384_SHA384[] = {
	0x30,0x65,0x02,0x31,0x00,0xbb,0x6b,0xca,0xf5,0x7f,0x24,0x30,0x3b,0xd4,0x9f,0x09,
	0x1c,0xa4,0x6e,0x7a,0xee,0x81,0xd4,0xf9,0x3e,0x11,0x8c,0x2e,0x81,0x3b,0x56,0x35,
	0x1e,0x19,0xa0,0x17,0xc9,0xb9,0x25,0x39,0x57,0x33,0xab,0xd4,0x0d,0xd1,0x88,0xfd,
	0xbb,0xf4,0x54,0xc9,0x09,0x02,0x30,0x22,0x6b,0x20,0xa5,0x85,0x70,0x7c,0x90,0x5b,
	0x39,0xcc,0xaf,0x59,0xd6,0x4b,0xd5,0xce,0x76,0xf6,0x19,0x3d,0x88,0xf5,0x48,0xe8,
	0xdf,0xcb,0x42,0x3b,0x19,0xa6,0x20,0x48,0x76,0xa5,0x86,0x4a,0x0f,0x27,0x15,0xf5,
	0xd0,0x19,0x27,0xf0,0x06,0x93,0xa5
};

const size_t DME_STRUCTURE_TESTING_TYPE5_SIG_ECC384_SHA384_LEN =
	sizeof (DME_STRUCTURE_TESTING_TYPE5_SIG_ECC384_SHA384);

const uint8_t DME_STRUCTURE_TESTING_TYPE5_SIG_ECC384_SHA384_RAW_R[] = {
	0xbb,0x6b,0xca,0xf5,0x7f,0x24,0x30,0x3b,0xd4,0x9f,0x09,0x1c,0xa4,0x6e,0x7a,0xee,
	0x81,0xd4,0xf9,0x3e,0x11,0x8c,0x2e,0x81,0x3b,0x56,0x35,0x1e,0x19,0xa0,0x17,0xc9,
	0xb9,0x25,0x39,0x57,0x33,0xab,0xd4,0x0d,0xd1,0x88,0xfd,0xbb,0xf4,0x54,0xc9,0x09
};

const uint8_t DME_STRUCTURE_TESTING_TYPE5_SIG_ECC384_SHA384_RAW_S[] = {
	0x22,0x6b,0x20,0xa5,0x85,0x70,0x7c,0x90,0x5b,0x39,0xcc,0xaf,0x59,0xd6,0x4b,0xd5,
	0xce,0x76,0xf6,0x19,0x3d,0x88,0xf5,0x48,0xe8,0xdf,0xcb,0x42,0x3b,0x19,0xa6,0x20,
	0x48,0x76,0xa5,0x86,0x4a,0x0f,0x27,0x15,0xf5,0xd0,0x19,0x27,0xf0,0x06,0x93,0xa5
};

/**
 * Signature of the test type 5 DME structure using ECC521_PRIVKEY and SHA512.
 */
const uint8_t DME_STRUCTURE_TESTING_TYPE5_SIG_ECC521_SHA512[] = {
	0x30,0x81,0x87,0x02,0x42,0x01,0xa0,0x84,0x6e,0x9a,0x44,0x1c,0xb6,0xf6,0x0b,0x6d,
	0x4b,0x0d,0x9c,0xdd,0x8b,0xa3,0xb7,0x01,0x0d,0xf4,0x47,0x22,0xe0,0x17,0x28,0x1f,
	0xed,0x13,0x0c,0xad,0xb5,0x0e,0xbf,0xcc,0x01,0x9a,0x19,0xf8,0xc7,0x7b,0xca,0x56,
	0x3e,0x36,0x5a,0x87,0x27,0x24,0xba,0x33,0xed,0x29,0x19,0xe2,0x67,0xb8,0x43,0x17,
	0xad,0x30,0xa8,0x0b,0x90,0x74,0x84,0x02,0x41,0x3f,0x3e,0x14,0xc8,0x6c,0x8b,0x34,
	0xf8,0x5f,0x05,0x58,0x31,0x59,0x0b,0xb6,0x12,0x78,0x0a,0x89,0x09,0xdb,0x0e,0x27,
	0xa5,0xe1,0x12,0xce,0x79,0x06,0xc0,0xdd,0xc9,0xd5,0x87,0xf4,0xf0,0x55,0x98,0x8f,
	0x02,0x9a,0xe6,0x74,0xe6,0x05,0x7f,0x30,0xc7,0x5e,0x9f,0x46,0x8f,0xf1,0x60,0xf8,
	0x11,0xf8,0xb2,0x0e,0xb1,0x98,0x28,0xbc,0x46,0xb0
};

const size_t DME_STRUCTURE_TESTING_TYPE5_SIG_ECC521_SHA512_LEN =
	sizeof (DME_STRUCTURE_TESTING_TYPE5_SIG_ECC521_SHA512);

const uint8_t DME_STRUCTURE_TESTING_TYPE5_SIG_ECC521_SHA512_RAW_R[] = {
	0x01,0xa0,0x84,0x6e,0x9a,0x44,0x1c,0xb6,0xf6,0x0b,0x6d,0x4b,0x0d,0x9c,0xdd,0x8b,
	0xa3,0xb7,0x01,0x0d,0xf4,0x47,0x22,0xe0,0x17,0x28,0x1f,0xed,0x13,0x0c,0xad,0xb5,
	0x0e,0xbf,0xcc,0x01,0x9a,0x19,0xf8,0xc7,0x7b,0xca,0x56,0x3e,0x36,0x5a,0x87,0x27,
	0x24,0xba,0x33,0xed,0x29,0x19,0xe2,0x67,0xb8,0x43,0x17,0xad,0x30,0xa8,0x0b,0x90,
	0x74,0x84
};

const uint8_t DME_STRUCTURE_TESTING_TYPE5_SIG_ECC521_SHA512_RAW_S[] = {
	0x00,0x3f,0x3e,0x14,0xc8,0x6c,0x8b,0x34,0xf8,0x5f,0x05,0x58,0x31,0x59,0x0b,0xb6,
	0x12,0x78,0x0a,0x89,0x09,0xdb,0x0e,0x27,0xa5,0xe1,0x12,0xce,0x79,0x06,0xc0,0xdd,
	0xc9,0xd5,0x87,0xf4,0xf0,0x55,0x98,0x8f,0x02,0x9a,0xe6,0x74,0xe6,0x05,0x7f,0x30,
	0xc7,0x5e,0x9f,0x46,0x8f,0xf1,0x60,0xf8,0x11,0xf8,0xb2,0x0e,0xb1,0x98,0x28,0xbc,
	0x46,0xb0
};

/**
 * Test OID for a DME structure format type 6.
 */
const uint8_t DME_STRUCTURE_TESTING_TYPE6_OID[] = {
	0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x66,0x03,0x02,0x06
};

const size_t DME_STRUCTURE_TESTING_TYPE6_OID_LEN = sizeof (DME_STRUCTURE_TESTING_TYPE6_OID);

/**
 * Test data for a DME structure type 6.
 */
const uint8_t DME_STRUCTURE_TESTING_TYPE6_DATA[] = {
	0xa1,0x03,0xe6,0xd7,0x59,0x1f,0x05,0x61,0x82,0xca,0x42,0x03,0xb4,0x27,0x84,0xf1,
	0x08,0xe4,0x2b,0xc0,0xda,0xef,0xc4,0xa1,0x75,0x97,0x03,0x60,0x20,0xad,0x6c,0x53,
	0x63,0x58,0x45,0x7e,0xef,0xca,0x87,0xab,0x86,0x20,0x71,0x50,0xba,0x5e,0x47,0x94,
	0x1c,0x9f,0x8f,0x6b,0x21,0xa9,0xde,0x8a,0x90,0xa9,0x28,0x9b,0x71,0xaa,0xb8,0x4b,
	0x9e,0xa9,0x93,0xa1,0x52,0xf0,0x72,0x9a,0xce,0xea,0x33,0xaf,0x46,0x6e,0x5b,0x19,
	0x8b,0xb9,0x82,0xb5,0x6c,0x90,0x8f,0xc0,0x9f,0xe0,0xb7,0xeb,0x0f,0x9e,0xfa,0xe0,
	0x18,0x82,0xf3,0x38,0x4b,0xde,0xc2,0x1e,0x3f,0x1b,0x83,0xf4,0xd8,0x54,0x4c,0x4b,
	0x8e,0x70,0xb8,0x81,0xce,0x9a,0x3d,0x67,0x20,0xcd,0x98,0x9d,0xc9,0xd3,0x24,0x4b,
	0x0c,0xe9,0x29,0xe4,0x03,0x17,0x44,0x75,0x15,0x53,0xe3,0x68,0x80,0xc9,0x79,0x2f,
	0xbd,0x5a,0x0b,0x77,0x1b,0xc5,0x56,0x3c,0x2e,0xaf,0x12,0x08,0x56,0x95,0x94,0xcc
};

const size_t DME_STRUCTURE_TESTING_TYPE6_DATA_LEN = sizeof (DME_STRUCTURE_TESTING_TYPE6_DATA);

/**
 * Signature of the test type 6 DME structure using ECC_PRIVKEY and SHA256.
 */
const uint8_t DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256[] = {
	0x30,0x46,0x02,0x21,0x00,0x8b,0x58,0xa9,0x54,0x58,0x76,0x0d,0xa3,0x81,0xc3,0xcc,
	0x75,0x02,0x87,0x57,0xb1,0x98,0xe2,0x0f,0xb4,0xd5,0xd0,0xc2,0x1d,0x01,0xc9,0x09,
	0x86,0x20,0x45,0x09,0x67,0x02,0x21,0x00,0x83,0x02,0xbe,0xdc,0x1f,0xb6,0xf4,0x28,
	0x58,0x1c,0x4c,0xdd,0x0a,0x3e,0x07,0x96,0x08,0xf8,0x61,0x6c,0x26,0xe5,0x60,0xbb,
	0xa0,0xa4,0xcc,0x4f,0x79,0xcb,0x7b,0xf5
};

const size_t DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_LEN =
	sizeof (DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256);

const uint8_t DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_RAW_R[] = {
	0x8b,0x58,0xa9,0x54,0x58,0x76,0x0d,0xa3,0x81,0xc3,0xcc,0x75,0x02,0x87,0x57,0xb1,
	0x98,0xe2,0x0f,0xb4,0xd5,0xd0,0xc2,0x1d,0x01,0xc9,0x09,0x86,0x20,0x45,0x09,0x67
};

const uint8_t DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_RAW_S[] = {
	0x83,0x02,0xbe,0xdc,0x1f,0xb6,0xf4,0x28,0x58,0x1c,0x4c,0xdd,0x0a,0x3e,0x07,0x96,
	0x08,0xf8,0x61,0x6c,0x26,0xe5,0x60,0xbb,0xa0,0xa4,0xcc,0x4f,0x79,0xcb,0x7b,0xf5
};

/**
 * Signature of the test type 6 DME structure using ECC384_PRIVKEY and SHA384.
 */
const uint8_t DME_STRUCTURE_TESTING_TYPE6_SIG_ECC384_SHA384[] = {
	0x30,0x65,0x02,0x31,0x00,0xb8,0xda,0x6c,0x9c,0xe7,0xee,0x02,0x30,0xe7,0x1b,0xe7,
	0xb6,0x26,0x2b,0x1f,0xb1,0xb5,0xe7,0x28,0x18,0x74,0xa2,0xe6,0xd4,0xfc,0xf9,0x49,
	0xff,0xea,0x13,0xcb,0xb6,0xcd,0x82,0x0f,0x31,0xe3,0x0a,0xe1,0xab,0xcf,0xda,0x43,
	0x9b,0x8c,0x66,0x8b,0x5e,0x02,0x30,0x4f,0x9b,0x1c,0xdc,0x1d,0xe9,0xdf,0xcb,0xbd,
	0xec,0xf7,0xcd,0xfa,0xff,0xc6,0xf6,0xca,0xfc,0x9c,0x84,0x10,0xb1,0x17,0xcb,0xd8,
	0x99,0x2c,0x64,0x34,0xb3,0xb1,0xb0,0x79,0xf9,0x7c,0xe1,0x50,0xbf,0xbf,0x02,0x5c,
	0x46,0x72,0x0e,0xae,0x5b,0x25,0xe4
};

const size_t DME_STRUCTURE_TESTING_TYPE6_SIG_ECC384_SHA384_LEN =
	sizeof (DME_STRUCTURE_TESTING_TYPE6_SIG_ECC384_SHA384);

const uint8_t DME_STRUCTURE_TESTING_TYPE6_SIG_ECC384_SHA384_RAW_R[] = {
	0xb8,0xda,0x6c,0x9c,0xe7,0xee,0x02,0x30,0xe7,0x1b,0xe7,0xb6,0x26,0x2b,0x1f,0xb1,
	0xb5,0xe7,0x28,0x18,0x74,0xa2,0xe6,0xd4,0xfc,0xf9,0x49,0xff,0xea,0x13,0xcb,0xb6,
	0xcd,0x82,0x0f,0x31,0xe3,0x0a,0xe1,0xab,0xcf,0xda,0x43,0x9b,0x8c,0x66,0x8b,0x5e
};

const uint8_t DME_STRUCTURE_TESTING_TYPE6_SIG_ECC384_SHA384_RAW_S[] = {
	0x4f,0x9b,0x1c,0xdc,0x1d,0xe9,0xdf,0xcb,0xbd,0xec,0xf7,0xcd,0xfa,0xff,0xc6,0xf6,
	0xca,0xfc,0x9c,0x84,0x10,0xb1,0x17,0xcb,0xd8,0x99,0x2c,0x64,0x34,0xb3,0xb1,0xb0,
	0x79,0xf9,0x7c,0xe1,0x50,0xbf,0xbf,0x02,0x5c,0x46,0x72,0x0e,0xae,0x5b,0x25,0xe4
};

/**
 * Signature of the test type 6 DME structure using ECC521_PRIVKEY and SHA512.
 */
const uint8_t DME_STRUCTURE_TESTING_TYPE6_SIG_ECC521_SHA512[] = {
	0x30,0x81,0x88,0x02,0x42,0x01,0x4d,0x8c,0xa5,0x84,0x34,0xf5,0x88,0xa3,0x7b,0xa0,
	0x88,0x59,0xe2,0x71,0xf0,0x56,0x9a,0xa4,0xab,0xdd,0xb7,0x87,0x81,0xd3,0xd3,0xe1,
	0x46,0x3b,0x4a,0xcf,0xab,0x3e,0x34,0xb0,0xbc,0xc6,0xa5,0x7c,0xf8,0x63,0xfc,0xcd,
	0xdc,0xa9,0xb1,0x0d,0xf7,0x32,0xc2,0x64,0x56,0xd7,0xfd,0x39,0x20,0xf6,0x6c,0x84,
	0x9b,0x67,0xbe,0xb3,0x0a,0x1e,0x27,0x02,0x42,0x01,0x1f,0xf2,0x4a,0xd2,0x91,0x06,
	0x4b,0xed,0xe1,0xa4,0xe3,0x1e,0x67,0xd3,0x92,0x07,0x94,0x76,0x04,0x4f,0xa2,0xd7,
	0x0d,0x19,0x63,0x2d,0xcd,0x3a,0x3b,0x80,0x8f,0x52,0x8e,0x06,0xd2,0x0a,0x8d,0xbe,
	0x13,0x3d,0xee,0x37,0x04,0x51,0xba,0xfd,0x2e,0x99,0xb0,0x00,0xbf,0x37,0x8a,0x4f,
	0x8d,0x2a,0xdb,0x78,0xeb,0xd5,0x90,0x11,0xf6,0x0e,0xae
};

const size_t DME_STRUCTURE_TESTING_TYPE6_SIG_ECC521_SHA512_LEN =
	sizeof (DME_STRUCTURE_TESTING_TYPE6_SIG_ECC521_SHA512);

const uint8_t DME_STRUCTURE_TESTING_TYPE6_SIG_ECC521_SHA512_RAW_R[] = {
	0x01,0x4d,0x8c,0xa5,0x84,0x34,0xf5,0x88,0xa3,0x7b,0xa0,0x88,0x59,0xe2,0x71,0xf0,
	0x56,0x9a,0xa4,0xab,0xdd,0xb7,0x87,0x81,0xd3,0xd3,0xe1,0x46,0x3b,0x4a,0xcf,0xab,
	0x3e,0x34,0xb0,0xbc,0xc6,0xa5,0x7c,0xf8,0x63,0xfc,0xcd,0xdc,0xa9,0xb1,0x0d,0xf7,
	0x32,0xc2,0x64,0x56,0xd7,0xfd,0x39,0x20,0xf6,0x6c,0x84,0x9b,0x67,0xbe,0xb3,0x0a,
	0x1e,0x27
};

const uint8_t DME_STRUCTURE_TESTING_TYPE6_SIG_ECC521_SHA512_RAW_S[] = {
	0x01,0x1f,0xf2,0x4a,0xd2,0x91,0x06,0x4b,0xed,0xe1,0xa4,0xe3,0x1e,0x67,0xd3,0x92,
	0x07,0x94,0x76,0x04,0x4f,0xa2,0xd7,0x0d,0x19,0x63,0x2d,0xcd,0x3a,0x3b,0x80,0x8f,
	0x52,0x8e,0x06,0xd2,0x0a,0x8d,0xbe,0x13,0x3d,0xee,0x37,0x04,0x51,0xba,0xfd,0x2e,
	0x99,0xb0,0x00,0xbf,0x37,0x8a,0x4f,0x8d,0x2a,0xdb,0x78,0xeb,0xd5,0x90,0x11,0xf6,
	0x0e,0xae
};


/**
 * Populate a DME structure with test data, signed using ECC384_PRIVKEY and SHA384.
 *
 * @param dme The DME struture to populate.
 */
void dme_structure_testing_structure_ecc384_sha384 (struct dme_structure *dme)
{
	dme->data_oid = DME_STRUCTURE_TESTING_OID_TYPE;
	dme->data_oid_length = DME_STRUCTURE_TESTING_OID_TYPE_LEN;
	dme->data = DME_STRUCTURE_TESTING_DATA;
	dme->data_length = DME_STRUCTURE_TESTING_DATA_LEN;
	dme->sig_oid = DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA384;
	dme->sig_oid_length = DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA384_LEN;
	dme->signature = DME_STRUCTURE_TESTING_SIG_ECC384_SHA384;
	dme->signature_length = DME_STRUCTURE_TESTING_SIG_ECC384_SHA384_LEN;
	dme->dme_pub_key = ECC384_PUBKEY_DER;
	dme->key_length = ECC384_PUBKEY_DER_LEN;
	dme->device_oid = X509_EKU_OID;
	dme->dev_oid_length = X509_EKU_OID_LEN;
	dme->renewal_counter = DME_STRUCTURE_TESTING_RENEWAL_COUNTER;
	dme->counter_length = DME_STRUCTURE_TESTING_RENEWAL_COUNTER_LEN;
}

/**
 * Populate a DME structure with test data, signed using ECC384_PRIVKEY and SHA384.  No device type
 * OID is provided.
 *
 * @param dme The DME struture to populate.
 */
void dme_structure_testing_structure_no_device_oid (struct dme_structure *dme)
{
	dme->data_oid = DME_STRUCTURE_TESTING_OID_TYPE;
	dme->data_oid_length = DME_STRUCTURE_TESTING_OID_TYPE_LEN;
	dme->data = DME_STRUCTURE_TESTING_DATA;
	dme->data_length = DME_STRUCTURE_TESTING_DATA_LEN;
	dme->sig_oid = DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA384;
	dme->sig_oid_length = DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA384_LEN;
	dme->signature = DME_STRUCTURE_TESTING_SIG_ECC384_SHA384;
	dme->signature_length = DME_STRUCTURE_TESTING_SIG_ECC384_SHA384_LEN;
	dme->dme_pub_key = ECC384_PUBKEY_DER;
	dme->key_length = ECC384_PUBKEY_DER_LEN;
	dme->device_oid = NULL;
	dme->dev_oid_length = 0;
	dme->renewal_counter = DME_STRUCTURE_TESTING_RENEWAL_COUNTER;
	dme->counter_length = DME_STRUCTURE_TESTING_RENEWAL_COUNTER_LEN;
}

/**
 * Populate a DME structure with test data, signed using ECC384_PRIVKEY and SHA384.  No DME renewal
 * counter is provided.
 *
 * @param dme The DME struture to populate.
 */
void dme_structure_testing_structure_no_renewal (struct dme_structure *dme)
{
	dme->data_oid = DME_STRUCTURE_TESTING_OID_TYPE;
	dme->data_oid_length = DME_STRUCTURE_TESTING_OID_TYPE_LEN;
	dme->data = DME_STRUCTURE_TESTING_DATA;
	dme->data_length = DME_STRUCTURE_TESTING_DATA_LEN;
	dme->sig_oid = DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA384;
	dme->sig_oid_length = DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA384_LEN;
	dme->signature = DME_STRUCTURE_TESTING_SIG_ECC384_SHA384;
	dme->signature_length = DME_STRUCTURE_TESTING_SIG_ECC384_SHA384_LEN;
	dme->dme_pub_key = ECC384_PUBKEY_DER;
	dme->key_length = ECC384_PUBKEY_DER_LEN;
	dme->device_oid = X509_EKU_OID;
	dme->dev_oid_length = X509_EKU_OID_LEN;
	dme->renewal_counter = NULL;
	dme->counter_length = 0;
}

/**
 * Populate a DME structure with test data, signed using ECC_PRIVKEY and SHA256.
 *
 * @param dme The DME struture to populate.
 */
void dme_structure_testing_structure_ecc256_sha256 (struct dme_structure *dme)
{
	dme->data_oid = DME_STRUCTURE_TESTING_OID_TYPE;
	dme->data_oid_length = DME_STRUCTURE_TESTING_OID_TYPE_LEN;
	dme->data = DME_STRUCTURE_TESTING_DATA;
	dme->data_length = DME_STRUCTURE_TESTING_DATA_LEN;
	dme->sig_oid = DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA256;
	dme->sig_oid_length = DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA256_LEN;
	dme->signature = DME_STRUCTURE_TESTING_SIG_ECC256_SHA256;
	dme->signature_length = DME_STRUCTURE_TESTING_SIG_ECC256_SHA256_LEN;
	dme->dme_pub_key = ECC_PUBKEY_DER;
	dme->key_length = ECC_PUBKEY_DER_LEN;
	dme->device_oid = X509_EKU_OID;
	dme->dev_oid_length = X509_EKU_OID_LEN;
	dme->renewal_counter = DME_STRUCTURE_TESTING_RENEWAL_COUNTER;
	dme->counter_length = DME_STRUCTURE_TESTING_RENEWAL_COUNTER_LEN;
}

/**
 * Populate a DME structure with test data, signed using ECC521_PRIVKEY and SHA512.
 *
 * @param dme The DME struture to populate.
 */
void dme_structure_testing_structure_ecc521_sha512 (struct dme_structure *dme)
{
	dme->data_oid = DME_STRUCTURE_TESTING_OID_TYPE;
	dme->data_oid_length = DME_STRUCTURE_TESTING_OID_TYPE_LEN;
	dme->data = DME_STRUCTURE_TESTING_DATA;
	dme->data_length = DME_STRUCTURE_TESTING_DATA_LEN;
	dme->sig_oid = DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA512;
	dme->sig_oid_length = DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA512_LEN;
	dme->signature = DME_STRUCTURE_TESTING_SIG_ECC521_SHA512;
	dme->signature_length = DME_STRUCTURE_TESTING_SIG_ECC521_SHA512_LEN;
	dme->dme_pub_key = ECC_PUBKEY_DER;
	dme->key_length = ECC_PUBKEY_DER_LEN;
	dme->device_oid = X509_EKU_OID;
	dme->dev_oid_length = X509_EKU_OID_LEN;
	dme->renewal_counter = DME_STRUCTURE_TESTING_RENEWAL_COUNTER;
	dme->counter_length = DME_STRUCTURE_TESTING_RENEWAL_COUNTER_LEN;
}


/*******************
 * Test cases
 *******************/

static void dme_structure_test_init_sha384_dme_key_ecc256 (CuTest *test)
{
	struct dme_structure dme;
	int status;

	TEST_START;

	status = dme_structure_init_sha384 (&dme, DME_STRUCTURE_TESTING_TYPE1_DATA,
		DME_STRUCTURE_TESTING_TYPE1_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE1_OID_LEN, dme.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE1_OID, dme.data_oid,
		dme.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE1_DATA_LEN, dme.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE1_DATA, (void*) dme.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA256_LEN, dme.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA256, dme.sig_oid,
		dme.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_LEN,
		dme.signature_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256,
		(void*) dme.signature);

	CuAssertIntEquals (test, ECC_PUBKEY2_DER_LEN, dme.key_length);
	CuAssertPtrEquals (test, (void*) ECC_PUBKEY2_DER, (void*) dme.dme_pub_key);

	CuAssertPtrEquals (test, NULL, (void*) dme.device_oid);
	CuAssertIntEquals (test, 0, dme.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.renewal_counter);
	CuAssertIntEquals (test, 0, dme.counter_length);
}

static void dme_structure_test_init_sha384_dme_key_ecc384 (CuTest *test)
{
	struct dme_structure dme;
	int status;

	TEST_START;

	status = dme_structure_init_sha384 (&dme, DME_STRUCTURE_TESTING_TYPE1_DATA,
		DME_STRUCTURE_TESTING_TYPE1_DATA_LEN, ECC384_PUBKEY2_DER, ECC384_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC384_SHA384,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC384_SHA384_LEN, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE1_OID_LEN, dme.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE1_OID, dme.data_oid,
		dme.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE1_DATA_LEN, dme.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE1_DATA, (void*) dme.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA384_LEN, dme.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA384, dme.sig_oid,
		dme.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE1_SIG_ECC384_SHA384_LEN,
		dme.signature_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE1_SIG_ECC384_SHA384,
		(void*) dme.signature);

	CuAssertIntEquals (test, ECC384_PUBKEY2_DER_LEN, dme.key_length);
	CuAssertPtrEquals (test, (void*) ECC384_PUBKEY2_DER, (void*) dme.dme_pub_key);

	CuAssertPtrEquals (test, NULL, (void*) dme.device_oid);
	CuAssertIntEquals (test, 0, dme.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.renewal_counter);
	CuAssertIntEquals (test, 0, dme.counter_length);
}

static void dme_structure_test_init_sha384_dme_key_ecc521 (CuTest *test)
{
	struct dme_structure dme;
	int status;

	TEST_START;

	status = dme_structure_init_sha384 (&dme, DME_STRUCTURE_TESTING_TYPE1_DATA,
		DME_STRUCTURE_TESTING_TYPE1_DATA_LEN, ECC521_PUBKEY2_DER, ECC521_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC521_SHA512,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC521_SHA512_LEN, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE1_OID_LEN, dme.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE1_OID, dme.data_oid,
		dme.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE1_DATA_LEN, dme.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE1_DATA, (void*) dme.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA512_LEN, dme.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA512, dme.sig_oid,
		dme.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE1_SIG_ECC521_SHA512_LEN,
		dme.signature_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE1_SIG_ECC521_SHA512,
		(void*) dme.signature);

	CuAssertIntEquals (test, ECC521_PUBKEY2_DER_LEN, dme.key_length);
	CuAssertPtrEquals (test, (void*) ECC521_PUBKEY2_DER, (void*) dme.dme_pub_key);

	CuAssertPtrEquals (test, NULL, (void*) dme.device_oid);
	CuAssertIntEquals (test, 0, dme.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.renewal_counter);
	CuAssertIntEquals (test, 0, dme.counter_length);
}

static void dme_structure_test_init_sha384_null (CuTest *test)
{
	struct dme_structure dme;
	int status;

	TEST_START;

	status = dme_structure_init_sha384 (NULL, DME_STRUCTURE_TESTING_TYPE1_DATA,
		DME_STRUCTURE_TESTING_TYPE1_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_init_sha384 (&dme, NULL,
		DME_STRUCTURE_TESTING_TYPE1_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_init_sha384 (&dme, DME_STRUCTURE_TESTING_TYPE1_DATA,
		DME_STRUCTURE_TESTING_TYPE1_DATA_LEN, NULL, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_init_sha384 (&dme, DME_STRUCTURE_TESTING_TYPE1_DATA,
		DME_STRUCTURE_TESTING_TYPE1_DATA_LEN, ECC_PUBKEY2_DER, 0,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_init_sha384 (&dme, DME_STRUCTURE_TESTING_TYPE1_DATA,
		DME_STRUCTURE_TESTING_TYPE1_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		NULL,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_init_sha384 (&dme, DME_STRUCTURE_TESTING_TYPE1_DATA,
		DME_STRUCTURE_TESTING_TYPE1_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256,
		0, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);
}

static void dme_structure_test_init_sha384_bad_structure_length (CuTest *test)
{
	struct dme_structure dme;
	int status;

	TEST_START;

	status = dme_structure_init_sha384 (&dme, DME_STRUCTURE_TESTING_TYPE1_DATA,
		DME_STRUCTURE_TESTING_TYPE1_DATA_LEN - 1, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_BAD_LENGTH, status);

	status = dme_structure_init_sha384 (&dme, DME_STRUCTURE_TESTING_TYPE1_DATA,
		DME_STRUCTURE_TESTING_TYPE1_DATA_LEN + 1, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_BAD_LENGTH, status);
}

static void dme_structure_test_init_sha384_unsupported_signature_hash (CuTest *test)
{
	struct dme_structure dme;
	int status;

	TEST_START;

	status = dme_structure_init_sha384 (&dme, DME_STRUCTURE_TESTING_TYPE1_DATA,
		DME_STRUCTURE_TESTING_TYPE1_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA1);
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_SIGNATURE, status);

	status = dme_structure_init_sha384 (&dme, DME_STRUCTURE_TESTING_TYPE1_DATA,
		DME_STRUCTURE_TESTING_TYPE1_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE1_SIG_ECC256_SHA256_LEN, (enum hash_type) 10);
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_SIGNATURE, status);
}

static void dme_structure_test_init_sha384_with_challenge_dme_key_ecc256 (CuTest *test)
{
	struct dme_structure dme;
	int status;

	TEST_START;

	status = dme_structure_init_sha384_with_challenge (&dme, DME_STRUCTURE_TESTING_TYPE2_DATA,
		DME_STRUCTURE_TESTING_TYPE2_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE2_OID_LEN, dme.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE2_OID, dme.data_oid,
		dme.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE2_DATA_LEN, dme.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE2_DATA, (void*) dme.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA256_LEN, dme.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA256, dme.sig_oid,
		dme.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_LEN,
		dme.signature_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256,
		(void*) dme.signature);

	CuAssertIntEquals (test, ECC_PUBKEY2_DER_LEN, dme.key_length);
	CuAssertPtrEquals (test, (void*) ECC_PUBKEY2_DER, (void*) dme.dme_pub_key);

	CuAssertPtrEquals (test, NULL, (void*) dme.device_oid);
	CuAssertIntEquals (test, 0, dme.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.renewal_counter);
	CuAssertIntEquals (test, 0, dme.counter_length);
}

static void dme_structure_test_init_sha384_with_challenge_dme_key_ecc384 (CuTest *test)
{
	struct dme_structure dme;
	int status;

	TEST_START;

	status = dme_structure_init_sha384_with_challenge (&dme, DME_STRUCTURE_TESTING_TYPE2_DATA,
		DME_STRUCTURE_TESTING_TYPE2_DATA_LEN, ECC384_PUBKEY2_DER, ECC384_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC384_SHA384,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC384_SHA384_LEN, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE2_OID_LEN, dme.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE2_OID, dme.data_oid,
		dme.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE2_DATA_LEN, dme.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE2_DATA, (void*) dme.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA384_LEN, dme.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA384, dme.sig_oid,
		dme.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE2_SIG_ECC384_SHA384_LEN,
		dme.signature_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE2_SIG_ECC384_SHA384,
		(void*) dme.signature);

	CuAssertIntEquals (test, ECC384_PUBKEY2_DER_LEN, dme.key_length);
	CuAssertPtrEquals (test, (void*) ECC384_PUBKEY2_DER, (void*) dme.dme_pub_key);

	CuAssertPtrEquals (test, NULL, (void*) dme.device_oid);
	CuAssertIntEquals (test, 0, dme.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.renewal_counter);
	CuAssertIntEquals (test, 0, dme.counter_length);
}

static void dme_structure_test_init_sha384_with_challenge_dme_key_ecc521 (CuTest *test)
{
	struct dme_structure dme;
	int status;

	TEST_START;

	status = dme_structure_init_sha384_with_challenge (&dme, DME_STRUCTURE_TESTING_TYPE2_DATA,
		DME_STRUCTURE_TESTING_TYPE2_DATA_LEN, ECC521_PUBKEY2_DER, ECC521_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC521_SHA512,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC521_SHA512_LEN, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE2_OID_LEN, dme.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE2_OID, dme.data_oid,
		dme.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE2_DATA_LEN, dme.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE2_DATA, (void*) dme.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA512_LEN, dme.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA512, dme.sig_oid,
		dme.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE2_SIG_ECC521_SHA512_LEN,
		dme.signature_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE2_SIG_ECC521_SHA512,
		(void*) dme.signature);

	CuAssertIntEquals (test, ECC521_PUBKEY2_DER_LEN, dme.key_length);
	CuAssertPtrEquals (test, (void*) ECC521_PUBKEY2_DER, (void*) dme.dme_pub_key);

	CuAssertPtrEquals (test, NULL, (void*) dme.device_oid);
	CuAssertIntEquals (test, 0, dme.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.renewal_counter);
	CuAssertIntEquals (test, 0, dme.counter_length);
}

static void dme_structure_test_init_sha384_with_challenge_null (CuTest *test)
{
	struct dme_structure dme;
	int status;

	TEST_START;

	status = dme_structure_init_sha384_with_challenge (NULL, DME_STRUCTURE_TESTING_TYPE2_DATA,
		DME_STRUCTURE_TESTING_TYPE2_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_init_sha384_with_challenge (&dme, NULL,
		DME_STRUCTURE_TESTING_TYPE2_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_init_sha384_with_challenge (&dme, DME_STRUCTURE_TESTING_TYPE2_DATA,
		DME_STRUCTURE_TESTING_TYPE2_DATA_LEN, NULL, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_init_sha384_with_challenge (&dme, DME_STRUCTURE_TESTING_TYPE2_DATA,
		DME_STRUCTURE_TESTING_TYPE2_DATA_LEN, ECC_PUBKEY2_DER, 0,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_init_sha384_with_challenge (&dme, DME_STRUCTURE_TESTING_TYPE2_DATA,
		DME_STRUCTURE_TESTING_TYPE2_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		NULL,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_init_sha384_with_challenge (&dme, DME_STRUCTURE_TESTING_TYPE2_DATA,
		DME_STRUCTURE_TESTING_TYPE2_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256,
		0, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);
}

static void dme_structure_test_init_sha384_with_challenge_bad_structure_length (CuTest *test)
{
	struct dme_structure dme;
	int status;

	TEST_START;

	status = dme_structure_init_sha384_with_challenge (&dme, DME_STRUCTURE_TESTING_TYPE2_DATA,
		DME_STRUCTURE_TESTING_TYPE2_DATA_LEN - 1, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_BAD_LENGTH, status);

	status = dme_structure_init_sha384_with_challenge (&dme, DME_STRUCTURE_TESTING_TYPE2_DATA,
		DME_STRUCTURE_TESTING_TYPE2_DATA_LEN + 1, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_BAD_LENGTH, status);
}

static void dme_structure_test_init_sha384_with_challenge_unsupported_signature_hash (CuTest *test)
{
	struct dme_structure dme;
	int status;

	TEST_START;

	status = dme_structure_init_sha384_with_challenge (&dme, DME_STRUCTURE_TESTING_TYPE2_DATA,
		DME_STRUCTURE_TESTING_TYPE2_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA1);
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_SIGNATURE, status);

	status = dme_structure_init_sha384_with_challenge (&dme, DME_STRUCTURE_TESTING_TYPE2_DATA,
		DME_STRUCTURE_TESTING_TYPE2_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE2_SIG_ECC256_SHA256_LEN, (enum hash_type) 10);
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_SIGNATURE, status);
}

static void dme_structure_test_init_sha256_dme_key_ecc256 (CuTest *test)
{
	struct dme_structure dme;
	int status;

	TEST_START;

	status = dme_structure_init_sha256 (&dme, DME_STRUCTURE_TESTING_TYPE3_DATA,
		DME_STRUCTURE_TESTING_TYPE3_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE3_OID_LEN, dme.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE3_OID, dme.data_oid,
		dme.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE3_DATA_LEN, dme.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE3_DATA, (void*) dme.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA256_LEN, dme.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA256, dme.sig_oid,
		dme.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_LEN,
		dme.signature_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256,
		(void*) dme.signature);

	CuAssertIntEquals (test, ECC_PUBKEY2_DER_LEN, dme.key_length);
	CuAssertPtrEquals (test, (void*) ECC_PUBKEY2_DER, (void*) dme.dme_pub_key);

	CuAssertPtrEquals (test, NULL, (void*) dme.device_oid);
	CuAssertIntEquals (test, 0, dme.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.renewal_counter);
	CuAssertIntEquals (test, 0, dme.counter_length);
}

static void dme_structure_test_init_sha256_dme_key_ecc384 (CuTest *test)
{
	struct dme_structure dme;
	int status;

	TEST_START;

	status = dme_structure_init_sha256 (&dme, DME_STRUCTURE_TESTING_TYPE3_DATA,
		DME_STRUCTURE_TESTING_TYPE3_DATA_LEN, ECC384_PUBKEY2_DER, ECC384_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC384_SHA384,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC384_SHA384_LEN, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE3_OID_LEN, dme.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE3_OID, dme.data_oid,
		dme.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE3_DATA_LEN, dme.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE3_DATA, (void*) dme.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA384_LEN, dme.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA384, dme.sig_oid,
		dme.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE3_SIG_ECC384_SHA384_LEN,
		dme.signature_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE3_SIG_ECC384_SHA384,
		(void*) dme.signature);

	CuAssertIntEquals (test, ECC384_PUBKEY2_DER_LEN, dme.key_length);
	CuAssertPtrEquals (test, (void*) ECC384_PUBKEY2_DER, (void*) dme.dme_pub_key);

	CuAssertPtrEquals (test, NULL, (void*) dme.device_oid);
	CuAssertIntEquals (test, 0, dme.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.renewal_counter);
	CuAssertIntEquals (test, 0, dme.counter_length);
}

static void dme_structure_test_init_sha256_dme_key_ecc521 (CuTest *test)
{
	struct dme_structure dme;
	int status;

	TEST_START;

	status = dme_structure_init_sha256 (&dme, DME_STRUCTURE_TESTING_TYPE3_DATA,
		DME_STRUCTURE_TESTING_TYPE3_DATA_LEN, ECC521_PUBKEY2_DER, ECC521_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC521_SHA512,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC521_SHA512_LEN, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE3_OID_LEN, dme.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE3_OID, dme.data_oid,
		dme.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE3_DATA_LEN, dme.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE3_DATA, (void*) dme.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA512_LEN, dme.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA512, dme.sig_oid,
		dme.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE3_SIG_ECC521_SHA512_LEN,
		dme.signature_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE3_SIG_ECC521_SHA512,
		(void*) dme.signature);

	CuAssertIntEquals (test, ECC521_PUBKEY2_DER_LEN, dme.key_length);
	CuAssertPtrEquals (test, (void*) ECC521_PUBKEY2_DER, (void*) dme.dme_pub_key);

	CuAssertPtrEquals (test, NULL, (void*) dme.device_oid);
	CuAssertIntEquals (test, 0, dme.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.renewal_counter);
	CuAssertIntEquals (test, 0, dme.counter_length);
}

static void dme_structure_test_init_sha256_null (CuTest *test)
{
	struct dme_structure dme;
	int status;

	TEST_START;

	status = dme_structure_init_sha256 (NULL, DME_STRUCTURE_TESTING_TYPE3_DATA,
		DME_STRUCTURE_TESTING_TYPE3_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_init_sha256 (&dme, NULL,
		DME_STRUCTURE_TESTING_TYPE3_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_init_sha256 (&dme, DME_STRUCTURE_TESTING_TYPE3_DATA,
		DME_STRUCTURE_TESTING_TYPE3_DATA_LEN, NULL, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_init_sha256 (&dme, DME_STRUCTURE_TESTING_TYPE3_DATA,
		DME_STRUCTURE_TESTING_TYPE3_DATA_LEN, ECC_PUBKEY2_DER, 0,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_init_sha256 (&dme, DME_STRUCTURE_TESTING_TYPE3_DATA,
		DME_STRUCTURE_TESTING_TYPE3_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		NULL,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_init_sha256 (&dme, DME_STRUCTURE_TESTING_TYPE3_DATA,
		DME_STRUCTURE_TESTING_TYPE3_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256,
		0, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);
}

static void dme_structure_test_init_sha256_bad_structure_length (CuTest *test)
{
	struct dme_structure dme;
	int status;

	TEST_START;

	status = dme_structure_init_sha256 (&dme, DME_STRUCTURE_TESTING_TYPE3_DATA,
		DME_STRUCTURE_TESTING_TYPE3_DATA_LEN - 1, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_BAD_LENGTH, status);

	status = dme_structure_init_sha256 (&dme, DME_STRUCTURE_TESTING_TYPE3_DATA,
		DME_STRUCTURE_TESTING_TYPE3_DATA_LEN + 1, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_BAD_LENGTH, status);
}

static void dme_structure_test_init_sha256_unsupported_signature_hash (CuTest *test)
{
	struct dme_structure dme;
	int status;

	TEST_START;

	status = dme_structure_init_sha256 (&dme, DME_STRUCTURE_TESTING_TYPE3_DATA,
		DME_STRUCTURE_TESTING_TYPE3_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA1);
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_SIGNATURE, status);

	status = dme_structure_init_sha256 (&dme, DME_STRUCTURE_TESTING_TYPE3_DATA,
		DME_STRUCTURE_TESTING_TYPE3_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE3_SIG_ECC256_SHA256_LEN, (enum hash_type) 10);
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_SIGNATURE, status);
}

static void dme_structure_test_init_sha256_with_challenge_dme_key_ecc256 (CuTest *test)
{
	struct dme_structure dme;
	int status;

	TEST_START;

	status = dme_structure_init_sha256_with_challenge (&dme, DME_STRUCTURE_TESTING_TYPE4_DATA,
		DME_STRUCTURE_TESTING_TYPE4_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE4_OID_LEN, dme.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE4_OID, dme.data_oid,
		dme.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE4_DATA_LEN, dme.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE4_DATA, (void*) dme.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA256_LEN, dme.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA256, dme.sig_oid,
		dme.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_LEN,
		dme.signature_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256,
		(void*) dme.signature);

	CuAssertIntEquals (test, ECC_PUBKEY2_DER_LEN, dme.key_length);
	CuAssertPtrEquals (test, (void*) ECC_PUBKEY2_DER, (void*) dme.dme_pub_key);

	CuAssertPtrEquals (test, NULL, (void*) dme.device_oid);
	CuAssertIntEquals (test, 0, dme.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.renewal_counter);
	CuAssertIntEquals (test, 0, dme.counter_length);
}

static void dme_structure_test_init_sha256_with_challenge_dme_key_ecc384 (CuTest *test)
{
	struct dme_structure dme;
	int status;

	TEST_START;

	status = dme_structure_init_sha256_with_challenge (&dme, DME_STRUCTURE_TESTING_TYPE4_DATA,
		DME_STRUCTURE_TESTING_TYPE4_DATA_LEN, ECC384_PUBKEY2_DER, ECC384_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC384_SHA384,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC384_SHA384_LEN, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE4_OID_LEN, dme.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE4_OID, dme.data_oid,
		dme.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE4_DATA_LEN, dme.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE4_DATA, (void*) dme.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA384_LEN, dme.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA384, dme.sig_oid,
		dme.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE4_SIG_ECC384_SHA384_LEN,
		dme.signature_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE4_SIG_ECC384_SHA384,
		(void*) dme.signature);

	CuAssertIntEquals (test, ECC384_PUBKEY2_DER_LEN, dme.key_length);
	CuAssertPtrEquals (test, (void*) ECC384_PUBKEY2_DER, (void*) dme.dme_pub_key);

	CuAssertPtrEquals (test, NULL, (void*) dme.device_oid);
	CuAssertIntEquals (test, 0, dme.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.renewal_counter);
	CuAssertIntEquals (test, 0, dme.counter_length);
}

static void dme_structure_test_init_sha256_with_challenge_dme_key_ecc521 (CuTest *test)
{
	struct dme_structure dme;
	int status;

	TEST_START;

	status = dme_structure_init_sha256_with_challenge (&dme, DME_STRUCTURE_TESTING_TYPE4_DATA,
		DME_STRUCTURE_TESTING_TYPE4_DATA_LEN, ECC521_PUBKEY2_DER, ECC521_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC521_SHA512,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC521_SHA512_LEN, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE4_OID_LEN, dme.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE4_OID, dme.data_oid,
		dme.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE4_DATA_LEN, dme.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE4_DATA, (void*) dme.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA512_LEN, dme.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA512, dme.sig_oid,
		dme.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE4_SIG_ECC521_SHA512_LEN,
		dme.signature_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE4_SIG_ECC521_SHA512,
		(void*) dme.signature);

	CuAssertIntEquals (test, ECC521_PUBKEY2_DER_LEN, dme.key_length);
	CuAssertPtrEquals (test, (void*) ECC521_PUBKEY2_DER, (void*) dme.dme_pub_key);

	CuAssertPtrEquals (test, NULL, (void*) dme.device_oid);
	CuAssertIntEquals (test, 0, dme.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.renewal_counter);
	CuAssertIntEquals (test, 0, dme.counter_length);
}

static void dme_structure_test_init_sha256_with_challenge_null (CuTest *test)
{
	struct dme_structure dme;
	int status;

	TEST_START;

	status = dme_structure_init_sha256_with_challenge (NULL, DME_STRUCTURE_TESTING_TYPE4_DATA,
		DME_STRUCTURE_TESTING_TYPE4_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_init_sha256_with_challenge (&dme, NULL,
		DME_STRUCTURE_TESTING_TYPE4_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_init_sha256_with_challenge (&dme, DME_STRUCTURE_TESTING_TYPE4_DATA,
		DME_STRUCTURE_TESTING_TYPE4_DATA_LEN, NULL, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_init_sha256_with_challenge (&dme, DME_STRUCTURE_TESTING_TYPE4_DATA,
		DME_STRUCTURE_TESTING_TYPE4_DATA_LEN, ECC_PUBKEY2_DER, 0,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_init_sha256_with_challenge (&dme, DME_STRUCTURE_TESTING_TYPE4_DATA,
		DME_STRUCTURE_TESTING_TYPE4_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		NULL,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_init_sha256_with_challenge (&dme, DME_STRUCTURE_TESTING_TYPE4_DATA,
		DME_STRUCTURE_TESTING_TYPE4_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256,
		0, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);
}

static void dme_structure_test_init_sha256_with_challenge_bad_structure_length (CuTest *test)
{
	struct dme_structure dme;
	int status;

	TEST_START;

	status = dme_structure_init_sha256_with_challenge (&dme, DME_STRUCTURE_TESTING_TYPE4_DATA,
		DME_STRUCTURE_TESTING_TYPE4_DATA_LEN - 1, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_BAD_LENGTH, status);

	status = dme_structure_init_sha256_with_challenge (&dme, DME_STRUCTURE_TESTING_TYPE4_DATA,
		DME_STRUCTURE_TESTING_TYPE4_DATA_LEN + 1, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_BAD_LENGTH, status);
}

static void dme_structure_test_init_sha256_with_challenge_unsupported_signature_hash (CuTest *test)
{
	struct dme_structure dme;
	int status;

	TEST_START;

	status = dme_structure_init_sha256_with_challenge (&dme, DME_STRUCTURE_TESTING_TYPE4_DATA,
		DME_STRUCTURE_TESTING_TYPE4_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA1);
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_SIGNATURE, status);

	status = dme_structure_init_sha256_with_challenge (&dme, DME_STRUCTURE_TESTING_TYPE4_DATA,
		DME_STRUCTURE_TESTING_TYPE4_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE4_SIG_ECC256_SHA256_LEN, (enum hash_type) 10);
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_SIGNATURE, status);
}

static void dme_structure_test_init_sha512_dme_key_ecc256 (CuTest *test)
{
	struct dme_structure dme;
	int status;

	TEST_START;

	status = dme_structure_init_sha512 (&dme, DME_STRUCTURE_TESTING_TYPE5_DATA,
		DME_STRUCTURE_TESTING_TYPE5_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE5_OID_LEN, dme.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE5_OID, dme.data_oid,
		dme.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE5_DATA_LEN, dme.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE5_DATA, (void*) dme.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA256_LEN, dme.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA256, dme.sig_oid,
		dme.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_LEN,
		dme.signature_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256,
		(void*) dme.signature);

	CuAssertIntEquals (test, ECC_PUBKEY2_DER_LEN, dme.key_length);
	CuAssertPtrEquals (test, (void*) ECC_PUBKEY2_DER, (void*) dme.dme_pub_key);

	CuAssertPtrEquals (test, NULL, (void*) dme.device_oid);
	CuAssertIntEquals (test, 0, dme.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.renewal_counter);
	CuAssertIntEquals (test, 0, dme.counter_length);
}

static void dme_structure_test_init_sha512_dme_key_ecc384 (CuTest *test)
{
	struct dme_structure dme;
	int status;

	TEST_START;

	status = dme_structure_init_sha512 (&dme, DME_STRUCTURE_TESTING_TYPE5_DATA,
		DME_STRUCTURE_TESTING_TYPE5_DATA_LEN, ECC384_PUBKEY2_DER, ECC384_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC384_SHA384,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC384_SHA384_LEN, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE5_OID_LEN, dme.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE5_OID, dme.data_oid,
		dme.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE5_DATA_LEN, dme.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE5_DATA, (void*) dme.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA384_LEN, dme.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA384, dme.sig_oid,
		dme.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE5_SIG_ECC384_SHA384_LEN,
		dme.signature_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE5_SIG_ECC384_SHA384,
		(void*) dme.signature);

	CuAssertIntEquals (test, ECC384_PUBKEY2_DER_LEN, dme.key_length);
	CuAssertPtrEquals (test, (void*) ECC384_PUBKEY2_DER, (void*) dme.dme_pub_key);

	CuAssertPtrEquals (test, NULL, (void*) dme.device_oid);
	CuAssertIntEquals (test, 0, dme.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.renewal_counter);
	CuAssertIntEquals (test, 0, dme.counter_length);
}

static void dme_structure_test_init_sha512_dme_key_ecc521 (CuTest *test)
{
	struct dme_structure dme;
	int status;

	TEST_START;

	status = dme_structure_init_sha512 (&dme, DME_STRUCTURE_TESTING_TYPE5_DATA,
		DME_STRUCTURE_TESTING_TYPE5_DATA_LEN, ECC521_PUBKEY2_DER, ECC521_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC521_SHA512,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC521_SHA512_LEN, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE5_OID_LEN, dme.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE5_OID, dme.data_oid,
		dme.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE5_DATA_LEN, dme.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE5_DATA, (void*) dme.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA512_LEN, dme.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA512, dme.sig_oid,
		dme.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE5_SIG_ECC521_SHA512_LEN,
		dme.signature_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE5_SIG_ECC521_SHA512,
		(void*) dme.signature);

	CuAssertIntEquals (test, ECC521_PUBKEY2_DER_LEN, dme.key_length);
	CuAssertPtrEquals (test, (void*) ECC521_PUBKEY2_DER, (void*) dme.dme_pub_key);

	CuAssertPtrEquals (test, NULL, (void*) dme.device_oid);
	CuAssertIntEquals (test, 0, dme.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.renewal_counter);
	CuAssertIntEquals (test, 0, dme.counter_length);
}

static void dme_structure_test_init_sha512_null (CuTest *test)
{
	struct dme_structure dme;
	int status;

	TEST_START;

	status = dme_structure_init_sha512 (NULL, DME_STRUCTURE_TESTING_TYPE5_DATA,
		DME_STRUCTURE_TESTING_TYPE5_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_init_sha512 (&dme, NULL,
		DME_STRUCTURE_TESTING_TYPE5_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_init_sha512 (&dme, DME_STRUCTURE_TESTING_TYPE5_DATA,
		DME_STRUCTURE_TESTING_TYPE5_DATA_LEN, NULL, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_init_sha512 (&dme, DME_STRUCTURE_TESTING_TYPE5_DATA,
		DME_STRUCTURE_TESTING_TYPE5_DATA_LEN, ECC_PUBKEY2_DER, 0,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_init_sha512 (&dme, DME_STRUCTURE_TESTING_TYPE5_DATA,
		DME_STRUCTURE_TESTING_TYPE5_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		NULL,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_init_sha512 (&dme, DME_STRUCTURE_TESTING_TYPE5_DATA,
		DME_STRUCTURE_TESTING_TYPE5_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256,
		0, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);
}

static void dme_structure_test_init_sha512_bad_structure_length (CuTest *test)
{
	struct dme_structure dme;
	int status;

	TEST_START;

	status = dme_structure_init_sha512 (&dme, DME_STRUCTURE_TESTING_TYPE5_DATA,
		DME_STRUCTURE_TESTING_TYPE5_DATA_LEN - 1, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_BAD_LENGTH, status);

	status = dme_structure_init_sha512 (&dme, DME_STRUCTURE_TESTING_TYPE5_DATA,
		DME_STRUCTURE_TESTING_TYPE5_DATA_LEN + 1, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_BAD_LENGTH, status);
}

static void dme_structure_test_init_sha512_unsupported_signature_hash (CuTest *test)
{
	struct dme_structure dme;
	int status;

	TEST_START;

	status = dme_structure_init_sha512 (&dme, DME_STRUCTURE_TESTING_TYPE5_DATA,
		DME_STRUCTURE_TESTING_TYPE5_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA1);
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_SIGNATURE, status);

	status = dme_structure_init_sha512 (&dme, DME_STRUCTURE_TESTING_TYPE5_DATA,
		DME_STRUCTURE_TESTING_TYPE5_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE5_SIG_ECC256_SHA256_LEN, (enum hash_type) 10);
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_SIGNATURE, status);
}

static void dme_structure_test_init_sha512_with_challenge_dme_key_ecc256 (CuTest *test)
{
	struct dme_structure dme;
	int status;

	TEST_START;

	status = dme_structure_init_sha512_with_challenge (&dme, DME_STRUCTURE_TESTING_TYPE6_DATA,
		DME_STRUCTURE_TESTING_TYPE6_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE6_OID_LEN, dme.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE6_OID, dme.data_oid,
		dme.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE6_DATA_LEN, dme.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE6_DATA, (void*) dme.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA256_LEN, dme.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA256, dme.sig_oid,
		dme.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_LEN,
		dme.signature_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256,
		(void*) dme.signature);

	CuAssertIntEquals (test, ECC_PUBKEY2_DER_LEN, dme.key_length);
	CuAssertPtrEquals (test, (void*) ECC_PUBKEY2_DER, (void*) dme.dme_pub_key);

	CuAssertPtrEquals (test, NULL, (void*) dme.device_oid);
	CuAssertIntEquals (test, 0, dme.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.renewal_counter);
	CuAssertIntEquals (test, 0, dme.counter_length);
}

static void dme_structure_test_init_sha512_with_challenge_dme_key_ecc384 (CuTest *test)
{
	struct dme_structure dme;
	int status;

	TEST_START;

	status = dme_structure_init_sha512_with_challenge (&dme, DME_STRUCTURE_TESTING_TYPE6_DATA,
		DME_STRUCTURE_TESTING_TYPE6_DATA_LEN, ECC384_PUBKEY2_DER, ECC384_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC384_SHA384,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC384_SHA384_LEN, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE6_OID_LEN, dme.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE6_OID, dme.data_oid,
		dme.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE6_DATA_LEN, dme.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE6_DATA, (void*) dme.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA384_LEN, dme.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA384, dme.sig_oid,
		dme.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE6_SIG_ECC384_SHA384_LEN,
		dme.signature_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE6_SIG_ECC384_SHA384,
		(void*) dme.signature);

	CuAssertIntEquals (test, ECC384_PUBKEY2_DER_LEN, dme.key_length);
	CuAssertPtrEquals (test, (void*) ECC384_PUBKEY2_DER, (void*) dme.dme_pub_key);

	CuAssertPtrEquals (test, NULL, (void*) dme.device_oid);
	CuAssertIntEquals (test, 0, dme.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.renewal_counter);
	CuAssertIntEquals (test, 0, dme.counter_length);
}

static void dme_structure_test_init_sha512_with_challenge_dme_key_ecc521 (CuTest *test)
{
	struct dme_structure dme;
	int status;

	TEST_START;

	status = dme_structure_init_sha512_with_challenge (&dme, DME_STRUCTURE_TESTING_TYPE6_DATA,
		DME_STRUCTURE_TESTING_TYPE6_DATA_LEN, ECC521_PUBKEY2_DER, ECC521_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC521_SHA512,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC521_SHA512_LEN, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE6_OID_LEN, dme.data_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_TYPE6_OID, dme.data_oid,
		dme.data_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE6_DATA_LEN, dme.data_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE6_DATA, (void*) dme.data);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA512_LEN, dme.sig_oid_length);
	status = testing_validate_array (DME_STRUCTURE_TESTING_OID_SIG_ECC_SHA512, dme.sig_oid,
		dme.sig_oid_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, DME_STRUCTURE_TESTING_TYPE6_SIG_ECC521_SHA512_LEN,
		dme.signature_length);
	CuAssertPtrEquals (test, (void*) DME_STRUCTURE_TESTING_TYPE6_SIG_ECC521_SHA512,
		(void*) dme.signature);

	CuAssertIntEquals (test, ECC521_PUBKEY2_DER_LEN, dme.key_length);
	CuAssertPtrEquals (test, (void*) ECC521_PUBKEY2_DER, (void*) dme.dme_pub_key);

	CuAssertPtrEquals (test, NULL, (void*) dme.device_oid);
	CuAssertIntEquals (test, 0, dme.dev_oid_length);

	CuAssertPtrEquals (test, NULL, (void*) dme.renewal_counter);
	CuAssertIntEquals (test, 0, dme.counter_length);
}

static void dme_structure_test_init_sha512_with_challenge_null (CuTest *test)
{
	struct dme_structure dme;
	int status;

	TEST_START;

	status = dme_structure_init_sha512_with_challenge (NULL, DME_STRUCTURE_TESTING_TYPE6_DATA,
		DME_STRUCTURE_TESTING_TYPE6_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_init_sha512_with_challenge (&dme, NULL,
		DME_STRUCTURE_TESTING_TYPE6_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_init_sha512_with_challenge (&dme, DME_STRUCTURE_TESTING_TYPE6_DATA,
		DME_STRUCTURE_TESTING_TYPE6_DATA_LEN, NULL, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_init_sha512_with_challenge (&dme, DME_STRUCTURE_TESTING_TYPE6_DATA,
		DME_STRUCTURE_TESTING_TYPE6_DATA_LEN, ECC_PUBKEY2_DER, 0,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_init_sha512_with_challenge (&dme, DME_STRUCTURE_TESTING_TYPE6_DATA,
		DME_STRUCTURE_TESTING_TYPE6_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		NULL,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);

	status = dme_structure_init_sha512_with_challenge (&dme, DME_STRUCTURE_TESTING_TYPE6_DATA,
		DME_STRUCTURE_TESTING_TYPE6_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256,
		0, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_INVALID_ARGUMENT, status);
}

static void dme_structure_test_init_sha512_with_challenge_bad_structure_length (CuTest *test)
{
	struct dme_structure dme;
	int status;

	TEST_START;

	status = dme_structure_init_sha512_with_challenge (&dme, DME_STRUCTURE_TESTING_TYPE6_DATA,
		DME_STRUCTURE_TESTING_TYPE6_DATA_LEN - 1, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_BAD_LENGTH, status);

	status = dme_structure_init_sha512_with_challenge (&dme, DME_STRUCTURE_TESTING_TYPE6_DATA,
		DME_STRUCTURE_TESTING_TYPE6_DATA_LEN + 1, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, DME_STRUCTURE_BAD_LENGTH, status);
}

static void dme_structure_test_init_sha512_with_challenge_unsupported_signature_hash (CuTest *test)
{
	struct dme_structure dme;
	int status;

	TEST_START;

	status = dme_structure_init_sha512_with_challenge (&dme, DME_STRUCTURE_TESTING_TYPE6_DATA,
		DME_STRUCTURE_TESTING_TYPE6_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_LEN, HASH_TYPE_SHA1);
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_SIGNATURE, status);

	status = dme_structure_init_sha512_with_challenge (&dme, DME_STRUCTURE_TESTING_TYPE6_DATA,
		DME_STRUCTURE_TESTING_TYPE6_DATA_LEN, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256,
		DME_STRUCTURE_TESTING_TYPE6_SIG_ECC256_SHA256_LEN, (enum hash_type) 10);
	CuAssertIntEquals (test, DME_STRUCTURE_UNSUPPORTED_SIGNATURE, status);
}


TEST_SUITE_START (dme_structure);

TEST (dme_structure_test_init_sha384_dme_key_ecc256);
TEST (dme_structure_test_init_sha384_dme_key_ecc384);
TEST (dme_structure_test_init_sha384_dme_key_ecc521);
TEST (dme_structure_test_init_sha384_null);
TEST (dme_structure_test_init_sha384_bad_structure_length);
TEST (dme_structure_test_init_sha384_unsupported_signature_hash);
TEST (dme_structure_test_init_sha384_with_challenge_dme_key_ecc256);
TEST (dme_structure_test_init_sha384_with_challenge_dme_key_ecc384);
TEST (dme_structure_test_init_sha384_with_challenge_dme_key_ecc521);
TEST (dme_structure_test_init_sha384_with_challenge_null);
TEST (dme_structure_test_init_sha384_with_challenge_bad_structure_length);
TEST (dme_structure_test_init_sha384_with_challenge_unsupported_signature_hash);
TEST (dme_structure_test_init_sha256_dme_key_ecc256);
TEST (dme_structure_test_init_sha256_dme_key_ecc384);
TEST (dme_structure_test_init_sha256_dme_key_ecc521);
TEST (dme_structure_test_init_sha256_null);
TEST (dme_structure_test_init_sha256_bad_structure_length);
TEST (dme_structure_test_init_sha256_unsupported_signature_hash);
TEST (dme_structure_test_init_sha256_with_challenge_dme_key_ecc256);
TEST (dme_structure_test_init_sha256_with_challenge_dme_key_ecc384);
TEST (dme_structure_test_init_sha256_with_challenge_dme_key_ecc521);
TEST (dme_structure_test_init_sha256_with_challenge_null);
TEST (dme_structure_test_init_sha256_with_challenge_bad_structure_length);
TEST (dme_structure_test_init_sha256_with_challenge_unsupported_signature_hash);
TEST (dme_structure_test_init_sha512_dme_key_ecc256);
TEST (dme_structure_test_init_sha512_dme_key_ecc384);
TEST (dme_structure_test_init_sha512_dme_key_ecc521);
TEST (dme_structure_test_init_sha512_null);
TEST (dme_structure_test_init_sha512_bad_structure_length);
TEST (dme_structure_test_init_sha512_unsupported_signature_hash);
TEST (dme_structure_test_init_sha512_with_challenge_dme_key_ecc256);
TEST (dme_structure_test_init_sha512_with_challenge_dme_key_ecc384);
TEST (dme_structure_test_init_sha512_with_challenge_dme_key_ecc521);
TEST (dme_structure_test_init_sha512_with_challenge_null);
TEST (dme_structure_test_init_sha512_with_challenge_bad_structure_length);
TEST (dme_structure_test_init_sha512_with_challenge_unsupported_signature_hash);

TEST_SUITE_END;
