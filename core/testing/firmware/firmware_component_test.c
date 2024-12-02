// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "firmware/firmware_component.h"
#include "testing/mock/crypto/signature_verification_mock.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/firmware/firmware_loader_mock.h"
#include "testing/mock/flash/flash_mock.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/common/image_header_testing.h"
#include "testing/crypto/aes_cbc_testing.h"
#include "testing/firmware/firmware_component_testing.h"


TEST_SUITE_LABEL ("firmware_component");


/**
 * Test component image.
 * 	- Signing key:  RSA_PRIVKEY
 */
const uint8_t FW_COMPONENT_DATA[] = {
	0x0e,0x00,0x00,0x00,0x78,0x56,0x34,0x12,0x03,0x01,0x00,0x00,0x00,0x01,0x01,0x00,
	0x01,0xc9,0x44,0x8c,0x40,0x6c,0x1f,0x64,0x8d,0xcb,0xa1,0xc7,0x3b,0x14,0xb4,0x89,
	0xd1,0x25,0x57,0x4a,0x5d,0xd5,0xaa,0x2c,0x1f,0x80,0x23,0x23,0xfc,0xc2,0xda,0xfc,
	0x7c,0xa6,0xad,0x35,0x83,0xab,0x92,0x1b,0x71,0x05,0xba,0x75,0x11,0x1e,0xdd,0x60,
	0x2a,0xe7,0xbe,0x91,0x3f,0xed,0xaa,0xe3,0x43,0x17,0x28,0x85,0x29,0xfd,0xb6,0x81,
	0x78,0x00,0xc0,0xe4,0xc1,0xb1,0x79,0x73,0x9e,0x91,0x5a,0x78,0x07,0x11,0x2a,0x24,
	0xd7,0xcc,0x22,0x35,0x2b,0xdf,0xbb,0xf7,0x62,0xdf,0x47,0x19,0xba,0x1f,0xbc,0x9a,
	0x5b,0x54,0xf5,0xa7,0x6a,0x39,0xcb,0x6b,0xe0,0xa5,0xb8,0x0a,0xa0,0x06,0x93,0xec,
	0xd8,0x03,0xbb,0x49,0x89,0xa8,0xfa,0x88,0x07,0x5e,0xc5,0x0f,0xad,0xb1,0xd1,0xa9,
	0x36,0x48,0x27,0x5f,0x40,0xa0,0x7c,0x2a,0x42,0x9c,0xdf,0x41,0x09,0x28,0xe0,0x05,
	0xad,0x51,0x44,0x96,0x98,0x34,0x7a,0x74,0xaa,0x9d,0xda,0x49,0x71,0xdd,0x6b,0xf0,
	0x74,0xf4,0x01,0xed,0x9d,0x42,0xd0,0x12,0x4a,0x63,0x7c,0xd0,0x6e,0x93,0x1f,0x9e,
	0xb6,0x40,0x93,0x23,0xa6,0x09,0xb7,0xac,0x2d,0x3e,0x79,0x8d,0x56,0x85,0x9f,0xc7,
	0x5a,0x58,0xa7,0x8f,0xdf,0x22,0x14,0x94,0x10,0x66,0xe6,0xd6,0xbb,0x2c,0x3f,0x05,
	0x63,0xb3,0x7a,0x64,0xf5,0x6d,0x52,0x82,0x82,0x3a,0x17,0x95,0x89,0xb1,0xb3,0x12,
	0x4d,0x21,0x64,0x4f,0x58,0xe9,0x4e,0x68,0xfa,0x5d,0x5e,0x80,0x49,0x78,0x70,0x4f,
	0x60,0xa3,0x59,0xca,0x3a,0xb0,0x04,0xb3,0xd2,0x34,0xae,0xac,0x7e,0xdc,0x17,0x16,
	0x81,0x16,0xef,0x27,0xac,0x73,0xbf,0xf5,0x72,0x5f,0xcd,0x32,0x48,0x23,0xf2,0x0c,
	0x4d,0x8c,0xed,0x93,0xab,0x5d,0x94,0x02,0x38,0x12,0xb6,0xd4,0xdf,0xa9,0xe7,0x1c,
	0x50,0xe1,0x7d,0x22,0xa2,0x7b,0xea,0xa7,0x3c,0x09,0x4b,0x8a,0xe8,0x15,0x3f,0x07,
	0xe3,0x76,0xfd,0x8c,0xa2,0xd3,0xd9,0x1a,0xbe,0x33,0x39,0x0c,0x9b,0xf3,0xa1,0x18,
	0x02,0xa5,0xb5,0x2a,0xb7,0xd8,0x17,0x4b,0xc3,0x31,0xff,0xa1,0xc9,0x09,0x45,0xa8,
	0xb7,0x5b,0x21,0x03,0x79,0xf8,0x1f,0x11,0xc1,0x3a,0xb2,0xcc,0xfc,0x63,0xfe,0x48,
	0x97,0x21,0x81,0x68,0x98,0xb4,0xb8,0x64,0xd5,0x57,0x69,0x87,0xac,0x1a,0xb6,0xea,
	0x01,0x40,0x47,0xa7,0x22,0x51,0x1b,0x28,0x73,0xd4,0x7b,0xdb,0x96,0xb3,0xe5,0xa4,
	0x26,0x9c,0xca,0xbe,0xd3,0xce,0x6b,0x7c,0xb5,0xd8,0xdb,0x78,0xbb,0x4e,0x1c,0x75,
	0xdf,0x8d,0x6e,0x00,0xf0,0x29,0xc4,0x05,0xe6,0x45,0xe1,0xd5,0xd1,0x62,0x57,0x49,
	0x63,0x53,0x1d,0xf5,0x91,0xfe,0xbe,0x1b,0x29,0x79,0xc9,0x60,0xab,0xea,0x9a,0xeb,
	0x2c,0x4e,0xf2,0xfc,0x5b,0x98,0x4a,0x52,0x44,0x89,0x85,0x9f,0x6e,0x97,0x03,0x21,
	0x4f,0xbb,0x1c,0x48,0xcd,0x53,0x46,0x36,0xf6,0xa3,0xb4,0xca,0xc1,0xaf,0x6d,0x7d,
	0xde,0x96,0x40,0x45,0x64,0x38,0x11,0xa1,0xe2,0xa7,0xbe,0x2c,0xfb,0x81,0x1e,0x7e,
	0xbf,0xb0,0x5f,0x3a,0xaf,0x35,0x73,0xf4,0x94,0xab,0x25,0x35,0x6e,0x96,0x36,0x36,
	0x75,0xcd,0x50,0xc1,0x67,0xbf,0x88,0x9e,0x3d,0x4d,0x9a,0xab,0xbd,0x8d,0x24,0xb2,
	0xd9
};

const size_t FW_COMPONENT_DATA_LEN = sizeof (FW_COMPONENT_DATA);

/**
 * The length of the component image, excluding the signature.
 */
static const size_t FW_COMPONENT_DATA_LENGTH = sizeof (FW_COMPONENT_DATA) - FW_COMPONENT_SIG_LENGTH;

/**
 * Offset in the data of the firmware component.
 */
#define	FW_COMPONENT_OFFSET			(FW_COMPONENT_HDR_LENGTH + IMAGE_HEADER_BASE_LEN)

/**
 * Length of just the component image, excluding header and signature bytes.
 */
static const size_t FW_COMPONENT_LENGTH = sizeof (FW_COMPONENT_DATA) - FW_COMPONENT_SIG_LENGTH -
	FW_COMPONENT_HDR_LENGTH - IMAGE_HEADER_BASE_LEN;

/**
 * The test component data.
 */
static const uint8_t *FW_COMPONENT = FW_COMPONENT_DATA + FW_COMPONENT_OFFSET;

/**
 * The SHA256 hash of the test component data, not including the signature.
 */
static const uint8_t FW_COMPONENT_HASH[] = {
	0x71,0x6b,0xcf,0x71,0xdd,0x7a,0x39,0xae,0x22,0x58,0x21,0xb8,0x8a,0x92,0xc6,0x7d,
	0xd6,0x6d,0x89,0x08,0xdc,0x3b,0xb8,0xcd,0xa0,0xd4,0x6e,0xb6,0x6f,0x91,0x5f,0x38
};

/**
 * The SHA256 hash of the test component data, including the image header.
 */
static const uint8_t FW_COMPONENT_HASH_WITH_HEADER[] = {
	0x2f,0x37,0x00,0x53,0x5f,0x5a,0x7e,0x57,0x43,0xe2,0xac,0xf7,0x6f,0xad,0xf4,0x79,
	0xc6,0xb5,0xc9,0x90,0xcc,0x36,0xb0,0xca,0x54,0xc6,0x8d,0x26,0xf4,0x76,0xdd,0x76
};

/**
 * Offset in the data of the signature.
 */
#define	FW_COMPONENT_SIG_OFFSET		((sizeof FW_COMPONENT_DATA) - FW_COMPONENT_SIG_LENGTH)

/**
 * The signature of the test component data.
 */
static const uint8_t *FW_COMPONENT_SIGNATURE = FW_COMPONENT_DATA + FW_COMPONENT_SIG_OFFSET;

/**
 * Test component image with extra header data.
 * 	- Signing key:  RSA_PRIVKEY
 */
const uint8_t FW_COMPONENT_HEADER_DATA[] = {
	0x00,0x11,0x22,0x33,0x44,0x55,0x0e,0x00,0x00,0x00,0x78,0x56,0x34,0x12,0x03,0x01,
	0x00,0x00,0x00,0x01,0x01,0x00,0x01,0xc9,0x44,0x8c,0x40,0x6c,0x1f,0x64,0x8d,0xcb,
	0xa1,0xc7,0x3b,0x14,0xb4,0x89,0xd1,0x25,0x57,0x4a,0x5d,0xd5,0xaa,0x2c,0x1f,0x80,
	0x23,0x23,0xfc,0xc2,0xda,0xfc,0x7c,0xa6,0xad,0x35,0x83,0xab,0x92,0x1b,0x71,0x05,
	0xba,0x75,0x11,0x1e,0xdd,0x60,0x2a,0xe7,0xbe,0x91,0x3f,0xed,0xaa,0xe3,0x43,0x17,
	0x28,0x85,0x29,0xfd,0xb6,0x81,0x78,0x00,0xc0,0xe4,0xc1,0xb1,0x79,0x73,0x9e,0x91,
	0x5a,0x78,0x07,0x11,0x2a,0x24,0xd7,0xcc,0x22,0x35,0x2b,0xdf,0xbb,0xf7,0x62,0xdf,
	0x47,0x19,0xba,0x1f,0xbc,0x9a,0x5b,0x54,0xf5,0xa7,0x6a,0x39,0xcb,0x6b,0xe0,0xa5,
	0xb8,0x0a,0xa0,0x06,0x93,0xec,0xd8,0x03,0xbb,0x49,0x89,0xa8,0xfa,0x88,0x07,0x5e,
	0xc5,0x0f,0xad,0xb1,0xd1,0xa9,0x36,0x48,0x27,0x5f,0x40,0xa0,0x7c,0x2a,0x42,0x9c,
	0xdf,0x41,0x09,0x28,0xe0,0x05,0xad,0x51,0x44,0x96,0x98,0x34,0x7a,0x74,0xaa,0x9d,
	0xda,0x49,0x71,0xdd,0x6b,0xf0,0x74,0xf4,0x01,0xed,0x9d,0x42,0xd0,0x12,0x4a,0x63,
	0x7c,0xd0,0x6e,0x93,0x1f,0x9e,0xb6,0x40,0x93,0x23,0xa6,0x09,0xb7,0xac,0x2d,0x3e,
	0x79,0x8d,0x56,0x85,0x9f,0xc7,0x5a,0x58,0xa7,0x8f,0xdf,0x22,0x14,0x94,0x10,0x66,
	0xe6,0xd6,0xbb,0x2c,0x3f,0x05,0x63,0xb3,0x7a,0x64,0xf5,0x6d,0x52,0x82,0x82,0x3a,
	0x17,0x95,0x89,0xb1,0xb3,0x12,0x4d,0x21,0x64,0x4f,0x58,0xe9,0x4e,0x68,0xfa,0x5d,
	0x5e,0x80,0x49,0x78,0x70,0x4f,0x60,0xa3,0x59,0xca,0x3a,0xb0,0x04,0xb3,0xd2,0x34,
	0xae,0xac,0x7e,0xdc,0x17,0x16,0x81,0x4a,0x03,0x53,0xda,0xae,0x52,0x00,0x7d,0x0f,
	0xc6,0x89,0x94,0x93,0x1a,0x79,0xf0,0xa8,0x39,0x76,0x99,0xe8,0x58,0x78,0x69,0x53,
	0x8f,0x2b,0x36,0x5d,0xa5,0xb6,0x43,0x90,0x64,0x54,0x77,0x71,0x4c,0x48,0x69,0x5e,
	0x68,0x05,0x77,0x49,0x0d,0x6a,0x46,0x6b,0x07,0x83,0xd2,0x0f,0x0e,0x91,0xbe,0x25,
	0xc0,0xce,0xfa,0xf1,0x99,0x44,0xed,0x97,0x95,0x5e,0x16,0x60,0x66,0x8e,0xf2,0x2e,
	0x21,0x55,0x3c,0x5a,0x5c,0xea,0x57,0xa7,0xfa,0x03,0xdd,0x92,0x6b,0xe7,0x0d,0x30,
	0x83,0x4a,0x54,0x3c,0xa6,0xb5,0x6c,0x5a,0x4a,0x98,0x31,0x60,0xcc,0x9d,0xcd,0x19,
	0x53,0x66,0xd1,0x34,0xf6,0xe7,0xa5,0x20,0x16,0xe2,0xdf,0x30,0x44,0x50,0xf7,0xc7,
	0x16,0x4c,0x2b,0xb3,0xf4,0xed,0xbf,0x07,0x9b,0x9d,0x82,0x9f,0x39,0xf5,0x3c,0x50,
	0xe3,0x03,0xeb,0x31,0xe3,0x60,0xdd,0xc3,0x85,0x30,0x52,0xc4,0xa0,0xf1,0xf7,0x68,
	0xd2,0x10,0xce,0xab,0xa8,0x4d,0x2e,0x2b,0xd9,0x62,0x92,0x89,0xe2,0x84,0x65,0xf3,
	0x43,0x50,0x17,0xdc,0x0a,0xa7,0x3e,0x31,0xab,0xd8,0x1c,0x86,0x53,0x04,0xcc,0x80,
	0xf3,0x22,0x3f,0x02,0x07,0xde,0xd3,0xed,0xce,0xa8,0xc6,0x9e,0x15,0xb6,0x0c,0x92,
	0x8d,0x11,0x01,0x33,0xed,0x1a,0xbf,0x72,0x89,0x9e,0x2d,0xb3,0xdc,0xfe,0x3a,0x05,
	0x2b,0x6e,0xc2,0x39,0xe5,0x7d,0x9f,0x41,0xdb,0xd1,0x75,0xa1,0xc9,0x84,0x63,0x62,
	0x85,0xee,0x84,0xa3,0x3c,0xe0,0xda,0xc9,0xde,0xf9,0x9a,0xf2,0x7e,0x11,0xb7,0xbf,
	0xd1,0x5f,0xb5,0xf2,0xe0,0xaa,0xd0
};

const size_t FW_COMPONENT_HEADER_DATA_LEN = sizeof (FW_COMPONENT_HEADER_DATA);

/**
 * Length of the extra header data on the component.
 */
#define	FW_COMPONENT_EXTRA_HDR_LENGTH	6

/**
 * The length of the component image with an extra header, excluding the signature.
 */
static const size_t FW_COMPONENT_HEADER_DATA_LENGTH = sizeof (FW_COMPONENT_HEADER_DATA) -
	FW_COMPONENT_SIG_LENGTH;

/**
 * Offset in the data of the firmware component.
 */
#define	FW_COMPONENT_HEADER_OFFSET			\
	(FW_COMPONENT_EXTRA_HDR_LENGTH + FW_COMPONENT_HDR_LENGTH + IMAGE_HEADER_BASE_LEN)

/**
 * Length of just the component image, excluding all header and signature bytes.
 */
static const size_t FW_COMPONENT_HEADER_LENGTH = sizeof (FW_COMPONENT_HEADER_DATA) -
	FW_COMPONENT_SIG_LENGTH - FW_COMPONENT_HDR_LENGTH - IMAGE_HEADER_BASE_LEN -
	FW_COMPONENT_EXTRA_HDR_LENGTH;

/**
 * The test component data with an extra header.
 */
static const uint8_t *FW_COMPONENT_HEADER = FW_COMPONENT_HEADER_DATA + FW_COMPONENT_HEADER_OFFSET;

/**
 * The SHA256 hash of the test component data with an extra header, not including the signature.
 */
static const uint8_t FW_COMPONENT_HEADER_HASH[] = {
	0x19,0x82,0x53,0xcf,0x56,0xad,0xe0,0xa1,0x4d,0xd9,0x0d,0x81,0x03,0x2a,0x4a,0x60,
	0xe8,0x13,0x08,0x8b,0x58,0x50,0x27,0x82,0xf1,0x8d,0x46,0x93,0x98,0x10,0xcd,0x91
};

/**
 * Offset in the data of the signature.
 */
#define	FW_COMPONENT_HEADER_SIG_OFFSET		\
	((sizeof FW_COMPONENT_HEADER_DATA) - FW_COMPONENT_SIG_LENGTH)

/**
 * The signature of the test component data.
 */
static const uint8_t *FW_COMPONENT_HEADER_SIGNATURE = FW_COMPONENT_HEADER_DATA +
	FW_COMPONENT_HEADER_SIG_OFFSET;

/**
 * Test component image using a format 1 header.
 * 	- Signing key:  RSA_PRIVKEY
 */
const uint8_t FW_COMPONENT_V1_DATA[] = {
	0x1f,0x00,0x01,0x00,0x21,0x43,0x65,0x87,0x80,0x00,0x00,0x00,0x00,0x01,0x01,0x00,
	0x00,0x00,0x20,0x00,0x00,0x00,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0xf8,
	0x8a,0x48,0xd9,0x0f,0xfc,0xea,0x40,0x3a,0x30,0xf6,0xfc,0x63,0x99,0x4d,0x51,0xe0,
	0x25,0xd0,0xca,0xf4,0x82,0x25,0x14,0x57,0x1f,0x12,0x36,0x72,0xf1,0x81,0x29,0x33,
	0xee,0xfb,0x1f,0xe8,0x9e,0x87,0x19,0x8e,0xc1,0xfb,0x91,0x1f,0xe8,0x68,0x55,0x61,
	0x4c,0x99,0xda,0x3b,0x9f,0x5e,0x2c,0x26,0xc5,0x63,0xe4,0x12,0x72,0x29,0x59,0x18,
	0x9e,0x4e,0x18,0xdd,0x83,0x82,0x5a,0x89,0x2e,0x3f,0x08,0x12,0x95,0xa0,0xbe,0x76,
	0xad,0x53,0x95,0xe3,0x0a,0xdf,0xa1,0xbb,0x7b,0xb1,0xe7,0xbe,0xf9,0xa4,0xbe,0x95,
	0x2b,0x42,0xa8,0x60,0xd7,0x5a,0x81,0x2e,0xba,0x8a,0x18,0x14,0x93,0x16,0x13,0xb4,
	0x61,0x0a,0xba,0x26,0x98,0x87,0x3c,0x7b,0xa1,0xe5,0xfc,0xc3,0x13,0x0b,0x51,0x67,
	0xb9,0x5a,0xcb,0xae,0x1a,0x06,0xdb,0x6a,0x6d,0x92,0xee,0x05,0x8b,0x47,0x42,0x56,
	0x31,0xc1,0x8b,0x92,0x27,0xf2,0x13,0x68,0xee,0x41,0xd6,0x42,0xd5,0x9d,0x1a,0xaa,
	0x84,0x13,0x55,0x5f,0xd2,0x3f,0x70,0x59,0xca,0x5d,0x23,0x0b,0x75,0x12,0x10,0xe2,
	0xa4,0x08,0xfe,0x44,0xed,0x83,0x32,0x51,0x4b,0xcf,0x4b,0x4c,0x81,0x04,0xed,0xaf,
	0xce,0x8f,0x1d,0x7f,0x09,0x9e,0x17,0x68,0x43,0x70,0xbe,0x11,0xe5,0x7d,0x8b,0xca,
	0x2c,0x11,0xc6,0x06,0x39,0xab,0x26,0xb3,0x1b,0xe2,0x34,0xd9,0x2c,0x1f,0x06,0xa9,
	0x53,0xc5,0x46,0xa0,0xa6,0xb5,0xbe,0x86,0x2b,0x02,0x31,0xaf,0xc9,0x1c,0x70,0x40,
	0x5b,0xfd,0xc4,0xf9,0x9d,0x12,0xa0,0x45,0x8b,0x24,0xfe,0xba,0xca,0x91,0x1a,0x16,
	0x0c,0x7c,0xba,0x82,0x98,0x68,0x46,0x64,0x34,0x37,0xa4,0x3d,0x1a,0xd4,0x95,0xd8,
	0xd1,0xd9,0xdf,0xfe,0xd8,0xb0,0x3f,0xc8,0x30,0x35,0xdc,0x55,0x41,0x90,0x6c,0x12,
	0x3e,0x68,0x9a,0x9d,0xb0,0x2c,0xf2,0x92,0xe1,0xe1,0x94,0x45,0x43,0xc4,0x4c,0x6c,
	0xc2,0xc2,0xbc,0xb3,0x68,0xa2,0xcf,0x1b,0xd6,0xfe,0xb2,0xa3,0x74,0x26,0x79,0xf9,
	0x5c,0x12,0x7e,0xb4,0x45,0xa2,0xe5,0x57,0x52,0xda,0x17,0x1d,0xbd,0x94,0xae,0xd3,
	0x37,0x61,0xda,0x05,0xcc,0x09,0x68,0x3c,0x46,0x4f,0x3a,0x14,0xc5,0x51,0x84,0xa4,
	0x6b,0xc5,0x8b,0x20,0xe5,0x47,0x56,0x30,0x26,0x61,0x5c,0x11,0x44,0x33,0xcf,0xe3,
	0xf8,0x28,0x10,0x69,0x90,0xd4,0x9d,0x71,0x2a,0x80,0xc2,0x97,0x25,0x29,0x81
};

const size_t FW_COMPONENT_V1_DATA_LEN = sizeof (FW_COMPONENT_V1_DATA);

/**
 * Offset in the format 1 header where the signature hash type is located.
 */
#define	FW_COMPONENT_V1_HASH_TYPE_OFFSET	(IMAGE_HEADER_BASE_LEN + 6)

/**
 * The target load address for the component.
 */
#define	FW_COMPONENT_V1_LOAD_ADDRESS		0x20000000

/**
 * Pointer to the target load address.
 */
static const uint8_t *FW_COMPONENT_V1_LOAD_ADDRESS_PTR = (uint8_t*) 0xf0000000;

/**
 * Offset in the format 1 header where the build version number is located.
 */
#define	FW_COMPONENT_V1_VERSION_OFFSET		(IMAGE_HEADER_BASE_LEN + 15)

/**
 * The build version number for the component.
 */
static const uint8_t *FW_COMPONENT_V1_BUILD_VERSION =
	FW_COMPONENT_V1_DATA + FW_COMPONENT_V1_VERSION_OFFSET;

/**
 * The length of the component image, excluding the signature.
 */
static const size_t FW_COMPONENT_V1_DATA_LENGTH =
	sizeof (FW_COMPONENT_V1_DATA) - FW_COMPONENT_SIG_LENGTH;

/**
 * Offset in the data of the firmware component.
 */
#define	FW_COMPONENT_V1_OFFSET		(FW_COMPONENT_HDR_V1_LENGTH + IMAGE_HEADER_BASE_LEN)

/**
 * Length of just the component image, excluding header and signature bytes.
 */
static const size_t FW_COMPONENT_V1_LENGTH = sizeof (FW_COMPONENT_V1_DATA) -
	FW_COMPONENT_SIG_LENGTH - FW_COMPONENT_HDR_V1_LENGTH - IMAGE_HEADER_BASE_LEN;

/**
 * The test component data.
 */
static const uint8_t *FW_COMPONENT_V1 = FW_COMPONENT_V1_DATA + FW_COMPONENT_V1_OFFSET;

/**
 * The SHA256 hash of the test component data, not including the signature.
 */
static const uint8_t FW_COMPONENT_V1_HASH[] = {
	0xc3,0x6f,0x35,0x19,0x2d,0x35,0x13,0x67,0x51,0x86,0xa7,0x70,0xed,0x86,0xa5,0xa6,
	0xab,0x60,0x9f,0x1c,0xe5,0x02,0x73,0xfa,0x93,0xe3,0x4c,0x90,0x11,0xdf,0xea,0xe1
};

/**
 * The SHA256 hash of the test component data, including the image header.
 */
static const uint8_t FW_COMPONENT_V1_HASH_WITH_HEADER[] = {
	0x14,0x60,0x3f,0x88,0x81,0x7f,0x75,0x2b,0xc0,0xac,0xa8,0x26,0x6d,0x4b,0xbb,0xe5,
	0x61,0x7f,0xb8,0xf7,0x22,0xca,0x7f,0x50,0x86,0x33,0x85,0x4c,0x6e,0x89,0xd6,0x08
};

/**
 * Offset in the data of the signature.
 */
#define	FW_COMPONENT_V1_SIG_OFFSET		((sizeof FW_COMPONENT_V1_DATA) - FW_COMPONENT_SIG_LENGTH)

/**
 * The signature of the test component data.
 */
static const uint8_t *FW_COMPONENT_V1_SIGNATURE = FW_COMPONENT_V1_DATA + FW_COMPONENT_V1_SIG_OFFSET;

/**
 * Test component image with ECC384/SHA384 signature.
 * 	- Signing key:  ECC384_PRIVKEY
 */
const uint8_t FW_COMPONENT_SHA384_DATA[] = {
	0x1f,0x00,0x01,0x00,0x21,0x43,0x65,0x87,0x00,0x01,0x00,0x00,0x68,0x00,0x02,0x00,
	0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xe9,
	0xef,0xad,0xa2,0x65,0x40,0x90,0x42,0x31,0xf6,0x3c,0x3b,0x7c,0x80,0x2f,0x3f,0xa2,
	0x0b,0x3a,0x3b,0x15,0x91,0x41,0x63,0x4c,0x47,0x03,0x47,0x16,0xf5,0x89,0xde,0x4a,
	0xdb,0xd6,0x0b,0xc8,0x90,0x03,0xf5,0x2d,0xd3,0xf7,0x03,0xcf,0x08,0xc0,0x12,0x86,
	0xd0,0xcf,0x29,0xc0,0x15,0xd4,0x68,0x28,0x32,0xac,0x81,0xb7,0x69,0xeb,0x5a,0x2f,
	0x81,0xf8,0xad,0xb6,0x9e,0xb2,0xa1,0x46,0xe7,0xee,0x7c,0xfd,0x30,0xdc,0xcc,0xd3,
	0x8d,0x6e,0x52,0x23,0xbc,0xf2,0x77,0xcc,0x9e,0x1e,0xc6,0x0b,0xd9,0x6c,0xac,0x36,
	0x1d,0xaa,0x23,0xf4,0x2a,0x59,0x1d,0x3a,0xf4,0x5a,0xdf,0x46,0x32,0x4f,0x2c,0x3c,
	0x3a,0xd9,0x76,0x03,0xf1,0x53,0x66,0x83,0x2d,0x93,0x4f,0x1f,0x6b,0x60,0xa5,0x79,
	0x45,0x12,0x14,0xc3,0xe2,0xd3,0xb7,0xa6,0x69,0x28,0xb5,0xc9,0x37,0x3d,0x47,0x0d,
	0x6e,0x6f,0xdd,0x51,0x9b,0xb3,0xd7,0x3b,0x66,0x93,0xb3,0xa5,0xff,0xde,0x4b,0x90,
	0x5e,0xac,0x5f,0xe6,0x0e,0x74,0x9c,0x74,0x8f,0xd8,0x7e,0xd8,0x45,0x40,0x40,0x22,
	0xb8,0xc6,0x17,0xbb,0x8d,0x7a,0x6c,0x39,0x91,0x85,0xc9,0x85,0xd9,0x19,0xb0,0xfa,
	0x36,0x52,0x88,0x90,0xd2,0x4f,0x8d,0xbf,0x6e,0x5b,0xa5,0x23,0x33,0x0e,0x8c,0x8c,
	0x50,0x24,0x93,0x98,0x73,0x30,0x5b,0x9c,0xf2,0xf5,0x43,0xcb,0x43,0xa9,0x6c,0xd3,
	0x99,0xf6,0xde,0x3a,0x6c,0xa4,0xe9,0x5d,0xcc,0x7c,0x6b,0x23,0xf8,0x9f,0x9b,0x1d,
	0xc5,0x74,0x57,0x92,0xa2,0xf8,0x12,0xe7,0xa3,0x0e,0x08,0xf8,0xea,0x19,0xf5,0x30,
	0x65,0x02,0x30,0x52,0x36,0xed,0x00,0xcf,0x9f,0xea,0xd1,0x4d,0xd4,0x1e,0x30,0xa6,
	0x3d,0xd0,0x42,0x19,0xb6,0xbc,0x29,0x07,0x5d,0x4b,0x95,0x3d,0x4d,0xfa,0xb5,0x30,
	0xa2,0x0e,0x82,0x2a,0xba,0x45,0xd1,0x8f,0x88,0x87,0x60,0x99,0x2a,0x23,0x06,0x63,
	0x25,0xf2,0x56,0x02,0x31,0x00,0x8f,0x3c,0x7e,0xb8,0xbe,0xbc,0x3b,0xb7,0xe9,0x9e,
	0x35,0x61,0x10,0x89,0x18,0x36,0xcf,0x33,0x15,0xbc,0xbb,0x07,0xdc,0x74,0x58,0xd5,
	0x10,0xb4,0x0f,0xf6,0x9f,0x2d,0xa5,0x0a,0x9b,0x76,0x35,0x93,0x2a,0x2b,0xf5,0x34,
	0x64,0xe4,0x69,0xd2,0x51,0xff,0x00
};

const size_t FW_COMPONENT_SHA384_DATA_LEN = sizeof (FW_COMPONENT_SHA384_DATA);

/**
 * The target load address for the component.
 */
#define	FW_COMPONENT_SHA384_LOAD_ADDRESS		0x10000

/**
 * Pointer to the target load address.
 */
static const uint8_t *FW_COMPONENT_SHA384_LOAD_ADDRESS_PTR =
	(uint8_t*) FW_COMPONENT_SHA384_LOAD_ADDRESS;

/**
 * The build version number for the component.
 */
static const uint8_t *FW_COMPONENT_SHA384_BUILD_VERSION =
	FW_COMPONENT_SHA384_DATA + FW_COMPONENT_V1_VERSION_OFFSET;

/**
 * The length of the component image, excluding the signature.
 */
static const size_t FW_COMPONENT_SHA384_DATA_LENGTH =
	sizeof (FW_COMPONENT_SHA384_DATA) - FW_COMPONENT_SIG_LENGTH_ECC384;

/**
 * Offset in the data of the firmware component.
 */
#define	FW_COMPONENT_SHA384_OFFSET			(FW_COMPONENT_HDR_V1_LENGTH + IMAGE_HEADER_BASE_LEN)

/**
 * Length of just the component image, excluding header and signature bytes.
 */
static const size_t FW_COMPONENT_SHA384_LENGTH = sizeof (FW_COMPONENT_SHA384_DATA) -
	FW_COMPONENT_SIG_LENGTH_ECC384 - FW_COMPONENT_HDR_V1_LENGTH - IMAGE_HEADER_BASE_LEN;

/**
 * The test component data.
 */
static const uint8_t *FW_COMPONENT_SHA384 = FW_COMPONENT_SHA384_DATA + FW_COMPONENT_SHA384_OFFSET;

/**
 * The SHA384 hash of the test component data, not including the signature.
 */
static const uint8_t FW_COMPONENT_SHA384_HASH[] = {
	0x7b,0x98,0x1e,0xad,0x5d,0x54,0x2f,0x50,0x89,0xaa,0x75,0xd0,0x47,0x11,0xd7,0x4b,
	0x7c,0x44,0xb9,0x04,0xe0,0xcb,0x42,0xea,0x37,0x9f,0xec,0x85,0x91,0x9a,0x48,0x68,
	0x77,0x04,0xcd,0x3b,0x6f,0x70,0x49,0x10,0x78,0x11,0x47,0x88,0x1e,0x13,0x92,0x1b
};

/**
 * The SHA384 hash of the test component data, including the image header.
 */
static const uint8_t FW_COMPONENT_SHA384_HASH_WITH_HEADER[] = {
	0xd0,0xe4,0xdf,0xab,0x31,0xa0,0x48,0xc0,0xce,0xe9,0x82,0xc0,0x14,0x3e,0x3c,0xd4,
	0xd8,0x2b,0x0b,0xf1,0x52,0x6b,0x75,0x83,0x4f,0x47,0x94,0xea,0x7a,0x4c,0xc5,0xca,
	0xc6,0xea,0xbf,0xf3,0x70,0xd0,0x76,0x52,0xbf,0xf8,0xff,0x0e,0x9a,0x9f,0x67,0xdb
};

/**
 * Offset in the data of the signature.
 */
#define	FW_COMPONENT_SHA384_SIG_OFFSET		\
	((sizeof FW_COMPONENT_SHA384_DATA) - FW_COMPONENT_SIG_LENGTH_ECC384)

/**
 * The signature of the test component data.
 */
static const uint8_t *FW_COMPONENT_SHA384_SIGNATURE =
	FW_COMPONENT_SHA384_DATA + FW_COMPONENT_SHA384_SIG_OFFSET;

/**
 * Test component image with ECC521/SHA512 signature.
 * 	- Signing key:  ECC512_PRIVKEY
 */
const uint8_t FW_COMPONENT_SHA512_DATA[] = {
	0x1f,0x00,0x01,0x00,0x21,0x43,0x65,0x87,0x80,0x01,0x00,0x00,0x8d,0x00,0x03,0x10,
	0x32,0x54,0x76,0x98,0xba,0xdc,0xfe,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x0a,
	0x5d,0x35,0xf7,0x00,0x0b,0x87,0xd2,0xfa,0xc5,0xb4,0xe2,0x4c,0x66,0xfd,0xc4,0x1f,
	0xcf,0x88,0x32,0x70,0xd3,0x7c,0xa8,0xb9,0xf7,0x56,0x5b,0xf7,0x09,0x27,0x24,0x9d,
	0x8f,0x36,0xab,0x3e,0xf2,0x0f,0x9e,0xb1,0x50,0x04,0xff,0xa6,0x26,0xf1,0x21,0xfc,
	0x0f,0x44,0xe9,0x83,0x76,0x11,0x04,0xe1,0x9f,0x12,0x82,0x91,0xc0,0x17,0xba,0x92,
	0x7d,0x7d,0xd1,0x39,0x78,0x58,0xd2,0xa7,0xaa,0xbd,0x2f,0xb7,0x79,0xb1,0x6d,0x30,
	0x6b,0x32,0xf0,0x6f,0xe5,0xbb,0x69,0x1d,0x3c,0x44,0x7c,0x8b,0xc1,0xa8,0xc3,0x83,
	0xeb,0x22,0x66,0x4a,0xd4,0xe7,0x92,0xf8,0x0b,0xe7,0x96,0xbd,0xbd,0xcb,0x41,0x8c,
	0xb6,0x4b,0x3a,0xd8,0x29,0x2a,0xbb,0x0a,0x73,0x63,0x6b,0xd1,0x43,0x43,0x82,0x34,
	0x42,0x81,0xc7,0x1f,0x41,0x2b,0x8b,0x5c,0x3b,0xf0,0xbd,0xee,0x88,0x9a,0x91,0x3c,
	0xd8,0x82,0x84,0x71,0xf1,0xea,0x07,0x4a,0x04,0x7e,0x36,0x9c,0x4b,0x76,0xb7,0x17,
	0x45,0xad,0x19,0xec,0xad,0x16,0xdb,0x73,0x03,0xc5,0x62,0xfd,0xd4,0x59,0xc1,0xc1,
	0x4d,0xa5,0x89,0xf6,0xf9,0x05,0x17,0xfd,0x14,0x20,0xc3,0x38,0xb1,0x57,0xfa,0xfd,
	0x89,0x70,0xb0,0x64,0xc7,0xac,0xe8,0x96,0x07,0x9f,0xf4,0xb8,0x2d,0x84,0x16,0xdb,
	0xda,0x2e,0x01,0x73,0x26,0x0d,0x46,0xca,0xb8,0xfb,0xbc,0x6c,0x81,0xed,0x5b,0x47,
	0x82,0x3f,0x97,0xda,0x18,0x5a,0x14,0xc1,0xa2,0x61,0x12,0x48,0x1a,0xae,0xdc,0x7c,
	0x46,0xa4,0xa2,0x50,0x18,0x56,0xfc,0x0e,0xa1,0x8f,0x0d,0xa5,0xe0,0xf1,0x19,0x2d,
	0x31,0x6b,0x0a,0xc0,0xd8,0x63,0x67,0x68,0x9e,0x67,0xb7,0xfb,0xcc,0x77,0x58,0x32,
	0x13,0x3e,0x80,0x6e,0xae,0xc2,0xf6,0x15,0xe8,0x37,0x7a,0xfe,0xbb,0x06,0xe7,0xd2,
	0x7d,0xb8,0x44,0x5a,0x7b,0x86,0x5c,0x3d,0x8b,0x20,0xde,0xe6,0x1b,0xff,0xd7,0xc7,
	0xaa,0x9d,0xef,0xff,0xc9,0x35,0x8e,0x42,0x85,0xdc,0x87,0x62,0xff,0x4c,0x45,0x06,
	0x46,0x92,0x05,0x91,0x04,0x14,0x23,0xbd,0x7e,0xbb,0x4f,0xa3,0x07,0xd2,0x04,0xf6,
	0xc1,0x89,0xa4,0x5a,0x51,0xe0,0x2b,0x23,0x6c,0x77,0xc6,0x0e,0xd0,0x0b,0x6d,0x78,
	0x53,0xec,0xf7,0x15,0xf9,0xeb,0xf1,0xc8,0xdf,0x20,0x7f,0x3a,0x30,0x8c,0x80,0x60,
	0x58,0xee,0x07,0x3a,0x6a,0x1c,0xb2,0x83,0xe5,0xc0,0x44,0x34,0x4c,0x31,0xcc,0x30,
	0x81,0x87,0x02,0x42,0x01,0x4e,0xb8,0x4d,0x40,0x73,0x65,0xb0,0xcb,0x69,0x1b,0x8c,
	0x35,0xb7,0x83,0xb9,0xf4,0xe6,0x2e,0x22,0x16,0x54,0xa7,0x4e,0x82,0x7c,0xb3,0x55,
	0x78,0x75,0xa1,0x14,0xc3,0x44,0xba,0xc2,0x30,0xb5,0x9d,0xf1,0x44,0xd6,0x1d,0x0e,
	0x2c,0x97,0xe0,0xc1,0x7e,0x47,0xb1,0x24,0xed,0x0d,0xbb,0xf5,0x54,0x98,0x44,0xb6,
	0xd8,0x60,0xb3,0x99,0xcd,0xb4,0x02,0x41,0x63,0xeb,0xaa,0x9f,0xa4,0xfd,0x62,0x0c,
	0x0d,0xf2,0xab,0x0f,0x3c,0x52,0xa7,0xe0,0xa7,0xe0,0xcb,0x30,0xac,0x99,0x22,0x63,
	0x9b,0xd4,0xed,0x78,0x52,0x4e,0x0d,0xfb,0x67,0xe8,0x78,0x3f,0x53,0xa8,0x1c,0x30,
	0xc0,0x87,0xad,0xa8,0x45,0x2a,0x7f,0x6a,0x96,0x7c,0xd7,0xf0,0x8e,0x64,0x09,0x2c,
	0xf0,0x82,0x85,0x11,0x34,0xa0,0x20,0xc9,0x24,0x00,0x00,0x00
};

const size_t FW_COMPONENT_SHA512_DATA_LEN = sizeof (FW_COMPONENT_SHA512_DATA);

/**
 * The target load address for the component.
 */
#define	FW_COMPONENT_SHA512_LOAD_ADDRESS		0xfedcba9876543210

/**
 * Pointer to the target load address.
 */
static const uint8_t *FW_COMPONENT_SHA512_LOAD_ADDRESS_PTR = (uint8_t*) 0xf8e7d6c5;

/**
 * The build version number for the component.
 */
static const uint8_t *FW_COMPONENT_SHA512_BUILD_VERSION =
	FW_COMPONENT_SHA512_DATA + FW_COMPONENT_V1_VERSION_OFFSET;

/**
 * The length of the component image, excluding the signature.
 */
static const size_t FW_COMPONENT_SHA512_DATA_LENGTH =
	sizeof (FW_COMPONENT_SHA512_DATA) - FW_COMPONENT_SIG_LENGTH_ECC521;

/**
 * Offset in the data of the firmware component.
 */
#define	FW_COMPONENT_SHA512_OFFSET			(FW_COMPONENT_HDR_V1_LENGTH + IMAGE_HEADER_BASE_LEN)

/**
 * Length of just the component image, excluding header and signature bytes.
 */
static const size_t FW_COMPONENT_SHA512_LENGTH = sizeof (FW_COMPONENT_SHA512_DATA) -
	FW_COMPONENT_SIG_LENGTH_ECC521 - FW_COMPONENT_HDR_V1_LENGTH - IMAGE_HEADER_BASE_LEN;

/**
 * The test component data.
 */
static const uint8_t *FW_COMPONENT_SHA512 = FW_COMPONENT_SHA512_DATA + FW_COMPONENT_SHA512_OFFSET;

/**
 * The SHA512 hash of the test component data, not including the signature.
 */
static const uint8_t FW_COMPONENT_SHA512_HASH[] = {
	0x8a,0xf4,0x59,0x2d,0x1a,0xc3,0xdc,0x79,0x0b,0xa9,0x9b,0xfc,0xf3,0x88,0x4a,0x2f,
	0xb9,0x45,0xd2,0x95,0x9d,0x03,0x51,0x99,0xf7,0x9f,0xc0,0x5d,0x28,0x58,0xf1,0x6f,
	0xa4,0xdc,0x92,0xcd,0x57,0x36,0x57,0x1f,0xf3,0x04,0xbb,0x78,0x70,0xe5,0xb5,0xd1,
	0xd0,0xb5,0x90,0x4c,0x70,0x7c,0x53,0xcc,0x6c,0xa3,0xc6,0x85,0xf6,0xd9,0xaf,0x9f
};

/**
 * The SHA512 hash of the test component data, including the image header.
 */
static const uint8_t FW_COMPONENT_SHA512_HASH_WITH_HEADER[] = {
	0xd3,0x81,0xb2,0x38,0x8f,0x5f,0xb4,0x68,0xb5,0xdb,0xd8,0xdb,0x6a,0x0a,0xa4,0x31,
	0xa0,0x6d,0x57,0x76,0x39,0xc4,0x4e,0xe8,0x21,0xfb,0xf4,0x4a,0x31,0xc0,0x5d,0xc4,
	0x08,0x59,0xd8,0xe9,0x44,0xbc,0xbe,0x96,0x0c,0x22,0x7b,0xcc,0x06,0x36,0xd5,0x51,
	0x67,0xa6,0xcc,0x18,0xea,0xc8,0xce,0x5d,0x5b,0x76,0xbb,0x12,0x5d,0xec,0x13,0x1b
};

/**
 * Offset in the data of the signature.
 */
#define	FW_COMPONENT_SHA512_SIG_OFFSET		\
	((sizeof FW_COMPONENT_SHA512_DATA) - FW_COMPONENT_SIG_LENGTH_ECC521)

/**
 * The signature of the test component data.
 */
static const uint8_t *FW_COMPONENT_SHA512_SIGNATURE =
	FW_COMPONENT_SHA512_DATA + FW_COMPONENT_SHA512_SIG_OFFSET;


/**
 * Initialize an image header instance for component verification.
 *
 * @param test The test framework.
 * @param header The image header instance to initialize.
 * @param flash Mock for the flash that contains the header data.
 */
static void firmware_component_testing_init_image_header (CuTest *test, struct image_header *header,
	struct flash_mock *flash)
{
	int status;

	status = mock_expect (&flash->mock, flash->base.read, flash, 0, MOCK_ARG (0x1122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash->mock, 1, IMAGE_HEADER_TEST, IMAGE_HEADER_TEST_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = image_header_init (header, &flash->base, 0x1122, IMAGE_HEADER_TEST_MARKER,
		IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash->mock, flash->base.read, flash, 0,
		MOCK_ARG (0x1122 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_TEST_DATA_LENGTH));
	status |= mock_expect_output (&flash->mock, 1, &IMAGE_HEADER_TEST[IMAGE_HEADER_BASE_LEN],
		IMAGE_HEADER_TEST_DATA_LENGTH, 2);

	CuAssertIntEquals (test, 0, status);

	status = image_header_load_data (header, &flash->base, 0x1122);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Action callback function for use with tests for firmware_component_load_to_memory_and_verify.
 * This callback will update a hash context with a specified data buffer.
 *
 * @param expected The expectation being executed.  The data to hash will be stored in the context
 * field of this structure.
 * @param called The function that was called.  The length of the data is argument index 2.  The
 * hash engine is argument index 6.
 *
 * @return Status of the hash update operation.
 */
int64_t firmware_component_testing_mock_action_update_digest (const struct mock_call *expected,
	const struct mock_call *called)
{
	const uint8_t *data = expected->context;
	size_t length = called->argv[2].value;
	struct hash_engine *hash = (struct hash_engine*) ((uintptr_t) called->argv[6].value);

	return hash->update (hash, data, length);
}

/*******************
 * Test cases
 *******************/

static void firmware_component_test_init (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_init_header_format1 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_init_unknown_header_format_max_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t max_header[1024];

	TEST_START;

	memcpy (max_header, FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN);
	*((uint16_t*) max_header) = 1024;
	*((uint16_t*) &max_header[2]) = 0xffff;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, max_header, sizeof (max_header), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (max_header) - IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, max_header + IMAGE_HEADER_BASE_LEN,
		sizeof (max_header) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_init_null (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (NULL, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_component_init (&image, NULL, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_init_bad_marker (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER + 1);
	CuAssertIntEquals (test, IMAGE_HEADER_BAD_MARKER, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_init_read_base_header_error (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_init_read_header_data_error (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_init_less_than_min_header_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t bad_header[IMAGE_HEADER_BASE_LEN];

	TEST_START;

	memcpy (bad_header, FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN);
	bad_header[0] = IMAGE_HEADER_BASE_LEN - 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, IMAGE_HEADER_NOT_MINIMUM_SIZE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_init_header_too_short (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t bad_header[IMAGE_HEADER_BASE_LEN];

	TEST_START;

	memcpy (bad_header, FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN);
	bad_header[0] = IMAGE_HEADER_BASE_LEN + FW_COMPONENT_HDR_LENGTH - 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_BAD_HEADER, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_init_header_too_long (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t bad_header[IMAGE_HEADER_BASE_LEN];

	TEST_START;

	memcpy (bad_header, FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN);
	bad_header[0] = IMAGE_HEADER_BASE_LEN + FW_COMPONENT_HDR_LENGTH + 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_BAD_HEADER, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_init_header_format1_too_short (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t bad_header[IMAGE_HEADER_BASE_LEN];

	TEST_START;

	memcpy (bad_header, FW_COMPONENT_V1_DATA, IMAGE_HEADER_BASE_LEN);
	bad_header[0] = IMAGE_HEADER_BASE_LEN + FW_COMPONENT_HDR_V1_LENGTH - 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_BAD_HEADER, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_init_header_format1_too_long (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t bad_header[IMAGE_HEADER_BASE_LEN];

	TEST_START;

	memcpy (bad_header, FW_COMPONENT_V1_DATA, IMAGE_HEADER_BASE_LEN);
	bad_header[0] = IMAGE_HEADER_BASE_LEN + FW_COMPONENT_HDR_V1_LENGTH + 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_BAD_HEADER, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_init_unknown_header_format_too_short (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t max_header[1024];

	TEST_START;

	memcpy (max_header, FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN);
	*((uint16_t*) max_header) = IMAGE_HEADER_BASE_LEN + FW_COMPONENT_HDR_V1_LENGTH - 1;
	*((uint16_t*) &max_header[2]) = 0xffff;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, max_header, sizeof (max_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_BAD_HEADER, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_init_unknown_header_format_too_long (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t max_header[1024];

	TEST_START;

	memcpy (max_header, FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN);
	*((uint16_t*) max_header) = 1025;
	*((uint16_t*) &max_header[2]) = 0xffff;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, max_header, sizeof (max_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, IMAGE_HEADER_TOO_LONG, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_init_with_header (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - IMAGE_HEADER_BASE_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_init_with_header_unknown_header_format_max_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t max_header[1024];

	TEST_START;

	memcpy (max_header, FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN);
	*((uint16_t*) max_header) = 1024;
	*((uint16_t*) &max_header[2]) = 0xffff;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + 3),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, max_header, sizeof (max_header), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + 3), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (max_header) - IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, max_header + IMAGE_HEADER_BASE_LEN,
		sizeof (max_header) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		3);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_init_with_header_zero_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		0);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_init_with_header_null (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (NULL, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_component_init_with_header (&image, NULL, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_init_with_header_bad_marker (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER + 1, FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, IMAGE_HEADER_BAD_MARKER, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_init_with_header_read_base_header_error (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_init_with_header_read_header_data_error (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_init_with_header_less_than_min_header_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t bad_header[IMAGE_HEADER_BASE_LEN];

	TEST_START;

	memcpy (bad_header, FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN);
	bad_header[0] = IMAGE_HEADER_BASE_LEN - 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + 3),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		3);
	CuAssertIntEquals (test, IMAGE_HEADER_NOT_MINIMUM_SIZE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_init_with_header_header_too_short (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t bad_header[IMAGE_HEADER_BASE_LEN];

	TEST_START;

	memcpy (bad_header, FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN);
	bad_header[0] = IMAGE_HEADER_BASE_LEN + FW_COMPONENT_HDR_LENGTH - 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + 3),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		3);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_BAD_HEADER, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_init_with_header_header_too_long (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t bad_header[IMAGE_HEADER_BASE_LEN];

	TEST_START;

	memcpy (bad_header, FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN);
	bad_header[0] = IMAGE_HEADER_BASE_LEN + FW_COMPONENT_HDR_LENGTH + 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + 3),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		3);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_BAD_HEADER, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_init_with_header_unknown_header_format_too_short (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t max_header[1024];

	TEST_START;

	memcpy (max_header, FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN);
	*((uint16_t*) max_header) = IMAGE_HEADER_BASE_LEN + FW_COMPONENT_HDR_LENGTH - 1;
	*((uint16_t*) &max_header[2]) = 0xffff;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + 3),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, max_header, sizeof (max_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		3);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_BAD_HEADER, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_init_with_header_unknown_header_format_too_long (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t max_header[1024];

	TEST_START;

	memcpy (max_header, FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN);
	*((uint16_t*) max_header) = 1025;
	*((uint16_t*) &max_header[2]) = 0xffff;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + 3),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, max_header, sizeof (max_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		3);
	CuAssertIntEquals (test, IMAGE_HEADER_TOO_LONG, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_release_null (CuTest *test)
{
	TEST_START;

	firmware_component_release (NULL);
}

static void firmware_component_test_get_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t length;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	length = firmware_component_get_length (&image);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, length);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_length_header_format1 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t length;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	length = firmware_component_get_length (&image);
	CuAssertIntEquals (test, FW_COMPONENT_V1_LENGTH, length);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_length_with_header (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t length;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - IMAGE_HEADER_BASE_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	length = firmware_component_get_length (&image);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, length);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_length_with_header_zero_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t length;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	length = firmware_component_get_length (&image);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, length);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_length_null (CuTest *test)
{
	size_t length;

	TEST_START;

	length = firmware_component_get_length (NULL);
	CuAssertIntEquals (test, 0, length);
}

static void firmware_component_test_get_signature_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t length;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	length = firmware_component_get_signature_length (&image);
	CuAssertIntEquals (test, FW_COMPONENT_SIG_LENGTH, length);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_signature_length_header_format1 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t length;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA,
		FW_COMPONENT_SHA384_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA384_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	length = firmware_component_get_signature_length (&image);
	CuAssertIntEquals (test, FW_COMPONENT_SIG_LENGTH_ECC384, length);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_signature_length_with_header (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t length;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - IMAGE_HEADER_BASE_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	length = firmware_component_get_signature_length (&image);
	CuAssertIntEquals (test, FW_COMPONENT_SIG_LENGTH, length);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_signature_length_with_header_zero_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t length;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	length = firmware_component_get_signature_length (&image);
	CuAssertIntEquals (test, FW_COMPONENT_SIG_LENGTH, length);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_signature_length_null (CuTest *test)
{
	size_t length;

	TEST_START;

	length = firmware_component_get_signature_length (NULL);
	CuAssertIntEquals (test, 0, length);
}

static void firmware_component_test_get_signature (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t sig_actual[FW_COMPONENT_SIG_LENGTH * 2];

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_PTR (&sig_actual),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_get_signature (&image, sig_actual, sizeof (sig_actual));
	CuAssertIntEquals (test, FW_COMPONENT_SIG_LENGTH, status);

	status = testing_validate_array (FW_COMPONENT_SIGNATURE, sig_actual, FW_COMPONENT_SIG_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_signature_header_format1 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t sig_actual[FW_COMPONENT_SIG_LENGTH * 2];

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_PTR (&sig_actual),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_get_signature (&image, sig_actual, sizeof (sig_actual));
	CuAssertIntEquals (test, FW_COMPONENT_SIG_LENGTH, status);

	status = testing_validate_array (FW_COMPONENT_V1_SIGNATURE, sig_actual,
		FW_COMPONENT_SIG_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_signature_ecc384 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t sig_actual[FW_COMPONENT_SIG_LENGTH * 2];

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA,
		FW_COMPONENT_SHA384_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA384_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SHA384_SIG_OFFSET), MOCK_ARG_PTR (&sig_actual),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC384));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH_ECC384, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_get_signature (&image, sig_actual, sizeof (sig_actual));
	CuAssertIntEquals (test, FW_COMPONENT_SIG_LENGTH_ECC384, status);

	status = testing_validate_array (FW_COMPONENT_SHA384_SIGNATURE, sig_actual,
		FW_COMPONENT_SIG_LENGTH_ECC384);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_signature_ecc521 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t sig_actual[FW_COMPONENT_SIG_LENGTH * 2];

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA,
		FW_COMPONENT_SHA512_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA512_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SHA512_SIG_OFFSET), MOCK_ARG_PTR (&sig_actual),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC521));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH_ECC521, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_get_signature (&image, sig_actual, sizeof (sig_actual));
	CuAssertIntEquals (test, FW_COMPONENT_SIG_LENGTH_ECC521, status);

	status = testing_validate_array (FW_COMPONENT_SHA512_SIGNATURE, sig_actual,
		FW_COMPONENT_SIG_LENGTH_ECC521);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_signature_with_header (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t sig_actual[FW_COMPONENT_SIG_LENGTH * 2];

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - IMAGE_HEADER_BASE_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_HEADER_SIG_OFFSET), MOCK_ARG_PTR (&sig_actual),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_HEADER_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_get_signature (&image, sig_actual, sizeof (sig_actual));
	CuAssertIntEquals (test, FW_COMPONENT_SIG_LENGTH, status);

	status = testing_validate_array (FW_COMPONENT_HEADER_SIGNATURE, sig_actual,
		FW_COMPONENT_SIG_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_signature_with_header_zero_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t sig_actual[FW_COMPONENT_SIG_LENGTH * 2];

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_PTR (&sig_actual),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_get_signature (&image, sig_actual, sizeof (sig_actual));
	CuAssertIntEquals (test, FW_COMPONENT_SIG_LENGTH, status);

	status = testing_validate_array (FW_COMPONENT_SIGNATURE, sig_actual, FW_COMPONENT_SIG_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_signature_null (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t sig_actual[FW_COMPONENT_SIG_LENGTH * 2];

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_get_signature (NULL, sig_actual, sizeof (sig_actual));
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_component_get_signature (&image, NULL, sizeof (sig_actual));
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_signature_small_sig_buffer (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t sig_actual[FW_COMPONENT_SIG_LENGTH * 2];

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_get_signature (&image, sig_actual, FW_COMPONENT_SIG_LENGTH - 1);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_SIG_BUFFER_TOO_SMALL, status);

	status = firmware_component_get_signature (&image, sig_actual, 0);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_SIG_BUFFER_TOO_SMALL, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_signature_read_error (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t sig_actual[FW_COMPONENT_SIG_LENGTH * 2];

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_PTR (&sig_actual),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_get_signature (&image, sig_actual, sizeof (sig_actual));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_hash_type (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	enum hash_type type;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	type = firmware_component_get_hash_type (&image);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_hash_type_header_format1 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	enum hash_type type;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	type = firmware_component_get_hash_type (&image);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_hash_type_sha384 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	enum hash_type type;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA,
		FW_COMPONENT_SHA384_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA384_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	type = firmware_component_get_hash_type (&image);
	CuAssertIntEquals (test, HASH_TYPE_SHA384, type);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_hash_type_sha512 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	enum hash_type type;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA,
		FW_COMPONENT_SHA512_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA512_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	type = firmware_component_get_hash_type (&image);
	CuAssertIntEquals (test, HASH_TYPE_SHA512, type);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_hash_type_with_header (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	enum hash_type type;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - IMAGE_HEADER_BASE_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	type = firmware_component_get_hash_type (&image);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_hash_type_with_header_zero_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	enum hash_type type;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	type = firmware_component_get_hash_type (&image);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_hash_type_null (CuTest *test)
{
	enum hash_type type;

	TEST_START;

	type = firmware_component_get_hash_type (NULL);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);
}

static void firmware_component_test_get_hash (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	int offset = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_DATA_LENGTH - offset));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + offset,
		FW_COMPONENT_DATA_LEN - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_get_hash (&image, &hash.base, hash_actual, sizeof (hash_actual),
		&type);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);

	status = testing_validate_array (FW_COMPONENT_HASH, hash_actual, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_get_hash_no_type_out (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	int offset = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_DATA_LENGTH - offset));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + offset,
		FW_COMPONENT_DATA_LEN - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_get_hash (&image, &hash.base, hash_actual, sizeof (hash_actual),
		NULL);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (FW_COMPONENT_HASH, hash_actual, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_get_hash_header_format1 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_V1_DATA_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_get_hash (&image, &hash.base, hash_actual, sizeof (hash_actual),
		&type);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);

	status = testing_validate_array (FW_COMPONENT_V1_HASH, hash_actual, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_get_hash_sha384 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t hash_actual[SHA384_HASH_LENGTH];
	enum hash_type type;
	int offset = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA,
		FW_COMPONENT_SHA384_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA384_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA,
		FW_COMPONENT_SHA384_DATA_LEN, 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_SHA384_DATA_LENGTH - offset));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA + offset,
		FW_COMPONENT_SHA384_DATA_LEN - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_get_hash (&image, &hash.base, hash_actual, sizeof (hash_actual),
		&type);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA384, type);

	status = testing_validate_array (FW_COMPONENT_SHA384_HASH, hash_actual, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_get_hash_sha512 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t hash_actual[SHA512_HASH_LENGTH];
	enum hash_type type;
	int offset = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA,
		FW_COMPONENT_SHA512_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA512_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA,
		FW_COMPONENT_SHA512_DATA_LEN, 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_SHA512_DATA_LENGTH - offset));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA + offset,
		FW_COMPONENT_SHA512_DATA_LEN - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_get_hash (&image, &hash.base, hash_actual, sizeof (hash_actual),
		&type);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA512, type);

	status = testing_validate_array (FW_COMPONENT_SHA512_HASH, hash_actual, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_get_hash_with_header (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	int offset = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - IMAGE_HEADER_BASE_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_HEADER_DATA,
		FW_COMPONENT_HEADER_DATA_LEN, 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HEADER_DATA_LENGTH - offset));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_HEADER_DATA + offset,
		FW_COMPONENT_HEADER_DATA_LEN - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_get_hash (&image, &hash.base, hash_actual, sizeof (hash_actual),
		&type);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);

	status = testing_validate_array (FW_COMPONENT_HEADER_HASH, hash_actual, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_get_hash_with_header_zero_length (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	int offset = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_DATA_LENGTH - offset));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + offset,
		FW_COMPONENT_DATA_LEN - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_get_hash (&image, &hash.base, hash_actual, sizeof (hash_actual),
		&type);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);

	status = testing_validate_array (FW_COMPONENT_HASH, hash_actual, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_get_hash_null (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_get_hash (NULL, &hash.base, hash_actual, sizeof (hash_actual),
		&type);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_component_get_hash (&image, NULL, hash_actual, sizeof (hash_actual),
		&type);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_component_get_hash (&image, &hash.base, NULL, sizeof (hash_actual),
		&type);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_get_hash_unknown_hash (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	uint8_t bad_header[FW_COMPONENT_V1_DATA_LEN];

	TEST_START;

	memcpy (bad_header, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN);
	bad_header[FW_COMPONENT_V1_HASH_TYPE_OFFSET] = 5;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, bad_header + IMAGE_HEADER_BASE_LEN,
		sizeof (bad_header) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_get_hash (&image, &hash.base, hash_actual, SHA256_HASH_LENGTH,
		&type);
	CuAssertIntEquals (test, HASH_ENGINE_UNKNOWN_HASH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_get_hash_small_buffer (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_get_hash (&image, &hash.base, hash_actual, SHA256_HASH_LENGTH - 1,
		&type);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_get_hash_small_buffer_sha384 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t hash_actual[SHA384_HASH_LENGTH];
	enum hash_type type;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA,
		FW_COMPONENT_SHA384_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA384_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_get_hash (&image, &hash.base, hash_actual, SHA384_HASH_LENGTH - 1,
		&type);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_get_hash_small_buffer_sha512 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t hash_actual[SHA512_HASH_LENGTH];
	enum hash_type type;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA,
		FW_COMPONENT_SHA512_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA512_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_get_hash (&image, &hash.base, hash_actual, SHA512_HASH_LENGTH - 1,
		&type);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_get_hash_read_error (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_get_hash (&image, &hash.base, hash_actual, sizeof (hash_actual),
		&type);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_verification (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	int offset = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_DATA_LENGTH - offset));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + offset,
		FW_COMPONENT_DATA_LEN - offset, 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_verification (&image, &hash.base, &verification.base, NULL, NULL, 0,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_verification_with_hash_out (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	int offset = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_DATA_LENGTH - offset));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + offset,
		FW_COMPONENT_DATA_LEN - offset, 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_verification (&image, &hash.base, &verification.base, NULL,
		hash_actual, sizeof (hash_actual), NULL);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (FW_COMPONENT_HASH, hash_actual, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_verification_with_hash_type_out (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	enum hash_type type;
	int offset = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_DATA_LENGTH - offset));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + offset,
		FW_COMPONENT_DATA_LEN - offset, 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_verification (&image, &hash.base, &verification.base, NULL, NULL, 0,
		&type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_verification_header_format1 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_V1_DATA_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_verification (&image, &hash.base, &verification.base, NULL,
		hash_actual, sizeof (hash_actual), &type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);

	status = testing_validate_array (FW_COMPONENT_V1_HASH, hash_actual, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_verification_header_format1_with_expected_version (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_V1_DATA_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_verification (&image, &hash.base, &verification.base,
		FW_COMPONENT_V1_BUILD_VERSION, hash_actual, sizeof (hash_actual), &type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);

	status = testing_validate_array (FW_COMPONENT_V1_HASH, hash_actual, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_verification_sha384 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	uint8_t hash_actual[SHA384_HASH_LENGTH];
	enum hash_type type;
	int status;
	int offset = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA,
		FW_COMPONENT_SHA384_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA384_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SHA384_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC384));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH_ECC384, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA,
		FW_COMPONENT_SHA384_DATA_LEN, 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_SHA384_DATA_LENGTH - offset));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA + offset,
		FW_COMPONENT_SHA384_DATA_LEN - offset, 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA384_HASH, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA384_SIGNATURE, FW_COMPONENT_SIG_LENGTH_ECC384),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC384));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_verification (&image, &hash.base, &verification.base,
		FW_COMPONENT_SHA384_BUILD_VERSION, hash_actual, sizeof (hash_actual), &type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA384, type);

	status = testing_validate_array (FW_COMPONENT_SHA384_HASH, hash_actual, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_verification_sha512 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	uint8_t hash_actual[SHA512_HASH_LENGTH];
	enum hash_type type;
	int status;
	int offset = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA,
		FW_COMPONENT_SHA512_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA512_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SHA512_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC521));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH_ECC521, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA,
		FW_COMPONENT_SHA512_DATA_LEN, 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_SHA512_DATA_LENGTH - offset));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA + offset,
		FW_COMPONENT_SHA512_DATA_LEN - offset, 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA512_HASH, SHA512_HASH_LENGTH),
		MOCK_ARG (SHA512_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA512_SIGNATURE, FW_COMPONENT_SIG_LENGTH_ECC521),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC521));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_verification (&image, &hash.base, &verification.base,
		FW_COMPONENT_SHA512_BUILD_VERSION, hash_actual, sizeof (hash_actual), &type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA512, type);

	status = testing_validate_array (FW_COMPONENT_SHA512_HASH, hash_actual, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_verification_with_header (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	int offset = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - IMAGE_HEADER_BASE_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_HEADER_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_HEADER_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_HEADER_DATA,
		FW_COMPONENT_HEADER_DATA_LEN, 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HEADER_DATA_LENGTH - offset));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_HEADER_DATA + offset,
		FW_COMPONENT_HEADER_DATA_LEN - offset, 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HEADER_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HEADER_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_verification (&image, &hash.base, &verification.base, NULL, NULL, 0,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_verification_with_header_zero_length (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	int offset = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_DATA_LENGTH - offset));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + offset,
		FW_COMPONENT_DATA_LEN - offset, 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_verification (&image, &hash.base, &verification.base, NULL, NULL, 0,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_verification_null (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_verification (NULL, &hash.base, &verification.base, NULL, NULL, 0,
		NULL);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_component_verification (&image, NULL, &verification.base, NULL, NULL, 0,
		NULL);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_component_verification (&image, &hash.base, NULL, NULL, NULL, 0,
		NULL);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_verification_unknown_hash (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t bad_header[FW_COMPONENT_V1_DATA_LEN];

	TEST_START;

	memcpy (bad_header, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN);
	bad_header[FW_COMPONENT_V1_HASH_TYPE_OFFSET] = 5;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, bad_header + IMAGE_HEADER_BASE_LEN,
		sizeof (bad_header) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_verification (&image, &hash.base, &verification.base, NULL, NULL, 0,
		NULL);
	CuAssertIntEquals (test, HASH_ENGINE_UNKNOWN_HASH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_verification_small_hash_buffer (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_verification (&image, &hash.base, &verification.base, NULL,
		hash_actual, SHA256_HASH_LENGTH - 1, NULL);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_verification_small_hash_buffer_sha384 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t hash_actual[SHA384_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA,
		FW_COMPONENT_SHA384_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA384_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_verification (&image, &hash.base, &verification.base, NULL,
		hash_actual, SHA384_HASH_LENGTH - 1, NULL);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_verification_small_hash_buffer_sha512 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t hash_actual[SHA512_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA,
		FW_COMPONENT_SHA512_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA512_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_verification (&image, &hash.base, &verification.base, NULL,
		hash_actual, SHA512_HASH_LENGTH - 1, NULL);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_verification_read_signature_error (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_verification (&image, &hash.base, &verification.base, NULL, NULL, 0,
		NULL);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_verification_read_data_error (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_verification (&image, &hash.base, &verification.base, NULL, NULL, 0,
		NULL);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_verification_verify_error (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	int offset = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_DATA_LENGTH - offset));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + offset,
		FW_COMPONENT_DATA_LEN - offset, 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		SIG_VERIFICATION_VERIFY_SIG_FAILED,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_verification (&image, &hash.base, &verification.base, NULL, NULL, 0,
		NULL);
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_verification_header_format0_with_expected_version (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_verification (&image, &hash.base, &verification.base,
		FW_COMPONENT_V1_BUILD_VERSION, NULL, 0, NULL);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_WRONG_VERSION, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_verification_header_format1_with_unexpected_version (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_verification (&image, &hash.base, &verification.base,
		FW_COMPONENT_SHA384_BUILD_VERSION, NULL, 0, NULL);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_WRONG_VERSION, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT, FW_COMPONENT_LENGTH, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load (&image, load_data, sizeof (load_data), &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT, load_data, FW_COMPONENT_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_no_length_out (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT, FW_COMPONENT_LENGTH, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load (&image, load_data, sizeof (load_data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (FW_COMPONENT, load_data, FW_COMPONENT_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_header_format1 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t load_data[FW_COMPONENT_V1_DATA_LEN];
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_V1_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1, FW_COMPONENT_V1_LENGTH, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load (&image, load_data, sizeof (load_data), &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_V1_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT_V1, load_data, FW_COMPONENT_V1_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_with_header (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - IMAGE_HEADER_BASE_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_HEADER_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_HEADER, FW_COMPONENT_HEADER_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load (&image, load_data, sizeof (load_data), &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_HEADER_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT_HEADER, load_data, FW_COMPONENT_HEADER_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_with_header_zero_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT, FW_COMPONENT_LENGTH, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load (&image, load_data, sizeof (load_data), &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT, load_data, FW_COMPONENT_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_null (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load (NULL, load_data, sizeof (load_data), &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_component_load (&image, NULL, sizeof (load_data), &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_image_too_large (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t load_data[FW_COMPONENT_LENGTH - 1];
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load (&image, load_data, sizeof (load_data), &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_TOO_LARGE, status);

	status = firmware_component_load (&image, load_data, 0, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_TOO_LARGE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_image_error (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000 + FW_COMPONENT_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load (&image, load_data, sizeof (load_data), &app_len);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_image_end (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint32_t length;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	length = firmware_component_get_image_end (&image);
	CuAssertIntEquals (test, 0x10000 + FW_COMPONENT_DATA_LEN, length);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_image_end_header_format1 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint32_t length;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	length = firmware_component_get_image_end (&image);
	CuAssertIntEquals (test, 0x10000 + FW_COMPONENT_V1_DATA_LEN, length);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_image_end_with_header (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint32_t length;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - IMAGE_HEADER_BASE_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	length = firmware_component_get_image_end (&image);
	CuAssertIntEquals (test, 0x10000 + FW_COMPONENT_HEADER_DATA_LEN, length);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_image_end_with_header_zero_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint32_t length;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	length = firmware_component_get_image_end (&image);
	CuAssertIntEquals (test, 0x10000 + FW_COMPONENT_DATA_LEN, length);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_image_end_null (CuTest *test)
{
	size_t length;

	TEST_START;

	length = firmware_component_get_image_end (NULL);
	CuAssertIntEquals (test, 0, length);
}

static void firmware_component_test_get_data_addr (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint32_t address;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	address = firmware_component_get_data_addr (&image);
	CuAssertIntEquals (test, 0x10000 + FW_COMPONENT_OFFSET, address);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_data_addr_header_format1 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint32_t address;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	address = firmware_component_get_data_addr (&image);
	CuAssertIntEquals (test, 0x10000 + FW_COMPONENT_V1_OFFSET, address);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_data_addr_with_header (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint32_t address;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - IMAGE_HEADER_BASE_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	address = firmware_component_get_data_addr (&image);
	CuAssertIntEquals (test, 0x10000 + FW_COMPONENT_HEADER_OFFSET, address);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_data_addr_with_header_zero_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint32_t address;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	address = firmware_component_get_data_addr (&image);
	CuAssertIntEquals (test, 0x10000 + FW_COMPONENT_OFFSET, address);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_data_addr_null (CuTest *test)
{
	size_t length;

	TEST_START;

	length = firmware_component_get_data_addr (NULL);
	CuAssertIntEquals (test, 0, length);
}

static void firmware_component_test_load_and_verify (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT, FW_COMPONENT_LENGTH, 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, NULL, hash_actual, sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT, load_data, FW_COMPONENT_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (FW_COMPONENT_HASH, hash_actual, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_no_hash_out (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT, FW_COMPONENT_LENGTH, 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, NULL, NULL, 0, &type, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT, load_data, FW_COMPONENT_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_no_hash_type_out (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT, FW_COMPONENT_LENGTH, 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, NULL, hash_actual, sizeof (hash_actual), NULL, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT, load_data, FW_COMPONENT_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (FW_COMPONENT_HASH, hash_actual, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_no_length_out (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT, FW_COMPONENT_LENGTH, 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, NULL, hash_actual, sizeof (hash_actual), &type, NULL);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);

	status = testing_validate_array (FW_COMPONENT, load_data, FW_COMPONENT_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (FW_COMPONENT_HASH, hash_actual, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_header_format1 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[FW_COMPONENT_V1_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_V1_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1, FW_COMPONENT_V1_LENGTH, 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual, sizeof (hash_actual), &type,
		&app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);
	CuAssertIntEquals (test, FW_COMPONENT_V1_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT_V1, load_data, FW_COMPONENT_V1_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (FW_COMPONENT_V1_HASH, hash_actual, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_header_format1_no_expected_version (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[FW_COMPONENT_V1_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_V1_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1, FW_COMPONENT_V1_LENGTH, 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, NULL, hash_actual, sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);
	CuAssertIntEquals (test, FW_COMPONENT_V1_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT_V1, load_data, FW_COMPONENT_V1_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (FW_COMPONENT_V1_HASH, hash_actual, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_sha384 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[FW_COMPONENT_SHA384_DATA_LEN];
	uint8_t hash_actual[SHA384_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA,
		FW_COMPONENT_SHA384_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA384_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SHA384_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC384));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH_ECC384, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SHA384_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_SHA384_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384, FW_COMPONENT_SHA384_LENGTH,
		2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA384_HASH, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA384_SIGNATURE, FW_COMPONENT_SIG_LENGTH_ECC384),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC384));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, FW_COMPONENT_SHA384_BUILD_VERSION, hash_actual, sizeof (hash_actual),
		&type, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA384, type);
	CuAssertIntEquals (test, FW_COMPONENT_SHA384_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT_SHA384, load_data, FW_COMPONENT_SHA384_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (FW_COMPONENT_SHA384_HASH, hash_actual, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_sha384_no_hash_out (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[FW_COMPONENT_SHA384_DATA_LEN];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA,
		FW_COMPONENT_SHA384_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA384_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SHA384_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC384));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH_ECC384, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SHA384_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_SHA384_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384, FW_COMPONENT_SHA384_LENGTH,
		2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA384_HASH, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA384_SIGNATURE, FW_COMPONENT_SIG_LENGTH_ECC384),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC384));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, FW_COMPONENT_SHA384_BUILD_VERSION, NULL, 0, &type, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA384, type);
	CuAssertIntEquals (test, FW_COMPONENT_SHA384_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT_SHA384, load_data, FW_COMPONENT_SHA384_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_sha512 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[FW_COMPONENT_SHA512_DATA_LEN];
	uint8_t hash_actual[SHA512_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA,
		FW_COMPONENT_SHA512_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA512_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SHA512_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC521));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH_ECC521, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SHA512_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_SHA512_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512, FW_COMPONENT_SHA512_LENGTH,
		2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA512_HASH, SHA512_HASH_LENGTH),
		MOCK_ARG (SHA512_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA512_SIGNATURE, FW_COMPONENT_SIG_LENGTH_ECC521),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC521));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, FW_COMPONENT_SHA512_BUILD_VERSION, hash_actual, sizeof (hash_actual),
		&type, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA512, type);
	CuAssertIntEquals (test, FW_COMPONENT_SHA512_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT_SHA512, load_data, FW_COMPONENT_SHA512_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (FW_COMPONENT_SHA512_HASH, hash_actual, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_sha512_no_hash_out (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[FW_COMPONENT_SHA512_DATA_LEN];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA,
		FW_COMPONENT_SHA512_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA512_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SHA512_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC521));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH_ECC521, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SHA512_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_SHA512_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512, FW_COMPONENT_SHA512_LENGTH,
		2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA512_HASH, SHA512_HASH_LENGTH),
		MOCK_ARG (SHA512_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA512_SIGNATURE, FW_COMPONENT_SIG_LENGTH_ECC521),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC521));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, FW_COMPONENT_SHA512_BUILD_VERSION, NULL, 0, &type, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA512, type);
	CuAssertIntEquals (test, FW_COMPONENT_SHA512_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT_SHA512, load_data, FW_COMPONENT_SHA512_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_extra_header (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - IMAGE_HEADER_BASE_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_HEADER_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_HEADER_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_EXTRA_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_HEADER_DATA,
		FW_COMPONENT_HEADER_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_HEADER_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_HEADER_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_HEADER, FW_COMPONENT_HEADER_LENGTH,
		2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HEADER_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HEADER_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, NULL, hash_actual, sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);
	CuAssertIntEquals (test, FW_COMPONENT_HEADER_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT_HEADER, load_data, FW_COMPONENT_HEADER_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (FW_COMPONENT_HEADER_HASH, hash_actual, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_extra_header_zero_length (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT, FW_COMPONENT_LENGTH, 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, NULL, hash_actual, sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT, load_data, FW_COMPONENT_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (FW_COMPONENT_HASH, hash_actual, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_null (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (NULL, load_data, sizeof (load_data), &hash.base,
		&verification.base, NULL, hash_actual, sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_component_load_and_verify (&image, NULL, sizeof (load_data), &hash.base,
		&verification.base, NULL, hash_actual, sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), NULL,
		&verification.base, NULL, hash_actual, sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		NULL, NULL, hash_actual, sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_unknown_hash (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[FW_COMPONENT_V1_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint8_t bad_header[FW_COMPONENT_V1_DATA_LEN];

	TEST_START;

	memcpy (bad_header, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN);
	bad_header[FW_COMPONENT_V1_HASH_TYPE_OFFSET] = 5;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, bad_header + IMAGE_HEADER_BASE_LEN,
		sizeof (bad_header) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, NULL, hash_actual, sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, HASH_ENGINE_UNKNOWN_HASH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_small_hash_buffer (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH - 1];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, NULL, hash_actual, sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, NULL, hash_actual, 0, &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_small_hash_buffer_sha384 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[FW_COMPONENT_SHA384_DATA_LEN];
	uint8_t hash_actual[SHA384_HASH_LENGTH - 1];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA,
		FW_COMPONENT_SHA384_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA384_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, NULL, hash_actual, sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, NULL, hash_actual, 0, &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_small_hash_buffer_sha512 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[FW_COMPONENT_SHA512_DATA_LEN];
	uint8_t hash_actual[SHA512_HASH_LENGTH - 1];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA,
		FW_COMPONENT_SHA512_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA512_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, NULL, hash_actual, sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, NULL, hash_actual, 0, &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_read_signature_error (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, NULL, hash_actual, sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_verify_error (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT, FW_COMPONENT_LENGTH, 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		SIG_VERIFICATION_VERIFY_SIG_FAILED,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, NULL, hash_actual, sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);

	status = testing_validate_array (FW_COMPONENT_HASH, hash_actual, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_hash_start_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash,
		HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, NULL, hash_actual, sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_and_verify_hash_header_info_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, NULL, hash_actual, sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_and_verify_hash_header_data_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN, FW_COMPONENT_HDR_LENGTH),
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, NULL, hash_actual, sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_and_verify_image_too_large (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[FW_COMPONENT_LENGTH - 1];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN, FW_COMPONENT_HDR_LENGTH),
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, NULL, hash_actual, sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_TOO_LARGE, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN, FW_COMPONENT_HDR_LENGTH),
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, 0, &hash.base,
		&verification.base, NULL, hash_actual, sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_TOO_LARGE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_and_verify_image_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN, FW_COMPONENT_HDR_LENGTH),
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000 + FW_COMPONENT_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, NULL, hash_actual, sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_and_verify_hash_image_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN, FW_COMPONENT_HDR_LENGTH),
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT, FW_COMPONENT_LENGTH, 2);

	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT, FW_COMPONENT_LENGTH), MOCK_ARG (FW_COMPONENT_LENGTH));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, NULL, hash_actual, sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_and_verify_hash_finish_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN, FW_COMPONENT_HDR_LENGTH),
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT, FW_COMPONENT_LENGTH, 2);

	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT, FW_COMPONENT_LENGTH), MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, HASH_ENGINE_FINISH_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, NULL, hash_actual, sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_and_verify_extra_header_read_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - IMAGE_HEADER_BASE_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_HEADER_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_HEADER_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_EXTRA_HDR_LENGTH));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, NULL, hash_actual, sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_and_verify_extra_header_hash_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - IMAGE_HEADER_BASE_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_HEADER_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_HEADER_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_EXTRA_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_HEADER_DATA,
		FW_COMPONENT_HEADER_DATA_LEN, 2);

	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HEADER_DATA, FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG (FW_COMPONENT_EXTRA_HDR_LENGTH));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, NULL, hash_actual, sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_and_verify_header_format0_with_expected_version (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, FW_COMPONENT_V1_BUILD_VERSION, NULL, 0, NULL, NULL);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_WRONG_VERSION, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_header_format1_with_unexpected_version (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[FW_COMPONENT_V1_DATA_LEN];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, FW_COMPONENT_SHA384_BUILD_VERSION, NULL, 0, NULL, NULL);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_WRONG_VERSION, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_with_header (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct image_header header;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT, FW_COMPONENT_LENGTH, 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HASH_WITH_HEADER, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, sizeof (load_data),
		&header, &hash.base, &verification.base, NULL, hash_actual, sizeof (hash_actual), &type,
		&app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT, load_data, FW_COMPONENT_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (FW_COMPONENT_HASH_WITH_HEADER, hash_actual,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_with_header_no_hash_out (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct image_header header;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT, FW_COMPONENT_LENGTH, 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HASH_WITH_HEADER, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, sizeof (load_data),
		&header, &hash.base, &verification.base, NULL, NULL, 0, &type, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT, load_data, FW_COMPONENT_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_with_header_no_hash_type_out (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct image_header header;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT, FW_COMPONENT_LENGTH, 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HASH_WITH_HEADER, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, sizeof (load_data),
		&header, &hash.base, &verification.base, NULL, hash_actual, sizeof (hash_actual), NULL,
		&app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT, load_data, FW_COMPONENT_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (FW_COMPONENT_HASH_WITH_HEADER, hash_actual,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_with_header_no_length_out (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct image_header header;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT, FW_COMPONENT_LENGTH, 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HASH_WITH_HEADER, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, sizeof (load_data),
		&header, &hash.base, &verification.base, NULL, hash_actual, sizeof (hash_actual), &type,
		NULL);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);

	status = testing_validate_array (FW_COMPONENT, load_data, FW_COMPONENT_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (FW_COMPONENT_HASH_WITH_HEADER, hash_actual,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_with_header_header_format1 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct image_header header;
	int status;
	uint8_t load_data[FW_COMPONENT_V1_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_V1_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1, FW_COMPONENT_V1_LENGTH, 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_HASH_WITH_HEADER, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, sizeof (load_data),
		&header, &hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);
	CuAssertIntEquals (test, FW_COMPONENT_V1_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT_V1, load_data, FW_COMPONENT_V1_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (FW_COMPONENT_V1_HASH_WITH_HEADER, hash_actual,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_with_header_header_format1_no_expected_version (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct image_header header;
	int status;
	uint8_t load_data[FW_COMPONENT_V1_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_V1_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1, FW_COMPONENT_V1_LENGTH, 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_HASH_WITH_HEADER, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, sizeof (load_data),
		&header, &hash.base, &verification.base, NULL, hash_actual, sizeof (hash_actual), &type,
		&app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);
	CuAssertIntEquals (test, FW_COMPONENT_V1_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT_V1, load_data, FW_COMPONENT_V1_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (FW_COMPONENT_V1_HASH_WITH_HEADER, hash_actual,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_with_header_sha384 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct image_header header;
	int status;
	uint8_t load_data[FW_COMPONENT_SHA384_DATA_LEN];
	uint8_t hash_actual[SHA384_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA,
		FW_COMPONENT_SHA384_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA384_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_SHA384_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC384));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH_ECC384, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_SHA384_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_SHA384_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384, FW_COMPONENT_SHA384_LENGTH,
		2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA384_HASH_WITH_HEADER, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA384_SIGNATURE, FW_COMPONENT_SIG_LENGTH_ECC384),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC384));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, sizeof (load_data),
		&header, &hash.base, &verification.base, FW_COMPONENT_SHA384_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA384, type);
	CuAssertIntEquals (test, FW_COMPONENT_SHA384_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT_SHA384, load_data, FW_COMPONENT_SHA384_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (FW_COMPONENT_SHA384_HASH_WITH_HEADER, hash_actual,
		SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_with_header_sha384_no_hash_out (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct image_header header;
	int status;
	uint8_t load_data[FW_COMPONENT_SHA384_DATA_LEN];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA,
		FW_COMPONENT_SHA384_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA384_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_SHA384_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC384));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH_ECC384, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_SHA384_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_SHA384_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384, FW_COMPONENT_SHA384_LENGTH,
		2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA384_HASH_WITH_HEADER, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA384_SIGNATURE, FW_COMPONENT_SIG_LENGTH_ECC384),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC384));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, sizeof (load_data),
		&header, &hash.base, &verification.base, FW_COMPONENT_SHA384_BUILD_VERSION, NULL, 0, &type,
		&app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA384, type);
	CuAssertIntEquals (test, FW_COMPONENT_SHA384_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT_SHA384, load_data, FW_COMPONENT_SHA384_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_with_header_sha512 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct image_header header;
	int status;
	uint8_t load_data[FW_COMPONENT_SHA512_DATA_LEN];
	uint8_t hash_actual[SHA512_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA,
		FW_COMPONENT_SHA512_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA512_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_SHA512_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC521));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH_ECC521, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_SHA512_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_SHA512_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512, FW_COMPONENT_SHA512_LENGTH,
		2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA512_HASH_WITH_HEADER, SHA512_HASH_LENGTH),
		MOCK_ARG (SHA512_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA512_SIGNATURE, FW_COMPONENT_SIG_LENGTH_ECC521),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC521));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, sizeof (load_data),
		&header, &hash.base, &verification.base, FW_COMPONENT_SHA512_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA512, type);
	CuAssertIntEquals (test, FW_COMPONENT_SHA512_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT_SHA512, load_data, FW_COMPONENT_SHA512_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (FW_COMPONENT_SHA512_HASH_WITH_HEADER, hash_actual,
		SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_with_header_sha512_no_hash_out (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct image_header header;
	int status;
	uint8_t load_data[FW_COMPONENT_SHA512_DATA_LEN];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA,
		FW_COMPONENT_SHA512_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA512_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_SHA512_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC521));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH_ECC521, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_SHA512_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_SHA512_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512, FW_COMPONENT_SHA512_LENGTH,
		2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA512_HASH_WITH_HEADER, SHA512_HASH_LENGTH),
		MOCK_ARG (SHA512_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA512_SIGNATURE, FW_COMPONENT_SIG_LENGTH_ECC521),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC521));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, sizeof (load_data),
		&header, &hash.base, &verification.base, FW_COMPONENT_SHA512_BUILD_VERSION, NULL, 0, &type,
		&app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA512, type);
	CuAssertIntEquals (test, FW_COMPONENT_SHA512_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT_SHA512, load_data, FW_COMPONENT_SHA512_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_with_header_read_from_flash (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - IMAGE_HEADER_BASE_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_HEADER_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_HEADER_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_EXTRA_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_HEADER_DATA,
		FW_COMPONENT_HEADER_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_HEADER_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_HEADER_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_HEADER, FW_COMPONENT_HEADER_LENGTH,
		2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HEADER_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HEADER_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, sizeof (load_data),
		NULL, &hash.base, &verification.base, NULL, hash_actual, sizeof (hash_actual), &type,
		&app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);
	CuAssertIntEquals (test, FW_COMPONENT_HEADER_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT_HEADER, load_data, FW_COMPONENT_HEADER_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (FW_COMPONENT_HEADER_HASH, hash_actual, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_with_header_zero_length_read_from_flash (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT, FW_COMPONENT_LENGTH, 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, sizeof (load_data),
		NULL, &hash.base, &verification.base, NULL, hash_actual, sizeof (hash_actual), &type,
		&app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT, load_data, FW_COMPONENT_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (FW_COMPONENT_HASH, hash_actual, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_with_header_no_flash_header (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct image_header header;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT, FW_COMPONENT_LENGTH, 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HASH_WITH_HEADER, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, sizeof (load_data),
		&header, &hash.base, &verification.base, NULL, hash_actual, sizeof (hash_actual), &type,
		&app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT, load_data, FW_COMPONENT_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (FW_COMPONENT_HASH_WITH_HEADER, hash_actual,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_with_header_null (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct image_header header;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify_with_header (NULL, load_data, sizeof (load_data),
		&header, &hash.base, &verification.base, NULL, hash_actual, sizeof (hash_actual), &type,
		&app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_component_load_and_verify_with_header (&image, NULL, sizeof (load_data),
		&header, &hash.base, &verification.base, NULL, hash_actual, sizeof (hash_actual), &type,
		&app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, sizeof (load_data),
		&header, NULL, &verification.base, NULL, hash_actual, sizeof (hash_actual), &type,
		&app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, sizeof (load_data),
		&header, &hash.base, NULL, NULL, hash_actual, sizeof (hash_actual), &type,
		&app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_with_header_unknown_hash (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct image_header header;
	int status;
	uint8_t load_data[FW_COMPONENT_V1_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;
	uint8_t bad_header[FW_COMPONENT_V1_DATA_LEN];

	TEST_START;

	memcpy (bad_header, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN);
	bad_header[FW_COMPONENT_V1_HASH_TYPE_OFFSET] = 5;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, bad_header + IMAGE_HEADER_BASE_LEN,
		sizeof (bad_header) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, sizeof (load_data),
		&header, &hash.base, &verification.base, NULL, hash_actual, sizeof (hash_actual), &type,
		&app_len);
	CuAssertIntEquals (test, HASH_ENGINE_UNKNOWN_HASH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_with_header_small_hash_buffer (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct image_header header;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH - 1];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, sizeof (load_data),
		&header, &hash.base, &verification.base, NULL, hash_actual, sizeof (hash_actual), &type,
		&app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, sizeof (load_data),
		&header, &hash.base, &verification.base, NULL, hash_actual, 0, &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_with_header_small_hash_buffer_sha384 (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct image_header header;
	int status;
	uint8_t load_data[FW_COMPONENT_SHA384_DATA_LEN];
	uint8_t hash_actual[SHA384_HASH_LENGTH - 1];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA,
		FW_COMPONENT_SHA384_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA384_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, sizeof (load_data),
		&header, &hash.base, &verification.base, NULL, hash_actual, sizeof (hash_actual), &type,
		&app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, sizeof (load_data),
		&header, &hash.base, &verification.base, NULL, hash_actual, 0, &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_with_header_small_hash_buffer_sha512 (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct image_header header;
	int status;
	uint8_t load_data[FW_COMPONENT_SHA512_DATA_LEN];
	uint8_t hash_actual[SHA512_HASH_LENGTH - 1];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA,
		FW_COMPONENT_SHA512_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA512_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, sizeof (load_data),
		&header, &hash.base, &verification.base, NULL, hash_actual, sizeof (hash_actual), &type,
		&app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, sizeof (load_data),
		&header, &hash.base, &verification.base, NULL, hash_actual, 0, &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_with_header_read_signature_error (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct image_header header;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (base_addr + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, sizeof (load_data),
		&header, &hash.base, &verification.base, NULL, hash_actual, sizeof (hash_actual), &type,
		&app_len);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_with_header_verify_error (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct image_header header;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT, FW_COMPONENT_LENGTH, 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		SIG_VERIFICATION_VERIFY_SIG_FAILED,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HASH_WITH_HEADER, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, sizeof (load_data),
		&header, &hash.base, &verification.base, NULL, hash_actual, sizeof (hash_actual), &type,
		&app_len);
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);

	status = testing_validate_array (FW_COMPONENT_HASH_WITH_HEADER, hash_actual,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_with_header_hash_start_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct image_header header;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash,
		HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, sizeof (load_data),
		&header, &hash.base, &verification.base, NULL, hash_actual, sizeof (hash_actual), &type,
		&app_len);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);
}

static void firmware_component_test_load_and_verify_with_header_hash_memory_header_error (
	CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct image_header header;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (IMAGE_HEADER_TEST, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, sizeof (load_data),
		&header, &hash.base, &verification.base, NULL, hash_actual, sizeof (hash_actual), &type,
		&app_len);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);
}

static void firmware_component_test_load_and_verify_with_header_hash_header_info_error (
	CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct image_header header;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (IMAGE_HEADER_TEST, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&IMAGE_HEADER_TEST[IMAGE_HEADER_BASE_LEN],
			IMAGE_HEADER_TEST_DATA_LENGTH),
		MOCK_ARG (IMAGE_HEADER_TEST_DATA_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, sizeof (load_data),
		&header, &hash.base, &verification.base, NULL, hash_actual, sizeof (hash_actual), &type,
		&app_len);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);
}

static void firmware_component_test_load_and_verify_with_header_hash_header_data_error (
	CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct image_header header;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (IMAGE_HEADER_TEST, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&IMAGE_HEADER_TEST[IMAGE_HEADER_BASE_LEN],
			IMAGE_HEADER_TEST_DATA_LENGTH),
		MOCK_ARG (IMAGE_HEADER_TEST_DATA_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN, FW_COMPONENT_HDR_LENGTH),
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, sizeof (load_data),
		&header, &hash.base, &verification.base, NULL, hash_actual, sizeof (hash_actual), &type,
		&app_len);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);
}

static void firmware_component_test_load_and_verify_with_header_image_too_large (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct image_header header;
	int status;
	uint8_t load_data[FW_COMPONENT_LENGTH - 1];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (IMAGE_HEADER_TEST, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&IMAGE_HEADER_TEST[IMAGE_HEADER_BASE_LEN],
			IMAGE_HEADER_TEST_DATA_LENGTH),
		MOCK_ARG (IMAGE_HEADER_TEST_DATA_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN, FW_COMPONENT_HDR_LENGTH),
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, sizeof (load_data),
		&header, &hash.base, &verification.base, NULL, hash_actual, sizeof (hash_actual), &type,
		&app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_TOO_LARGE, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (IMAGE_HEADER_TEST, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&IMAGE_HEADER_TEST[IMAGE_HEADER_BASE_LEN],
			IMAGE_HEADER_TEST_DATA_LENGTH),
		MOCK_ARG (IMAGE_HEADER_TEST_DATA_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN, FW_COMPONENT_HDR_LENGTH),
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, 0, &header,
		&hash.base, &verification.base, NULL, hash_actual, sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_TOO_LARGE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);
}

static void firmware_component_test_load_and_verify_with_header_image_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct image_header header;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (IMAGE_HEADER_TEST, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&IMAGE_HEADER_TEST[IMAGE_HEADER_BASE_LEN],
			IMAGE_HEADER_TEST_DATA_LENGTH),
		MOCK_ARG (IMAGE_HEADER_TEST_DATA_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN, FW_COMPONENT_HDR_LENGTH),
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (base_addr + FW_COMPONENT_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, sizeof (load_data),
		&header, &hash.base, &verification.base, NULL, hash_actual, sizeof (hash_actual), &type,
		&app_len);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);
}

static void firmware_component_test_load_and_verify_with_header_hash_image_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct image_header header;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (IMAGE_HEADER_TEST, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&IMAGE_HEADER_TEST[IMAGE_HEADER_BASE_LEN],
			IMAGE_HEADER_TEST_DATA_LENGTH),
		MOCK_ARG (IMAGE_HEADER_TEST_DATA_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN, FW_COMPONENT_HDR_LENGTH),
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT, FW_COMPONENT_LENGTH, 2);

	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT, FW_COMPONENT_LENGTH), MOCK_ARG (FW_COMPONENT_LENGTH));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, sizeof (load_data),
		&header, &hash.base, &verification.base, NULL, hash_actual, sizeof (hash_actual), &type,
		&app_len);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);
}

static void firmware_component_test_load_and_verify_with_header_hash_finish_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct image_header header;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (IMAGE_HEADER_TEST, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&IMAGE_HEADER_TEST[IMAGE_HEADER_BASE_LEN],
			IMAGE_HEADER_TEST_DATA_LENGTH),
		MOCK_ARG (IMAGE_HEADER_TEST_DATA_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN, FW_COMPONENT_HDR_LENGTH),
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_OFFSET), MOCK_ARG_PTR (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT, FW_COMPONENT_LENGTH, 2);

	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT, FW_COMPONENT_LENGTH), MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, HASH_ENGINE_FINISH_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, sizeof (load_data),
		&header, &hash.base, &verification.base, NULL, hash_actual, sizeof (hash_actual), &type,
		&app_len);
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);
}

static void firmware_component_test_load_and_verify_with_header_extra_header_read_error (
	CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - IMAGE_HEADER_BASE_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_HEADER_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_HEADER_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_EXTRA_HDR_LENGTH));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, sizeof (load_data),
		NULL, &hash.base, &verification.base, NULL, hash_actual, sizeof (hash_actual), &type,
		&app_len);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_and_verify_with_header_extra_header_hash_error (
	CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - IMAGE_HEADER_BASE_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_HEADER_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_HEADER_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_EXTRA_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_HEADER_DATA,
		FW_COMPONENT_HEADER_DATA_LEN, 2);

	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HEADER_DATA, FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG (FW_COMPONENT_EXTRA_HDR_LENGTH));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, sizeof (load_data),
		NULL, &hash.base, &verification.base, NULL, hash_actual, sizeof (hash_actual), &type,
		&app_len);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_and_verify_with_header_header_format0_with_expected_version (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct image_header header;
	int status;
	uint8_t load_data[FW_COMPONENT_DATA_LEN];
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, sizeof (load_data),
		&header, &hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, NULL, 0, NULL,
		NULL);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_WRONG_VERSION, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_with_header_header_format1_with_unexpected_version (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct image_header header;
	int status;
	uint8_t load_data[FW_COMPONENT_V1_DATA_LEN];
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify_with_header (&image, load_data, sizeof (load_data),
		&header, &hash.base, &verification.base, FW_COMPONENT_SHA384_BUILD_VERSION, NULL, 0, NULL,
		NULL);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_WRONG_VERSION, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_copy (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash (&flash, 0x40000, 0x10000);
	status |= flash_mock_expect_copy_flash_verify (&flash, &flash, 0x40000,
		0x10000 + FW_COMPONENT_OFFSET, FW_COMPONENT, FW_COMPONENT_LENGTH);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_copy (&image, &flash.base, 0x40000, 0x10000, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, app_len);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_copy_no_length_out (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash (&flash, 0x40000, 0x10000);
	status |= flash_mock_expect_copy_flash_verify (&flash, &flash, 0x40000,
		0x10000 + FW_COMPONENT_OFFSET, FW_COMPONENT, FW_COMPONENT_LENGTH);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_copy (&image, &flash.base, 0x40000, 0x10000, NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_copy_header_format1 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash (&flash, 0x40000, 0x10000);
	status |= flash_mock_expect_copy_flash_verify (&flash, &flash, 0x40000,
		0x10000 + FW_COMPONENT_V1_OFFSET, FW_COMPONENT_V1, FW_COMPONENT_V1_LENGTH);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_copy (&image, &flash.base, 0x40000, 0x10000, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_V1_LENGTH, app_len);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_copy_with_header (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - IMAGE_HEADER_BASE_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash (&flash, 0x40000, 0x10000);
	status |= flash_mock_expect_copy_flash_verify (&flash, &flash, 0x40000,
		0x10000 + FW_COMPONENT_HEADER_OFFSET, FW_COMPONENT_HEADER, FW_COMPONENT_HEADER_LENGTH);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_copy (&image, &flash.base, 0x40000, 0x10000, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, app_len);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_copy_with_header_zero_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash (&flash, 0x40000, 0x10000);
	status |= flash_mock_expect_copy_flash_verify (&flash, &flash, 0x40000,
		0x10000 + FW_COMPONENT_OFFSET, FW_COMPONENT, FW_COMPONENT_LENGTH);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_copy (&image, &flash.base, 0x40000, 0x10000, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, app_len);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_copy_null (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_copy (NULL, &flash.base, 0x40000, 0x10000, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_component_copy (&image, NULL, 0x40000, 0x10000, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_copy_image_too_large (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_copy (&image, &flash.base, 0x40000, FW_COMPONENT_LENGTH - 1,
		&app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_TOO_LARGE, status);

	status = firmware_component_copy (&image, &flash.base, 0x40000, 0, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_TOO_LARGE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_copy_erase_error (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, FLASH_BLOCK_SIZE_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_copy (&image, &flash.base, 0x40000, 0x10000, &app_len);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_copy_copy_error (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash (&flash, 0x40000, 0x10000);
	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, FLASH_BLOCK_SIZE_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_copy (&image, &flash.base, 0x40000, 0x10000, &app_len);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_compare_and_copy (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_verify_copy (&flash, 0x10000 + FW_COMPONENT_OFFSET, FW_COMPONENT,
		&flash, 0x40000, FW_COMPONENT_DATA, FLASH_VERIFICATION_BLOCK);
	status |= flash_mock_expect_erase_flash (&flash, 0x40000, 0x10000);
	status |= flash_mock_expect_copy_flash_verify (&flash, &flash, 0x40000,
		0x10000 + FW_COMPONENT_OFFSET, FW_COMPONENT, FW_COMPONENT_LENGTH);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_compare_and_copy (&image, &flash.base, 0x40000, 0x10000, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, app_len);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_compare_and_copy_destination_matches (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_verify_copy (&flash, 0x10000 + FW_COMPONENT_OFFSET, FW_COMPONENT,
		&flash, 0x40000, FW_COMPONENT, FW_COMPONENT_LENGTH);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_compare_and_copy (&image, &flash.base, 0x40000, 0x10000, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, app_len);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_compare_and_copy_no_length_out (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_verify_copy (&flash, 0x10000 + FW_COMPONENT_OFFSET, FW_COMPONENT,
		&flash, 0x40000, FW_COMPONENT_DATA, FLASH_VERIFICATION_BLOCK);
	status |= flash_mock_expect_erase_flash (&flash, 0x40000, 0x10000);
	status |= flash_mock_expect_copy_flash_verify (&flash, &flash, 0x40000,
		0x10000 + FW_COMPONENT_OFFSET, FW_COMPONENT, FW_COMPONENT_LENGTH);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_compare_and_copy (&image, &flash.base, 0x40000, 0x10000, NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_compare_and_copy_header_format1 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_verify_copy (&flash, 0x10000 + FW_COMPONENT_V1_OFFSET,
		FW_COMPONENT_V1, &flash, 0x40000, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_LENGTH);
	status |= flash_mock_expect_erase_flash (&flash, 0x40000, 0x10000);
	status |= flash_mock_expect_copy_flash_verify (&flash, &flash, 0x40000,
		0x10000 + FW_COMPONENT_V1_OFFSET, FW_COMPONENT_V1, FW_COMPONENT_V1_LENGTH);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_compare_and_copy (&image, &flash.base, 0x40000, 0x10000, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_V1_LENGTH, app_len);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_compare_and_copy_with_header (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - IMAGE_HEADER_BASE_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_verify_copy (&flash, 0x10000 + FW_COMPONENT_HEADER_OFFSET,
		FW_COMPONENT, &flash, 0x40000, FW_COMPONENT_DATA, FLASH_VERIFICATION_BLOCK);
	status |= flash_mock_expect_erase_flash (&flash, 0x40000, 0x10000);
	status |= flash_mock_expect_copy_flash_verify (&flash, &flash, 0x40000,
		0x10000 + FW_COMPONENT_HEADER_OFFSET, FW_COMPONENT, FW_COMPONENT_LENGTH);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_compare_and_copy (&image, &flash.base, 0x40000, 0x10000, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, app_len);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_compare_and_copy_with_header_destination_matches (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - IMAGE_HEADER_BASE_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_verify_copy (&flash, 0x10000 + FW_COMPONENT_HEADER_OFFSET,
		FW_COMPONENT, &flash, 0x40000, FW_COMPONENT, FW_COMPONENT_LENGTH);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_compare_and_copy (&image, &flash.base, 0x40000, 0x10000, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, app_len);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_compare_and_copy_with_header_zero_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_verify_copy (&flash, 0x10000 + FW_COMPONENT_OFFSET, FW_COMPONENT,
		&flash, 0x40000, FW_COMPONENT_DATA, FLASH_VERIFICATION_BLOCK);
	status |= flash_mock_expect_erase_flash (&flash, 0x40000, 0x10000);
	status |= flash_mock_expect_copy_flash_verify (&flash, &flash, 0x40000,
		0x10000 + FW_COMPONENT_OFFSET, FW_COMPONENT, FW_COMPONENT_LENGTH);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_compare_and_copy (&image, &flash.base, 0x40000, 0x10000, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, app_len);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_compare_and_copy_null (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_compare_and_copy (NULL, &flash.base, 0x40000, 0x10000, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_component_compare_and_copy (&image, NULL, 0x40000, 0x10000, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_compare_and_copy_image_too_large (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_compare_and_copy (&image, &flash.base, 0x40000,
		FW_COMPONENT_LENGTH - 1, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_TOO_LARGE, status);

	status = firmware_component_compare_and_copy (&image, &flash.base, 0x40000, 0, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_TOO_LARGE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_compare_and_copy_compare_error (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000 + FW_COMPONENT_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FLASH_VERIFICATION_BLOCK));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_compare_and_copy (&image, &flash.base, 0x40000, 0x10000, &app_len);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_compare_and_copy_erase_error (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_verify_copy (&flash, 0x10000 + FW_COMPONENT_OFFSET, FW_COMPONENT,
		&flash, 0x40000, FW_COMPONENT_DATA, FLASH_VERIFICATION_BLOCK);
	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, FLASH_BLOCK_SIZE_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_compare_and_copy (&image, &flash.base, 0x40000, 0x10000, &app_len);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_compare_and_copy_copy_error (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_verify_copy (&flash, 0x10000 + FW_COMPONENT_OFFSET, FW_COMPONENT,
		&flash, 0x40000, FW_COMPONENT_DATA, FLASH_VERIFICATION_BLOCK);
	status |= flash_mock_expect_erase_flash (&flash, 0x40000, 0x10000);
	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, FLASH_BLOCK_SIZE_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_compare_and_copy (&image, &flash.base, 0x40000, 0x10000, &app_len);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_load_address_header_format0 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint64_t addr;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	addr = firmware_component_get_load_address (&image);
	CuAssertIntEquals (test, 0, addr);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_load_address_header_format1 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint64_t addr;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	addr = firmware_component_get_load_address (&image);
	CuAssertIntEquals (test, FW_COMPONENT_V1_LOAD_ADDRESS, addr);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_load_address_with_header (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint64_t addr;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA,
		FW_COMPONENT_SHA384_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA384_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	addr = firmware_component_get_load_address (&image);
	CuAssertIntEquals (test, FW_COMPONENT_SHA384_LOAD_ADDRESS, addr);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_load_address_with_header_zero_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint64_t addr;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA,
		FW_COMPONENT_SHA512_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA512_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	addr = firmware_component_get_load_address (&image);
	CuAssertTrue (test, (FW_COMPONENT_SHA512_LOAD_ADDRESS == addr));

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_load_address_null (CuTest *test)
{
	uint64_t addr;

	TEST_START;

	addr = firmware_component_get_load_address (NULL);
	CuAssertIntEquals (test, 0, addr);
}

static void firmware_component_test_get_build_version_header_format0 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	const uint8_t *version;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	version = firmware_component_get_build_version (&image);
	CuAssertPtrEquals (test, NULL, (void*) version);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_build_version_header_format1 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	const uint8_t *version;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	version = firmware_component_get_build_version (&image);
	CuAssertPtrNotNull (test, version);

	status = testing_validate_array (FW_COMPONENT_V1_BUILD_VERSION, version, 8);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_build_version_with_header (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	const uint8_t *version;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA,
		FW_COMPONENT_SHA384_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA384_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	version = firmware_component_get_build_version (&image);
	CuAssertPtrNotNull (test, version);

	status = testing_validate_array (FW_COMPONENT_SHA384_BUILD_VERSION, version, 8);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_build_version_with_header_zero_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	const uint8_t *version;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA,
		FW_COMPONENT_SHA512_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA512_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	version = firmware_component_get_build_version (&image);
	CuAssertPtrNotNull (test, version);

	status = testing_validate_array (FW_COMPONENT_SHA512_BUILD_VERSION, version, 8);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_build_version_null (CuTest *test)
{
	const uint8_t *version;

	TEST_START;

	version = firmware_component_get_build_version (NULL);
	CuAssertPtrEquals (test, NULL, (void*) version);
}

static void firmware_component_test_load_to_memory_header_format0 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	struct firmware_loader_mock loader;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory (&image, &loader.base, NULL, 0, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_NO_LOAD_ADDRESS, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_to_memory_header_format1 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	struct firmware_loader_mock loader;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_V1_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_V1_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image, &loader, 0, MOCK_ARG_PTR (&flash),
		MOCK_ARG (0x10000 + FW_COMPONENT_V1_OFFSET), MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0), MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory (&image, &loader.base, NULL, 0, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_V1_LENGTH, app_len);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_to_memory_no_length_out (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	struct firmware_loader_mock loader;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_V1_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_V1_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image, &loader, 0, MOCK_ARG_PTR (&flash),
		MOCK_ARG (0x10000 + FW_COMPONENT_V1_OFFSET), MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0), MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory (&image, &loader.base, NULL, 0, NULL);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_to_memory_encrypted_image (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	struct firmware_loader_mock loader;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_V1_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_V1_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image, &loader, 0, MOCK_ARG_PTR (&flash),
		MOCK_ARG (0x10000 + FW_COMPONENT_V1_OFFSET), MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR),
		MOCK_ARG_PTR_CONTAINS (AES_CBC_TESTING_SINGLE_BLOCK_IV, AES_CBC_TESTING_IV_LEN),
		MOCK_ARG (AES_CBC_TESTING_IV_LEN), MOCK_ARG_PTR (NULL), MOCK_ARG (0), MOCK_ARG_PTR (NULL),
		MOCK_ARG (0));

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory (&image, &loader.base,
		AES_CBC_TESTING_SINGLE_BLOCK_IV, AES_CBC_TESTING_IV_LEN, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_V1_LENGTH, app_len);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_to_memory_with_header (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	struct firmware_loader_mock loader;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA,
		FW_COMPONENT_SHA384_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA384_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_SHA384_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_SHA384_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_SHA384_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_SHA384_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image, &loader, 0, MOCK_ARG_PTR (&flash),
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH + FW_COMPONENT_SHA384_OFFSET),
		MOCK_ARG (FW_COMPONENT_SHA384_LENGTH), MOCK_ARG_PTR (FW_COMPONENT_SHA384_LOAD_ADDRESS_PTR),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0), MOCK_ARG_PTR (NULL), MOCK_ARG (0), MOCK_ARG_PTR (NULL),
		MOCK_ARG (0));

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_SHA384_LOAD_ADDRESS_PTR));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory (&image, &loader.base, NULL, 0, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_SHA384_LENGTH, app_len);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_to_memory_with_header_zero_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	struct firmware_loader_mock loader;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA,
		FW_COMPONENT_SHA512_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA512_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_SHA512_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_SHA512_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_SHA512_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_SHA512_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image, &loader, 0, MOCK_ARG_PTR (&flash),
		MOCK_ARG (0x10000 + FW_COMPONENT_SHA512_OFFSET), MOCK_ARG (FW_COMPONENT_SHA512_LENGTH),
		MOCK_ARG_PTR (FW_COMPONENT_SHA512_LOAD_ADDRESS_PTR), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0), MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_SHA512_LOAD_ADDRESS_PTR));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory (&image, &loader.base, NULL, 0, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_SHA512_LENGTH, app_len);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_to_memory_null (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	struct firmware_loader_mock loader;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory (NULL, &loader.base, NULL, 0, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_component_load_to_memory (&image, NULL, NULL, 0, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_to_memory_map_error (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	struct firmware_loader_mock loader;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&loader.mock, loader.base.map_address, &loader,
		FIRMWARE_LOADER_MAP_ADDR_FAILED, MOCK_ARG (FW_COMPONENT_V1_LOAD_ADDRESS),
		MOCK_ARG (FW_COMPONENT_V1_LENGTH), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory (&image, &loader.base, NULL, 0, &app_len);
	CuAssertIntEquals (test, FIRMWARE_LOADER_MAP_ADDR_FAILED, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_to_memory_load_error (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	struct firmware_loader_mock loader;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_V1_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_V1_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image, &loader,
		FIRMWARE_LOADER_LOAD_IMG_FAILED, MOCK_ARG_PTR (&flash),
		MOCK_ARG (0x10000 + FW_COMPONENT_V1_OFFSET), MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0), MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory (&image, &loader.base, NULL, 0, &app_len);
	CuAssertIntEquals (test, FIRMWARE_LOADER_LOAD_IMG_FAILED, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_to_memory_and_verify_header_format0 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify (&image, &loader.base, NULL, 0,
		&hash.base, &verification.base, NULL, hash_actual, sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_NO_LOAD_ADDRESS, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_header_format1 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_V1_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_V1_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image_update_digest, &loader, 0,
		MOCK_ARG_PTR (&flash), MOCK_ARG (0x10000 + FW_COMPONENT_V1_OFFSET),
		MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR (&hash.base));
	status |= mock_expect_external_action (&loader.mock,
		firmware_component_testing_mock_action_update_digest, (void*) FW_COMPONENT_V1);

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR));

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify (&image, &loader.base, NULL, 0,
		&hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);
	CuAssertIntEquals (test, FW_COMPONENT_V1_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT_V1_HASH, hash_actual, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_no_hash_out (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	int status;
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_V1_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_V1_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image_update_digest, &loader, 0,
		MOCK_ARG_PTR (&flash), MOCK_ARG (0x10000 + FW_COMPONENT_V1_OFFSET),
		MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR (&hash.base));
	status |= mock_expect_external_action (&loader.mock,
		firmware_component_testing_mock_action_update_digest, (void*) FW_COMPONENT_V1);

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR));

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify (&image, &loader.base, NULL, 0,
		&hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, NULL, 0, &type, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);
	CuAssertIntEquals (test, FW_COMPONENT_V1_LENGTH, app_len);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_no_hash_type_out (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_V1_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_V1_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image_update_digest, &loader, 0,
		MOCK_ARG_PTR (&flash), MOCK_ARG (0x10000 + FW_COMPONENT_V1_OFFSET),
		MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR (&hash.base));
	status |= mock_expect_external_action (&loader.mock,
		firmware_component_testing_mock_action_update_digest, (void*) FW_COMPONENT_V1);

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR));

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify (&image, &loader.base, NULL, 0,
		&hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), NULL, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_V1_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT_V1_HASH, hash_actual, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_no_length_out (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_V1_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_V1_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image_update_digest, &loader, 0,
		MOCK_ARG_PTR (&flash), MOCK_ARG (0x10000 + FW_COMPONENT_V1_OFFSET),
		MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR (&hash.base));
	status |= mock_expect_external_action (&loader.mock,
		firmware_component_testing_mock_action_update_digest, (void*) FW_COMPONENT_V1);

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR));

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify (&image, &loader.base, NULL, 0,
		&hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, NULL);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);

	status = testing_validate_array (FW_COMPONENT_V1_HASH, hash_actual, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_no_expected_version (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_V1_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_V1_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image_update_digest, &loader, 0,
		MOCK_ARG_PTR (&flash), MOCK_ARG (0x10000 + FW_COMPONENT_V1_OFFSET),
		MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR (&hash.base));
	status |= mock_expect_external_action (&loader.mock,
		firmware_component_testing_mock_action_update_digest, (void*) FW_COMPONENT_V1);

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR));

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify (&image, &loader.base, NULL, 0,
		&hash.base, &verification.base, NULL, hash_actual, sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);
	CuAssertIntEquals (test, FW_COMPONENT_V1_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT_V1_HASH, hash_actual, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_encrypted_image (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_V1_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_V1_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image_update_digest, &loader, 0,
		MOCK_ARG_PTR (&flash), MOCK_ARG (0x10000 + FW_COMPONENT_V1_OFFSET),
		MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR),
		MOCK_ARG_PTR_CONTAINS (AES_CBC_TESTING_MULTI_BLOCK_IV, AES_CBC_TESTING_IV_LEN),
		MOCK_ARG (AES_CBC_TESTING_IV_LEN), MOCK_ARG_PTR (&hash.base));
	status |= mock_expect_external_action (&loader.mock,
		firmware_component_testing_mock_action_update_digest, (void*) FW_COMPONENT_V1);

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR));

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify (&image, &loader.base,
		AES_CBC_TESTING_MULTI_BLOCK_IV, AES_CBC_TESTING_IV_LEN, &hash.base, &verification.base,
		FW_COMPONENT_V1_BUILD_VERSION, hash_actual, sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);
	CuAssertIntEquals (test, FW_COMPONENT_V1_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT_V1_HASH, hash_actual, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_sha384 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	int status;
	uint8_t hash_actual[SHA384_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA,
		FW_COMPONENT_SHA384_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA384_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SHA384_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC384));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH_ECC384, 2);

	status |= mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_SHA384_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_SHA384_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_SHA384_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_SHA384_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image_update_digest, &loader, 0,
		MOCK_ARG_PTR (&flash), MOCK_ARG (0x10000 + FW_COMPONENT_SHA384_OFFSET),
		MOCK_ARG (FW_COMPONENT_SHA384_LENGTH),
		MOCK_ARG_PTR (FW_COMPONENT_SHA384_LOAD_ADDRESS_PTR), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR (&hash.base));
	status |= mock_expect_external_action (&loader.mock,
		firmware_component_testing_mock_action_update_digest, (void*) FW_COMPONENT_SHA384);

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_SHA384_LOAD_ADDRESS_PTR));

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA384_HASH, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA384_SIGNATURE, FW_COMPONENT_SIG_LENGTH_ECC384),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC384));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify (&image, &loader.base, NULL, 0,
		&hash.base, &verification.base, FW_COMPONENT_SHA384_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA384, type);
	CuAssertIntEquals (test, FW_COMPONENT_SHA384_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT_SHA384_HASH, hash_actual, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_sha384_no_hash_out (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	int status;
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA,
		FW_COMPONENT_SHA384_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA384_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SHA384_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC384));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH_ECC384, 2);

	status |= mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_SHA384_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_SHA384_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_SHA384_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_SHA384_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image_update_digest, &loader, 0,
		MOCK_ARG_PTR (&flash), MOCK_ARG (0x10000 + FW_COMPONENT_SHA384_OFFSET),
		MOCK_ARG (FW_COMPONENT_SHA384_LENGTH),
		MOCK_ARG_PTR (FW_COMPONENT_SHA384_LOAD_ADDRESS_PTR), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR (&hash.base));
	status |= mock_expect_external_action (&loader.mock,
		firmware_component_testing_mock_action_update_digest, (void*) FW_COMPONENT_SHA384);

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_SHA384_LOAD_ADDRESS_PTR));

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA384_HASH, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA384_SIGNATURE, FW_COMPONENT_SIG_LENGTH_ECC384),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC384));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify (&image, &loader.base, NULL, 0,
		&hash.base, &verification.base, FW_COMPONENT_SHA384_BUILD_VERSION, NULL, 0, &type,
		&app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA384, type);
	CuAssertIntEquals (test, FW_COMPONENT_SHA384_LENGTH, app_len);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_sha512 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	int status;
	uint8_t hash_actual[SHA512_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA,
		FW_COMPONENT_SHA512_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA512_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SHA512_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC521));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH_ECC521, 2);

	status |= mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_SHA512_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_SHA512_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_SHA512_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_SHA512_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image_update_digest, &loader, 0,
		MOCK_ARG_PTR (&flash), MOCK_ARG (0x10000 + FW_COMPONENT_SHA512_OFFSET),
		MOCK_ARG (FW_COMPONENT_SHA512_LENGTH),
		MOCK_ARG_PTR (FW_COMPONENT_SHA512_LOAD_ADDRESS_PTR), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR (&hash.base));
	status |= mock_expect_external_action (&loader.mock,
		firmware_component_testing_mock_action_update_digest, (void*) FW_COMPONENT_SHA512);

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_SHA512_LOAD_ADDRESS_PTR));

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA512_HASH, SHA512_HASH_LENGTH),
		MOCK_ARG (SHA512_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA512_SIGNATURE, FW_COMPONENT_SIG_LENGTH_ECC521),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC521));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify (&image, &loader.base, NULL, 0,
		&hash.base, &verification.base, FW_COMPONENT_SHA512_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA512, type);
	CuAssertIntEquals (test, FW_COMPONENT_SHA512_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT_SHA512_HASH, hash_actual, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_sha512_no_hash_out (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	int status;
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA,
		FW_COMPONENT_SHA512_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA512_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SHA512_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC521));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH_ECC521, 2);

	status |= mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_SHA512_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_SHA512_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_SHA512_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_SHA512_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image_update_digest, &loader, 0,
		MOCK_ARG_PTR (&flash), MOCK_ARG (0x10000 + FW_COMPONENT_SHA512_OFFSET),
		MOCK_ARG (FW_COMPONENT_SHA512_LENGTH),
		MOCK_ARG_PTR (FW_COMPONENT_SHA512_LOAD_ADDRESS_PTR), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR (&hash.base));
	status |= mock_expect_external_action (&loader.mock,
		firmware_component_testing_mock_action_update_digest, (void*) FW_COMPONENT_SHA512);

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_SHA512_LOAD_ADDRESS_PTR));

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA512_HASH, SHA512_HASH_LENGTH),
		MOCK_ARG (SHA512_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA512_SIGNATURE, FW_COMPONENT_SIG_LENGTH_ECC521),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC521));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify (&image, &loader.base, NULL, 0,
		&hash.base, &verification.base, FW_COMPONENT_SHA512_BUILD_VERSION, NULL, 0, &type,
		&app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA512, type);
	CuAssertIntEquals (test, FW_COMPONENT_SHA512_LENGTH, app_len);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_extra_header (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	int status;
	uint8_t hash_actual[SHA384_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_TEST_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA,
		FW_COMPONENT_SHA384_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + IMAGE_HEADER_TEST_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA384_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_TEST_LEN + FW_COMPONENT_SHA384_SIG_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC384));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH_ECC384, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_TEST_LEN));
	status |= mock_expect_output (&flash.mock, 1, IMAGE_HEADER_TEST, IMAGE_HEADER_TEST_LEN, 2);

	status |= mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_SHA384_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_SHA384_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_SHA384_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_SHA384_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image_update_digest, &loader, 0,
		MOCK_ARG_PTR (&flash),
		MOCK_ARG (0x10000 + IMAGE_HEADER_TEST_LEN + FW_COMPONENT_SHA384_OFFSET),
		MOCK_ARG (FW_COMPONENT_SHA384_LENGTH),
		MOCK_ARG_PTR (FW_COMPONENT_SHA384_LOAD_ADDRESS_PTR), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR (&hash.base));
	status |= mock_expect_external_action (&loader.mock,
		firmware_component_testing_mock_action_update_digest, (void*) FW_COMPONENT_SHA384);

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_SHA384_LOAD_ADDRESS_PTR));

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA384_HASH_WITH_HEADER, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA384_SIGNATURE, FW_COMPONENT_SIG_LENGTH_ECC384),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC384));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify (&image, &loader.base, NULL, 0,
		&hash.base, &verification.base, FW_COMPONENT_SHA384_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA384, type);
	CuAssertIntEquals (test, FW_COMPONENT_SHA384_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT_SHA384_HASH_WITH_HEADER, hash_actual,
		SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_extra_header_zero_length (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	int status;
	uint8_t hash_actual[SHA512_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA,
		FW_COMPONENT_SHA512_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA512_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, 0);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SHA512_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC521));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH_ECC521, 2);

	status |= mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_SHA512_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_SHA512_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_SHA512_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_SHA512_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image_update_digest, &loader, 0,
		MOCK_ARG_PTR (&flash), MOCK_ARG (0x10000 + FW_COMPONENT_SHA512_OFFSET),
		MOCK_ARG (FW_COMPONENT_SHA512_LENGTH),
		MOCK_ARG_PTR (FW_COMPONENT_SHA512_LOAD_ADDRESS_PTR), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR (&hash.base));
	status |= mock_expect_external_action (&loader.mock,
		firmware_component_testing_mock_action_update_digest, (void*) FW_COMPONENT_SHA512);

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_SHA512_LOAD_ADDRESS_PTR));

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA512_HASH, SHA512_HASH_LENGTH),
		MOCK_ARG (SHA512_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA512_SIGNATURE, FW_COMPONENT_SIG_LENGTH_ECC521),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC521));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify (&image, &loader.base, NULL, 0,
		&hash.base, &verification.base, FW_COMPONENT_SHA512_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA512, type);
	CuAssertIntEquals (test, FW_COMPONENT_SHA512_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT_SHA512_HASH, hash_actual, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_null (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify (NULL, &loader.base, NULL, 0,
		&hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_component_load_to_memory_and_verify (&image, NULL, NULL, 0,
		&hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_component_load_to_memory_and_verify (&image, &loader.base, NULL, 0,
		NULL, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_component_load_to_memory_and_verify (&image, &loader.base, NULL, 0,
		&hash.base, NULL, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_with_unexpected_version (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify (&image, &loader.base, NULL, 0,
		&hash.base, &verification.base, FW_COMPONENT_SHA384_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_WRONG_VERSION, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_unknown_hash (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint8_t bad_header[FW_COMPONENT_V1_DATA_LEN];

	TEST_START;

	memcpy (bad_header, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN);
	bad_header[FW_COMPONENT_V1_HASH_TYPE_OFFSET] = 5;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, bad_header + IMAGE_HEADER_BASE_LEN,
		sizeof (bad_header) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify (&image, &loader.base, NULL, 0,
		&hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, HASH_ENGINE_UNKNOWN_HASH, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_small_hash_buffer (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH - 1];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify (&image, &loader.base, NULL, 0,
		&hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL, status);

	status = firmware_component_load_to_memory_and_verify (&image, &loader.base, NULL, 0,
		&hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual, 0, &type,
		&app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_small_hash_buffer_sha384 (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	int status;
	uint8_t hash_actual[SHA384_HASH_LENGTH - 1];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA,
		FW_COMPONENT_SHA384_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA384_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify (&image, &loader.base, NULL, 0,
		&hash.base, &verification.base, FW_COMPONENT_SHA384_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL, status);

	status = firmware_component_load_to_memory_and_verify (&image, &loader.base, NULL, 0,
		&hash.base, &verification.base, FW_COMPONENT_SHA384_BUILD_VERSION, hash_actual, 0, &type,
		&app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_small_hash_buffer_sha512 (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	int status;
	uint8_t hash_actual[SHA512_HASH_LENGTH - 1];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA,
		FW_COMPONENT_SHA512_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA512_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify (&image, &loader.base, NULL, 0,
		&hash.base, &verification.base, FW_COMPONENT_SHA512_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL, status);

	status = firmware_component_load_to_memory_and_verify (&image, &loader.base, NULL, 0,
		&hash.base, &verification.base, FW_COMPONENT_SHA512_BUILD_VERSION, hash_actual, 0, &type,
		&app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_read_signature_error (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000 + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify (&image, &loader.base, NULL, 0,
		&hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_verify_error (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_V1_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_V1_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image_update_digest, &loader, 0,
		MOCK_ARG_PTR (&flash), MOCK_ARG (0x10000 + FW_COMPONENT_V1_OFFSET),
		MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR (&hash.base));
	status |= mock_expect_external_action (&loader.mock,
		firmware_component_testing_mock_action_update_digest, (void*) FW_COMPONENT_V1);

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR));

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		SIG_VERIFICATION_VERIFY_SIG_FAILED,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify (&image, &loader.base, NULL, 0,
		&hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);

	status = testing_validate_array (FW_COMPONENT_V1_HASH, hash_actual, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_hash_start_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash,
		HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify (&image, &loader.base, NULL, 0,
		&hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_to_memory_and_verify_hash_header_info_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_DATA, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify (&image, &loader.base, NULL, 0,
		&hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_to_memory_and_verify_hash_header_data_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_DATA, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
			FW_COMPONENT_HDR_V1_LENGTH),
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify (&image, &loader.base, NULL, 0,
		&hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_to_memory_and_verify_map_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_DATA, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
			FW_COMPONENT_HDR_V1_LENGTH),
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));

	status |= mock_expect (&loader.mock, loader.base.map_address, &loader,
		FIRMWARE_LOADER_MAP_ADDR_FAILED, MOCK_ARG (FW_COMPONENT_V1_LOAD_ADDRESS),
		MOCK_ARG (FW_COMPONENT_V1_LENGTH), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify (&image, &loader.base, NULL, 0,
		&hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_LOADER_MAP_ADDR_FAILED, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_to_memory_and_verify_load_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_DATA, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
			FW_COMPONENT_HDR_V1_LENGTH),
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));

	status |= mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_V1_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_V1_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image_update_digest, &loader,
		FIRMWARE_LOADER_LOAD_IMG_FAILED, MOCK_ARG_PTR (&flash),
		MOCK_ARG (0x10000 + FW_COMPONENT_V1_OFFSET), MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR (&hash.base));

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify (&image, &loader.base, NULL, 0,
		&hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_LOADER_LOAD_IMG_FAILED, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_to_memory_and_verify_hash_finish_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_DATA, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
			FW_COMPONENT_HDR_V1_LENGTH),
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));

	status |= mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_V1_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_V1_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image_update_digest, &loader, 0,
		MOCK_ARG_PTR (&flash), MOCK_ARG (0x10000 + FW_COMPONENT_V1_OFFSET),
		MOCK_ARG (FW_COMPONENT_V1_LENGTH), MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0), MOCK_ARG_PTR (&hash.base));

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR));

	status |= mock_expect (&hash.mock, hash.base.finish, &hash, HASH_ENGINE_FINISH_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify (&image, &loader.base, NULL, 0,
		&hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_to_memory_and_verify_extra_header_read_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	int status;
	uint8_t hash_actual[SHA384_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA,
		FW_COMPONENT_SHA384_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA384_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH + FW_COMPONENT_SHA384_SIG_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC384));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH_ECC384, 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha384, &hash, 0);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_EXTRA_HDR_LENGTH));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify (&image, &loader.base, NULL, 0,
		&hash.base, &verification.base, FW_COMPONENT_SHA384_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_to_memory_and_verify_extra_header_hash_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	int status;
	uint8_t hash_actual[SHA384_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA,
		FW_COMPONENT_SHA384_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA384_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH + FW_COMPONENT_SHA384_SIG_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC384));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH_ECC384, 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha384, &hash, 0);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_EXTRA_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_HEADER_DATA,
		FW_COMPONENT_HEADER_DATA_LEN, 2);

	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HEADER_DATA, FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG (FW_COMPONENT_EXTRA_HDR_LENGTH));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify (&image, &loader.base, NULL, 0,
		&hash.base, &verification.base, FW_COMPONENT_SHA384_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_to_memory_and_verify_with_header_header_format0 (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	struct image_header header;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify_with_header (&image, &loader.base, NULL,
		0, &header, &hash.base, &verification.base, NULL, hash_actual, sizeof (hash_actual), &type,
		&app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_NO_LOAD_ADDRESS, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_with_header_header_format1 (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	struct image_header header;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_V1_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_V1_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image_update_digest, &loader, 0,
		MOCK_ARG_PTR (&flash), MOCK_ARG (base_addr + FW_COMPONENT_V1_OFFSET),
		MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR (&hash.base));
	status |= mock_expect_external_action (&loader.mock,
		firmware_component_testing_mock_action_update_digest, (void*) FW_COMPONENT_V1);

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR));

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_HASH_WITH_HEADER, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify_with_header (&image, &loader.base, NULL,
		0, &header, &hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);
	CuAssertIntEquals (test, FW_COMPONENT_V1_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT_V1_HASH_WITH_HEADER, hash_actual,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_with_header_no_hash_out (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	struct image_header header;
	int status;
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_V1_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_V1_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image_update_digest, &loader, 0,
		MOCK_ARG_PTR (&flash), MOCK_ARG (base_addr + FW_COMPONENT_V1_OFFSET),
		MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR (&hash.base));
	status |= mock_expect_external_action (&loader.mock,
		firmware_component_testing_mock_action_update_digest, (void*) FW_COMPONENT_V1);

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR));

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_HASH_WITH_HEADER, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify_with_header (&image, &loader.base, NULL,
		0, &header, &hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, NULL, 0, &type,
		&app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);
	CuAssertIntEquals (test, FW_COMPONENT_V1_LENGTH, app_len);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_with_header_no_hash_type_out (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	struct image_header header;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_V1_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_V1_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image_update_digest, &loader, 0,
		MOCK_ARG_PTR (&flash), MOCK_ARG (base_addr + FW_COMPONENT_V1_OFFSET),
		MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR (&hash.base));
	status |= mock_expect_external_action (&loader.mock,
		firmware_component_testing_mock_action_update_digest, (void*) FW_COMPONENT_V1);

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR));

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_HASH_WITH_HEADER, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify_with_header (&image, &loader.base, NULL,
		0, &header, &hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), NULL, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_V1_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT_V1_HASH_WITH_HEADER, hash_actual,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_with_header_no_length_out (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	struct image_header header;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_V1_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_V1_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image_update_digest, &loader, 0,
		MOCK_ARG_PTR (&flash), MOCK_ARG (base_addr + FW_COMPONENT_V1_OFFSET),
		MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR (&hash.base));
	status |= mock_expect_external_action (&loader.mock,
		firmware_component_testing_mock_action_update_digest, (void*) FW_COMPONENT_V1);

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR));

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_HASH_WITH_HEADER, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify_with_header (&image, &loader.base, NULL,
		0, &header, &hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, NULL);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);

	status = testing_validate_array (FW_COMPONENT_V1_HASH_WITH_HEADER, hash_actual,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_with_header_no_expected_version (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	struct image_header header;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_V1_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_V1_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image_update_digest, &loader, 0,
		MOCK_ARG_PTR (&flash), MOCK_ARG (base_addr + FW_COMPONENT_V1_OFFSET),
		MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR (&hash.base));
	status |= mock_expect_external_action (&loader.mock,
		firmware_component_testing_mock_action_update_digest, (void*) FW_COMPONENT_V1);

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR));

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_HASH_WITH_HEADER, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify_with_header (&image, &loader.base, NULL,
		0, &header, &hash.base, &verification.base, NULL, hash_actual, sizeof (hash_actual), &type,
		&app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);
	CuAssertIntEquals (test, FW_COMPONENT_V1_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT_V1_HASH_WITH_HEADER, hash_actual,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_with_header_encrypted_image (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	struct image_header header;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_V1_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_V1_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image_update_digest, &loader, 0,
		MOCK_ARG_PTR (&flash), MOCK_ARG (base_addr + FW_COMPONENT_V1_OFFSET),
		MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR),
		MOCK_ARG_PTR_CONTAINS (AES_CBC_TESTING_MULTI_BLOCK_IV, AES_CBC_TESTING_IV_LEN),
		MOCK_ARG (AES_CBC_TESTING_IV_LEN), MOCK_ARG_PTR (&hash.base));
	status |= mock_expect_external_action (&loader.mock,
		firmware_component_testing_mock_action_update_digest, (void*) FW_COMPONENT_V1);

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR));

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_HASH_WITH_HEADER, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify_with_header (&image, &loader.base,
		AES_CBC_TESTING_MULTI_BLOCK_IV, AES_CBC_TESTING_IV_LEN, &header, &hash.base,
		&verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual, sizeof (hash_actual), &type,
		&app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);
	CuAssertIntEquals (test, FW_COMPONENT_V1_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT_V1_HASH_WITH_HEADER, hash_actual,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_with_header_sha384 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	struct image_header header;
	int status;
	uint8_t hash_actual[SHA384_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA,
		FW_COMPONENT_SHA384_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA384_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_SHA384_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC384));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH_ECC384, 2);

	status |= mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_SHA384_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_SHA384_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_SHA384_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_SHA384_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image_update_digest, &loader, 0,
		MOCK_ARG_PTR (&flash), MOCK_ARG (base_addr + FW_COMPONENT_SHA384_OFFSET),
		MOCK_ARG (FW_COMPONENT_SHA384_LENGTH),
		MOCK_ARG_PTR (FW_COMPONENT_SHA384_LOAD_ADDRESS_PTR), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR (&hash.base));
	status |= mock_expect_external_action (&loader.mock,
		firmware_component_testing_mock_action_update_digest, (void*) FW_COMPONENT_SHA384);

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_SHA384_LOAD_ADDRESS_PTR));

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA384_HASH_WITH_HEADER, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA384_SIGNATURE, FW_COMPONENT_SIG_LENGTH_ECC384),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC384));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify_with_header (&image, &loader.base, NULL,
		0, &header, &hash.base, &verification.base, FW_COMPONENT_SHA384_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA384, type);
	CuAssertIntEquals (test, FW_COMPONENT_SHA384_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT_SHA384_HASH_WITH_HEADER, hash_actual,
		SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_with_header_sha384_no_hash_out (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	struct image_header header;
	int status;
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA,
		FW_COMPONENT_SHA384_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA384_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_SHA384_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC384));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH_ECC384, 2);

	status |= mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_SHA384_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_SHA384_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_SHA384_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_SHA384_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image_update_digest, &loader, 0,
		MOCK_ARG_PTR (&flash), MOCK_ARG (base_addr + FW_COMPONENT_SHA384_OFFSET),
		MOCK_ARG (FW_COMPONENT_SHA384_LENGTH),
		MOCK_ARG_PTR (FW_COMPONENT_SHA384_LOAD_ADDRESS_PTR), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR (&hash.base));
	status |= mock_expect_external_action (&loader.mock,
		firmware_component_testing_mock_action_update_digest, (void*) FW_COMPONENT_SHA384);

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_SHA384_LOAD_ADDRESS_PTR));

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA384_HASH_WITH_HEADER, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA384_SIGNATURE, FW_COMPONENT_SIG_LENGTH_ECC384),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC384));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify_with_header (&image, &loader.base, NULL,
		0, &header, &hash.base, &verification.base, FW_COMPONENT_SHA384_BUILD_VERSION, NULL, 0,
		&type, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA384, type);
	CuAssertIntEquals (test, FW_COMPONENT_SHA384_LENGTH, app_len);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_with_header_sha512 (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	struct image_header header;
	int status;
	uint8_t hash_actual[SHA512_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA,
		FW_COMPONENT_SHA512_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA512_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_SHA512_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC521));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH_ECC521, 2);

	status |= mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_SHA512_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_SHA512_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_SHA512_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_SHA512_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image_update_digest, &loader, 0,
		MOCK_ARG_PTR (&flash), MOCK_ARG (base_addr + FW_COMPONENT_SHA512_OFFSET),
		MOCK_ARG (FW_COMPONENT_SHA512_LENGTH),
		MOCK_ARG_PTR (FW_COMPONENT_SHA512_LOAD_ADDRESS_PTR), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR (&hash.base));
	status |= mock_expect_external_action (&loader.mock,
		firmware_component_testing_mock_action_update_digest, (void*) FW_COMPONENT_SHA512);

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_SHA512_LOAD_ADDRESS_PTR));

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA512_HASH_WITH_HEADER, SHA512_HASH_LENGTH),
		MOCK_ARG (SHA512_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA512_SIGNATURE, FW_COMPONENT_SIG_LENGTH_ECC521),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC521));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify_with_header (&image, &loader.base, NULL,
		0, &header, &hash.base, &verification.base, FW_COMPONENT_SHA512_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA512, type);
	CuAssertIntEquals (test, FW_COMPONENT_SHA512_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT_SHA512_HASH_WITH_HEADER, hash_actual,
		SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_with_header_sha512_no_hash_out (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	struct image_header header;
	int status;
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA,
		FW_COMPONENT_SHA512_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA512_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_SHA512_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC521));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH_ECC521, 2);

	status |= mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_SHA512_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_SHA512_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_SHA512_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_SHA512_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image_update_digest, &loader, 0,
		MOCK_ARG_PTR (&flash), MOCK_ARG (base_addr + FW_COMPONENT_SHA512_OFFSET),
		MOCK_ARG (FW_COMPONENT_SHA512_LENGTH),
		MOCK_ARG_PTR (FW_COMPONENT_SHA512_LOAD_ADDRESS_PTR), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR (&hash.base));
	status |= mock_expect_external_action (&loader.mock,
		firmware_component_testing_mock_action_update_digest, (void*) FW_COMPONENT_SHA512);

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_SHA512_LOAD_ADDRESS_PTR));

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA512_HASH_WITH_HEADER, SHA512_HASH_LENGTH),
		MOCK_ARG (SHA512_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA512_SIGNATURE, FW_COMPONENT_SIG_LENGTH_ECC521),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC521));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify_with_header (&image, &loader.base, NULL,
		0, &header, &hash.base, &verification.base, FW_COMPONENT_SHA512_BUILD_VERSION, NULL, 0,
		&type, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA512, type);
	CuAssertIntEquals (test, FW_COMPONENT_SHA512_LENGTH, app_len);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_with_header_read_from_flash (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	struct image_header header;
	int status;
	uint8_t hash_actual[SHA384_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_TEST_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA,
		FW_COMPONENT_SHA384_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + IMAGE_HEADER_TEST_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA384_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_TEST_LEN + FW_COMPONENT_SHA384_SIG_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC384));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH_ECC384, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_TEST_LEN));
	status |= mock_expect_output (&flash.mock, 1, IMAGE_HEADER_TEST, IMAGE_HEADER_TEST_LEN, 2);

	status |= mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_SHA384_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_SHA384_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_SHA384_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_SHA384_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image_update_digest, &loader, 0,
		MOCK_ARG_PTR (&flash),
		MOCK_ARG (0x10000 + IMAGE_HEADER_TEST_LEN + FW_COMPONENT_SHA384_OFFSET),
		MOCK_ARG (FW_COMPONENT_SHA384_LENGTH),
		MOCK_ARG_PTR (FW_COMPONENT_SHA384_LOAD_ADDRESS_PTR), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR (&hash.base));
	status |= mock_expect_external_action (&loader.mock,
		firmware_component_testing_mock_action_update_digest, (void*) FW_COMPONENT_SHA384);

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_SHA384_LOAD_ADDRESS_PTR));

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA384_HASH_WITH_HEADER, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA384_SIGNATURE, FW_COMPONENT_SIG_LENGTH_ECC384),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC384));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify_with_header (&image, &loader.base, NULL,
		0, NULL, &hash.base, &verification.base, FW_COMPONENT_SHA384_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA384, type);
	CuAssertIntEquals (test, FW_COMPONENT_SHA384_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT_SHA384_HASH_WITH_HEADER, hash_actual,
		SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_with_header_zero_length_read_from_flash (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	struct image_header header;
	int status;
	uint8_t hash_actual[SHA512_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA,
		FW_COMPONENT_SHA512_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA512_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, 0);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SHA512_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC521));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH_ECC521, 2);

	status |= mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_SHA512_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_SHA512_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_SHA512_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_SHA512_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image_update_digest, &loader, 0,
		MOCK_ARG_PTR (&flash), MOCK_ARG (0x10000 + FW_COMPONENT_SHA512_OFFSET),
		MOCK_ARG (FW_COMPONENT_SHA512_LENGTH),
		MOCK_ARG_PTR (FW_COMPONENT_SHA512_LOAD_ADDRESS_PTR), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR (&hash.base));
	status |= mock_expect_external_action (&loader.mock,
		firmware_component_testing_mock_action_update_digest, (void*) FW_COMPONENT_SHA512);

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_SHA512_LOAD_ADDRESS_PTR));

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA512_HASH, SHA512_HASH_LENGTH),
		MOCK_ARG (SHA512_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SHA512_SIGNATURE, FW_COMPONENT_SIG_LENGTH_ECC521),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC521));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify_with_header (&image, &loader.base, NULL,
		0, NULL, &hash.base, &verification.base, FW_COMPONENT_SHA512_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA512, type);
	CuAssertIntEquals (test, FW_COMPONENT_SHA512_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT_SHA512_HASH, hash_actual, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_with_header_no_flash_header (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	struct image_header header;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_V1_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_V1_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image_update_digest, &loader, 0,
		MOCK_ARG_PTR (&flash), MOCK_ARG (base_addr + FW_COMPONENT_V1_OFFSET),
		MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR (&hash.base));
	status |= mock_expect_external_action (&loader.mock,
		firmware_component_testing_mock_action_update_digest, (void*) FW_COMPONENT_V1);

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR));

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_HASH_WITH_HEADER, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify_with_header (&image, &loader.base, NULL,
		0, &header, &hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);
	CuAssertIntEquals (test, FW_COMPONENT_V1_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT_V1_HASH_WITH_HEADER, hash_actual,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_with_header_null (CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	struct image_header header;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify_with_header (NULL, &loader.base, NULL,
		0, &header, &hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_component_load_to_memory_and_verify_with_header (&image, NULL, NULL,
		0, &header, &hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_component_load_to_memory_and_verify_with_header (&image, &loader.base, NULL,
		0, &header, NULL, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_component_load_to_memory_and_verify_with_header (&image, &loader.base, NULL,
		0, &header, &hash.base, NULL, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_with_header_with_unexpected_version (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	struct image_header header;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify_with_header (&image, &loader.base, NULL,
		0, &header, &hash.base, &verification.base, FW_COMPONENT_SHA384_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_WRONG_VERSION, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_with_header_unknown_hash (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	struct image_header header;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;
	uint8_t bad_header[FW_COMPONENT_V1_DATA_LEN];

	TEST_START;

	memcpy (bad_header, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN);
	bad_header[FW_COMPONENT_V1_HASH_TYPE_OFFSET] = 5;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, bad_header + IMAGE_HEADER_BASE_LEN,
		sizeof (bad_header) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify_with_header (&image, &loader.base, NULL,
		0, &header, &hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, HASH_ENGINE_UNKNOWN_HASH, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_with_header_small_hash_buffer (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	struct image_header header;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH - 1];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify_with_header (&image, &loader.base, NULL,
		0, &header, &hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL, status);

	status = firmware_component_load_to_memory_and_verify_with_header (&image, &loader.base, NULL,
		0, &header, &hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual, 0,
		&type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_with_header_small_hash_buffer_sha384 (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	struct image_header header;
	int status;
	uint8_t hash_actual[SHA384_HASH_LENGTH - 1];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA,
		FW_COMPONENT_SHA384_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA384_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify_with_header (&image, &loader.base, NULL,
		0, &header, &hash.base, &verification.base, FW_COMPONENT_SHA384_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL, status);

	status = firmware_component_load_to_memory_and_verify_with_header (&image, &loader.base, NULL,
		0, &header, &hash.base, &verification.base, FW_COMPONENT_SHA384_BUILD_VERSION, hash_actual,
		0, &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_with_header_small_hash_buffer_sha512 (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	struct image_header header;
	int status;
	uint8_t hash_actual[SHA512_HASH_LENGTH - 1];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA,
		FW_COMPONENT_SHA512_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA512_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA512_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify_with_header (&image, &loader.base, NULL,
		0, &header, &hash.base, &verification.base, FW_COMPONENT_SHA512_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL, status);

	status = firmware_component_load_to_memory_and_verify_with_header (&image, &loader.base, NULL,
		0, &header, &hash.base, &verification.base, FW_COMPONENT_SHA512_BUILD_VERSION, hash_actual,
		0, &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_with_header_read_signature_error (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	struct image_header header;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (base_addr + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify_with_header (&image, &loader.base, NULL,
		0, &header, &hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_with_header_verify_error (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	struct image_header header;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_V1_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_V1_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image_update_digest, &loader, 0,
		MOCK_ARG_PTR (&flash), MOCK_ARG (base_addr + FW_COMPONENT_V1_OFFSET),
		MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR (&hash.base));
	status |= mock_expect_external_action (&loader.mock,
		firmware_component_testing_mock_action_update_digest, (void*) FW_COMPONENT_V1);

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR));

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		SIG_VERIFICATION_VERIFY_SIG_FAILED,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_HASH_WITH_HEADER, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify_with_header (&image, &loader.base, NULL,
		0, &header, &hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, type);

	status = testing_validate_array (FW_COMPONENT_V1_HASH_WITH_HEADER, hash_actual,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_to_memory_and_verify_with_header_hash_start_error (
	CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	struct image_header header;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash,
		HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify_with_header (&image, &loader.base, NULL,
		0, &header, &hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);
}

static void firmware_component_test_load_to_memory_and_verify_with_header_hash_memory_header_error (
	CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	struct image_header header;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (IMAGE_HEADER_TEST, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify_with_header (&image, &loader.base, NULL,
		0, &header, &hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);
}

static void firmware_component_test_load_to_memory_and_verify_with_header_hash_header_info_error (
	CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	struct image_header header;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (IMAGE_HEADER_TEST, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&IMAGE_HEADER_TEST[IMAGE_HEADER_BASE_LEN],
			IMAGE_HEADER_TEST_DATA_LENGTH),
		MOCK_ARG (IMAGE_HEADER_TEST_DATA_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_DATA, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify_with_header (&image, &loader.base, NULL,
		0, &header, &hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);
}

static void firmware_component_test_load_to_memory_and_verify_with_header_hash_header_data_error (
	CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	struct image_header header;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (IMAGE_HEADER_TEST, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&IMAGE_HEADER_TEST[IMAGE_HEADER_BASE_LEN],
			IMAGE_HEADER_TEST_DATA_LENGTH),
		MOCK_ARG (IMAGE_HEADER_TEST_DATA_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_DATA, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
			FW_COMPONENT_HDR_V1_LENGTH),
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify_with_header (&image, &loader.base, NULL,
		0, &header, &hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);
}

static void firmware_component_test_load_to_memory_and_verify_with_header_map_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	struct image_header header;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (IMAGE_HEADER_TEST, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&IMAGE_HEADER_TEST[IMAGE_HEADER_BASE_LEN],
			IMAGE_HEADER_TEST_DATA_LENGTH),
		MOCK_ARG (IMAGE_HEADER_TEST_DATA_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_DATA, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
			FW_COMPONENT_HDR_V1_LENGTH),
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));

	status |= mock_expect (&loader.mock, loader.base.map_address, &loader,
		FIRMWARE_LOADER_MAP_ADDR_FAILED, MOCK_ARG (FW_COMPONENT_V1_LOAD_ADDRESS),
		MOCK_ARG (FW_COMPONENT_V1_LENGTH), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify_with_header (&image, &loader.base, NULL,
		0, &header, &hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_LOADER_MAP_ADDR_FAILED, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);
}

static void firmware_component_test_load_to_memory_and_verify_with_header_load_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	struct image_header header;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (IMAGE_HEADER_TEST, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&IMAGE_HEADER_TEST[IMAGE_HEADER_BASE_LEN],
			IMAGE_HEADER_TEST_DATA_LENGTH),
		MOCK_ARG (IMAGE_HEADER_TEST_DATA_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_DATA, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
			FW_COMPONENT_HDR_V1_LENGTH),
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));

	status |= mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_V1_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_V1_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image_update_digest, &loader,
		FIRMWARE_LOADER_LOAD_IMG_FAILED, MOCK_ARG_PTR (&flash),
		MOCK_ARG (base_addr + FW_COMPONENT_V1_OFFSET), MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), MOCK_ARG_PTR (NULL), MOCK_ARG (0),
		MOCK_ARG_PTR (&hash.base));

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify_with_header (&image, &loader.base, NULL,
		0, &header, &hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FIRMWARE_LOADER_LOAD_IMG_FAILED, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);
}

static void firmware_component_test_load_to_memory_and_verify_with_header_hash_finish_error (
	CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	struct image_header header;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;
	uint32_t base_addr = 0x10000 + IMAGE_HEADER_TEST_LEN;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (base_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	firmware_component_testing_init_image_header (test, &header, &flash);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (base_addr + FW_COMPONENT_V1_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (IMAGE_HEADER_TEST, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&IMAGE_HEADER_TEST[IMAGE_HEADER_BASE_LEN],
			IMAGE_HEADER_TEST_DATA_LENGTH),
		MOCK_ARG (IMAGE_HEADER_TEST_DATA_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_DATA, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
			FW_COMPONENT_HDR_V1_LENGTH),
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));

	status |= mock_expect (&loader.mock, loader.base.map_address, &loader, 0,
		MOCK_ARG (FW_COMPONENT_V1_LOAD_ADDRESS), MOCK_ARG (FW_COMPONENT_V1_LENGTH),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&loader.mock, 2, &FW_COMPONENT_V1_LOAD_ADDRESS_PTR,
		sizeof (FW_COMPONENT_V1_LOAD_ADDRESS_PTR), -1);

	status |= mock_expect (&loader.mock, loader.base.load_image_update_digest, &loader, 0,
		MOCK_ARG_PTR (&flash), MOCK_ARG (base_addr + FW_COMPONENT_V1_OFFSET),
		MOCK_ARG (FW_COMPONENT_V1_LENGTH), MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0), MOCK_ARG_PTR (&hash.base));

	status |= mock_expect (&loader.mock, loader.base.unmap_address, &loader, 0,
		MOCK_ARG_PTR (FW_COMPONENT_V1_LOAD_ADDRESS_PTR));

	status |= mock_expect (&hash.mock, hash.base.finish, &hash, HASH_ENGINE_FINISH_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify_with_header (&image, &loader.base, NULL,
		0, &header, &hash.base, &verification.base, FW_COMPONENT_V1_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
	image_header_release (&header);
}

static void firmware_component_test_load_to_memory_and_verify_with_header_extra_header_read_error (
	CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	int status;
	uint8_t hash_actual[SHA384_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA,
		FW_COMPONENT_SHA384_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA384_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH + FW_COMPONENT_SHA384_SIG_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC384));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH_ECC384, 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha384, &hash, 0);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_EXTRA_HDR_LENGTH));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify_with_header (&image, &loader.base, NULL,
		0, NULL, &hash.base, &verification.base, FW_COMPONENT_SHA384_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_to_memory_and_verify_with_header_extra_header_hash_error (
	CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	struct firmware_loader_mock loader;
	int status;
	uint8_t hash_actual[SHA384_HASH_LENGTH];
	enum hash_type type;
	size_t app_len;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_loader_mock_init (&loader);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA,
		FW_COMPONENT_SHA384_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_SHA384_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER_V1, FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH + FW_COMPONENT_SHA384_SIG_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_SIG_LENGTH_ECC384));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SHA384_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH_ECC384, 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha384, &hash, 0);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_EXTRA_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_HEADER_DATA,
		FW_COMPONENT_HEADER_DATA_LEN, 2);

	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HEADER_DATA, FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG (FW_COMPONENT_EXTRA_HDR_LENGTH));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_to_memory_and_verify_with_header (&image, &loader.base, NULL,
		0, NULL, &hash.base, &verification.base, FW_COMPONENT_SHA384_BUILD_VERSION, hash_actual,
		sizeof (hash_actual), &type, &app_len);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = firmware_loader_mock_validate_and_release (&loader);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_total_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t length;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	length = firmware_component_get_total_length (&image);
	CuAssertIntEquals (test, FW_COMPONENT_DATA_LEN, length);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_total_length_header_format1 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t length;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA, FW_COMPONENT_V1_DATA_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_V1_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_V1_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_V1_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER_V1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	length = firmware_component_get_total_length (&image);
	CuAssertIntEquals (test, FW_COMPONENT_V1_DATA_LEN, length);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_total_length_with_header (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t length;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH,
		FW_COMPONENT_HEADER_DATA_LEN - IMAGE_HEADER_BASE_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	length = firmware_component_get_total_length (&image);
	CuAssertIntEquals (test, FW_COMPONENT_HEADER_DATA_LEN, length);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_total_length_with_header_zero_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t length;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, FW_COMPONENT_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		FW_COMPONENT_DATA_LEN - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	length = firmware_component_get_total_length (&image);
	CuAssertIntEquals (test, FW_COMPONENT_DATA_LEN, length);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_total_length_null (CuTest *test)
{
	size_t length;

	TEST_START;

	length = firmware_component_get_total_length (NULL);
	CuAssertIntEquals (test, 0, length);
}


// *INDENT-OFF*
TEST_SUITE_START (firmware_component);

TEST (firmware_component_test_init);
TEST (firmware_component_test_init_header_format1);
TEST (firmware_component_test_init_unknown_header_format_max_length);
TEST (firmware_component_test_init_null);
TEST (firmware_component_test_init_bad_marker);
TEST (firmware_component_test_init_read_base_header_error);
TEST (firmware_component_test_init_read_header_data_error);
TEST (firmware_component_test_init_less_than_min_header_length);
TEST (firmware_component_test_init_header_too_short);
TEST (firmware_component_test_init_header_too_long);
TEST (firmware_component_test_init_header_format1_too_short);
TEST (firmware_component_test_init_header_format1_too_long);
TEST (firmware_component_test_init_unknown_header_format_too_short);
TEST (firmware_component_test_init_unknown_header_format_too_long);
TEST (firmware_component_test_init_with_header);
TEST (firmware_component_test_init_with_header_unknown_header_format_max_length);
TEST (firmware_component_test_init_with_header_zero_length);
TEST (firmware_component_test_init_with_header_null);
TEST (firmware_component_test_init_with_header_bad_marker);
TEST (firmware_component_test_init_with_header_read_base_header_error);
TEST (firmware_component_test_init_with_header_read_header_data_error);
TEST (firmware_component_test_init_with_header_less_than_min_header_length);
TEST (firmware_component_test_init_with_header_header_too_short);
TEST (firmware_component_test_init_with_header_header_too_long);
TEST (firmware_component_test_init_with_header_unknown_header_format_too_short);
TEST (firmware_component_test_init_with_header_unknown_header_format_too_long);
TEST (firmware_component_test_release_null);
TEST (firmware_component_test_get_length);
TEST (firmware_component_test_get_length_header_format1);
TEST (firmware_component_test_get_length_with_header);
TEST (firmware_component_test_get_length_with_header_zero_length);
TEST (firmware_component_test_get_length_null);
TEST (firmware_component_test_get_signature_length);
TEST (firmware_component_test_get_signature_length_header_format1);
TEST (firmware_component_test_get_signature_length_with_header);
TEST (firmware_component_test_get_signature_length_with_header_zero_length);
TEST (firmware_component_test_get_signature_length_null);
TEST (firmware_component_test_get_signature);
TEST (firmware_component_test_get_signature_header_format1);
TEST (firmware_component_test_get_signature_ecc384);
TEST (firmware_component_test_get_signature_ecc521);
TEST (firmware_component_test_get_signature_with_header);
TEST (firmware_component_test_get_signature_with_header_zero_length);
TEST (firmware_component_test_get_signature_null);
TEST (firmware_component_test_get_signature_small_sig_buffer);
TEST (firmware_component_test_get_signature_read_error);
TEST (firmware_component_test_get_hash_type);
TEST (firmware_component_test_get_hash_type_header_format1);
TEST (firmware_component_test_get_hash_type_sha384);
TEST (firmware_component_test_get_hash_type_sha512);
TEST (firmware_component_test_get_hash_type_with_header);
TEST (firmware_component_test_get_hash_type_with_header_zero_length);
TEST (firmware_component_test_get_hash_type_null);
TEST (firmware_component_test_get_hash);
TEST (firmware_component_test_get_hash_no_type_out);
TEST (firmware_component_test_get_hash_header_format1);
TEST (firmware_component_test_get_hash_sha384);
TEST (firmware_component_test_get_hash_sha512);
TEST (firmware_component_test_get_hash_with_header);
TEST (firmware_component_test_get_hash_with_header_zero_length);
TEST (firmware_component_test_get_hash_null);
TEST (firmware_component_test_get_hash_unknown_hash);
TEST (firmware_component_test_get_hash_small_buffer);
TEST (firmware_component_test_get_hash_small_buffer_sha384);
TEST (firmware_component_test_get_hash_small_buffer_sha512);
TEST (firmware_component_test_get_hash_read_error);
TEST (firmware_component_test_verification);
TEST (firmware_component_test_verification_with_hash_out);
TEST (firmware_component_test_verification_with_hash_type_out);
TEST (firmware_component_test_verification_header_format1);
TEST (firmware_component_test_verification_header_format1_with_expected_version);
TEST (firmware_component_test_verification_sha384);
TEST (firmware_component_test_verification_sha512);
TEST (firmware_component_test_verification_with_header);
TEST (firmware_component_test_verification_with_header_zero_length);
TEST (firmware_component_test_verification_null);
TEST (firmware_component_test_verification_unknown_hash);
TEST (firmware_component_test_verification_small_hash_buffer);
TEST (firmware_component_test_verification_small_hash_buffer_sha384);
TEST (firmware_component_test_verification_small_hash_buffer_sha512);
TEST (firmware_component_test_verification_read_signature_error);
TEST (firmware_component_test_verification_read_data_error);
TEST (firmware_component_test_verification_verify_error);
TEST (firmware_component_test_verification_header_format0_with_expected_version);
TEST (firmware_component_test_verification_header_format1_with_unexpected_version);
TEST (firmware_component_test_load);
TEST (firmware_component_test_load_no_length_out);
TEST (firmware_component_test_load_header_format1);
TEST (firmware_component_test_load_with_header);
TEST (firmware_component_test_load_with_header_zero_length);
TEST (firmware_component_test_load_null);
TEST (firmware_component_test_load_image_too_large);
TEST (firmware_component_test_load_image_error);
TEST (firmware_component_test_get_image_end);
TEST (firmware_component_test_get_image_end_header_format1);
TEST (firmware_component_test_get_image_end_with_header);
TEST (firmware_component_test_get_image_end_with_header_zero_length);
TEST (firmware_component_test_get_image_end_null);
TEST (firmware_component_test_get_data_addr);
TEST (firmware_component_test_get_data_addr_header_format1);
TEST (firmware_component_test_get_data_addr_with_header);
TEST (firmware_component_test_get_data_addr_with_header_zero_length);
TEST (firmware_component_test_get_data_addr_null);
TEST (firmware_component_test_load_and_verify);
TEST (firmware_component_test_load_and_verify_no_hash_out);
TEST (firmware_component_test_load_and_verify_no_hash_type_out);
TEST (firmware_component_test_load_and_verify_no_length_out);
TEST (firmware_component_test_load_and_verify_header_format1);
TEST (firmware_component_test_load_and_verify_header_format1_no_expected_version);
TEST (firmware_component_test_load_and_verify_sha384);
TEST (firmware_component_test_load_and_verify_sha384_no_hash_out);
TEST (firmware_component_test_load_and_verify_sha512);
TEST (firmware_component_test_load_and_verify_sha512_no_hash_out);
TEST (firmware_component_test_load_and_verify_extra_header);
TEST (firmware_component_test_load_and_verify_extra_header_zero_length);
TEST (firmware_component_test_load_and_verify_null);
TEST (firmware_component_test_load_and_verify_unknown_hash);
TEST (firmware_component_test_load_and_verify_small_hash_buffer);
TEST (firmware_component_test_load_and_verify_small_hash_buffer_sha384);
TEST (firmware_component_test_load_and_verify_small_hash_buffer_sha512);
TEST (firmware_component_test_load_and_verify_read_signature_error);
TEST (firmware_component_test_load_and_verify_verify_error);
TEST (firmware_component_test_load_and_verify_hash_start_error);
TEST (firmware_component_test_load_and_verify_hash_header_info_error);
TEST (firmware_component_test_load_and_verify_hash_header_data_error);
TEST (firmware_component_test_load_and_verify_image_too_large);
TEST (firmware_component_test_load_and_verify_image_error);
TEST (firmware_component_test_load_and_verify_hash_image_error);
TEST (firmware_component_test_load_and_verify_hash_finish_error);
TEST (firmware_component_test_load_and_verify_extra_header_read_error);
TEST (firmware_component_test_load_and_verify_extra_header_hash_error);
TEST (firmware_component_test_load_and_verify_header_format0_with_expected_version);
TEST (firmware_component_test_load_and_verify_header_format1_with_unexpected_version);
TEST (firmware_component_test_load_and_verify_with_header);
TEST (firmware_component_test_load_and_verify_with_header_no_hash_out);
TEST (firmware_component_test_load_and_verify_with_header_no_hash_type_out);
TEST (firmware_component_test_load_and_verify_with_header_no_length_out);
TEST (firmware_component_test_load_and_verify_with_header_header_format1);
TEST (firmware_component_test_load_and_verify_with_header_header_format1_no_expected_version);
TEST (firmware_component_test_load_and_verify_with_header_sha384);
TEST (firmware_component_test_load_and_verify_with_header_sha384_no_hash_out);
TEST (firmware_component_test_load_and_verify_with_header_sha512);
TEST (firmware_component_test_load_and_verify_with_header_sha512_no_hash_out);
TEST (firmware_component_test_load_and_verify_with_header_read_from_flash);
TEST (firmware_component_test_load_and_verify_with_header_zero_length_read_from_flash);
TEST (firmware_component_test_load_and_verify_with_header_no_flash_header);
TEST (firmware_component_test_load_and_verify_with_header_null);
TEST (firmware_component_test_load_and_verify_with_header_unknown_hash);
TEST (firmware_component_test_load_and_verify_with_header_small_hash_buffer);
TEST (firmware_component_test_load_and_verify_with_header_small_hash_buffer_sha384);
TEST (firmware_component_test_load_and_verify_with_header_small_hash_buffer_sha512);
TEST (firmware_component_test_load_and_verify_with_header_read_signature_error);
TEST (firmware_component_test_load_and_verify_with_header_verify_error);
TEST (firmware_component_test_load_and_verify_with_header_hash_start_error);
TEST (firmware_component_test_load_and_verify_with_header_hash_memory_header_error);
TEST (firmware_component_test_load_and_verify_with_header_hash_header_info_error);
TEST (firmware_component_test_load_and_verify_with_header_hash_header_data_error);
TEST (firmware_component_test_load_and_verify_with_header_image_too_large);
TEST (firmware_component_test_load_and_verify_with_header_image_error);
TEST (firmware_component_test_load_and_verify_with_header_hash_image_error);
TEST (firmware_component_test_load_and_verify_with_header_hash_finish_error);
TEST (firmware_component_test_load_and_verify_with_header_extra_header_read_error);
TEST (firmware_component_test_load_and_verify_with_header_extra_header_hash_error);
TEST (firmware_component_test_load_and_verify_with_header_header_format0_with_expected_version);
TEST (firmware_component_test_load_and_verify_with_header_header_format1_with_unexpected_version);
TEST (firmware_component_test_copy);
TEST (firmware_component_test_copy_no_length_out);
TEST (firmware_component_test_copy_header_format1);
TEST (firmware_component_test_copy_with_header);
TEST (firmware_component_test_copy_with_header_zero_length);
TEST (firmware_component_test_copy_null);
TEST (firmware_component_test_copy_image_too_large);
TEST (firmware_component_test_copy_erase_error);
TEST (firmware_component_test_copy_copy_error);
TEST (firmware_component_test_compare_and_copy);
TEST (firmware_component_test_compare_and_copy_destination_matches);
TEST (firmware_component_test_compare_and_copy_no_length_out);
TEST (firmware_component_test_compare_and_copy_header_format1);
TEST (firmware_component_test_compare_and_copy_with_header);
TEST (firmware_component_test_compare_and_copy_with_header_destination_matches);
TEST (firmware_component_test_compare_and_copy_with_header_zero_length);
TEST (firmware_component_test_compare_and_copy_null);
TEST (firmware_component_test_compare_and_copy_image_too_large);
TEST (firmware_component_test_compare_and_copy_compare_error);
TEST (firmware_component_test_compare_and_copy_erase_error);
TEST (firmware_component_test_compare_and_copy_copy_error);
TEST (firmware_component_test_get_load_address_header_format0);
TEST (firmware_component_test_get_load_address_header_format1);
TEST (firmware_component_test_get_load_address_with_header);
TEST (firmware_component_test_get_load_address_with_header_zero_length);
TEST (firmware_component_test_get_load_address_null);
TEST (firmware_component_test_get_build_version_header_format0);
TEST (firmware_component_test_get_build_version_header_format1);
TEST (firmware_component_test_get_build_version_with_header);
TEST (firmware_component_test_get_build_version_with_header_zero_length);
TEST (firmware_component_test_get_build_version_null);
TEST (firmware_component_test_load_to_memory_header_format0);
TEST (firmware_component_test_load_to_memory_header_format1);
TEST (firmware_component_test_load_to_memory_no_length_out);
TEST (firmware_component_test_load_to_memory_encrypted_image);
TEST (firmware_component_test_load_to_memory_with_header);
TEST (firmware_component_test_load_to_memory_with_header_zero_length);
TEST (firmware_component_test_load_to_memory_null);
TEST (firmware_component_test_load_to_memory_map_error);
TEST (firmware_component_test_load_to_memory_load_error);
TEST (firmware_component_test_load_to_memory_and_verify_header_format0);
TEST (firmware_component_test_load_to_memory_and_verify_header_format1);
TEST (firmware_component_test_load_to_memory_and_verify_no_hash_out);
TEST (firmware_component_test_load_to_memory_and_verify_no_hash_type_out);
TEST (firmware_component_test_load_to_memory_and_verify_no_length_out);
TEST (firmware_component_test_load_to_memory_and_verify_no_expected_version);
TEST (firmware_component_test_load_to_memory_and_verify_encrypted_image);
TEST (firmware_component_test_load_to_memory_and_verify_sha384);
TEST (firmware_component_test_load_to_memory_and_verify_sha384_no_hash_out);
TEST (firmware_component_test_load_to_memory_and_verify_sha512);
TEST (firmware_component_test_load_to_memory_and_verify_sha512_no_hash_out);
TEST (firmware_component_test_load_to_memory_and_verify_extra_header);
TEST (firmware_component_test_load_to_memory_and_verify_extra_header_zero_length);
TEST (firmware_component_test_load_to_memory_and_verify_null);
TEST (firmware_component_test_load_to_memory_and_verify_with_unexpected_version);
TEST (firmware_component_test_load_to_memory_and_verify_unknown_hash);
TEST (firmware_component_test_load_to_memory_and_verify_small_hash_buffer);
TEST (firmware_component_test_load_to_memory_and_verify_small_hash_buffer_sha384);
TEST (firmware_component_test_load_to_memory_and_verify_small_hash_buffer_sha512);
TEST (firmware_component_test_load_to_memory_and_verify_read_signature_error);
TEST (firmware_component_test_load_to_memory_and_verify_verify_error);
TEST (firmware_component_test_load_to_memory_and_verify_hash_start_error);
TEST (firmware_component_test_load_to_memory_and_verify_hash_header_info_error);
TEST (firmware_component_test_load_to_memory_and_verify_hash_header_data_error);
TEST (firmware_component_test_load_to_memory_and_verify_map_error);
TEST (firmware_component_test_load_to_memory_and_verify_load_error);
TEST (firmware_component_test_load_to_memory_and_verify_hash_finish_error);
TEST (firmware_component_test_load_to_memory_and_verify_extra_header_read_error);
TEST (firmware_component_test_load_to_memory_and_verify_extra_header_hash_error);
TEST (firmware_component_test_load_to_memory_and_verify_with_header_header_format0);
TEST (firmware_component_test_load_to_memory_and_verify_with_header_header_format1);
TEST (firmware_component_test_load_to_memory_and_verify_with_header_no_hash_out);
TEST (firmware_component_test_load_to_memory_and_verify_with_header_no_hash_type_out);
TEST (firmware_component_test_load_to_memory_and_verify_with_header_no_length_out);
TEST (firmware_component_test_load_to_memory_and_verify_with_header_no_expected_version);
TEST (firmware_component_test_load_to_memory_and_verify_with_header_encrypted_image);
TEST (firmware_component_test_load_to_memory_and_verify_with_header_sha384);
TEST (firmware_component_test_load_to_memory_and_verify_with_header_sha384_no_hash_out);
TEST (firmware_component_test_load_to_memory_and_verify_with_header_sha512);
TEST (firmware_component_test_load_to_memory_and_verify_with_header_sha512_no_hash_out);
TEST (firmware_component_test_load_to_memory_and_verify_with_header_read_from_flash);
TEST (firmware_component_test_load_to_memory_and_verify_with_header_zero_length_read_from_flash);
TEST (firmware_component_test_load_to_memory_and_verify_with_header_no_flash_header);
TEST (firmware_component_test_load_to_memory_and_verify_with_header_null);
TEST (firmware_component_test_load_to_memory_and_verify_with_header_with_unexpected_version);
TEST (firmware_component_test_load_to_memory_and_verify_with_header_unknown_hash);
TEST (firmware_component_test_load_to_memory_and_verify_with_header_small_hash_buffer);
TEST (firmware_component_test_load_to_memory_and_verify_with_header_small_hash_buffer_sha384);
TEST (firmware_component_test_load_to_memory_and_verify_with_header_small_hash_buffer_sha512);
TEST (firmware_component_test_load_to_memory_and_verify_with_header_read_signature_error);
TEST (firmware_component_test_load_to_memory_and_verify_with_header_verify_error);
TEST (firmware_component_test_load_to_memory_and_verify_with_header_hash_start_error);
TEST (firmware_component_test_load_to_memory_and_verify_with_header_hash_memory_header_error);
TEST (firmware_component_test_load_to_memory_and_verify_with_header_hash_header_info_error);
TEST (firmware_component_test_load_to_memory_and_verify_with_header_hash_header_data_error);
TEST (firmware_component_test_load_to_memory_and_verify_with_header_map_error);
TEST (firmware_component_test_load_to_memory_and_verify_with_header_load_error);
TEST (firmware_component_test_load_to_memory_and_verify_with_header_hash_finish_error);
TEST (firmware_component_test_load_to_memory_and_verify_with_header_extra_header_read_error);
TEST (firmware_component_test_load_to_memory_and_verify_with_header_extra_header_hash_error);
TEST (firmware_component_test_get_total_length);
TEST (firmware_component_test_get_total_length_header_format1);
TEST (firmware_component_test_get_total_length_with_header);
TEST (firmware_component_test_get_total_length_with_header_zero_length);
TEST (firmware_component_test_get_total_length_null);


TEST_SUITE_END;
// *INDENT-ON*
