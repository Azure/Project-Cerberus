// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "manifest/pfm/pfm_manager_flash.h"
#include "manifest/pfm/pfm_format.h"
#include "host_fw/host_state_manager.h"
#include "mock/flash_master_mock.h"
#include "mock/pfm_observer_mock.h"
#include "mock/signature_verification_mock.h"
#include "engines/hash_testing_engine.h"
#include "engines/rsa_testing_engine.h"
#include "flash/flash_common.h"
#include "crypto/ecc.h"
#include "rsa_testing.h"
#include "pfm_testing.h"


static const char *SUITE = "pfm_manager_flash";


/**
 * PFM with ID 2 for testing.
 */
const uint8_t PFM2_DATA[] = {
	0x5c,0x03,0x4d,0x50,0x02,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x30,0x01,0x01,0x00,
	0x2c,0x01,0x07,0xff,0x45,0x23,0x01,0x00,0x01,0x01,0x00,0x00,0x54,0x65,0x73,0x74,
	0x69,0x6e,0x67,0x00,0x00,0x00,0x00,0x02,0xff,0xff,0xff,0x03,0x10,0x01,0x01,0x00,
	0x00,0x01,0x00,0x01,0xf6,0x25,0x00,0x18,0x27,0x7c,0xa8,0xe9,0x4d,0xa3,0xb4,0xc1,
	0x1c,0x44,0x0e,0xf6,0x52,0xb5,0x76,0xc8,0x4b,0x20,0x68,0x14,0xa4,0xa9,0xdd,0xc7,
	0xbd,0x6d,0x68,0xb3,0xa7,0x04,0xe8,0x3b,0x0b,0xb5,0x53,0x9b,0x49,0xe3,0x83,0x09,
	0xfd,0x73,0xa1,0x73,0xe4,0x54,0x4a,0x65,0x65,0xb1,0xef,0xc0,0xe7,0x04,0x28,0x8a,
	0x69,0x99,0x9d,0xf9,0x4b,0x7b,0x40,0xcf,0x03,0xd2,0xb4,0xe5,0x3b,0xc3,0x93,0x6a,
	0x03,0x90,0x56,0x03,0x4a,0xdd,0x08,0x1b,0xb4,0xf4,0xa1,0x5a,0xc3,0xa8,0x85,0x22,
	0xa6,0x35,0xc8,0xcd,0x21,0x65,0xc6,0xa5,0x78,0x84,0xc9,0xf0,0x0a,0x95,0xb3,0x7e,
	0xa7,0x0a,0x13,0x1a,0xaa,0x30,0xb7,0x03,0x78,0xc8,0x22,0xcf,0x0c,0xd7,0xc6,0x27,
	0x41,0xc7,0x4c,0xcc,0x4b,0xf1,0x5f,0xf5,0x8f,0x31,0x58,0x83,0xc4,0x2a,0x70,0xe0,
	0x76,0x2d,0x1a,0x3e,0xd2,0xe3,0x4f,0x03,0x55,0x37,0xa0,0xbb,0xc8,0x43,0xa7,0xed,
	0xa7,0xe1,0x79,0xf1,0x02,0x12,0xdc,0x01,0x01,0x09,0x4e,0x54,0x94,0x3a,0x44,0x02,
	0xf1,0x16,0xf8,0x11,0x82,0xb0,0x5d,0x53,0xb1,0x6c,0xcf,0x79,0x37,0xf2,0xff,0x23,
	0xa9,0xe7,0x4f,0xc0,0xde,0xff,0x57,0x3b,0x49,0x70,0xdf,0x44,0x77,0x63,0x4e,0x98,
	0x45,0xd8,0x9b,0xa0,0xe6,0x24,0xf9,0x5e,0xc5,0xdf,0x4e,0x2a,0x72,0x9c,0x0b,0x95,
	0x5a,0x13,0x0a,0x22,0xfc,0xa3,0x83,0x0f,0xf2,0x6b,0x8b,0x39,0x06,0x1c,0x34,0xe8,
	0x9a,0xaa,0xca,0x0e,0x04,0xb6,0xe1,0x78,0xf1,0xdb,0x49,0x31,0x7c,0xd6,0x02,0x52,
	0x4a,0x0a,0xa9,0xb6,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0x01,0x10,0x01,0x01,0x00,
	0x0c,0x01,0x00,0x01,0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0xc9,0x44,0x8c,0x40,
	0x6c,0x1f,0x64,0x8d,0xcb,0xa1,0xc7,0x3b,0x14,0xb4,0x89,0xd1,0x25,0x57,0x4a,0x5d,
	0xd5,0xaa,0x2c,0x1f,0x80,0x23,0x23,0xfc,0xc2,0xda,0xfc,0x7c,0xa6,0xad,0x35,0x83,
	0xab,0x92,0x1b,0x71,0x05,0xba,0x75,0x11,0x1e,0xdd,0x60,0x2a,0xe7,0xbe,0x91,0x3f,
	0xed,0xaa,0xe3,0x43,0x17,0x28,0x85,0x29,0xfd,0xb6,0x81,0x78,0x00,0xc0,0xe4,0xc1,
	0xb1,0x79,0x73,0x9e,0x91,0x5a,0x78,0x07,0x11,0x2a,0x24,0xd7,0xcc,0x22,0x35,0x2b,
	0xdf,0xbb,0xf7,0x62,0xdf,0x47,0x19,0xba,0x1f,0xbc,0x9a,0x5b,0x54,0xf5,0xa7,0x6a,
	0x39,0xcb,0x6b,0xe0,0xa5,0xb8,0x0a,0xa0,0x06,0x93,0xec,0xd8,0x03,0xbb,0x49,0x89,
	0xa8,0xfa,0x88,0x07,0x5e,0xc5,0x0f,0xad,0xb1,0xd1,0xa9,0x36,0x48,0x27,0x5f,0x40,
	0xa0,0x7c,0x2a,0x42,0x9c,0xdf,0x41,0x09,0x28,0xe0,0x05,0xad,0x51,0x44,0x96,0x98,
	0x34,0x7a,0x74,0xaa,0x9d,0xda,0x49,0x71,0xdd,0x6b,0xf0,0x74,0xf4,0x01,0xed,0x9d,
	0x42,0xd0,0x12,0x4a,0x63,0x7c,0xd0,0x6e,0x93,0x1f,0x9e,0xb6,0x40,0x93,0x23,0xa6,
	0x09,0xb7,0xac,0x2d,0x3e,0x79,0x8d,0x56,0x85,0x9f,0xc7,0x5a,0x58,0xa7,0x8f,0xdf,
	0x22,0x14,0x94,0x10,0x66,0xe6,0xd6,0xbb,0x2c,0x3f,0x05,0x63,0xb3,0x7a,0x64,0xf5,
	0x6d,0x52,0x82,0x82,0x3a,0x17,0x95,0x89,0xb1,0xb3,0x12,0x4d,0x21,0x64,0x4f,0x58,
	0xe9,0x4e,0x68,0xfa,0x5d,0x5e,0x80,0x49,0x78,0x70,0x4f,0x60,0xa3,0x59,0xca,0x3a,
	0xb0,0x04,0xb3,0xd2,0x34,0xae,0xac,0x7e,0xdc,0x17,0x16,0x81,0x10,0x00,0x09,0x00,
	0x50,0x46,0x4d,0x20,0x54,0x65,0x73,0x74,0x31,0x00,0x00,0x00,0x6b,0xd8,0x7f,0xe3,
	0x85,0x36,0x26,0x8e,0xa8,0xf6,0xd5,0x5b,0xfc,0xac,0xbb,0x70,0x28,0x98,0x6a,0x94,
	0x1b,0x6f,0x4c,0x4c,0x23,0x2c,0xca,0x45,0xcb,0x2d,0x63,0x65,0x72,0x0c,0x32,0x9a,
	0xc2,0x78,0xf4,0x8c,0x9b,0xb1,0x85,0x71,0xab,0x98,0x52,0x56,0xd1,0x2e,0x4b,0xe9,
	0xc3,0xe1,0x23,0xce,0x99,0xcf,0x48,0xa5,0xc7,0x6b,0x71,0x13,0xd1,0xdb,0x92,0xe4,
	0xc3,0x80,0x7c,0xcf,0xc9,0xc0,0xe4,0xac,0x7a,0x6e,0xe7,0x93,0x12,0x1d,0xe4,0x59,
	0x8b,0x78,0x39,0xa6,0xbc,0xe3,0x53,0x35,0x77,0xc4,0x2e,0x06,0xa5,0x28,0xd6,0x20,
	0x96,0xce,0xd3,0x57,0x71,0x1e,0x2c,0x5a,0x3e,0x80,0x4d,0xfa,0xe4,0x5d,0xe7,0x9d,
	0x92,0xcc,0xf2,0x45,0x86,0xcc,0x61,0x6c,0xdd,0x47,0x4e,0x5d,0x07,0x99,0xac,0xa0,
	0xc7,0x48,0x55,0xcd,0x4b,0x86,0x49,0x52,0xca,0x8f,0xe5,0xf8,0x14,0x6a,0xc8,0x8d,
	0x10,0x57,0x99,0x11,0x7d,0xd1,0x78,0x94,0x59,0xdb,0xbf,0xc9,0xbb,0x9f,0xea,0xaa,
	0xaa,0xf5,0x8e,0xe6,0xf8,0x5b,0x52,0xa6,0x23,0x0e,0x44,0x65,0xba,0xfe,0x0e,0x85,
	0x6d,0x2f,0x3d,0x57,0x02,0xb3,0x60,0x42,0x07,0xc4,0x6b,0xcf,0xfc,0x3a,0x10,0x22,
	0x42,0x34,0xa2,0x87,0x7b,0x92,0x01,0x20,0xb1,0x85,0xf0,0xda,0x0a,0xbc,0x84,0x3b,
	0xd9,0x39,0x0d,0x5c,0x7a,0x68,0x68,0xb9,0x08,0x15,0x9a,0xcc,0x83,0x5e,0x3b,0xf8,
	0x4b,0xba,0x75,0xc9,0xb9,0xf0,0xdd,0x5e,0xdc,0x37,0xf0,0x72,0x91,0xcd,0x52,0x16,
	0x9d,0xf3,0xc8,0xb1,0xa5,0xab,0x2e,0xf2,0xe2,0x32,0x71,0x49
};

/**
 * Length of the second testing PFM.
 */
const uint32_t PFM2_DATA_LEN = sizeof (PFM2_DATA);

/**
 * The signature for the second PFM.
 */
const uint8_t *PFM2_SIGNATURE = PFM2_DATA + (sizeof (PFM2_DATA) - 256);

/**
 * PFM2_DATA hash for testing.
 */
const uint8_t PFM2_HASH[] = {
	0x1f,0xaa,0x02,0xf5,0xf6,0xb1,0x6c,0x82,0x23,0x55,0x7c,0x8d,0x88,0x7a,0xfa,0xab,
	0xfb,0xf8,0x9b,0xdd,0xa8,0xeb,0xbe,0x04,0xfe,0xec,0x38,0x49,0x9a,0x21,0x9e,0x11
};

/**
 * PFM with ID 2 with platform ID "PFM Test2".
 */
const uint8_t PFM_PLATFORM2_DATA[] = {
	0x5c,0x03,0x4d,0x50,0x02,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x30,0x01,0x01,0x00,
	0x2c,0x01,0x07,0xff,0x45,0x23,0x01,0x00,0x01,0x01,0x00,0x00,0x54,0x65,0x73,0x74,
	0x69,0x6e,0x67,0x00,0x00,0x00,0x00,0x02,0xff,0xff,0xff,0x03,0x10,0x01,0x01,0x00,
	0x00,0x01,0x00,0x01,0xc6,0xd5,0xc1,0x28,0x7e,0x27,0xdc,0xa2,0xfb,0x2d,0x4b,0x0a,
	0xe0,0x9f,0xab,0x05,0xcb,0xd5,0xfc,0x68,0xdb,0xa7,0x93,0x8e,0x81,0x57,0x5d,0x34,
	0x56,0xee,0xcb,0x5a,0xd3,0xda,0x0a,0x34,0x7f,0x92,0x4f,0x3b,0xa7,0x7e,0xfb,0x55,
	0x7a,0xfb,0x55,0xa0,0xab,0x93,0xf8,0xff,0xeb,0x36,0x72,0xd8,0x13,0x03,0x05,0x2b,
	0x5f,0x07,0x6e,0x54,0x9c,0x2e,0xad,0x18,0xaa,0x38,0xe7,0x0e,0x8e,0x43,0xbd,0xa0,
	0xe7,0x0d,0x31,0x6b,0xfa,0xb4,0x09,0x38,0x96,0xb2,0x2a,0x44,0x8b,0xfe,0xfb,0x0f,
	0xa4,0x47,0xfe,0xd6,0x67,0x42,0x34,0xf7,0xf2,0x87,0x65,0x4e,0x82,0x05,0x9f,0x04,
	0xf8,0x98,0x83,0xe6,0x6a,0xe5,0x62,0xa8,0xf8,0xa6,0x7d,0xf9,0x06,0x39,0x58,0xba,
	0xfc,0xc4,0x4c,0x63,0xe2,0x41,0xc0,0xf7,0xdf,0xeb,0xc9,0x98,0x2f,0xee,0x15,0x1a,
	0xd0,0xba,0xce,0xc4,0x0d,0xb7,0x89,0x8d,0x15,0xc8,0x7a,0x26,0x58,0x77,0xb7,0xaa,
	0x66,0x59,0xf8,0x3d,0xfd,0x23,0x23,0x82,0xa7,0x5e,0x74,0x76,0xc8,0x59,0x40,0x6b,
	0x64,0x8b,0xf0,0xaa,0xac,0x76,0x15,0xfa,0xc9,0x0f,0xf8,0x21,0x55,0x35,0xd4,0x4e,
	0x8b,0xc9,0x66,0x14,0xba,0xbf,0x5a,0x01,0x2d,0xde,0x18,0xcf,0x43,0xfe,0x86,0xda,
	0xcc,0x2d,0x58,0x90,0x36,0xc9,0xb5,0x3e,0xfa,0x5c,0xb4,0x7a,0x73,0xc1,0xad,0x3d,
	0xed,0xb9,0x13,0xc2,0x28,0x7c,0xeb,0x4e,0xb1,0xad,0x1d,0xff,0x46,0xd9,0x51,0x3e,
	0x85,0xe8,0x29,0xac,0x74,0x25,0x04,0x71,0x15,0x26,0xf2,0xe8,0xf2,0x8b,0xe4,0x35,
	0x49,0x38,0x6d,0x57,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0x01,0x10,0x01,0x01,0x00,
	0x0c,0x01,0x00,0x01,0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0xc9,0x44,0x8c,0x40,
	0x6c,0x1f,0x64,0x8d,0xcb,0xa1,0xc7,0x3b,0x14,0xb4,0x89,0xd1,0x25,0x57,0x4a,0x5d,
	0xd5,0xaa,0x2c,0x1f,0x80,0x23,0x23,0xfc,0xc2,0xda,0xfc,0x7c,0xa6,0xad,0x35,0x83,
	0xab,0x92,0x1b,0x71,0x05,0xba,0x75,0x11,0x1e,0xdd,0x60,0x2a,0xe7,0xbe,0x91,0x3f,
	0xed,0xaa,0xe3,0x43,0x17,0x28,0x85,0x29,0xfd,0xb6,0x81,0x78,0x00,0xc0,0xe4,0xc1,
	0xb1,0x79,0x73,0x9e,0x91,0x5a,0x78,0x07,0x11,0x2a,0x24,0xd7,0xcc,0x22,0x35,0x2b,
	0xdf,0xbb,0xf7,0x62,0xdf,0x47,0x19,0xba,0x1f,0xbc,0x9a,0x5b,0x54,0xf5,0xa7,0x6a,
	0x39,0xcb,0x6b,0xe0,0xa5,0xb8,0x0a,0xa0,0x06,0x93,0xec,0xd8,0x03,0xbb,0x49,0x89,
	0xa8,0xfa,0x88,0x07,0x5e,0xc5,0x0f,0xad,0xb1,0xd1,0xa9,0x36,0x48,0x27,0x5f,0x40,
	0xa0,0x7c,0x2a,0x42,0x9c,0xdf,0x41,0x09,0x28,0xe0,0x05,0xad,0x51,0x44,0x96,0x98,
	0x34,0x7a,0x74,0xaa,0x9d,0xda,0x49,0x71,0xdd,0x6b,0xf0,0x74,0xf4,0x01,0xed,0x9d,
	0x42,0xd0,0x12,0x4a,0x63,0x7c,0xd0,0x6e,0x93,0x1f,0x9e,0xb6,0x40,0x93,0x23,0xa6,
	0x09,0xb7,0xac,0x2d,0x3e,0x79,0x8d,0x56,0x85,0x9f,0xc7,0x5a,0x58,0xa7,0x8f,0xdf,
	0x22,0x14,0x94,0x10,0x66,0xe6,0xd6,0xbb,0x2c,0x3f,0x05,0x63,0xb3,0x7a,0x64,0xf5,
	0x6d,0x52,0x82,0x82,0x3a,0x17,0x95,0x89,0xb1,0xb3,0x12,0x4d,0x21,0x64,0x4f,0x58,
	0xe9,0x4e,0x68,0xfa,0x5d,0x5e,0x80,0x49,0x78,0x70,0x4f,0x60,0xa3,0x59,0xca,0x3a,
	0xb0,0x04,0xb3,0xd2,0x34,0xae,0xac,0x7e,0xdc,0x17,0x16,0x81,0x10,0x00,0x09,0x00,
	0x50,0x46,0x4d,0x20,0x54,0x65,0x73,0x74,0x32,0x00,0x00,0x00,0x10,0xd9,0x80,0xd9,
	0x53,0x4a,0x8c,0x21,0x3b,0x81,0x9c,0xed,0xac,0x6e,0x77,0x40,0x83,0x31,0xf3,0x1c,
	0x68,0x2d,0xcd,0x4c,0x0d,0xf4,0x06,0xda,0x4a,0x41,0x04,0xa1,0x9b,0x5f,0x6a,0x16,
	0x63,0x7e,0x10,0xc4,0xde,0xec,0x96,0x76,0xde,0x14,0x94,0x18,0xb0,0xb3,0x56,0x87,
	0xa3,0x27,0xdd,0xf2,0x7c,0xc5,0x60,0x4e,0x17,0xf3,0x27,0x92,0x01,0xa9,0x37,0x17,
	0xe4,0xfa,0x21,0xe6,0xe2,0xac,0xdc,0xd6,0x3d,0x43,0x2e,0x9e,0xfc,0xcc,0x4d,0xfb,
	0x09,0xe1,0xbc,0xff,0xb1,0x8f,0x99,0xfd,0x43,0xce,0x0e,0xc9,0x21,0xa0,0xc2,0x87,
	0xb8,0xfa,0xfb,0xa6,0xa5,0xcb,0x74,0xb7,0x9f,0x1a,0xfb,0x3c,0x1c,0x1c,0x2b,0x4f,
	0x96,0x7e,0x75,0x37,0xf0,0xcb,0xc4,0x09,0xaa,0xd1,0x47,0xc8,0xb7,0x51,0x97,0x36,
	0xba,0x15,0xd6,0x24,0xa1,0x6f,0x65,0x57,0x66,0x16,0x0d,0xaa,0xe5,0x6d,0x67,0x06,
	0xb9,0xae,0xdc,0x1d,0xdf,0xa3,0x8b,0x69,0xe3,0xc6,0xc8,0xb3,0x70,0x66,0x94,0xd7,
	0x37,0x88,0x7e,0x37,0x8a,0x6a,0x63,0x42,0x60,0xa0,0x1a,0x97,0xcc,0xfd,0x10,0x33,
	0x02,0xe5,0x03,0xd3,0x3f,0xa0,0x18,0xe1,0xad,0xa2,0x0f,0x8f,0xd1,0x67,0x1d,0x71,
	0x37,0x6c,0x24,0x01,0xff,0x82,0xba,0x84,0xc5,0xf1,0xa2,0xe2,0x14,0xd5,0xb7,0x08,
	0x59,0xd0,0x2b,0xfa,0x90,0xdd,0x69,0x3d,0x65,0xf5,0xba,0xa7,0x49,0x38,0x9e,0xc2,
	0xcd,0x0f,0x96,0xc7,0xa9,0xd8,0xa2,0x5c,0xaa,0x0f,0xb6,0x18,0x59,0x50,0xdd,0x58,
	0xff,0x00,0xa9,0xb6,0x73,0xeb,0x31,0xc1,0x5c,0xab,0x6e,0xa1
};

/**
 * Length of the testing PFM with a different platform ID.
 */
const uint32_t PFM_PLATFORM2_DATA_LEN = sizeof (PFM_PLATFORM2_DATA);

/**
 * The signature for the PFM with a different platform ID.
 */
const uint8_t *PFM_PLATFORM2_SIGNATURE = PFM_PLATFORM2_DATA + (sizeof (PFM_PLATFORM2_DATA) - 256);

/**
 * PFM_PLATFORM2_DATA hash for testing.
 */
const uint8_t PFM_PLATFORM2_HASH[] = {
	0xda,0x5d,0xa1,0xd3,0xfe,0xc3,0x53,0xd3,0xca,0x2e,0x2b,0xd9,0xe2,0x39,0xb0,0x7e,
	0xec,0x4a,0x1a,0x8f,0xea,0xac,0x12,0x20,0x1d,0xa4,0xe7,0x2e,0xe6,0x49,0xe7,0x96
};


/**
 * Initialize the host state manager for testing.
 *
 * @param test The testing framework.
 * @param state The host state instance to initialize.
 * @param flash_mock The mock for the flash state storage.
 * @param flash The flash device to initialize for state.
 */
static void pfm_manager_flash_testing_init_host_state (CuTest *test,
	struct state_manager *state, struct flash_master_mock *flash_mock, struct spi_flash *flash)
{
	int status;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};

	status = flash_master_mock_init (flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (flash, &flash_mock->base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, (uint8_t*) end, sizeof (end),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, 8));

	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, (uint8_t*) end, sizeof (end),
		FLASH_EXP_READ_CMD (0x03, 0x11000, 0, -1, 8));

	status |= flash_master_mock_expect_erase_flash_sector_verify (flash_mock, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (state, &flash->base, 0x10000);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Set up expectations for verifying a PFM on flash.
 *
 * @param flash_mock The mock for the PFM flash storage.
 * @param verification The mock for PFM verification.
 * @param pfm The PFM data to read.
 * @param length The length of the PFM data.
 * @param hash The PFM hash.
 * @param signature The PFM signature.
 * @param address The base address of the PFM.
 *
 * @return 0 if the expectations were set up successfully or an error code.
 */
static int pfm_manager_flash_testing_verify_pfm (struct flash_master_mock *flash_mock,
	struct signature_verification_mock *verification, const uint8_t *pfm, size_t length,
	const uint8_t *hash, const uint8_t *signature, uint32_t address)
{
	int status;

	status = flash_master_mock_expect_rx_xfer (flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, pfm, length,
		FLASH_EXP_READ_CMD (0x03, address, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, signature, PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, address + PFM_SIGNATURE_OFFSET, 0, -1, PFM_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (flash_mock, address, pfm,
		length - PFM_SIGNATURE_LEN);

	status |= mock_expect (&verification->mock, verification->base.verify_signature, verification,
		0, MOCK_ARG_PTR_CONTAINS (hash, PFM_HASH_LEN), MOCK_ARG (PFM_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (signature, PFM_SIGNATURE_LEN), MOCK_ARG (PFM_SIGNATURE_LEN));

	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, pfm, length,
		FLASH_EXP_READ_CMD (0x03, address, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, pfm + PFM_ALLOWED_HDR_OFFSET,
		length - PFM_ALLOWED_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, address + PFM_ALLOWED_HDR_OFFSET, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, pfm + PFM_MANIFEST_OFFSET,
		length - PFM_MANIFEST_OFFSET,
		FLASH_EXP_READ_CMD (0x03, address + PFM_MANIFEST_OFFSET, 0, -1, PFM_MANIFEST_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0,
		pfm + PFM_PLATFORM_HEADER_OFFSET, length - PFM_PLATFORM_HEADER_OFFSET,
		FLASH_EXP_READ_CMD (0x03, address + PFM_PLATFORM_HEADER_OFFSET, 0, -1,
			PFM_PLATFORM_HEADER_SIZE));

	return status;
}

/**
 * Set up expectations for verifying an empty PFM on flash.
 *
 * @param flash_mock The mock for the PFM flash storage.
 * @param verification The mock for PFM verification.
 * @param pfm The PFM data to read.
 * @param length The length of the PFM data.
 * @param man_offset Offset of the key manifest section.
 * @param plat_offset Offset of the platform section.
 * @param sig_offset Offset of the signature.
 * @param address The base address of the PFM.
 *
 * @return 0 if the expectations were set up successfully or an error code.
 */
static int pfm_manager_flash_testing_verify_empty_pfm (struct flash_master_mock *flash_mock,
	struct signature_verification_mock *verification, const uint8_t *pfm, size_t length,
	int man_offset, int plat_offset, int sig_offset, uint32_t address)
{
	int status;

	status = flash_master_mock_expect_rx_xfer (flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, pfm, length,
		FLASH_EXP_READ_CMD (0x03, address, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, &pfm[sig_offset], PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, address + sig_offset, 0, -1, PFM_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (flash_mock, address, pfm,
		length - PFM_SIGNATURE_LEN);

	status |= mock_expect (&verification->mock, verification->base.verify_signature, verification,
		0, MOCK_ARG_ANY, MOCK_ARG (PFM_HASH_LEN), MOCK_ARG_ANY, MOCK_ARG (PFM_SIGNATURE_LEN));

	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, pfm, length,
		FLASH_EXP_READ_CMD (0x03, address, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, pfm + PFM_HEADER_SIZE,
		length - PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, address + PFM_HEADER_SIZE, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, pfm + man_offset,
		length - man_offset,
		FLASH_EXP_READ_CMD (0x03, address + man_offset, 0, -1, PFM_MANIFEST_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, pfm + plat_offset,
		length - plat_offset,
		FLASH_EXP_READ_CMD (0x03, address + plat_offset, 0, -1, PFM_PLATFORM_HEADER_SIZE));

	return status;
}

/**
 * Set up expectations for reading the platform ID.
 *
 * @param flash_mock The mock for the PFM flash storage.
 * @param pfm The PFM data to read.
 * @param length The length of the PFM data.
 * @param address The base address of the PFM.
 *
 * @return 0 if the expectations were set up successfully or an error code.
 */
static int pfm_manager_flash_testing_read_platform_id (struct flash_master_mock *flash_mock,
	const uint8_t *pfm, size_t length, uint32_t address)
{
	int status;

	status = flash_master_mock_expect_rx_xfer (flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, pfm, length,
		FLASH_EXP_READ_CMD (0x03, address, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, pfm + PFM_ALLOWED_HDR_OFFSET,
		length - PFM_ALLOWED_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, address + PFM_ALLOWED_HDR_OFFSET, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, pfm + PFM_MANIFEST_OFFSET,
		length - PFM_MANIFEST_OFFSET,
		FLASH_EXP_READ_CMD (0x03, address + PFM_MANIFEST_OFFSET, 0, -1, PFM_MANIFEST_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0,
		pfm + PFM_PLATFORM_HEADER_OFFSET, length - PFM_PLATFORM_HEADER_OFFSET,
		FLASH_EXP_READ_CMD (0x03, address + PFM_PLATFORM_HEADER_OFFSET, 0, -1,
			PFM_PLATFORM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, pfm + PFM_PLATFORM_ID_OFFSET,
		length - PFM_PLATFORM_ID_OFFSET,
		FLASH_EXP_READ_CMD (0x03, address + PFM_PLATFORM_ID_OFFSET, 0, -1,
			strlen (PFM_PLATFORM_ID)));

	return status;
}

/**
 * Set up expectations for verifying the PFMs during initialization.
 *
 * @param flash_mock The mock for the PFM flash storage.
 * @param verification The mock for PFM verification.
 * @param pfm1 The PFM data to read in region 1.
 * @param length1 The length of the PFM data in region 1.
 * @param hash1 The PFM hash in region 1.
 * @param signature1 The PFM signature in region 1.
 * @param pfm2 The PFM data to read in region 2.
 * @param length2 The length of the PFM data in region 2.
 * @param hash2 The PFM hash in region 2.
 * @param signature2 The PFM signature in region 2.
 * @param pfm1_active Flag indicating if region 1 is active.
 *
 * @return 0 if the expectations were set up successfully or an error code.
 */
static int pfm_manager_flash_testing_initial_pfm_validation (struct flash_master_mock *flash_mock,
	struct signature_verification_mock *verification, const uint8_t *pfm1, size_t length1,
	const uint8_t *hash1, const uint8_t *signature1, const uint8_t* pfm2, size_t length2,
	const uint8_t *hash2, const uint8_t *signature2, bool pfm1_active)
{
	const uint8_t *active;
	size_t active_len;
	uint32_t active_addr;
	const uint8_t *pending;
	size_t pending_len;
	uint32_t pending_addr;
	int status;

	if (pfm1_active) {
		active = pfm1;
		active_len = length1;
		active_addr = 0x10000;
		pending = pfm2;
		pending_len = length2;
		pending_addr = 0x20000;
	}
	else {
		active = pfm2;
		active_len = length2;
		active_addr = 0x20000;
		pending = pfm1;
		pending_len = length1;
		pending_addr = 0x10000;
	}

	/* Base PFM verification.  Use blank check to simulate empty PFM regions. */
	if (pfm1) {
		status = pfm_manager_flash_testing_verify_pfm (flash_mock, verification, pfm1, length1,
			hash1, signature1, 0x10000);
	}
	else {
		status = flash_master_mock_expect_blank_check (flash_mock, 0x10000, PFM_HEADER_SIZE);
	}
	if (pfm2) {
		status |= pfm_manager_flash_testing_verify_pfm (flash_mock, verification, pfm2, length2,
			hash2, signature2, 0x20000);
	}
	else {
		status |= flash_master_mock_expect_blank_check (flash_mock, 0x20000, PFM_HEADER_SIZE);
	}

	if (pfm1 && pfm2) {
		/* Check PFM IDs. */
		status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, active, active_len,
			FLASH_EXP_READ_CMD (0x03, active_addr, 0, -1, PFM_HEADER_SIZE));
		status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, pending, pending_len,
			FLASH_EXP_READ_CMD (0x03, pending_addr, 0, -1, PFM_HEADER_SIZE));

		/* Compare platform IDs. */
		status |= pfm_manager_flash_testing_read_platform_id (flash_mock, active, active_len,
			active_addr);
		status |= pfm_manager_flash_testing_read_platform_id (flash_mock, pending, pending_len,
			pending_addr);
	}

	if (pending) {
		/* Get versions list. */
		status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, pending, pending_len,
			FLASH_EXP_READ_CMD (0x03, pending_addr, 0, -1, PFM_HEADER_SIZE));

		status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, pending + PFM_HEADER_SIZE,
			pending_len - PFM_HEADER_SIZE,
			FLASH_EXP_READ_CMD (0x03, pending_addr + PFM_HEADER_SIZE, 0, -1,
				PFM_ALLOWED_HEADER_SIZE));

		status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, pending + PFM_FW_HEADER_OFFSET,
			pending_len - PFM_FW_HEADER_OFFSET,
			FLASH_EXP_READ_CMD (0x03, pending_addr + PFM_FW_HEADER_OFFSET, 0, -1,
				PFM_FW_HEADER_SIZE));

		status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, &WIP_STATUS, 1,
			FLASH_EXP_READ_STATUS_REG);
		status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, pending + PFM_VERSION_OFFSET,
			pending_len - PFM_VERSION_OFFSET,
			FLASH_EXP_READ_CMD (0x03, pending_addr + PFM_VERSION_OFFSET, 0, -1,
				strlen (PFM_VERSION_ID)));
	}

	return status;
}

/**
 * Write complete PFM data to the manager to enable pending PFM verification.
 *
 * @param test The test framework.
 * @param manager The manager to use for writing PFM data.
 * @param flash_mock The mock for PFM flash storage.
 * @param addr The expected address of PFM writes.
 *
 * @return The number of PFM bytes written.
 */
static int pfm_manager_flash_testing_write_new_pfm (CuTest *test, struct pfm_manager_flash *manager,
	struct flash_master_mock *flash_mock, uint32_t addr)
{
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	status = flash_master_mock_expect_erase_flash_verify (flash_mock, addr, 0x10000);
	status |= flash_master_mock_expect_write_ext (flash_mock, addr, data, sizeof (data), true,
		false);

	CuAssertIntEquals (test, 0, status);

	status = manager->base.base.clear_pending_region (&manager->base.base, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager->base.base.write_pending_data (&manager->base.base, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock->mock);
	CuAssertIntEquals (test, 0, status);

	return sizeof (data);
}


/*******************
 * Test cases
 *******************/

static void pfm_manager_flash_test_init (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_port (&manager.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, manager.base.get_active_pfm);
	CuAssertPtrNotNull (test, manager.base.get_pending_pfm);
	CuAssertPtrNotNull (test, manager.base.free_pfm);
	CuAssertPtrNotNull (test, manager.base.base.activate_pending_manifest);
	CuAssertPtrNotNull (test, manager.base.base.clear_pending_region);
	CuAssertPtrNotNull (test, manager.base.base.write_pending_data);
	CuAssertPtrNotNull (test, manager.base.base.verify_pending_manifest);
	CuAssertPtrNotNull (test, manager.base.base.clear_all_manifests);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	manager.base.get_active_pfm (&manager.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_init_only_active_region1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_init_only_active_region2 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = state_mgr.save_active_manifest (&state_mgr, 0, MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL, 0,
		NULL, NULL, PFM_DATA, PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, false);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &pfm2, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_init_only_pending_region2 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL, 0,
		NULL, NULL, PFM_DATA, PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, &pfm2, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_init_only_pending_region1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = state_mgr.save_active_manifest (&state_mgr, 0, MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, NULL, 0, NULL, NULL, false);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, &pfm1, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_init_active_and_pending (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, PFM2_DATA, PFM2_DATA_LEN, PFM2_HASH,
		PFM2_SIGNATURE, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, &pfm2, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_init_region2_pending_lower_id (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM2_DATA,
		PFM2_DATA_LEN, PFM2_HASH, PFM2_SIGNATURE, 0x10000);
	status |= pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, 0x20000);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM2_DATA, PFM2_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x20000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_init_region2_pending_same_id (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, 0x10000);
	status |= pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, 0x20000);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x20000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_init_region2_pending_different_platform_id (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, 0x10000);
	status |= pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM_PLATFORM2_DATA,
		PFM_PLATFORM2_DATA_LEN, PFM_PLATFORM2_HASH, PFM_PLATFORM2_SIGNATURE, 0x20000);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_PLATFORM2_DATA,
		PFM_PLATFORM2_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x20000, 0, -1, PFM_HEADER_SIZE));

	status |= pfm_manager_flash_testing_read_platform_id (&flash_mock, PFM_DATA, PFM_DATA_LEN,
		0x10000);
	status |= pfm_manager_flash_testing_read_platform_id (&flash_mock, PFM_PLATFORM2_DATA,
		PFM_PLATFORM2_DATA_LEN, 0x20000);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_init_region1_pending_lower_id (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = state_mgr.save_active_manifest (&state_mgr, 0, MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, 0x10000);
	status |= pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM2_DATA,
		PFM2_DATA_LEN, PFM2_HASH, PFM2_SIGNATURE, 0x20000);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM2_DATA, PFM2_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x20000, 0, -1, PFM_HEADER_SIZE));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &pfm2, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_init_region1_pending_same_id (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = state_mgr.save_active_manifest (&state_mgr, 0, MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, 0x10000);
	status |= pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, 0x20000);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x20000, 0, -1, PFM_HEADER_SIZE));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &pfm2, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_init_only_pending_region2_empty_manifest (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	struct manifest_header *header;
	struct pfm_allowable_firmware_header *allowed_header;
	struct pfm_key_manifest_header *manifest_header;
	struct pfm_platform_header *platform_header;
	int man_offset = PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE;
	int plat_offset = man_offset + PFM_MANIFEST_HEADER_SIZE;
	int sig_offset = plat_offset + PFM_PLATFORM_HEADER_SIZE + strlen (PFM_PLATFORM_ID) + 3;
	uint8_t pfm[sig_offset + PFM_SIGNATURE_LEN];
	size_t length = sizeof (pfm);

	TEST_START;

	memset (pfm, 0, sizeof (pfm));

	header = (struct manifest_header*) pfm;
	header->length = sizeof (pfm);
	header->magic = PFM_MAGIC_NUM;
	header->sig_length = PFM_SIGNATURE_LEN;

	allowed_header = (struct pfm_allowable_firmware_header*) &pfm[PFM_HEADER_SIZE];
	allowed_header->length = PFM_ALLOWED_HEADER_SIZE;
	allowed_header->fw_count = 0;

	manifest_header = (struct pfm_key_manifest_header*) &pfm[man_offset];
	manifest_header->length = PFM_MANIFEST_HEADER_SIZE;
	manifest_header->key_count = 0;

	platform_header = (struct pfm_platform_header*) &pfm[plat_offset];
	platform_header->length = PFM_PLATFORM_HEADER_SIZE + strlen (PFM_PLATFORM_ID) + 3;
	platform_header->id_length = strlen (PFM_PLATFORM_ID);
	memcpy (&pfm[plat_offset + PFM_PLATFORM_HEADER_SIZE], PFM_PLATFORM_ID,
		strlen (PFM_PLATFORM_ID));

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	/* Use blank check to simulate empty PFM regions. */
	status = flash_master_mock_expect_blank_check (&flash_mock, 0x10000, PFM_HEADER_SIZE);

	status |= pfm_manager_flash_testing_verify_empty_pfm (&flash_mock, &verification, pfm, length,
		man_offset, plat_offset, sig_offset, 0x20000);

	/* Get versions list. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm, sizeof (pfm),
		FLASH_EXP_READ_CMD (0x03, 0x20000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm + PFM_HEADER_SIZE,
		length - PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x20000 + PFM_HEADER_SIZE, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	/* Erase manifest regions. */
	status |= flash_master_mock_expect_erase_flash (&flash_mock, 0x20000);
	status |= flash_master_mock_expect_erase_flash (&flash_mock, 0x10000);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_init_only_pending_region1_empty_manifest (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	struct manifest_header *header;
	struct pfm_allowable_firmware_header *allowed_header;
	struct pfm_key_manifest_header *manifest_header;
	struct pfm_platform_header *platform_header;
	int man_offset = PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE;
	int plat_offset = man_offset + PFM_MANIFEST_HEADER_SIZE;
	int sig_offset = plat_offset + PFM_PLATFORM_HEADER_SIZE + strlen (PFM_PLATFORM_ID) + 3;
	uint8_t pfm[sig_offset + PFM_SIGNATURE_LEN];
	size_t length = sizeof (pfm);

	TEST_START;

	memset (pfm, 0, sizeof (pfm));

	header = (struct manifest_header*) pfm;
	header->length = sizeof (pfm);
	header->magic = PFM_MAGIC_NUM;
	header->sig_length = PFM_SIGNATURE_LEN;

	allowed_header = (struct pfm_allowable_firmware_header*) &pfm[PFM_HEADER_SIZE];
	allowed_header->length = PFM_ALLOWED_HEADER_SIZE;
	allowed_header->fw_count = 0;

	manifest_header = (struct pfm_key_manifest_header*) &pfm[man_offset];
	manifest_header->length = PFM_MANIFEST_HEADER_SIZE;
	manifest_header->key_count = 0;

	platform_header = (struct pfm_platform_header*) &pfm[plat_offset];
	platform_header->length = PFM_PLATFORM_HEADER_SIZE + strlen (PFM_PLATFORM_ID) + 3;
	platform_header->id_length = strlen (PFM_PLATFORM_ID);
	memcpy (&pfm[plat_offset + PFM_PLATFORM_HEADER_SIZE], PFM_PLATFORM_ID,
		strlen (PFM_PLATFORM_ID));

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = state_mgr.save_active_manifest (&state_mgr, 0, MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_verify_empty_pfm (&flash_mock, &verification, pfm, length,
		man_offset, plat_offset, sig_offset, 0x10000);

	/* Use blank check to simulate empty PFM regions. */
	status |= flash_master_mock_expect_blank_check (&flash_mock, 0x20000, PFM_HEADER_SIZE);

	/* Get versions list. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm, sizeof (pfm),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm + PFM_HEADER_SIZE,
		length - PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_HEADER_SIZE, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	/* Erase manifest regions. */
	status |= flash_master_mock_expect_erase_flash (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_erase_flash (&flash_mock, 0x20000);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_init_active_and_pending_empty_manifest (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	struct manifest_header *header;
	struct pfm_allowable_firmware_header *allowed_header;
	struct pfm_key_manifest_header *manifest_header;
	struct pfm_platform_header *platform_header;
	int man_offset = PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE;
	int plat_offset = man_offset + PFM_MANIFEST_HEADER_SIZE;
	int id_offset = plat_offset + PFM_PLATFORM_HEADER_SIZE;
	int sig_offset = id_offset + strlen (PFM_PLATFORM_ID) + 3;
	uint8_t pfm[sig_offset + PFM_SIGNATURE_LEN];
	size_t length = sizeof (pfm);

	TEST_START;

	memset (pfm, 0, sizeof (pfm));

	header = (struct manifest_header*) pfm;
	header->length = sizeof (pfm);
	header->magic = PFM_MAGIC_NUM;
	header->id = 2;
	header->sig_length = PFM_SIGNATURE_LEN;

	allowed_header = (struct pfm_allowable_firmware_header*) &pfm[PFM_HEADER_SIZE];
	allowed_header->length = PFM_ALLOWED_HEADER_SIZE;
	allowed_header->fw_count = 0;

	manifest_header = (struct pfm_key_manifest_header*) &pfm[man_offset];
	manifest_header->length = PFM_MANIFEST_HEADER_SIZE;
	manifest_header->key_count = 0;

	platform_header = (struct pfm_platform_header*) &pfm[plat_offset];
	platform_header->length = PFM_PLATFORM_HEADER_SIZE + strlen (PFM_PLATFORM_ID) + 3;
	platform_header->id_length = strlen (PFM_PLATFORM_ID);
	memcpy (&pfm[id_offset], PFM_PLATFORM_ID, strlen (PFM_PLATFORM_ID));

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, 0x10000);
	status |= pfm_manager_flash_testing_verify_empty_pfm (&flash_mock, &verification, pfm, length,
		man_offset, plat_offset, sig_offset, 0x20000);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm, length,
		FLASH_EXP_READ_CMD (0x03, 0x20000, 0, -1, PFM_HEADER_SIZE));

	status |= pfm_manager_flash_testing_read_platform_id (&flash_mock, PFM_DATA, PFM_DATA_LEN,
		0x10000);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm, length,
		FLASH_EXP_READ_CMD (0x03, 0x20000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm + PFM_HEADER_SIZE,
		length - PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x20000 + PFM_HEADER_SIZE, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm + man_offset,
		length - man_offset,
		FLASH_EXP_READ_CMD (0x03, 0x20000 + man_offset, 0, -1, PFM_MANIFEST_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm + plat_offset,
		length - plat_offset,
		FLASH_EXP_READ_CMD (0x03, 0x20000 + plat_offset, 0, -1, PFM_PLATFORM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm + id_offset, length - id_offset,
		FLASH_EXP_READ_CMD (0x03, 0x20000 + id_offset, 0, -1, strlen (PFM_PLATFORM_ID)));

	/* Get versions list. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm, sizeof (pfm),
		FLASH_EXP_READ_CMD (0x03, 0x20000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm + PFM_HEADER_SIZE,
		length - PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x20000 + PFM_HEADER_SIZE, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	/* Erase manifest regions. */
	status |= flash_master_mock_expect_erase_flash (&flash_mock, 0x20000);
	status |= flash_master_mock_expect_erase_flash (&flash_mock, 0x10000);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_init_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (NULL, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = pfm_manager_flash_init (&manager, NULL, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = pfm_manager_flash_init (&manager, &pfm1, NULL, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, NULL, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, NULL,
		&verification.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		NULL);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_init_region1_flash_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_init_region2_flash_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	/* Use blank check to simulate empty PFM regions. */
	status = flash_master_mock_expect_blank_check (&flash_mock, 0x10000, PFM_HEADER_SIZE);

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_init_pfm_bad_signature (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_SIGNATURE, PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_SIGNATURE_OFFSET, 0, -1, PFM_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PFM_DATA,
		PFM_DATA_LEN - PFM_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG_NOT_NULL, MOCK_ARG (PFM_HASH_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (PFM_SIGNATURE_LEN));

	/* Use blank check to simulate empty PFM regions. */
	status |= flash_master_mock_expect_blank_check (&flash_mock, 0x20000, PFM_HEADER_SIZE);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_init_pfm_bad_signature_ecc (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_SIGNATURE, PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_SIGNATURE_OFFSET, 0, -1, PFM_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PFM_DATA,
		PFM_DATA_LEN - PFM_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		ECC_ENGINE_BAD_SIGNATURE, MOCK_ARG_NOT_NULL, MOCK_ARG (PFM_HASH_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (PFM_SIGNATURE_LEN));

	/* Use blank check to simulate empty PFM regions. */
	status |= flash_master_mock_expect_blank_check (&flash_mock, 0x20000, PFM_HEADER_SIZE);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_init_bad_length (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	uint8_t pfm_bad_data[PFM_SIGNATURE_OFFSET];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[9] = 0xff;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_bad_data, sizeof (pfm_bad_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	/* Use blank check to simulate empty PFM regions. */
	status |= flash_master_mock_expect_blank_check (&flash_mock, 0x20000, PFM_HEADER_SIZE);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_init_bad_magic_number (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	uint8_t pfm_bad_data[PFM_SIGNATURE_OFFSET];

	TEST_START;

	memcpy (pfm_bad_data, PFM_DATA, sizeof (pfm_bad_data));
	pfm_bad_data[2] ^= 0x55;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_bad_data, sizeof (pfm_bad_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	/* Use blank check to simulate empty PFM regions. */
	status |= flash_master_mock_expect_blank_check (&flash_mock, 0x20000, PFM_HEADER_SIZE);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_init_malformed (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	const char *version1 = "V1";
	struct manifest_header *header;
	struct pfm_allowable_firmware_header *allowed_header;
	struct pfm_firmware_header *fw_header;
	struct pfm_image_header *img_header;
	struct pfm_flash_region *region;
	struct pfm_key_manifest_header *manifest_header;
	struct pfm_public_key_header *key_header;
	int ver_offset1 = PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE;
	int img_offset1 = ver_offset1 + PFM_FW_HEADER_SIZE + 4;
	int sig_offset1 = img_offset1 + PFM_IMG_HEADER_SIZE;
	int reg_offset1 = sig_offset1 + PFM_IMG_KEY_SIZE;
	int man_offset = reg_offset1 + PFM_REGION_SIZE;
	int pub_offset = man_offset + PFM_MANIFEST_HEADER_SIZE;
	int key_offset = pub_offset + PFM_KEY_HEADER_SIZE;
	int sig_offset = key_offset + PFM_IMG_KEY_SIZE;
	uint8_t pfm_data[sig_offset + PFM_SIGNATURE_LEN];

	TEST_START;

	memset (pfm_data, 0, sizeof (pfm_data));

	header = (struct manifest_header*) pfm_data;
	header->length = sizeof (pfm_data);
	header->magic = PFM_MAGIC_NUM;
	header->sig_length = PFM_SIGNATURE_LEN;

	allowed_header = (struct pfm_allowable_firmware_header*) &pfm_data[PFM_HEADER_SIZE];
	allowed_header->length = PFM_ALLOWED_HEADER_SIZE;
	allowed_header->fw_count = 3;

	img_header = (struct pfm_image_header*) &pfm_data[img_offset1];
	img_header->length = PFM_IMG_HEADER_SIZE + PFM_IMG_KEY_SIZE + PFM_REGION_SIZE;
	img_header->flags = PFM_IMAGE_MUST_VALIDATE;
	img_header->key_id = 0;
	img_header->sig_length = PFM_IMG_KEY_SIZE;
	img_header->region_count = 1;
	pfm_data[sig_offset1] = 11;
	fw_header = (struct pfm_firmware_header*) &pfm_data[ver_offset1];
	fw_header->length = PFM_FW_HEADER_SIZE + 4 + img_header->length;
	fw_header->version_addr = 0x12345;
	fw_header->version_length = strlen (version1);
	fw_header->img_count = 1;
	memcpy (&pfm_data[ver_offset1 + PFM_FW_HEADER_SIZE], version1, strlen (version1));
	allowed_header->length += fw_header->length;
	region = (struct pfm_flash_region*) &pfm_data[reg_offset1];
	region->start_addr = 0x1000000;
	region->end_addr = 0x1ffffff;

	manifest_header = (struct pfm_key_manifest_header*) &pfm_data[man_offset];
	manifest_header->length = PFM_MANIFEST_HEADER_SIZE + PFM_KEY_HEADER_SIZE + PFM_IMG_KEY_SIZE;
	manifest_header->key_count = 1;

	key_header = (struct pfm_public_key_header*) &pfm_data[pub_offset];
	key_header->length = PFM_KEY_HEADER_SIZE + PFM_IMG_KEY_SIZE;
	key_header->key_length = PFM_IMG_KEY_SIZE;
	key_header->key_exponent = 3;
	key_header->id = 0;
	pfm_data[key_offset] = 1;

	status = RSA_TESTING_ENGINE_SIGN (pfm_data, sizeof (pfm_data) - PFM_SIGNATURE_LEN,
		RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, &pfm_data[sig_offset], PFM_SIGNATURE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data, sizeof (pfm_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &pfm_data[sig_offset],
		PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + sig_offset, 0, -1, PFM_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, pfm_data,
		sizeof (pfm_data) - PFM_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_NOT_NULL, MOCK_ARG (PFM_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (&pfm_data[sig_offset], PFM_SIGNATURE_LEN),
		MOCK_ARG (PFM_SIGNATURE_LEN));

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm_data, sizeof (pfm_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) allowed_header,
		allowed_header->length,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_HEADER_SIZE, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) manifest_header,
		manifest_header->length,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + man_offset, 0, -1, PFM_MANIFEST_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &pfm_data[sig_offset],
		PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + sig_offset, 0, -1, PFM_PLATFORM_HEADER_SIZE));

	/* Use blank check to simulate empty PFM regions. */
	status |= flash_master_mock_expect_blank_check (&flash_mock, 0x20000, PFM_HEADER_SIZE);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_init_region1_id_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, 0x10000);
	status |= pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM2_DATA,
		PFM2_DATA_LEN, PFM2_HASH, PFM2_SIGNATURE, 0x20000);

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_init_region2_id_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, 0x10000);
	status |= pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM2_DATA,
		PFM2_DATA_LEN, PFM2_HASH, PFM2_SIGNATURE, 0x20000);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_init_region1_platform_id_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, 0x10000);
	status |= pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM2_DATA,
		PFM2_DATA_LEN, PFM2_HASH, PFM2_SIGNATURE, 0x20000);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM2_DATA, PFM2_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x20000, 0, -1, PFM_HEADER_SIZE));

	status = flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_init_region2_platform_id_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, 0x10000);
	status |= pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM2_DATA,
		PFM2_DATA_LEN, PFM2_HASH, PFM2_SIGNATURE, 0x20000);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM2_DATA, PFM2_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x20000, 0, -1, PFM_HEADER_SIZE));

	status |= pfm_manager_flash_testing_read_platform_id (&flash_mock, PFM_DATA, PFM_DATA_LEN,
		0x10000);
	status = flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_init_pending_versions_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, 0x10000);
	status |= pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM2_DATA,
		PFM2_DATA_LEN, PFM2_HASH, PFM2_SIGNATURE, 0x20000);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM2_DATA, PFM2_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x20000, 0, -1, PFM_HEADER_SIZE));

	status |= pfm_manager_flash_testing_read_platform_id (&flash_mock, PFM_DATA, PFM_DATA_LEN,
		0x10000);
	status |= pfm_manager_flash_testing_read_platform_id (&flash_mock, PFM2_DATA, PFM2_DATA_LEN,
		0x20000);

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_init_empty_manifest_pending_erase_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	struct manifest_header *header;
	struct pfm_allowable_firmware_header *allowed_header;
	struct pfm_key_manifest_header *manifest_header;
	struct pfm_platform_header *platform_header;
	int man_offset = PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE;
	int plat_offset = man_offset + PFM_MANIFEST_HEADER_SIZE;
	int sig_offset = plat_offset + PFM_PLATFORM_HEADER_SIZE + strlen (PFM_PLATFORM_ID) + 3;
	uint8_t pfm[sig_offset + PFM_SIGNATURE_LEN];
	size_t length = sizeof (pfm);

	TEST_START;

	memset (pfm, 0, sizeof (pfm));

	header = (struct manifest_header*) pfm;
	header->length = sizeof (pfm);
	header->magic = PFM_MAGIC_NUM;
	header->sig_length = PFM_SIGNATURE_LEN;

	allowed_header = (struct pfm_allowable_firmware_header*) &pfm[PFM_HEADER_SIZE];
	allowed_header->length = PFM_ALLOWED_HEADER_SIZE;
	allowed_header->fw_count = 0;

	manifest_header = (struct pfm_key_manifest_header*) &pfm[man_offset];
	manifest_header->length = PFM_MANIFEST_HEADER_SIZE;
	manifest_header->key_count = 0;

	platform_header = (struct pfm_platform_header*) &pfm[plat_offset];
	platform_header->length = PFM_PLATFORM_HEADER_SIZE + strlen (PFM_PLATFORM_ID) + 3;
	platform_header->id_length = strlen (PFM_PLATFORM_ID);
	memcpy (&pfm[plat_offset + PFM_PLATFORM_HEADER_SIZE], PFM_PLATFORM_ID,
		strlen (PFM_PLATFORM_ID));

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	/* Use blank check to simulate empty PFM regions. */
	status = flash_master_mock_expect_blank_check (&flash_mock, 0x10000, PFM_HEADER_SIZE);

	status |= pfm_manager_flash_testing_verify_empty_pfm (&flash_mock, &verification, pfm, length,
		man_offset, plat_offset, sig_offset, 0x20000);

	/* Get versions list. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm, sizeof (pfm),
		FLASH_EXP_READ_CMD (0x03, 0x20000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm + PFM_HEADER_SIZE,
		length - PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x20000 + PFM_HEADER_SIZE, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	/* Erase manifest regions. */
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_init_empty_manifest_active_erase_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	struct manifest_header *header;
	struct pfm_allowable_firmware_header *allowed_header;
	struct pfm_key_manifest_header *manifest_header;
	struct pfm_platform_header *platform_header;
	int man_offset = PFM_HEADER_SIZE + PFM_ALLOWED_HEADER_SIZE;
	int plat_offset = man_offset + PFM_MANIFEST_HEADER_SIZE;
	int sig_offset = plat_offset + PFM_PLATFORM_HEADER_SIZE + strlen (PFM_PLATFORM_ID) + 3;
	uint8_t pfm[sig_offset + PFM_SIGNATURE_LEN];
	size_t length = sizeof (pfm);

	TEST_START;

	memset (pfm, 0, sizeof (pfm));

	header = (struct manifest_header*) pfm;
	header->length = sizeof (pfm);
	header->magic = PFM_MAGIC_NUM;
	header->sig_length = PFM_SIGNATURE_LEN;

	allowed_header = (struct pfm_allowable_firmware_header*) &pfm[PFM_HEADER_SIZE];
	allowed_header->length = PFM_ALLOWED_HEADER_SIZE;
	allowed_header->fw_count = 0;

	manifest_header = (struct pfm_key_manifest_header*) &pfm[man_offset];
	manifest_header->length = PFM_MANIFEST_HEADER_SIZE;
	manifest_header->key_count = 0;

	platform_header = (struct pfm_platform_header*) &pfm[plat_offset];
	platform_header->length = PFM_PLATFORM_HEADER_SIZE + strlen (PFM_PLATFORM_ID) + 3;
	platform_header->id_length = strlen (PFM_PLATFORM_ID);
	memcpy (&pfm[plat_offset + PFM_PLATFORM_HEADER_SIZE], PFM_PLATFORM_ID,
		strlen (PFM_PLATFORM_ID));

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	/* Use blank check to simulate empty PFM regions. */
	status = flash_master_mock_expect_blank_check (&flash_mock, 0x10000, PFM_HEADER_SIZE);

	status |= pfm_manager_flash_testing_verify_empty_pfm (&flash_mock, &verification, pfm, length,
		man_offset, plat_offset, sig_offset, 0x20000);

	/* Get versions list. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm, sizeof (pfm),
		FLASH_EXP_READ_CMD (0x03, 0x20000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pfm + PFM_HEADER_SIZE,
		length - PFM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x20000 + PFM_HEADER_SIZE, 0, -1, PFM_ALLOWED_HEADER_SIZE));

	/* Erase manifest regions. */
	status |= flash_master_mock_expect_erase_flash (&flash_mock, 0x20000);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_init_port (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init_port (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_port (&manager.base.base);
	CuAssertIntEquals (test, 1, status);

	CuAssertPtrNotNull (test, manager.base.get_active_pfm);
	CuAssertPtrNotNull (test, manager.base.get_pending_pfm);
	CuAssertPtrNotNull (test, manager.base.free_pfm);
	CuAssertPtrNotNull (test, manager.base.base.activate_pending_manifest);
	CuAssertPtrNotNull (test, manager.base.base.clear_pending_region);
	CuAssertPtrNotNull (test, manager.base.base.write_pending_data);
	CuAssertPtrNotNull (test, manager.base.base.verify_pending_manifest);
	CuAssertPtrNotNull (test, manager.base.base.clear_all_manifests);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	manager.base.get_active_pfm (&manager.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_init_port_negative (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init_port (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base, -1);
	CuAssertIntEquals (test, 0, status);

	status = manifest_manager_get_port (&manager.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, manager.base.get_active_pfm);
	CuAssertPtrNotNull (test, manager.base.get_pending_pfm);
	CuAssertPtrNotNull (test, manager.base.free_pfm);
	CuAssertPtrNotNull (test, manager.base.base.activate_pending_manifest);
	CuAssertPtrNotNull (test, manager.base.base.clear_pending_region);
	CuAssertPtrNotNull (test, manager.base.base.write_pending_data);
	CuAssertPtrNotNull (test, manager.base.base.verify_pending_manifest);
	CuAssertPtrNotNull (test, manager.base.base.clear_all_manifests);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	manager.base.get_active_pfm (&manager.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_init_port_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init_port (NULL, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base, 1);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = pfm_manager_flash_init_port (&manager, NULL, &pfm2, &state_mgr, &hash.base,
		&verification.base, 1);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = pfm_manager_flash_init_port (&manager, &pfm1, NULL, &state_mgr, &hash.base,
		&verification.base, 1);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = pfm_manager_flash_init_port (&manager, &pfm1, &pfm2, NULL, &hash.base,
		&verification.base, 1);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = pfm_manager_flash_init_port (&manager, &pfm1, &pfm2, &state_mgr, NULL,
		&verification.base, 1);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = pfm_manager_flash_init_port (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		NULL, 1);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_release_null (CuTest *test)
{
	TEST_START;

	pfm_manager_flash_release (NULL);
}

static void pfm_manager_flash_test_get_active_pfm_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (NULL));

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}



static void pfm_manager_flash_test_get_pending_pfm_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = state_mgr.save_active_manifest (&state_mgr, 0, MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, NULL, 0, NULL, NULL, false);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (NULL));

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_activate_pending_pfm_region2 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	enum manifest_region active;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, PFM2_DATA, PFM2_DATA_LEN, PFM2_HASH,
		PFM2_SIGNATURE, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, true);

	status = manager.base.base.activate_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &pfm2, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	active = state_mgr.get_active_manifest (&state_mgr, 0);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, false, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_activate_pending_pfm_region1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	enum manifest_region active;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = state_mgr.save_active_manifest (&state_mgr, 0, MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification,
		PFM2_DATA, PFM2_DATA_LEN, PFM2_HASH, PFM2_SIGNATURE, PFM_DATA, PFM_DATA_LEN, PFM_HASH,
		PFM_SIGNATURE, false);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, true);

	status = manager.base.base.activate_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	active = state_mgr.get_active_manifest (&state_mgr, 0);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, false, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_activate_pending_pfm_region2_notify_observers (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	struct pfm_observer_mock observer;
	int status;
	enum manifest_region active;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, PFM2_DATA, PFM2_DATA_LEN, PFM2_HASH,
		PFM2_SIGNATURE, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_add_observer (&manager.base, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_pfm_activated, &observer, 0,
		MOCK_ARG (&pfm2));
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, true);

	status = manager.base.base.activate_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &pfm2, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	active = state_mgr.get_active_manifest (&state_mgr, 0);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, false, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_activate_pending_pfm_region1_notify_observers (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	struct pfm_observer_mock observer;
	int status;
	enum manifest_region active;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = state_mgr.save_active_manifest (&state_mgr, 0, MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification,
		PFM2_DATA, PFM2_DATA_LEN, PFM2_HASH, PFM2_SIGNATURE, PFM_DATA, PFM_DATA_LEN, PFM_HASH,
		PFM_SIGNATURE, false);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_add_observer (&manager.base, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_pfm_activated, &observer, 0,
		MOCK_ARG (&pfm1));
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, true);

	status = manager.base.base.activate_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	active = state_mgr.get_active_manifest (&state_mgr, 0);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, false, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_activate_pending_pfm_no_pending_region2 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, true);

	status = manager.base.base.activate_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_NONE_PENDING, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_activate_pending_pfm_no_pending_region1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = state_mgr.save_active_manifest (&state_mgr, 0, MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL, 0,
		NULL, NULL, PFM_DATA, PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, false);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, true);

	status = manager.base.base.activate_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_NONE_PENDING, status);

	CuAssertPtrEquals (test, &pfm2, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_activate_pending_pfm_no_pending_notify_observers (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	struct pfm_observer_mock observer;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_add_observer (&manager.base, &observer.base);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, true);

	status = manager.base.base.activate_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_NONE_PENDING, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_activate_pending_pfm_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, PFM2_DATA, PFM2_DATA_LEN, PFM2_HASH,
		PFM2_SIGNATURE, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, true);

	status = manager.base.base.activate_pending_manifest (NULL);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_clear_pending_region_region2 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);

	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock, 0x20000, 0x10000);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_clear_pending_region_region1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = state_mgr.save_active_manifest (&state_mgr, 0, MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);

	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock, 0x10000, 0x10000);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_clear_pending_region_invalidate_pending_region2 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, PFM2_DATA, PFM2_DATA_LEN, PFM2_HASH,
		PFM2_SIGNATURE, true);
	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock, 0x20000, 0x10000);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_clear_pending_region_invalidate_pending_region1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = state_mgr.save_active_manifest (&state_mgr, 0, MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification,
		PFM2_DATA, PFM2_DATA_LEN, PFM2_HASH, PFM2_SIGNATURE, PFM_DATA, PFM_DATA_LEN, PFM_HASH,
		PFM_SIGNATURE, false);

	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock, 0x10000, 0x10000);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &pfm2, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_clear_pending_region_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_pending_region (NULL, 1);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_clear_pending_region_manifest_too_large (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_pending_region (&manager.base.base, FLASH_BLOCK_SIZE + 1);
	CuAssertIntEquals (test, FLASH_UPDATER_TOO_LARGE, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_clear_pending_region_manifest_too_large_with_pending (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, PFM2_DATA, PFM2_DATA_LEN, PFM2_HASH,
		PFM2_SIGNATURE, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_pending_region (&manager.base.base, FLASH_BLOCK_SIZE + 1);
	CuAssertIntEquals (test, FLASH_UPDATER_TOO_LARGE, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, &pfm2, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_clear_pending_region_erase_error_region2 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, PFM2_DATA, PFM2_DATA_LEN, PFM2_HASH,
		PFM2_SIGNATURE, true);

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_clear_pending_region_erase_error_region1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = state_mgr.save_active_manifest (&state_mgr, 0, MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification,
		PFM2_DATA, PFM2_DATA_LEN, PFM2_HASH, PFM2_SIGNATURE, PFM_DATA, PFM_DATA_LEN, PFM_HASH,
		PFM_SIGNATURE, false);

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, &pfm2, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_clear_pending_region_pfm_in_use_region2 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	struct pfm *pending;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, PFM2_DATA, PFM2_DATA_LEN, PFM2_HASH,
		PFM2_SIGNATURE, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	pending = manager.base.get_pending_pfm (&manager.base);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, MANIFEST_MANAGER_PENDING_IN_USE, status);

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	manager.base.free_pfm (&manager.base, pending);

	status = flash_master_mock_expect_erase_flash_verify (&flash_mock, 0x20000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	manager.base.get_pending_pfm (&manager.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_clear_pending_region_pfm_in_use_region1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	struct pfm *pending;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = state_mgr.save_active_manifest (&state_mgr, 0, MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification,
		PFM2_DATA, PFM2_DATA_LEN, PFM2_HASH, PFM2_SIGNATURE, PFM_DATA, PFM_DATA_LEN, PFM_HASH,
		PFM_SIGNATURE, false);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	pending = manager.base.get_pending_pfm (&manager.base);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, MANIFEST_MANAGER_PENDING_IN_USE, status);

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	manager.base.free_pfm (&manager.base, pending);

	status = flash_master_mock_expect_erase_flash_verify (&flash_mock, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	manager.base.get_pending_pfm (&manager.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_clear_pending_region_pfm_in_use_multiple_region2 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	struct pfm *pending1;
	struct pfm *pending2;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, PFM2_DATA, PFM2_DATA_LEN, PFM2_HASH,
		PFM2_SIGNATURE, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	pending1 = manager.base.get_pending_pfm (&manager.base);
	pending2 = manager.base.get_pending_pfm (&manager.base);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, MANIFEST_MANAGER_PENDING_IN_USE, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	manager.base.free_pfm (&manager.base, pending1);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, MANIFEST_MANAGER_PENDING_IN_USE, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	manager.base.free_pfm (&manager.base, pending2);

	status = flash_master_mock_expect_erase_flash_verify (&flash_mock, 0x20000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	manager.base.get_pending_pfm (&manager.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_clear_pending_region_pfm_in_use_multiple_region1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	struct pfm *pending1;
	struct pfm *pending2;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = state_mgr.save_active_manifest (&state_mgr, 0, MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification,
		PFM2_DATA, PFM2_DATA_LEN, PFM2_HASH, PFM2_SIGNATURE, PFM_DATA, PFM_DATA_LEN, PFM_HASH,
		PFM_SIGNATURE, false);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	pending1 = manager.base.get_pending_pfm (&manager.base);
	pending2 = manager.base.get_pending_pfm (&manager.base);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, MANIFEST_MANAGER_PENDING_IN_USE, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	manager.base.free_pfm (&manager.base, pending1);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, MANIFEST_MANAGER_PENDING_IN_USE, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	manager.base.free_pfm (&manager.base, pending2);

	status = flash_master_mock_expect_erase_flash_verify (&flash_mock, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	manager.base.get_pending_pfm (&manager.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_clear_pending_region_in_use_after_activate_region2 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	struct pfm *active;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, PFM2_DATA, PFM2_DATA_LEN, PFM2_HASH,
		PFM2_SIGNATURE, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	active = manager.base.get_active_pfm (&manager.base);

	status = manager.base.base.activate_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, MANIFEST_MANAGER_PENDING_IN_USE, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	manager.base.free_pfm (&manager.base, active);

	status = flash_master_mock_expect_erase_flash_verify (&flash_mock, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	manager.base.get_pending_pfm (&manager.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_clear_pending_region_in_use_after_activate_region1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	struct pfm *active;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = state_mgr.save_active_manifest (&state_mgr, 0, MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification,
		PFM2_DATA, PFM2_DATA_LEN, PFM2_HASH, PFM2_SIGNATURE, PFM_DATA, PFM_DATA_LEN, PFM_HASH,
		PFM_SIGNATURE, false);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	active = manager.base.get_active_pfm (&manager.base);

	status = manager.base.base.activate_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, MANIFEST_MANAGER_PENDING_IN_USE, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	manager.base.free_pfm (&manager.base, active);

	status = flash_master_mock_expect_erase_flash_verify (&flash_mock, 0x20000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	manager.base.get_pending_pfm (&manager.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_clear_pending_no_pending_in_use_region2 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	manager.base.get_pending_pfm (&manager.base);

	status = flash_master_mock_expect_erase_flash_verify (&flash_mock, 0x20000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_clear_pending_no_pending_in_use_region1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = state_mgr.save_active_manifest (&state_mgr, 0, MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL, 0,
		NULL, NULL, PFM_DATA, PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, false);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	manager.base.get_pending_pfm (&manager.base);

	status = flash_master_mock_expect_erase_flash_verify (&flash_mock, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_clear_pending_region_extra_free_call (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	struct pfm *pending;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, PFM2_DATA, PFM2_DATA_LEN, PFM2_HASH,
		PFM2_SIGNATURE, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	pending = manager.base.get_pending_pfm (&manager.base);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, MANIFEST_MANAGER_PENDING_IN_USE, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	manager.base.free_pfm (&manager.base, pending);
	manager.base.free_pfm (&manager.base, pending);

	pending = manager.base.get_pending_pfm (&manager.base);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, MANIFEST_MANAGER_PENDING_IN_USE, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	manager.base.free_pfm (&manager.base, pending);

	status = flash_master_mock_expect_erase_flash_verify (&flash_mock, 0x20000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	manager.base.get_pending_pfm (&manager.base);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_clear_pending_region_free_null_region2 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, PFM2_DATA, PFM2_DATA_LEN, PFM2_HASH,
		PFM2_SIGNATURE, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	manager.base.get_pending_pfm (&manager.base);
	manager.base.free_pfm (&manager.base, NULL);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, MANIFEST_MANAGER_PENDING_IN_USE, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_clear_pending_region_free_null_region1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = state_mgr.save_active_manifest (&state_mgr, 0, MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification,
		PFM2_DATA, PFM2_DATA_LEN, PFM2_HASH, PFM2_SIGNATURE, PFM_DATA, PFM_DATA_LEN, PFM_HASH,
		PFM_SIGNATURE, false);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	manager.base.get_pending_pfm (&manager.base);
	manager.base.free_pfm (&manager.base, NULL);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, MANIFEST_MANAGER_PENDING_IN_USE, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_clear_pending_region_free_null_manager (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	struct pfm *pending;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, PFM2_DATA, PFM2_DATA_LEN, PFM2_HASH,
		PFM2_SIGNATURE, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	pending = manager.base.get_pending_pfm (&manager.base);
	manager.base.free_pfm (NULL, pending);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, MANIFEST_MANAGER_PENDING_IN_USE, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_write_pending_data_region2 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);

	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock, 0x20000, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x20000, data, sizeof (data));

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.write_pending_data (&manager.base.base, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_write_pending_data_region1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = state_mgr.save_active_manifest (&state_mgr, 0, MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);

	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock, 0x10000, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x10000, data, sizeof (data));

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.write_pending_data (&manager.base.base, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_write_pending_data_multiple (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t data2[] = {0x05, 0x06, 0x07, 0x08, 0x09};
	uint8_t data3[] = {0x0a, 0x0b, 0x0c};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);

	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock, 0x20000, 0x10000);

	status |= flash_master_mock_expect_write (&flash_mock, 0x20000, data1, 4);
	status |= flash_master_mock_expect_write (&flash_mock, 0x20004, data2, 5);
	status |= flash_master_mock_expect_write (&flash_mock, 0x20009, data3, 3);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.write_pending_data (&manager.base.base, data1, sizeof (data1));
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.write_pending_data (&manager.base.base, data2, sizeof (data2));
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.write_pending_data (&manager.base.base, data3, sizeof (data3));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_write_pending_data_block_end (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t fill[FLASH_BLOCK_SIZE - sizeof (data)] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);

	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock, 0x20000, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x20000, fill, sizeof (fill));
	status |= flash_master_mock_expect_write (&flash_mock, 0x2fffc, data, sizeof (data));

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	/* Fill with data to write at the end of the flash block. */
	status = manager.base.base.write_pending_data (&manager.base.base, fill, sizeof (fill));
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.write_pending_data (&manager.base.base, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_write_pending_data_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);

	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock, 0x20000, 0x10000);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.write_pending_data (NULL, data, sizeof (data));
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = manager.base.base.write_pending_data (&manager.base.base, NULL, sizeof (data));
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_write_pending_data_write_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);

	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock, 0x20000, 0x10000);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.write_pending_data (&manager.base.base, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_write_pending_data_write_after_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t data2[] = {0x05, 0x06, 0x07, 0x08, 0x09};
	uint8_t data3[] = {0x0a, 0x0b, 0x0c};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);

	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock, 0x20000, 0x10000);

	status |= flash_master_mock_expect_write (&flash_mock, 0x20000, data1, 4);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_write (&flash_mock, 0x20004, data3, 3);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.write_pending_data (&manager.base.base, data1, sizeof (data1));
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.write_pending_data (&manager.base.base, data2, sizeof (data2));
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = manager.base.base.write_pending_data (&manager.base.base, data3, sizeof (data3));
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_write_pending_data_partial_write (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t fill[FLASH_PAGE_SIZE - 1] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);

	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock, 0x20000, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x20000, fill, sizeof (fill));

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&flash_mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&flash_mock, 0,
		FLASH_EXP_WRITE_CMD (0x02, 0x200ff, 0, data, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	/* Partially fill the page to force a write across pages. */
	status = manager.base.base.write_pending_data (&manager.base.base, fill, sizeof (fill));
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.write_pending_data (&manager.base.base, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_UPDATER_INCOMPLETE_WRITE, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_write_pending_data_write_after_partial_write (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t data2[] = {0x05, 0x06, 0x07, 0x08, 0x09};
	uint8_t fill[FLASH_PAGE_SIZE - 1] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);

	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock, 0x20000, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x20000, fill, sizeof (fill));

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&flash_mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&flash_mock, 0,
		FLASH_EXP_WRITE_CMD (0x02, 0x200ff, 0, data1, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);

	status |= flash_master_mock_expect_write (&flash_mock, 0x20100, data2, 5);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	/* Partially fill the page to force a write across pages. */
	status = manager.base.base.write_pending_data (&manager.base.base, fill, sizeof (fill));
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.write_pending_data (&manager.base.base, data1, sizeof (data1));
	CuAssertIntEquals (test, FLASH_UPDATER_INCOMPLETE_WRITE, status);

	status = manager.base.base.write_pending_data (&manager.base.base, data2, sizeof (data2));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_write_pending_data_without_clear (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.write_pending_data (&manager.base.base, data, sizeof (data));
	CuAssertIntEquals (test, MANIFEST_MANAGER_NOT_CLEARED, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_write_pending_data_restart_write (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t data2[] = {0x05, 0x06, 0x07, 0x08, 0x09};
	uint8_t data3[] = {0x0a, 0x0b, 0x0c};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);

	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock, 0x20000, 0x10000);

	status |= flash_master_mock_expect_write (&flash_mock, 0x20000, data1, 4);
	status |= flash_master_mock_expect_write (&flash_mock, 0x20004, data2, 5);

	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock, 0x20000, 0x10000);

	status |= flash_master_mock_expect_write (&flash_mock, 0x20000, data3, 3);

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.write_pending_data (&manager.base.base, data1, sizeof (data1));
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.write_pending_data (&manager.base.base, data2, sizeof (data2));
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.write_pending_data (&manager.base.base, data3, sizeof (data3));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_write_pending_data_too_long (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t fill[FLASH_BLOCK_SIZE - sizeof (data) + 1] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);

	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock, 0x20000, 0x10000);
	status |= flash_master_mock_expect_write (&flash_mock, 0x20000, fill, sizeof (fill));

	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	/* Fill with data to write at the end of the flash block. */
	status = manager.base.base.write_pending_data (&manager.base.base, fill, sizeof (fill));
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.write_pending_data (&manager.base.base, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_UPDATER_OUT_OF_SPACE, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_write_pending_data_pfm_in_use (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	struct pfm *pending;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, PFM2_DATA, PFM2_DATA_LEN, PFM2_HASH,
		PFM2_SIGNATURE, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	pending = manager.base.get_pending_pfm (&manager.base);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, MANIFEST_MANAGER_PENDING_IN_USE, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.write_pending_data (&manager.base.base, data, sizeof (data));
	CuAssertIntEquals (test, MANIFEST_MANAGER_NOT_CLEARED, status);

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	manager.base.free_pfm (&manager.base, pending);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_region2 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	pfm_manager_flash_testing_write_new_pfm (test, &manager, &flash_mock, 0x20000);

	status = pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, 0x20000);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, &pfm2, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_region1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = state_mgr.save_active_manifest (&state_mgr, 0, MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	pfm_manager_flash_testing_write_new_pfm (test, &manager, &flash_mock, 0x10000);

	status |= pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, 0x10000);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, &pfm1, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_region2_notify_observers (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	struct pfm_observer_mock observer;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	pfm_manager_flash_testing_write_new_pfm (test, &manager, &flash_mock, 0x20000);

	status = pfm_manager_add_observer (&manager.base, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, 0x20000);
	status |= mock_expect (&observer.mock, observer.base.on_pfm_verified, &observer, 0,
		MOCK_ARG (&pfm2));

	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, &pfm2, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_region1_notify_observers (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	struct pfm_observer_mock observer;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = state_mgr.save_active_manifest (&state_mgr, 0, MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	pfm_manager_flash_testing_write_new_pfm (test, &manager, &flash_mock, 0x10000);

	status = pfm_manager_add_observer (&manager.base, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, 0x10000);
	status |= mock_expect (&observer.mock, observer.base.on_pfm_verified, &observer, 0,
		MOCK_ARG (&pfm1));

	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, &pfm1, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_already_valid_region2 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL, 0,
		NULL, NULL, PFM_DATA, PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, &pfm2, manager.base.get_pending_pfm (&manager.base));

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_HAS_PENDING, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, &pfm2, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, false, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_already_valid_region1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = state_mgr.save_active_manifest (&state_mgr, 0, MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, NULL, 0, NULL, NULL, false);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, &pfm1, manager.base.get_pending_pfm (&manager.base));

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_HAS_PENDING, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, &pfm1, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, false, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_already_valid_notify_observers (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	struct pfm_observer_mock observer;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL, 0,
		NULL, NULL, PFM_DATA, PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, &pfm2, manager.base.get_pending_pfm (&manager.base));

	status = pfm_manager_add_observer (&manager.base, &observer.base);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_HAS_PENDING, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, &pfm2, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, false, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_with_active (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	pfm_manager_flash_testing_write_new_pfm (test, &manager, &flash_mock, 0x20000);

	status = pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM2_DATA,
		PFM2_DATA_LEN, PFM2_HASH, PFM2_SIGNATURE, 0x20000);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM2_DATA, PFM2_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x20000, 0, -1, PFM_HEADER_SIZE));

	status |= pfm_manager_flash_testing_read_platform_id (&flash_mock, PFM_DATA, PFM_DATA_LEN,
		0x10000);
	status |= pfm_manager_flash_testing_read_platform_id (&flash_mock, PFM2_DATA, PFM2_DATA_LEN,
		0x20000);

	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, &pfm2, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_already_valid_with_active (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, PFM2_DATA, PFM2_DATA_LEN, PFM2_HASH,
		PFM2_SIGNATURE, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, &pfm2, manager.base.get_pending_pfm (&manager.base));

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_HAS_PENDING, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, &pfm2, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, false, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_lower_id (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification,
		PFM2_DATA, PFM2_DATA_LEN, PFM2_HASH, PFM2_SIGNATURE, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	pfm_manager_flash_testing_write_new_pfm (test, &manager, &flash_mock, 0x20000);

	status = pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, 0x20000);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM2_DATA, PFM2_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x20000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ID, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, false, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_same_id (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	pfm_manager_flash_testing_write_new_pfm (test, &manager, &flash_mock, 0x20000);

	status = pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, 0x20000);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x20000, 0, -1, PFM_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ID, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, false, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_different_platform_id (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	pfm_manager_flash_testing_write_new_pfm (test, &manager, &flash_mock, 0x20000);

	status = pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM_PLATFORM2_DATA,
		PFM_PLATFORM2_DATA_LEN, PFM_PLATFORM2_HASH, PFM_PLATFORM2_SIGNATURE, 0x20000);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_PLATFORM2_DATA,
		PFM_PLATFORM2_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x20000, 0, -1, PFM_HEADER_SIZE));

	status |= pfm_manager_flash_testing_read_platform_id (&flash_mock, PFM_DATA, PFM_DATA_LEN,
		0x10000);
	status |= pfm_manager_flash_testing_read_platform_id (&flash_mock, PFM_PLATFORM2_DATA,
		PFM_PLATFORM2_DATA_LEN, 0x20000);

	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INCOMPATIBLE, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, false, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_no_clear_region2 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_NONE_PENDING, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, false, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_no_clear_region1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = state_mgr.save_active_manifest (&state_mgr, 0, MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_NONE_PENDING, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, false, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_extra_data_written (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int offset;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	offset = pfm_manager_flash_testing_write_new_pfm (test, &manager, &flash_mock, 0x20000);

	status = flash_master_mock_expect_write (&flash_mock, 0x20000 + offset, data, sizeof (data));

	status |= pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, 0x20000);

	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.write_pending_data (&manager.base.base, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, &pfm2, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	pfm_manager_flash_testing_write_new_pfm (test, &manager, &flash_mock, 0x20000);

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (NULL);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, false, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_verify_error_region2 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	pfm_manager_flash_testing_write_new_pfm (test, &manager, &flash_mock, 0x20000);

	status = flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, false, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_verify_error_region1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = state_mgr.save_active_manifest (&state_mgr, 0, MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	pfm_manager_flash_testing_write_new_pfm (test, &manager, &flash_mock, 0x10000);

	status = flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, false, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_verify_error_notify_observers (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	struct pfm_observer_mock observer;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	pfm_manager_flash_testing_write_new_pfm (test, &manager, &flash_mock, 0x20000);

	status = pfm_manager_add_observer (&manager.base, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, false, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = pfm_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_verify_fail_region2 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	pfm_manager_flash_testing_write_new_pfm (test, &manager, &flash_mock, 0x20000);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x20000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM2_SIGNATURE, PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x20000 + PFM_SIGNATURE_OFFSET, 0, -1, PFM_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x20000, PFM_DATA,
		PFM_DATA_LEN - PFM_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG_NOT_NULL, MOCK_ARG (PFM_HASH_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (PFM_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, false, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_verify_fail_region1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = state_mgr.save_active_manifest (&state_mgr, 0, MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	pfm_manager_flash_testing_write_new_pfm (test, &manager, &flash_mock, 0x10000);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM2_SIGNATURE, PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_SIGNATURE_OFFSET, 0, -1, PFM_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PFM_DATA,
		PFM_DATA_LEN - PFM_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG_NOT_NULL, MOCK_ARG (PFM_HASH_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (PFM_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, false, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_verify_fail_ecc_region2 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	pfm_manager_flash_testing_write_new_pfm (test, &manager, &flash_mock, 0x20000);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x20000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM2_SIGNATURE, PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x20000 + PFM_SIGNATURE_OFFSET, 0, -1, PFM_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x20000, PFM_DATA,
		PFM_DATA_LEN - PFM_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		ECC_ENGINE_BAD_SIGNATURE, MOCK_ARG_NOT_NULL, MOCK_ARG (PFM_HASH_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (PFM_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, ECC_ENGINE_BAD_SIGNATURE, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, false, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_verify_fail_ecc_region1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = state_mgr.save_active_manifest (&state_mgr, 0, MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	pfm_manager_flash_testing_write_new_pfm (test, &manager, &flash_mock, 0x10000);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM2_SIGNATURE, PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PFM_SIGNATURE_OFFSET, 0, -1, PFM_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PFM_DATA,
		PFM_DATA_LEN - PFM_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		ECC_ENGINE_BAD_SIGNATURE, MOCK_ARG_NOT_NULL, MOCK_ARG (PFM_HASH_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (PFM_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, ECC_ENGINE_BAD_SIGNATURE, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, false, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_verify_after_verify_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	pfm_manager_flash_testing_write_new_pfm (test, &manager, &flash_mock, 0x20000);

	status = flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, false, status);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_NONE_PENDING, status);

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, false, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_verify_after_verify_fail (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	pfm_manager_flash_testing_write_new_pfm (test, &manager, &flash_mock, 0x20000);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x20000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM2_SIGNATURE, PFM_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x20000 + PFM_SIGNATURE_OFFSET, 0, -1, PFM_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x20000, PFM_DATA,
		PFM_DATA_LEN - PFM_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG_NOT_NULL, MOCK_ARG (PFM_HASH_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (PFM_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, false, status);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_NONE_PENDING, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_write_after_verify (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_write_new_pfm (test, &manager, &flash_mock, 0x20000);

	status = pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, 0x20000);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, &pfm2, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = manager.base.base.write_pending_data (&manager.base.base, data, sizeof (data));
	CuAssertIntEquals (test, MANIFEST_MANAGER_NOT_CLEARED, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, &pfm2, manager.base.get_pending_pfm (&manager.base));

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_write_after_verify_with_active (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_write_new_pfm (test, &manager, &flash_mock, 0x20000);

	status = pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM2_DATA,
		PFM2_DATA_LEN, PFM2_HASH, PFM2_SIGNATURE, 0x20000);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM2_DATA, PFM2_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x20000, 0, -1, PFM_HEADER_SIZE));

	status |= pfm_manager_flash_testing_read_platform_id (&flash_mock, PFM_DATA, PFM_DATA_LEN,
		0x10000);
	status |= pfm_manager_flash_testing_read_platform_id (&flash_mock, PFM2_DATA, PFM2_DATA_LEN,
		0x20000);

	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, &pfm2, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = manager.base.base.write_pending_data (&manager.base.base, data, sizeof (data));
	CuAssertIntEquals (test, MANIFEST_MANAGER_NOT_CLEARED, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, &pfm2, manager.base.get_pending_pfm (&manager.base));

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_write_after_verify_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_write_new_pfm (test, &manager, &flash_mock, 0x20000);

	status = flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, false, status);

	status = manager.base.base.write_pending_data (&manager.base.base, data, sizeof (data));
	CuAssertIntEquals (test, MANIFEST_MANAGER_NOT_CLEARED, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_with_active_id2_error_region2 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	pfm_manager_flash_testing_write_new_pfm (test, &manager, &flash_mock, 0x20000);

	status = pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM2_DATA,
		PFM2_DATA_LEN, PFM2_HASH, PFM2_SIGNATURE, 0x20000);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, false, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_with_active_id2_error_region1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = state_mgr.save_active_manifest (&state_mgr, 0, MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL, 0,
		NULL, NULL, PFM_DATA, PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, false);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &pfm2, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	pfm_manager_flash_testing_write_new_pfm (test, &manager, &flash_mock, 0x10000);

	status = pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM2_DATA,
		PFM2_DATA_LEN, PFM2_HASH, PFM2_SIGNATURE, 0x10000);

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, &pfm2, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, false, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_with_active_id1_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	pfm_manager_flash_testing_write_new_pfm (test, &manager, &flash_mock, 0x20000);

	status = pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM2_DATA,
		PFM2_DATA_LEN, PFM2_HASH, PFM2_SIGNATURE, 0x20000);

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, false, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_write_after_id_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_write_new_pfm (test, &manager, &flash_mock, 0x20000);

	status = pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM2_DATA,
		PFM2_DATA_LEN, PFM2_HASH, PFM2_SIGNATURE, 0x20000);

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, false, status);

	status = manager.base.base.write_pending_data (&manager.base.base, data, sizeof (data));
	CuAssertIntEquals (test, MANIFEST_MANAGER_NOT_CLEARED, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_platform_id2_error_region2 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	pfm_manager_flash_testing_write_new_pfm (test, &manager, &flash_mock, 0x20000);

	status = pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM2_DATA,
		PFM2_DATA_LEN, PFM2_HASH, PFM2_SIGNATURE, 0x20000);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM2_DATA, PFM2_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x20000, 0, -1, PFM_HEADER_SIZE));

	status |= pfm_manager_flash_testing_read_platform_id (&flash_mock, PFM_DATA, PFM_DATA_LEN,
		0x10000);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, false, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_platform_id2_error_region1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = state_mgr.save_active_manifest (&state_mgr, 0, MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL, 0,
		NULL, NULL, PFM_DATA, PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, false);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &pfm2, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	pfm_manager_flash_testing_write_new_pfm (test, &manager, &flash_mock, 0x10000);

	status = pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM2_DATA,
		PFM2_DATA_LEN, PFM2_HASH, PFM2_SIGNATURE, 0x10000);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x20000, 0, -1, PFM_HEADER_SIZE));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM2_DATA, PFM2_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, &pfm2, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, false, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_platform_id1_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	pfm_manager_flash_testing_write_new_pfm (test, &manager, &flash_mock, 0x20000);

	status |= pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM2_DATA,
		PFM2_DATA_LEN, PFM2_HASH, PFM2_SIGNATURE, 0x20000);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM2_DATA, PFM2_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x20000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, false, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_write_after_platform_id_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_write_new_pfm (test, &manager, &flash_mock, 0x20000);

	status = pfm_manager_flash_testing_verify_pfm (&flash_mock, &verification, PFM2_DATA,
		PFM2_DATA_LEN, PFM2_HASH, PFM2_SIGNATURE, 0x20000);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM_DATA, PFM_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PFM_HEADER_SIZE));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PFM2_DATA, PFM2_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x20000, 0, -1, PFM_HEADER_SIZE));

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, false, status);

	status = manager.base.base.write_pending_data (&manager.base.base, data, sizeof (data));
	CuAssertIntEquals (test, MANIFEST_MANAGER_NOT_CLEARED, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_incomplete_pfm (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock, 0x20000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_pending_region (&manager.base.base, 2);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INCOMPLETE_UPDATE, status);

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, false, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_verify_pending_pfm_write_after_incomplete_pfm (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock, 0x20000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_pending_region (&manager.base.base, 2);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_pfm_dirty (&state_mgr, false);

	status = manager.base.base.verify_pending_manifest (&manager.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INCOMPLETE_UPDATE, status);

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, false, status);

	status = manager.base.base.write_pending_data (&manager.base.base, data, sizeof (data));
	CuAssertIntEquals (test, MANIFEST_MANAGER_NOT_CLEARED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_clear_all_manifests_region1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, PFM2_DATA, PFM2_DATA_LEN, PFM2_HASH,
		PFM2_SIGNATURE, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock, 0x20000);
	status |= flash_master_mock_expect_erase_flash (&flash_mock, 0x10000);

	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_all_manifests (&manager.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_clear_all_manifests_region2 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = state_mgr.save_active_manifest (&state_mgr, 0, MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification,
		PFM2_DATA, PFM2_DATA_LEN, PFM2_HASH, PFM2_SIGNATURE, PFM_DATA, PFM_DATA_LEN, PFM_HASH,
		PFM_SIGNATURE, false);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock, 0x10000);
	status |= flash_master_mock_expect_erase_flash (&flash_mock, 0x20000);

	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_all_manifests (&manager.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_clear_all_manifests_only_active (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock, 0x20000);
	status |= flash_master_mock_expect_erase_flash (&flash_mock, 0x10000);

	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_all_manifests (&manager.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_clear_all_manifests_only_pending (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL, 0,
		NULL, NULL, PFM_DATA, PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock, 0x20000);
	status |= flash_master_mock_expect_erase_flash (&flash_mock, 0x10000);

	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_all_manifests (&manager.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_clear_all_manifests_no_pfms (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, NULL,
		0, NULL, NULL, NULL, 0, NULL, NULL, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock, 0x20000);
	status |= flash_master_mock_expect_erase_flash (&flash_mock, 0x10000);

	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_all_manifests (&manager.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_clear_all_manifests_pending_in_use (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	struct pfm *pending;
	struct pfm *active;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, PFM2_DATA, PFM2_DATA_LEN, PFM2_HASH,
		PFM2_SIGNATURE, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	pending = manager.base.get_pending_pfm (&manager.base);

	status = manager.base.base.clear_all_manifests (&manager.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_PENDING_IN_USE, status);

	manager.base.free_pfm (&manager.base, pending);

	active = manager.base.get_active_pfm (&manager.base);
	CuAssertPtrEquals (test, &pfm1, active);
	manager.base.free_pfm (&manager.base, active);

	pending = manager.base.get_pending_pfm (&manager.base);
	CuAssertPtrEquals (test, &pfm2, pending);
	manager.base.free_pfm (&manager.base, pending);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock, 0x20000);
	status |= flash_master_mock_expect_erase_flash (&flash_mock, 0x10000);

	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_all_manifests (&manager.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_clear_all_manifests_active_in_use (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	struct pfm *pending;
	struct pfm *active;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, PFM2_DATA, PFM2_DATA_LEN, PFM2_HASH,
		PFM2_SIGNATURE, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	active = manager.base.get_active_pfm (&manager.base);

	status = flash_master_mock_expect_erase_flash (&flash_mock, 0x20000);

	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_all_manifests (&manager.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_ACTIVE_IN_USE, status);

	manager.base.free_pfm (&manager.base, active);

	active = manager.base.get_active_pfm (&manager.base);
	CuAssertPtrEquals (test, &pfm1, active);
	manager.base.free_pfm (&manager.base, active);

	pending = manager.base.get_pending_pfm (&manager.base);
	CuAssertPtrEquals (test, NULL, pending);
	manager.base.free_pfm (&manager.base, pending);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock, 0x20000);
	status |= flash_master_mock_expect_erase_flash (&flash_mock, 0x10000);

	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_all_manifests (&manager.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_clear_all_manifests_during_update (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, PFM2_DATA, PFM2_DATA_LEN, PFM2_HASH,
		PFM2_SIGNATURE, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_verify (&flash_mock, 0x20000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_pending_region (&manager.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock, 0x20000);
	status |= flash_master_mock_expect_erase_flash (&flash_mock, 0x10000);

	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_all_manifests (&manager.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = manager.base.base.write_pending_data (&manager.base.base, data, sizeof (data));
	CuAssertIntEquals (test, MANIFEST_MANAGER_NOT_CLEARED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_clear_all_manifests_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, PFM2_DATA, PFM2_DATA_LEN, PFM2_HASH,
		PFM2_SIGNATURE, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_all_manifests (NULL);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, &pfm2, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_clear_all_manifests_erase_pending_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, PFM2_DATA, PFM2_DATA_LEN, PFM2_HASH,
		PFM2_SIGNATURE, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_all_manifests (&manager.base.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, &pfm1, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pfm_manager_flash_test_clear_all_manifests_erase_active_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct flash_master_mock flash_mock_state;
	struct spi_flash flash;
	struct spi_flash flash_state;
	struct state_manager state_mgr;
	struct pfm_flash pfm1;
	struct pfm_flash pfm2;
	struct pfm_manager_flash manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_testing_init_host_state (test, &state_mgr, &flash_mock_state, &flash_state);

	status = pfm_flash_init (&pfm1, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_flash_init (&pfm2, &flash, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_testing_initial_pfm_validation (&flash_mock, &verification, PFM_DATA,
		PFM_DATA_LEN, PFM_HASH, PFM_SIGNATURE, PFM2_DATA, PFM2_DATA_LEN, PFM2_HASH,
		PFM2_SIGNATURE, true);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_flash_init (&manager, &pfm1, &pfm2, &state_mgr, &hash.base,
		&verification.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock, 0x20000);
	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manager.base.base.clear_all_manifests (&manager.base.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, NULL, manager.base.get_active_pfm (&manager.base));
	CuAssertPtrEquals (test, NULL, manager.base.get_pending_pfm (&manager.base));

	status = host_state_manager_is_pfm_dirty (&state_mgr);
	CuAssertIntEquals (test, true, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pfm_manager_flash_release (&manager);

	host_state_manager_release (&state_mgr);
	pfm_flash_release (&pfm1);
	pfm_flash_release (&pfm2);
	spi_flash_release (&flash);
	spi_flash_release (&flash_state);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}


CuSuite* get_pfm_manager_flash_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, pfm_manager_flash_test_init);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_init_only_active_region1);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_init_only_active_region2);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_init_only_pending_region2);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_init_only_pending_region1);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_init_active_and_pending);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_init_region2_pending_lower_id);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_init_region2_pending_same_id);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_init_region2_pending_different_platform_id);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_init_region1_pending_lower_id);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_init_region1_pending_same_id);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_init_only_pending_region2_empty_manifest);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_init_only_pending_region1_empty_manifest);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_init_active_and_pending_empty_manifest);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_init_null);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_init_region1_flash_error);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_init_region2_flash_error);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_init_pfm_bad_signature);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_init_pfm_bad_signature_ecc);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_init_bad_length);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_init_bad_magic_number);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_init_malformed);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_init_region1_id_error);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_init_region2_id_error);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_init_region1_platform_id_error);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_init_region2_platform_id_error);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_init_pending_versions_error);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_init_empty_manifest_pending_erase_error);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_init_empty_manifest_active_erase_error);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_init_port);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_init_port_negative);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_init_port_null);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_release_null);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_get_active_pfm_null);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_get_pending_pfm_null);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_activate_pending_pfm_region2);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_activate_pending_pfm_region1);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_activate_pending_pfm_region2_notify_observers);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_activate_pending_pfm_region1_notify_observers);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_activate_pending_pfm_no_pending_region2);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_activate_pending_pfm_no_pending_region1);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_activate_pending_pfm_no_pending_notify_observers);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_activate_pending_pfm_null);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_clear_pending_region_region2);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_clear_pending_region_region1);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_clear_pending_region_invalidate_pending_region2);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_clear_pending_region_invalidate_pending_region1);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_clear_pending_region_null);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_clear_pending_region_manifest_too_large);
	SUITE_ADD_TEST (suite,
		pfm_manager_flash_test_clear_pending_region_manifest_too_large_with_pending);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_clear_pending_region_erase_error_region2);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_clear_pending_region_erase_error_region1);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_clear_pending_region_pfm_in_use_region2);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_clear_pending_region_pfm_in_use_region1);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_clear_pending_region_pfm_in_use_multiple_region2);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_clear_pending_region_pfm_in_use_multiple_region1);
	SUITE_ADD_TEST (suite,
		pfm_manager_flash_test_clear_pending_region_in_use_after_activate_region2);
	SUITE_ADD_TEST (suite,
		pfm_manager_flash_test_clear_pending_region_in_use_after_activate_region1);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_clear_pending_no_pending_in_use_region2);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_clear_pending_no_pending_in_use_region1);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_clear_pending_region_extra_free_call);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_clear_pending_region_free_null_region2);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_clear_pending_region_free_null_region1);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_clear_pending_region_free_null_manager);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_write_pending_data_region2);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_write_pending_data_region1);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_write_pending_data_multiple);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_write_pending_data_block_end);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_write_pending_data_null);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_write_pending_data_write_error);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_write_pending_data_write_after_error);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_write_pending_data_partial_write);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_write_pending_data_write_after_partial_write);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_write_pending_data_without_clear);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_write_pending_data_restart_write);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_write_pending_data_too_long);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_write_pending_data_pfm_in_use);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_verify_pending_pfm_region2);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_verify_pending_pfm_region1);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_verify_pending_pfm_region2_notify_observers);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_verify_pending_pfm_region1_notify_observers);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_verify_pending_pfm_already_valid_region2);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_verify_pending_pfm_already_valid_region1);
	SUITE_ADD_TEST (suite,
		pfm_manager_flash_test_verify_pending_pfm_already_valid_notify_observers);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_verify_pending_pfm_with_active);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_verify_pending_pfm_already_valid_with_active);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_verify_pending_pfm_lower_id);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_verify_pending_pfm_same_id);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_verify_pending_pfm_different_platform_id);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_verify_pending_pfm_no_clear_region2);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_verify_pending_pfm_no_clear_region1);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_verify_pending_pfm_extra_data_written);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_verify_pending_pfm_null);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_verify_pending_pfm_verify_error_region2);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_verify_pending_pfm_verify_error_region1);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_verify_pending_pfm_verify_error_notify_observers);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_verify_pending_pfm_verify_fail_region2);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_verify_pending_pfm_verify_fail_region1);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_verify_pending_pfm_verify_fail_ecc_region2);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_verify_pending_pfm_verify_fail_ecc_region1);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_verify_pending_pfm_verify_after_verify_error);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_verify_pending_pfm_verify_after_verify_fail);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_verify_pending_pfm_write_after_verify);
	SUITE_ADD_TEST (suite,
		pfm_manager_flash_test_verify_pending_pfm_write_after_verify_with_active);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_verify_pending_pfm_write_after_verify_error);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_verify_pending_pfm_with_active_id2_error_region2);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_verify_pending_pfm_with_active_id2_error_region1);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_verify_pending_pfm_with_active_id1_error);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_verify_pending_pfm_write_after_id_error);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_verify_pending_pfm_platform_id2_error_region2);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_verify_pending_pfm_platform_id2_error_region1);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_verify_pending_pfm_platform_id1_error);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_verify_pending_pfm_write_after_platform_id_error);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_verify_pending_pfm_incomplete_pfm);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_verify_pending_pfm_write_after_incomplete_pfm);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_clear_all_manifests_region1);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_clear_all_manifests_region2);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_clear_all_manifests_only_active);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_clear_all_manifests_only_pending);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_clear_all_manifests_no_pfms);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_clear_all_manifests_pending_in_use);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_clear_all_manifests_active_in_use);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_clear_all_manifests_during_update);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_clear_all_manifests_null);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_clear_all_manifests_erase_pending_error);
	SUITE_ADD_TEST (suite, pfm_manager_flash_test_clear_all_manifests_erase_active_error);

	return suite;
}
