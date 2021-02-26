// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "manifest/pcd/pcd_manager_flash.h"
#include "manifest/pcd/pcd_format.h"
#include "flash/spi_flash.h"
#include "state_manager/system_state_manager.h"
#include "mock/flash_master_mock.h"
#include "mock/pcd_observer_mock.h"
#include "mock/signature_verification_mock.h"
#include "engines/hash_testing_engine.h"
#include "flash/flash_common.h"
#include "crypto/ecc.h"
#include "manifest_flash_v2_testing.h"
#include "pcd_testing.h"


static const char *SUITE = "pcd_manager_flash";


/**
 * PCD with ID 0x1A for testing.
 */
const uint8_t PCD_DATA[] = {
	0x54,0x02,0x29,0x10,0x1a,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x05,0x05,0x00,0x00,
	0x00,0xff,0x01,0x00,0xf8,0x00,0x0c,0x00,0x41,0xff,0x01,0x01,0x04,0x01,0x0c,0x00,
	0x42,0xff,0x01,0x02,0x10,0x01,0x14,0x00,0x43,0xff,0x01,0x03,0x24,0x01,0x18,0x00,
	0x40,0xff,0x01,0x04,0x3c,0x01,0x18,0x00,0xe4,0xbc,0x4b,0xc0,0x40,0x7e,0x07,0xf7,
	0x96,0x9b,0x2e,0xab,0xb8,0x70,0xf8,0x6d,0x26,0xfa,0x7d,0x0d,0x15,0x06,0x47,0xd0,
	0xef,0x37,0xd4,0x4a,0x1a,0xd2,0xf2,0x22,0x4d,0x9a,0x65,0x85,0x38,0xe7,0x61,0xba,
	0xbb,0xb3,0xdc,0x6a,0x01,0x3f,0xb4,0x11,0x77,0x16,0x30,0x68,0x93,0x9c,0xc5,0x89,
	0xf1,0xd1,0x9a,0x66,0xab,0xc9,0x09,0x7f,0x5e,0x7a,0xf5,0x15,0xba,0x4f,0x0b,0x4a,
	0x80,0xea,0x69,0x22,0xcc,0x77,0xdc,0x29,0x23,0xa3,0xc3,0x17,0x46,0x4e,0xe4,0xb3,
	0xda,0x61,0xbe,0x6f,0xdf,0xbd,0xc9,0xe8,0x6e,0xb5,0x9d,0xc9,0x35,0x16,0xed,0xce,
	0x7c,0xc4,0x2b,0xb8,0xad,0x2a,0x87,0xe7,0x47,0x2f,0x15,0x7d,0xfd,0x94,0xdc,0xa2,
	0x2f,0x27,0xb4,0xbc,0xc8,0x4e,0x9c,0x72,0x09,0x3e,0xb3,0x0f,0x76,0x3d,0x15,0x0d,
	0x80,0x0a,0x24,0x95,0xf3,0xca,0xd1,0x27,0x5d,0x24,0x18,0x80,0xb2,0xae,0x4b,0x81,
	0xd3,0x15,0x6f,0x9e,0x0f,0xe6,0xc5,0xc8,0x72,0x00,0xb4,0x25,0x6b,0x90,0xa5,0x37,
	0x4f,0x4d,0x16,0x22,0x06,0x84,0x92,0x5d,0xf3,0xf8,0x96,0x79,0x70,0xd8,0x27,0xe7,
	0xb7,0x82,0x05,0xfa,0xe8,0x85,0x73,0xb2,0x05,0x00,0x00,0x00,0x43,0x32,0x30,0x33,
	0x30,0x00,0x00,0x00,0x02,0x02,0x22,0x14,0x66,0x07,0x00,0x00,0x45,0x04,0x00,0x00,
	0x00,0x50,0xe0,0x07,0x43,0x6f,0x72,0x73,0x69,0x63,0x61,0x00,0x01,0x03,0x75,0x77,
	0x55,0x03,0x00,0x00,0x00,0x70,0xf0,0x08,0x4f,0x76,0x65,0x72,0x6c,0x61,0x6b,0x65,
	0x0a,0x00,0x0b,0x00,0x0c,0x00,0x0d,0x00,0x02,0x30,0x00,0x00,0x00,0x02,0x02,0x41,
	0x0b,0x10,0x0a,0x00,0x00,0x01,0x00,0x00,0x00,0x48,0xe8,0x01,0x01,0x04,0x01,0x00,
	0x00,0x90,0xd0,0x03,0xb5,0xe6,0xb0,0x8d,0xa1,0x0e,0xdf,0xa9,0xed,0xf6,0xca,0x00,
	0x35,0xfc,0x0f,0x66,0xa6,0x4d,0xa6,0x0d,0x38,0x66,0x82,0x84,0xec,0xcb,0xfb,0xea,
	0x00,0x05,0x60,0x48,0x75,0xbb,0xe9,0xc9,0x08,0xb9,0x63,0x7e,0xe1,0x16,0xf2,0xae,
	0x69,0x28,0x1b,0x06,0xea,0x75,0x6d,0xd6,0x7a,0xa3,0xb7,0x13,0xec,0x71,0xcf,0x94,
	0xc9,0x98,0x54,0x23,0x65,0xdc,0x1c,0xb5,0x8b,0xaa,0x80,0x5b,0xb6,0x72,0xee,0xf5,
	0xb0,0x8c,0xc8,0x22,0x06,0xc6,0xc6,0xed,0xba,0x7a,0x04,0x95,0x28,0x38,0xc2,0x10,
	0xfa,0xbd,0x46,0x1a,0x1c,0x66,0x97,0x17,0xa0,0xeb,0xec,0xeb,0x23,0x42,0x35,0x85,
	0x32,0x22,0x92,0x05,0x68,0xcf,0x71,0x81,0xd7,0x3f,0x29,0x0e,0xb5,0x1c,0xa7,0x88,
	0x14,0xd0,0x86,0x7d,0x06,0x01,0xde,0xb5,0xe6,0x4e,0x6b,0x53,0xec,0xaa,0x48,0x78,
	0x66,0x8f,0xc0,0xd3,0x6b,0xe0,0xcc,0x55,0xaa,0xb1,0x97,0x98,0x89,0x0d,0x4f,0x23,
	0x2d,0x13,0xec,0xcd,0xb5,0xe8,0xcb,0x2d,0x5f,0x49,0x28,0x71,0x0a,0x06,0xbc,0x49,
	0xb2,0xb5,0xf1,0x52,0xa4,0x57,0xdf,0xf8,0x85,0xb5,0xc2,0x38,0xbf,0x50,0x1f,0xed,
	0x8f,0xd3,0x82,0xd5,0xd1,0x7c,0x2f,0x66,0x14,0xf8,0xf4,0x89,0xc7,0x13,0xea,0xb9,
	0x96,0xf1,0xff,0x29,0x68,0x20,0x6c,0x58,0x82,0x5c,0x85,0xd4,0x8c,0x1c,0x11,0x91,
	0xe2,0x99,0xf6,0xa3,0xb4,0x34,0x74,0x07,0xca,0x06,0xe0,0xf6,0xbd,0x7f,0x74,0x37,
	0xfc,0x07,0xf6,0x01,0xa0,0xd1,0x2b,0xda,0xfd,0xc8,0x12,0x07,0x80,0x6f,0x17,0x3a,
	0x18,0x73,0xdd,0x9a
};

/**
 * PCD with ID 0x9B for testing.
 */
const uint8_t PCD2_DATA[] = {
	0x54,0x02,0x29,0x10,0x9b,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x05,0x05,0x00,0x00,
	0x00,0xff,0x01,0x00,0xf8,0x00,0x0c,0x00,0x41,0xff,0x01,0x01,0x04,0x01,0x0c,0x00,
	0x42,0xff,0x01,0x02,0x10,0x01,0x14,0x00,0x43,0xff,0x01,0x03,0x24,0x01,0x18,0x00,
	0x40,0xff,0x01,0x04,0x3c,0x01,0x18,0x00,0xe4,0xbc,0x4b,0xc0,0x40,0x7e,0x07,0xf7,
	0x96,0x9b,0x2e,0xab,0xb8,0x70,0xf8,0x6d,0x26,0xfa,0x7d,0x0d,0x15,0x06,0x47,0xd0,
	0xef,0x37,0xd4,0x4a,0x1a,0xd2,0xf2,0x22,0x4d,0x9a,0x65,0x85,0x38,0xe7,0x61,0xba,
	0xbb,0xb3,0xdc,0x6a,0x01,0x3f,0xb4,0x11,0x77,0x16,0x30,0x68,0x93,0x9c,0xc5,0x89,
	0xf1,0xd1,0x9a,0x66,0xab,0xc9,0x09,0x7f,0x5e,0x7a,0xf5,0x15,0xba,0x4f,0x0b,0x4a,
	0x80,0xea,0x69,0x22,0xcc,0x77,0xdc,0x29,0x23,0xa3,0xc3,0x17,0x46,0x4e,0xe4,0xb3,
	0xda,0x61,0xbe,0x6f,0xdf,0xbd,0xc9,0xe8,0x6e,0xb5,0x9d,0xc9,0x35,0x16,0xed,0xce,
	0x7c,0xc4,0x2b,0xb8,0xad,0x2a,0x87,0xe7,0x47,0x2f,0x15,0x7d,0xfd,0x94,0xdc,0xa2,
	0x2f,0x27,0xb4,0xbc,0xc8,0x4e,0x9c,0x72,0x09,0x3e,0xb3,0x0f,0x76,0x3d,0x15,0x0d,
	0x80,0x0a,0x24,0x95,0xf3,0xca,0xd1,0x27,0x5d,0x24,0x18,0x80,0xb2,0xae,0x4b,0x81,
	0xd3,0x15,0x6f,0x9e,0x0f,0xe6,0xc5,0xc8,0x72,0x00,0xb4,0x25,0x6b,0x90,0xa5,0x37,
	0x4f,0x4d,0x16,0x22,0x06,0x84,0x92,0x5d,0xf3,0xf8,0x96,0x79,0x70,0xd8,0x27,0xe7,
	0xb7,0x82,0x05,0xfa,0xe8,0x85,0x73,0xb2,0x05,0x00,0x00,0x00,0x43,0x32,0x30,0x33,
	0x30,0x00,0x00,0x00,0x02,0x02,0x22,0x14,0x66,0x07,0x00,0x00,0x45,0x04,0x00,0x00,
	0x00,0x50,0xe0,0x07,0x43,0x6f,0x72,0x73,0x69,0x63,0x61,0x00,0x01,0x03,0x75,0x77,
	0x55,0x03,0x00,0x00,0x00,0x70,0xf0,0x08,0x4f,0x76,0x65,0x72,0x6c,0x61,0x6b,0x65,
	0x0a,0x00,0x0b,0x00,0x0c,0x00,0x0d,0x00,0x02,0x30,0x00,0x00,0x00,0x02,0x02,0x41,
	0x0b,0x10,0x0a,0x00,0x00,0x01,0x00,0x00,0x00,0x48,0xe8,0x01,0x01,0x04,0x01,0x00,
	0x00,0x90,0xd0,0x03,0x93,0x53,0xdc,0x3c,0x72,0xc9,0x57,0x7c,0xa5,0xd9,0x67,0x75,
	0x69,0x73,0x8b,0xbd,0x4d,0xaf,0x84,0xc4,0x85,0xb4,0x07,0x69,0xb5,0xa0,0xec,0x0d,
	0x71,0x90,0xac,0xcd,0x4b,0x6a,0xb5,0x84,0xf6,0x8c,0xa6,0x9d,0x27,0xd2,0xfb,0x31,
	0xcb,0xfc,0x6a,0x0e,0x16,0xbd,0x43,0xcb,0x29,0xfc,0xe4,0x7e,0x6f,0x36,0x25,0x5d,
	0x5b,0x9c,0xa9,0xde,0xfb,0x7e,0xe0,0xde,0x5e,0x21,0x9a,0x94,0xe4,0x25,0xda,0x07,
	0x69,0xd6,0xa2,0xbc,0xb5,0x75,0x9b,0x5a,0x5a,0x04,0xd2,0x4e,0x5d,0xe0,0xc7,0x3e,
	0x08,0xdc,0x57,0xe0,0x31,0x16,0x3b,0xc2,0x5e,0x53,0x23,0x19,0x06,0x64,0x45,0x78,
	0x83,0x30,0x73,0xa1,0x0e,0x9b,0xa3,0xfa,0xe0,0xc4,0x7d,0xea,0x41,0xe0,0xbf,0xfa,
	0xf9,0x40,0x8c,0xdf,0x6b,0x03,0x4b,0x39,0x21,0xd5,0xbf,0x4c,0x17,0xcf,0x74,0x59,
	0xdd,0xcd,0x0a,0x7c,0x61,0x0a,0x1e,0x5a,0x9d,0x44,0x50,0x0c,0xdb,0xa3,0x24,0x34,
	0x9a,0x70,0x96,0x42,0x2c,0xc9,0x22,0x17,0xce,0x9d,0xdc,0xb3,0xb2,0x40,0x14,0xae,
	0xc2,0xca,0x53,0xc0,0xe8,0x86,0x83,0x0f,0x72,0x63,0x48,0x50,0x43,0x36,0xa2,0x76,
	0xcd,0xe2,0x58,0x36,0xaa,0x78,0x1c,0x6f,0x45,0x71,0xa2,0x22,0x71,0x7c,0x63,0xec,
	0xab,0x8e,0x5b,0x4a,0x55,0x27,0x7f,0x89,0xac,0x40,0xd2,0x31,0x0a,0x76,0x36,0x5d,
	0xb6,0x3d,0x67,0x90,0x26,0x8a,0xa4,0xc1,0x61,0x01,0x63,0x2a,0x4f,0x58,0xa2,0xce,
	0xed,0xf0,0xc2,0x1f,0x5f,0xeb,0xcb,0x82,0xf0,0xa6,0x63,0x9e,0xdc,0xe8,0x8b,0xdc,
	0x4e,0xee,0x51,0xeb
};

/**
 * PCD with ID 0x1A and C2090 platform ID for testing.
 */
const uint8_t PCD3_DATA[] = {
	0x54,0x02,0x29,0x10,0x1a,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x05,0x05,0x00,0x00,
	0x00,0xff,0x01,0x00,0xf8,0x00,0x0c,0x00,0x41,0xff,0x01,0x01,0x04,0x01,0x0c,0x00,
	0x42,0xff,0x01,0x02,0x10,0x01,0x14,0x00,0x43,0xff,0x01,0x03,0x24,0x01,0x18,0x00,
	0x40,0xff,0x01,0x04,0x3c,0x01,0x18,0x00,0x6f,0xf0,0x1a,0x8a,0xc4,0xa7,0xef,0x13,
	0x7b,0xf2,0x78,0x7b,0x07,0x53,0x1b,0x6d,0xa4,0x8c,0x1b,0xca,0x8c,0xdb,0xf2,0xda,
	0x30,0xf5,0xc8,0x64,0xc0,0xca,0x48,0x65,0x4d,0x9a,0x65,0x85,0x38,0xe7,0x61,0xba,
	0xbb,0xb3,0xdc,0x6a,0x01,0x3f,0xb4,0x11,0x77,0x16,0x30,0x68,0x93,0x9c,0xc5,0x89,
	0xf1,0xd1,0x9a,0x66,0xab,0xc9,0x09,0x7f,0x5e,0x7a,0xf5,0x15,0xba,0x4f,0x0b,0x4a,
	0x80,0xea,0x69,0x22,0xcc,0x77,0xdc,0x29,0x23,0xa3,0xc3,0x17,0x46,0x4e,0xe4,0xb3,
	0xda,0x61,0xbe,0x6f,0xdf,0xbd,0xc9,0xe8,0x6e,0xb5,0x9d,0xc9,0x35,0x16,0xed,0xce,
	0x7c,0xc4,0x2b,0xb8,0xad,0x2a,0x87,0xe7,0x47,0x2f,0x15,0x7d,0xfd,0x94,0xdc,0xa2,
	0x2f,0x27,0xb4,0xbc,0xc8,0x4e,0x9c,0x72,0x09,0x3e,0xb3,0x0f,0x76,0x3d,0x15,0x0d,
	0x80,0x0a,0x24,0x95,0xf3,0xca,0xd1,0x27,0x5d,0x24,0x18,0x80,0xb2,0xae,0x4b,0x81,
	0xd3,0x15,0x6f,0x9e,0x0f,0xe6,0xc5,0xc8,0x5a,0x2b,0xf5,0x45,0x44,0x03,0x63,0x5e,
	0xd3,0xf3,0x3d,0xe7,0x8c,0x6a,0x06,0x91,0xb0,0x37,0xd8,0x09,0x1f,0x68,0xc9,0x31,
	0x30,0x52,0x3d,0x80,0xee,0x72,0x6e,0xff,0x05,0x00,0x00,0x00,0x43,0x32,0x30,0x39,
	0x30,0x00,0x00,0x00,0x02,0x02,0x22,0x14,0x66,0x07,0x00,0x00,0x45,0x04,0x00,0x00,
	0x00,0x50,0xe0,0x07,0x43,0x6f,0x72,0x73,0x69,0x63,0x61,0x00,0x01,0x03,0x75,0x77,
	0x55,0x03,0x00,0x00,0x00,0x70,0xf0,0x08,0x4f,0x76,0x65,0x72,0x6c,0x61,0x6b,0x65,
	0x0a,0x00,0x0b,0x00,0x0c,0x00,0x0d,0x00,0x02,0x30,0x00,0x00,0x00,0x02,0x02,0x41,
	0x0b,0x10,0x0a,0x00,0x00,0x01,0x00,0x00,0x00,0x48,0xe8,0x01,0x01,0x04,0x01,0x00,
	0x00,0x90,0xd0,0x03,0x55,0x69,0x1b,0x0e,0x2f,0x65,0xc7,0xdf,0x59,0x14,0x4a,0xfb,
	0xb2,0x0b,0x03,0x9c,0x6f,0x55,0x14,0x4d,0x6a,0xca,0xa2,0xf9,0x09,0x09,0xb8,0x93,
	0x7f,0x54,0x95,0x80,0xf6,0x20,0x8c,0xec,0x13,0x7c,0x0b,0x1b,0x78,0x32,0x49,0xd5,
	0xb6,0xb5,0x0d,0xf8,0xf5,0x95,0xb4,0xfa,0x6d,0x2f,0x40,0x44,0x43,0x01,0xc1,0xa4,
	0x06,0xb0,0x70,0x71,0x56,0x2e,0x46,0xdf,0x8b,0x69,0xa0,0x63,0xa6,0x81,0xe0,0xc2,
	0x5b,0xd5,0xaf,0xe8,0x40,0xa7,0xcc,0x8d,0xa5,0xc2,0xae,0x0f,0x55,0x52,0xef,0xb2,
	0x49,0x88,0x10,0xff,0x20,0xd8,0x31,0x11,0xc5,0xe4,0xfc,0x4f,0xea,0x3c,0x1e,0x2e,
	0xfb,0x97,0x8c,0xf0,0x55,0x6d,0xb2,0x0f,0x43,0x8b,0xe9,0x7e,0x03,0x07,0x7e,0x18,
	0x9f,0x6e,0x76,0xd4,0x07,0xeb,0x44,0x10,0x41,0x59,0x29,0x27,0xe7,0xb9,0xdb,0xb8,
	0x7d,0x98,0x5e,0xcf,0x3f,0xd8,0x43,0xe8,0xb1,0x0e,0xc4,0x57,0x37,0x2c,0x1a,0xf7,
	0xc3,0xec,0x26,0x55,0x54,0xfa,0xbb,0x25,0x65,0x2f,0xef,0x2e,0x66,0x8a,0x36,0xc8,
	0x67,0xb5,0x7f,0x73,0xab,0x55,0x6b,0x95,0x79,0x75,0x31,0xb8,0x44,0x0d,0x16,0x37,
	0x55,0xa2,0x10,0xf9,0x4e,0x75,0xf7,0x15,0xe6,0xb3,0xc9,0x64,0xa1,0xda,0x4d,0x51,
	0x8a,0xdf,0x9f,0xed,0xe4,0x14,0x08,0x2e,0xdd,0x62,0xb3,0xc9,0x68,0x12,0xeb,0xf4,
	0x59,0xb9,0x0c,0x02,0xbd,0x2b,0x72,0x4d,0x26,0xa3,0x21,0x04,0x7e,0x4f,0x56,0x63,
	0xf1,0x34,0x9b,0x7e,0x08,0xae,0xf9,0xf8,0xb3,0x38,0x43,0xd6,0x56,0x78,0x93,0xd7,
	0x80,0xc3,0xf3,0x30
};

/**
 * Length of the testing PCD.
 */
const uint32_t PCD_DATA_LEN = sizeof (PCD_DATA);

/**
 * Length of the second testing PCD.
 */
const uint32_t PCD2_DATA_LEN = sizeof (PCD2_DATA);

/**
 * Length of the third testing PCD.
 */
const uint32_t PCD3_DATA_LEN = sizeof (PCD3_DATA);

/**
 * The offset from the base for the PCD header.
 */
const uint32_t PCD_HEADER_OFFSET = MANIFEST_V2_HEADER_SIZE;

/**
 * The platform ID for the PCD.
 */
const char PCD_PLATFORM_ID[] = "C2030";

/**
 * The platform ID for the PCD.
 */
const char PCD3_PLATFORM_ID[] = "C2090";

/**
 * The length of the PCD platform ID.
 */
const size_t PCD_PLATFORM_ID_LEN = sizeof (PCD_PLATFORM_ID) - 1;

/**
 * The length of the PCD platform ID.
 */
const size_t PCD3_PLATFORM_ID_LEN = sizeof (PCD3_PLATFORM_ID) - 1;

/**
 * The offset from the base for the PCD signature.
 */
const uint32_t PCD_SIGNATURE_OFFSET = (sizeof (PCD_DATA) - 256);

/**
 * The offset from the base for the second PCD signature.
 */
const uint32_t PCD2_SIGNATURE_OFFSET = (sizeof (PCD2_DATA) - 256);

/**
 * The offset from the base for the third PCD signature.
 */
const uint32_t PCD3_SIGNATURE_OFFSET = (sizeof (PCD3_DATA) - 256);

/**
 * The signature for the PCD.
 */
const uint8_t *PCD_SIGNATURE = PCD_DATA + (sizeof (PCD_DATA) - 256);

/**
 * The signature for the second PCD.
 */
const uint8_t *PCD2_SIGNATURE = PCD2_DATA + (sizeof (PCD2_DATA) - 256);

/**
 * The signature for the third PCD.
 */
const uint8_t *PCD3_SIGNATURE = PCD3_DATA + (sizeof (PCD3_DATA) - 256);

/**
 * The length of the PCD signature.
 */
const size_t PCD_SIGNATURE_LEN = 256;

/**
 * PCD_DATA hash for testing.
 */
const uint8_t PCD_HASH[] = {
	0xb3,0xf4,0x7a,0xb7,0xee,0x99,0x99,0x50,0x46,0xf2,0x1f,0x70,0x5f,0xf5,0xa1,0x74,
	0x85,0xeb,0xe9,0x01,0x12,0xde,0x10,0x12,0x46,0x6d,0x51,0x53,0x59,0xc9,0x57,0x16
};

/**
 * PCD_DATA hash digest for testing.
 */
const uint8_t PCD_HASH_DIGEST[] = {
	0x30,0x93,0x07,0xfb,0x2d,0xf1,0xd4,0xf8,0x8c,0x8b,0x35,0x93,0x09,0x5e,0x72,0xb1,
	0xd9,0x3d,0xf3,0x53,0x46,0x0b,0x6e,0x08,0x17,0x86,0x40,0xde,0x13,0x3b,0xf6,0x09
};

/**
 * PCD2_DATA hash for testing.
 */
const uint8_t PCD2_HASH[] = {
	0x09,0xad,0xa4,0x99,0x5b,0xaa,0x27,0x7b,0x89,0x03,0x9d,0xcd,0xd4,0x1b,0x3e,0x36,
	0xc1,0x6d,0x21,0x32,0x67,0xb1,0x32,0x71,0xf1,0x14,0x6b,0x64,0x8a,0xaa,0x87,0xc7
};

/**
 * PCD3_DATA hash for testing.
 */
const uint8_t PCD3_HASH[] = {
	0x25,0x7e,0x50,0x93,0xb4,0x94,0x5d,0x18,0xb3,0x27,0x44,0x40,0xaa,0xfc,0xac,0x5c,
	0x24,0x63,0xa1,0xb7,0x98,0x25,0x62,0x56,0xef,0x6c,0x21,0x64,0x82,0xae,0x09,0xc3
};

/**
 * PCD TOC hash for testing.
 */
const uint8_t PCD_TOC_HASH[] = {
	0x72,0x00,0xb4,0x25,0x6b,0x90,0xa5,0x37,0x4f,0x4d,0x16,0x22,0x06,0x84,0x92,0x5d,
	0xf3,0xf8,0x96,0x79,0x70,0xd8,0x27,0xe7,0xb7,0x82,0x05,0xfa,0xe8,0x85,0x73,0xb2
};

/**
 * Length of the test PCD hash.
 */
const uint32_t PCD_HASH_LEN = sizeof (PCD_HASH);


/**
 * Components of the test PCD.
 */
const struct pcd_testing_data PCD_TESTING = {
	.manifest = {
		.raw = PCD_DATA,
		.length = sizeof (PCD_DATA),
		.hash = PCD_HASH,
		.hash_len = sizeof (PCD_HASH),
		.id = 0x1A,
		.signature = PCD_DATA + (sizeof (PCD_DATA) - 256),
		.sig_len = 256,
		.sig_offset = (sizeof (PCD_DATA) - 256),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = PCD_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = MANIFEST_V2_TOC_HEADER_SIZE + MANIFEST_V2_TOC_ENTRY_SIZE * 5 +
			SHA256_HASH_LENGTH * 6,
		.toc_hash = PCD_TOC_HASH,
		.toc_hash_len = SHA256_HASH_LENGTH,
		.toc_hash_offset = MANIFEST_V2_TOC_ENTRY_OFFSET + MANIFEST_V2_TOC_ENTRY_SIZE * 5 +
			SHA256_HASH_LENGTH * 5,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 5,
		.toc_hashes = 5,
		.plat_id = PCD_DATA + MANIFEST_V2_TOC_ENTRY_OFFSET + MANIFEST_V2_TOC_ENTRY_SIZE * 5 +
			SHA256_HASH_LENGTH * 6,
		.plat_id_len = sizeof (PCD_PLATFORM_ID) + sizeof (struct manifest_platform_id) + 2,
		.plat_id_str = PCD_PLATFORM_ID,
		.plat_id_str_len = sizeof (PCD_PLATFORM_ID) - 1,
		.plat_id_str_pad = 3,
		.plat_id_offset = MANIFEST_V2_TOC_ENTRY_OFFSET + MANIFEST_V2_TOC_ENTRY_SIZE * 5 +
			SHA256_HASH_LENGTH * 6,
		.plat_id_entry = 0,
		.plat_id_hash = 0
	},
	.rot_len = sizeof (struct pcd_rot_element) + 2 * sizeof (struct pcd_port),
	.rot_offset = sizeof (PCD_DATA) - 256 -
		(sizeof (struct pcd_port) * 2 + sizeof (struct pcd_rot_element)),
	.rot_entry = 4,
	.rot_hash = 4,
	.power_ctrl_len = sizeof (struct pcd_power_controller_element) + 2 * sizeof (struct pcd_mux),
	.power_ctrl_offset = MANIFEST_V2_TOC_ENTRY_OFFSET + MANIFEST_V2_TOC_ENTRY_SIZE * 5 +
			SHA256_HASH_LENGTH * 6 + sizeof (PCD_PLATFORM_ID) +
			sizeof (struct manifest_platform_id) + 2,
	.power_ctrl_entry = 1,
	.power_ctrl_hash = 1,
	.bridge_component_len = 24,
	.bridge_component_offset = 292,
	.bridge_component_entry = 3,
	.bridge_component_hash = 3,
	.direct_component_len = 20,
	.direct_component_offset = 272,
	.direct_component_entry = 2,
	.direct_component_hash = 2
};


/**
 * Dependencies for testing the PCD manager.
 */
struct pcd_manager_flash_testing {
	HASH_TESTING_ENGINE hash;							/**< Hashing engine for validation. */
	struct signature_verification_mock verification;	/**< PCD signature verification. */
	struct flash_master_mock flash_mock;				/**< Flash master for PCD flash. */
	struct flash_master_mock flash_mock_state;			/**< Flash master for host state flash. */
	struct spi_flash flash;								/**< Flash containing the PCD data. */
	struct spi_flash flash_state;						/**< Flash containing the host state. */
	struct state_manager state_mgr;						/**< Manager for host state. */
	struct pcd_flash pcd1;								/**< The first PCD. */
	uint8_t signature1[256];							/**< Buffer for the first manifest signature. */
	uint8_t platform_id1[256];							/**< Cache for the first platform ID. */
	uint32_t pcd1_addr;									/**< Base address of the first PCD. */
	struct pcd_flash pcd2;								/**< The second PCD. */
	uint8_t signature2[256];							/**< Buffer for the second manifest signature. */
	uint8_t platform_id2[256];							/**< Cache for the second platform ID. */
	uint32_t pcd2_addr;									/**< Base address of the second PCD. */
	struct pcd_observer_mock observer;					/**< Observer of manager events. */
	struct pcd_manager_flash test;						/**< Manager instance under test. */
};


/**
 * Initialize the system state manager for testing.
 *
 * @param test The testing framework.
 * @param manager The testing components being initialized.
 */
static void pcd_manager_flash_testing_init_system_state (CuTest *test,
	struct pcd_manager_flash_testing *manager)
{
	int status;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};

	status = flash_master_mock_init (&manager->flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&manager->flash_state, &manager->flash_mock_state.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&manager->flash_state, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&manager->flash_mock_state, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock_state, 0, (uint8_t*) end,
		sizeof (end),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, 8));

	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock_state, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock_state, 0, (uint8_t*) end,
		sizeof (end),
		FLASH_EXP_READ_CMD (0x03, 0x11000, 0, -1, 8));

	status |= flash_master_mock_expect_erase_flash_sector_verify (&manager->flash_mock_state,
		0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = system_state_manager_init (&manager->state_mgr, &manager->flash_state.base, 0x10000);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize common PCD manager testing dependencies.
 *
 * @param test The testing framework.
 * @param manager The testing components to initialize.
 * @param addr1 Base address of the first PCD.
 * @param addr2 Base address of the second PCD.
 */
static void pcd_manager_flash_testing_init_dependencies (CuTest *test,
	struct pcd_manager_flash_testing *manager, uint32_t addr1, uint32_t addr2)
{
	int status;

	status = HASH_TESTING_ENGINE_INIT (&manager->hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&manager->verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&manager->flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&manager->flash, &manager->flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&manager->flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	pcd_manager_flash_testing_init_system_state (test, manager);

	status = pcd_flash_init (&manager->pcd1, &manager->flash.base, &manager->hash.base, addr1,
		manager->signature1, sizeof (manager->signature1), manager->platform_id1,
		sizeof (manager->platform_id1));
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&manager->pcd2, &manager->flash.base, &manager->hash.base, addr2,
		manager->signature2, sizeof (manager->signature2), manager->platform_id2,
		sizeof (manager->platform_id2));
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_mock_init (&manager->observer);
	CuAssertIntEquals (test, 0, status);

	manager->pcd1_addr = addr1;
	manager->pcd2_addr = addr2;
}

/**
 * Release test dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param pcd The testing components to release.
 */
void pcd_manager_flash_testing_validate_and_release_dependencies (CuTest *test,
	struct pcd_manager_flash_testing *manager)
{
	int status;

	status = flash_master_mock_validate_and_release (&manager->flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&manager->flash_mock_state);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&manager->verification);
	CuAssertIntEquals (test, 0, status);

	status = pcd_observer_mock_validate_and_release (&manager->observer);
	CuAssertIntEquals (test, 0, status);

	state_manager_release (&manager->state_mgr);
	pcd_flash_release (&manager->pcd1);
	pcd_flash_release (&manager->pcd2);
	spi_flash_release (&manager->flash);
	spi_flash_release (&manager->flash_state);
	HASH_TESTING_ENGINE_RELEASE (&manager->hash);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param manager The testing components to release.
 */
static void pcd_manager_flash_testing_validate_and_release (CuTest *test,
	struct pcd_manager_flash_testing *manager)
{
	pcd_manager_flash_release (&manager->test);

	pcd_manager_flash_testing_validate_and_release_dependencies (test, manager);
}

/**
 * Set up expectations for verifying a PCD on flash.
 *
 * @param manager The testing components.
 * @param address The base address of the PCD.
 * @param pcd Buffer of PCD to verify.
 * @param pcd_len Length of PCD.
 * @param pcd_signature Buffer of PCD signature.
 * @param pcd_signature_offset Offset from start of PCD where signature starts.
 * @param pcd_hash Buffer of PCD hash.
 * @param sig_verification_result Result of the signature verification call.
 *
 * @return 0 if the expectations were set up successfully or an error code.
 */
static int pcd_manager_flash_testing_verify_a_pcd (struct pcd_manager_flash_testing *manager,
	uint32_t address, const uint8_t *pcd, size_t pcd_len, const uint8_t *pcd_signature,
	uint32_t pcd_signature_offset, const uint8_t *pcd_hash, int sig_verification_result)
{
	uint32_t pcd_offset;
	int status;

	status = flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, pcd,
		MANIFEST_V2_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, address, 0, -1, MANIFEST_V2_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, pcd_signature,
		PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, address + pcd_signature_offset, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0,
		pcd + MANIFEST_V2_TOC_HDR_OFFSET, MANIFEST_V2_TOC_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, address + MANIFEST_V2_TOC_HDR_OFFSET, 0, -1,
		MANIFEST_V2_TOC_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0,
		pcd + MANIFEST_V2_TOC_ENTRY_OFFSET, MANIFEST_V2_TOC_ENTRY_SIZE,
		FLASH_EXP_READ_CMD (0x03, address + MANIFEST_V2_TOC_ENTRY_OFFSET, 0, -1,
		MANIFEST_V2_TOC_ENTRY_SIZE));

	status |= flash_master_mock_expect_verify_flash (&manager->flash_mock, address +
		MANIFEST_V2_TOC_ENTRY_OFFSET + MANIFEST_V2_TOC_ENTRY_SIZE, pcd +
		MANIFEST_V2_TOC_ENTRY_OFFSET + MANIFEST_V2_TOC_ENTRY_SIZE, MANIFEST_V2_TOC_ENTRY_SIZE * 4 +
		SHA256_HASH_LENGTH * 5);

	pcd_offset = MANIFEST_V2_TOC_ENTRY_OFFSET + MANIFEST_V2_TOC_ENTRY_SIZE * 5 +
		SHA256_HASH_LENGTH * 5;

	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0,
		pcd + pcd_offset, SHA256_HASH_LENGTH,
		FLASH_EXP_READ_CMD (0x03, address + pcd_offset, 0, -1, SHA256_HASH_LENGTH));

	pcd_offset += SHA256_HASH_LENGTH;

	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0,
		pcd + pcd_offset, MANIFEST_V2_PLATFORM_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, address + pcd_offset, 0, -1, MANIFEST_V2_PLATFORM_HEADER_SIZE));

	pcd_offset += MANIFEST_V2_PLATFORM_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager->flash_mock, 0,
		pcd + pcd_offset, PCD_PLATFORM_ID_LEN,
		FLASH_EXP_READ_CMD (0x03, address + pcd_offset, 0, -1, PCD_PLATFORM_ID_LEN));

	pcd_offset += PCD_PLATFORM_ID_LEN;

	status |= flash_master_mock_expect_verify_flash (&manager->flash_mock, address +
		pcd_offset, pcd + pcd_offset, pcd_len - pcd_offset - PCD_SIGNATURE_LEN);

	status |= mock_expect (&manager->verification.mock,
		manager->verification.base.verify_signature, &manager->verification,
		sig_verification_result, MOCK_ARG_PTR_CONTAINS (pcd_hash, PCD_HASH_LEN),
		MOCK_ARG (PCD_HASH_LEN), MOCK_ARG_PTR_CONTAINS (pcd_signature, PCD_SIGNATURE_LEN),
		MOCK_ARG (PCD_SIGNATURE_LEN));

	return status;
}

/**
 * Set up expectations for verifying a PCD on flash.
 *
 * @param manager The testing components.
 * @param address The base address of the PCD.
 *
 * @return 0 if the expectations were set up successfully or an error code.
 */
static int pcd_manager_flash_testing_verify_pcd (struct pcd_manager_flash_testing *manager,
	uint32_t address)
{
	return pcd_manager_flash_testing_verify_a_pcd (manager, address, PCD_DATA, PCD_DATA_LEN,
		PCD_SIGNATURE, PCD_SIGNATURE_OFFSET, PCD_HASH, 0);
}

/**
 * Set up expectations for verifying a PCD on flash.
 *
 * @param manager The testing components.
 * @param address The base address of the PCD.
 *
 * @return 0 if the expectations were set up successfully or an error code.
 */
static int pcd_manager_flash_testing_verify_pcd2 (struct pcd_manager_flash_testing *manager,
	uint32_t address)
{
	return pcd_manager_flash_testing_verify_a_pcd (manager, address, PCD2_DATA, PCD2_DATA_LEN,
		PCD2_SIGNATURE, PCD2_SIGNATURE_OFFSET, PCD2_HASH, 0);
}

/**
 * Set up expectations for verifying the PCDs during initialization.
 *
 * @param manager The testing components.
 * @param pcd1 The PCD verification function for region 1.
 * @param pcd2 The PCD verification function for region 2.
 *
 * @return 0 if the expectations were set up successfully or an error code.
 */
static int pcd_manager_flash_testing_initial_pcd_validation (
	struct pcd_manager_flash_testing *manager,
	int (*pcd1) (struct pcd_manager_flash_testing*, uint32_t),
	int (*pcd2) (struct pcd_manager_flash_testing*, uint32_t))
{
	int status;

	/* Base PCD verification.  Use blank check to simulate empty PCD regions. */
	if (pcd1) {
		status = pcd1 (manager, manager->pcd1_addr);
	}
	else {
		status = flash_master_mock_expect_blank_check (&manager->flash_mock, manager->pcd1_addr,
			MANIFEST_V2_HEADER_SIZE);
	}
	if (pcd2) {
		status |= pcd2 (manager, manager->pcd2_addr);
	}
	else {
		status |= flash_master_mock_expect_blank_check (&manager->flash_mock, manager->pcd2_addr,
			MANIFEST_V2_HEADER_SIZE);
	}

	return status;
}

/**
 * Initialize PCD manager for testing.
 *
 * @param test The testing framework.
 * @param manager The testing components to initialize.
 * @param addr1 The base address for the first PFM.
 * @param addr2 The base address for the second PFM.
 * @param pcd1 The PCD verification function for region 1.
 * @param pcd2 The PCD verification function for region 2.
 * @param pcd1_active Flag indicating if region 1 is active.
 */
static void pcd_manager_flash_testing_init (CuTest *test, struct pcd_manager_flash_testing *manager,
	uint32_t addr1, uint32_t addr2, int (*pcd1) (struct pcd_manager_flash_testing*, uint32_t),
	int (*pcd2) (struct pcd_manager_flash_testing*, uint32_t), bool pcd1_active)
{
	int status;

	pcd_manager_flash_testing_init_dependencies (test, manager, addr1, addr2);

	if (!pcd1_active) {
		status = manager->state_mgr.save_active_manifest (&manager->state_mgr,
			SYSTEM_STATE_MANIFEST_PCD, MANIFEST_REGION_2);
		CuAssertIntEquals (test, 0, status);
	}

	status = pcd_manager_flash_testing_initial_pcd_validation (manager, pcd1, pcd2);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_init (&manager->test, &manager->pcd1, &manager->pcd2,
		&manager->state_mgr, &manager->hash.base, &manager->verification.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager->flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager->flash_mock_state.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager->verification.mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Write complete PCD data to the manager to enable pending PCD verification.
 *
 * @param test The test framework.
 * @param manager The testing components.
 * @param addr The expected address of PCD writes.
 *
 * @return The number of PCD bytes written.
 */
static int pcd_manager_flash_testing_write_new_pcd (CuTest *test,
	struct pcd_manager_flash_testing *manager, uint32_t addr)
{
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	status = flash_master_mock_expect_erase_flash_verify (&manager->flash_mock, addr, 0x10000);
	status |= flash_master_mock_expect_write_ext (&manager->flash_mock, addr, data, sizeof (data),
		true, 0);

	CuAssertIntEquals (test, 0, status);

	status = manager->test.base.base.clear_pending_region (&manager->test.base.base, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager->test.base.base.write_pending_data (&manager->test.base.base, data,
		sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager->flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	return sizeof (data);
}

/*******************
 * Test cases
 *******************/

static void pcd_manager_flash_test_init (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	/* Use blank check to simulate empty PCD regions. */
	status = pcd_manager_flash_testing_initial_pcd_validation (&manager, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, manager.test.base.get_active_pcd);
	CuAssertPtrNotNull (test, manager.test.base.free_pcd);

	CuAssertPtrNotNull (test, manager.test.base.base.activate_pending_manifest);
	CuAssertPtrNotNull (test, manager.test.base.base.clear_pending_region);
	CuAssertPtrNotNull (test, manager.test.base.base.write_pending_data);
	CuAssertPtrNotNull (test, manager.test.base.base.verify_pending_manifest);
	CuAssertPtrNotNull (test, manager.test.base.base.clear_all_manifests);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_init_region1 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = pcd_manager_flash_testing_initial_pcd_validation (&manager,
		pcd_manager_flash_testing_verify_pcd, NULL);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_init_region2 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = manager.state_mgr.save_active_manifest (&manager.state_mgr, SYSTEM_STATE_MANIFEST_PCD,
		MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_testing_initial_pcd_validation (&manager, NULL,
		pcd_manager_flash_testing_verify_pcd);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_init_activate_pending (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = pcd_manager_flash_testing_initial_pcd_validation (&manager,
		pcd_manager_flash_testing_verify_pcd, pcd_manager_flash_testing_verify_pcd2);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_init_null (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = pcd_manager_flash_init (NULL, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = pcd_manager_flash_init (&manager.test, NULL, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, NULL,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		NULL, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, NULL, &manager.verification.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, NULL);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	pcd_manager_flash_testing_validate_and_release_dependencies (test, &manager);
}

static void pcd_manager_flash_test_init_region1_flash_error (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = flash_master_mock_expect_xfer (&manager.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	pcd_manager_flash_testing_validate_and_release_dependencies (test, &manager);
}

static void pcd_manager_flash_test_init_region2_flash_error (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	/* Use blank check to simulate empty PCD regions. */
	status = flash_master_mock_expect_blank_check (&manager.flash_mock, 0x10000,
		MANIFEST_V2_HEADER_SIZE);
	status |= flash_master_mock_expect_xfer (&manager.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	pcd_manager_flash_testing_validate_and_release_dependencies (test, &manager);
}

static void pcd_manager_flash_test_init_pcd_bad_signature (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = pcd_manager_flash_testing_verify_a_pcd (&manager, 0x10000, PCD_DATA, PCD_DATA_LEN,
		PCD_SIGNATURE, PCD_SIGNATURE_OFFSET, PCD_HASH, RSA_ENGINE_BAD_SIGNATURE);
	CuAssertIntEquals (test, 0, status);

	/* Use blank check to simulate empty PCD regions. */
	status = flash_master_mock_expect_blank_check (&manager.flash_mock, 0x20000,
		MANIFEST_V2_HEADER_SIZE);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_init_pcd_bad_signature_ecc (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = pcd_manager_flash_testing_verify_a_pcd (&manager, 0x10000, PCD_DATA, PCD_DATA_LEN,
		PCD_SIGNATURE, PCD_SIGNATURE_OFFSET, PCD_HASH, ECC_ENGINE_BAD_SIGNATURE);
	CuAssertIntEquals (test, 0, status);

	/* Use blank check to simulate empty PCD regions. */
	status |= flash_master_mock_expect_blank_check (&manager.flash_mock, 0x20000,
		MANIFEST_V2_HEADER_SIZE);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_init_bad_length (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t pcd_bad_data[PCD_SIGNATURE_OFFSET];

	TEST_START;

	memcpy (pcd_bad_data, PCD_DATA, sizeof (pcd_bad_data));
	pcd_bad_data[9] = 0xff;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, pcd_bad_data,
		sizeof (pcd_bad_data), FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1,
		MANIFEST_V2_HEADER_SIZE));

	/* Use blank check to simulate empty PCD regions. */
	status |= flash_master_mock_expect_blank_check (&manager.flash_mock, 0x20000,
		MANIFEST_V2_HEADER_SIZE);

	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_init_bad_magic_number (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t pcd_bad_data[PCD_SIGNATURE_OFFSET];

	TEST_START;

	memcpy (pcd_bad_data, PCD_DATA, sizeof (pcd_bad_data));
	pcd_bad_data[2] ^= 0x55;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, pcd_bad_data,
		sizeof (pcd_bad_data), FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1,
		MANIFEST_V2_HEADER_SIZE));
	/* Use blank check to simulate empty PCD regions. */
	status |= flash_master_mock_expect_blank_check (&manager.flash_mock, 0x20000,
		MANIFEST_V2_HEADER_SIZE);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_init_region2_pending_lower_id (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = pcd_manager_flash_testing_verify_pcd2 (&manager, 0x10000);
	status |= pcd_manager_flash_testing_verify_pcd (&manager, 0x20000);

	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_init_region2_pending_same_id (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = pcd_manager_flash_testing_verify_pcd (&manager, 0x10000);
	status |= pcd_manager_flash_testing_verify_pcd (&manager, 0x20000);

	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_init_region2_pending_different_platform_id (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = pcd_manager_flash_testing_verify_pcd (&manager, 0x10000);
	status |= pcd_manager_flash_testing_verify_a_pcd (&manager, 0x20000, PCD3_DATA, PCD3_DATA_LEN,
		PCD3_SIGNATURE, PCD3_SIGNATURE_OFFSET, PCD3_HASH, 0);

	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_init_region1_pending_lower_id (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = manager.state_mgr.save_active_manifest (&manager.state_mgr, SYSTEM_STATE_MANIFEST_PCD,
		MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_testing_verify_pcd (&manager, 0x10000);
	status |= pcd_manager_flash_testing_verify_pcd2 (&manager, 0x20000);

	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_init_region1_pending_same_id (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init_dependencies (test, &manager, 0x10000, 0x20000);

	status = manager.state_mgr.save_active_manifest (&manager.state_mgr, SYSTEM_STATE_MANIFEST_PCD,
		MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_testing_verify_pcd (&manager, 0x10000);
	status |= pcd_manager_flash_testing_verify_pcd (&manager, 0x20000);

	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_init (&manager.test, &manager.pcd1, &manager.pcd2,
		&manager.state_mgr, &manager.hash.base, &manager.verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_get_active_pcd_null (CuTest *test)
{
	struct pcd_manager_flash_testing manager;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, NULL, true);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (NULL));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_activate_pending_pcd_region2_after_write (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	enum manifest_region active;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, NULL, true);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = pcd_manager_flash_testing_verify_pcd2 (&manager, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	status = manager.test.base.base.activate_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

	active = manager.state_mgr.get_active_manifest (&manager.state_mgr, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_activate_pending_pcd_region1_after_write (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	enum manifest_region active;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL,
		pcd_manager_flash_testing_verify_pcd, false);

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x10000);

	status = pcd_manager_flash_testing_verify_pcd2 (&manager, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

	status = manager.test.base.base.activate_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	active = manager.state_mgr.get_active_manifest (&manager.state_mgr, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_activate_pending_pcd_region2_after_write_notify_observers (
	CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	enum manifest_region active;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, NULL, true);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = pcd_manager_flash_testing_verify_pcd2 (&manager, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_add_observer (&manager.test.base, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_pcd_activated,
		&manager.observer, 0, MOCK_ARG (&manager.pcd2));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	status = manager.test.base.base.activate_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

	active = manager.state_mgr.get_active_manifest (&manager.state_mgr, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_activate_pending_pcd_region1_after_write_notify_observers (
	CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	enum manifest_region active;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL,
		pcd_manager_flash_testing_verify_pcd, false);

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x10000);

	status = pcd_manager_flash_testing_verify_pcd2 (&manager, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_add_observer (&manager.test.base, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&manager.observer.mock, manager.observer.base.on_pcd_activated,
		&manager.observer, 0, MOCK_ARG (&manager.pcd1));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

	status = manager.test.base.base.activate_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	active = manager.state_mgr.get_active_manifest (&manager.state_mgr, SYSTEM_STATE_MANIFEST_PCD);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_activate_pending_pcd_no_pending_region2 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, NULL, true);

	status = manager.test.base.base.activate_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_NONE_PENDING, status);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_activate_pending_pcd_no_pending_region1 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL,
		pcd_manager_flash_testing_verify_pcd, false);

	status = manager.test.base.base.activate_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_NONE_PENDING, status);

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_activate_pending_pcd_no_pending_notify_observers (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, NULL, true);

	status = pcd_manager_add_observer (&manager.test.base, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.activate_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_NONE_PENDING, status);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_activate_pending_pcd_null (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, pcd_manager_flash_testing_verify_pcd2, true);

	status = manager.test.base.base.activate_pending_manifest (NULL);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_pending_region_region2 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x20000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_pending_region_region1 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, false);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_pending_region_invalidate_pending_region2 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, pcd_manager_flash_testing_verify_pcd2, true);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_pending_region_invalidate_pending_region1 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd2, pcd_manager_flash_testing_verify_pcd, false);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x20000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_pending_region_null (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	status = manager.test.base.base.clear_pending_region (NULL, 1);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_pending_region_manifest_too_large (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base,
		FLASH_BLOCK_SIZE + 1);
	CuAssertIntEquals (test, FLASH_UPDATER_TOO_LARGE, status);

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_pending_region_erase_error_region2 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd2, pcd_manager_flash_testing_verify_pcd, true);

	status = flash_master_mock_expect_xfer (&manager.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_pending_region_erase_error_region1 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, pcd_manager_flash_testing_verify_pcd2, true);

	status = flash_master_mock_expect_xfer (&manager.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_pending_no_pending_in_use_region2 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, NULL, true);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x20000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_pending_no_pending_in_use_region1 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL,
		pcd_manager_flash_testing_verify_pcd, false);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_write_pending_data_region2 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x20000, 0x10000);
	status |= flash_master_mock_expect_write (&manager.flash_mock, 0x20000, data, sizeof (data));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data,
		sizeof (data));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_write_pending_data_region1 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, false);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x10000, 0x10000);
	status |= flash_master_mock_expect_write (&manager.flash_mock, 0x10000, data, sizeof (data));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data,
		sizeof (data));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_write_pending_data_multiple (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t data2[] = {0x05, 0x06, 0x07, 0x08, 0x09};
	uint8_t data3[] = {0x0a, 0x0b, 0x0c};

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x20000, 0x10000);

	status |= flash_master_mock_expect_write (&manager.flash_mock, 0x20000, data1, 4);
	status |= flash_master_mock_expect_write (&manager.flash_mock, 0x20004, data2, 5);
	status |= flash_master_mock_expect_write (&manager.flash_mock, 0x20009, data3, 3);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data1,
		sizeof (data1));
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data2,
		sizeof (data2));
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data3,
		sizeof (data3));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_write_pending_data_block_end (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t fill[FLASH_BLOCK_SIZE - sizeof (data)] = {0};

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x20000, 0x10000);
	status |= flash_master_mock_expect_write (&manager.flash_mock, 0x20000, fill, sizeof (fill));
	status |= flash_master_mock_expect_write (&manager.flash_mock, 0x2fffc, data, sizeof (data));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	/* Fill with data to write at the end of the flash block. */
	status = manager.test.base.base.write_pending_data (&manager.test.base.base, fill,
		sizeof (fill));
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data,
		sizeof (data));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_write_pending_data_null (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x20000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.write_pending_data (NULL, data, sizeof (data));
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, NULL,
		sizeof (data));
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_write_pending_data_write_error (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x20000, 0x10000);
	status |= flash_master_mock_expect_xfer (&manager.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data,
		sizeof (data));
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_write_pending_data_write_after_error (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t data2[] = {0x05, 0x06, 0x07, 0x08, 0x09};
	uint8_t data3[] = {0x0a, 0x0b, 0x0c};

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x20000, 0x10000);

	status |= flash_master_mock_expect_write (&manager.flash_mock, 0x20000, data1, 4);
	status |= flash_master_mock_expect_xfer (&manager.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_write (&manager.flash_mock, 0x20004, data3, 3);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data1,
		sizeof (data1));
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data2,
		sizeof (data2));
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data3,
		sizeof (data3));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_write_pending_data_partial_write (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t fill[FLASH_PAGE_SIZE - 1] = {0};

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x20000, 0x10000);
	status |= flash_master_mock_expect_write (&manager.flash_mock, 0x20000, fill, sizeof (fill));

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&manager.flash_mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&manager.flash_mock, 0,
		FLASH_EXP_WRITE_CMD (0x02, 0x200ff, 0, data, 1));
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_xfer (&manager.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	/* Partially fill the page to force a write across pages. */
	status = manager.test.base.base.write_pending_data (&manager.test.base.base, fill,
		sizeof (fill));
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data,
		sizeof (data));
	CuAssertIntEquals (test, FLASH_UPDATER_INCOMPLETE_WRITE, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_write_pending_data_write_after_partial_write (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t data2[] = {0x05, 0x06, 0x07, 0x08, 0x09};
	uint8_t fill[FLASH_PAGE_SIZE - 1] = {0};

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x20000, 0x10000);
	status |= flash_master_mock_expect_write (&manager.flash_mock, 0x20000, fill, sizeof (fill));

	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&manager.flash_mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&manager.flash_mock, 0,
		FLASH_EXP_WRITE_CMD (0x02, 0x200ff, 0, data1, 1));
	status |= flash_master_mock_expect_rx_xfer (&manager.flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_xfer (&manager.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);

	status |= flash_master_mock_expect_write (&manager.flash_mock, 0x20100, data2, 5);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	/* Partially fill the page to force a write across pages. */
	status = manager.test.base.base.write_pending_data (&manager.test.base.base, fill,
		sizeof (fill));
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data1,
		sizeof (data1));
	CuAssertIntEquals (test, FLASH_UPDATER_INCOMPLETE_WRITE, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data2,
		sizeof (data2));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_write_pending_data_without_clear (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data,
		sizeof (data));
	CuAssertIntEquals (test, MANIFEST_MANAGER_NOT_CLEARED, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_write_pending_data_restart_write (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t data2[] = {0x05, 0x06, 0x07, 0x08, 0x09};
	uint8_t data3[] = {0x0a, 0x0b, 0x0c};

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x20000, 0x10000);

	status |= flash_master_mock_expect_write (&manager.flash_mock, 0x20000, data1, 4);
	status |= flash_master_mock_expect_write (&manager.flash_mock, 0x20004, data2, 5);

	status |= flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x20000, 0x10000);

	status |= flash_master_mock_expect_write (&manager.flash_mock, 0x20000, data3, 3);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data1,
		sizeof (data1));
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data2,
		sizeof (data2));
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data3,
		sizeof (data3));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_write_pending_data_too_long (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t fill[FLASH_BLOCK_SIZE - sizeof (data) + 1] = {0};

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x20000, 0x10000);
	status |= flash_master_mock_expect_write (&manager.flash_mock, 0x20000, fill, sizeof (fill));

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	/* Fill with data to write at the end of the flash block. */
	status = manager.test.base.base.write_pending_data (&manager.test.base.base, fill,
		sizeof (fill));
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data,
		sizeof (data));
	CuAssertIntEquals (test, FLASH_UPDATER_OUT_OF_SPACE, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_region2 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = pcd_manager_flash_testing_verify_pcd (&manager, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_region1 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, false);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x10000);

	status = pcd_manager_flash_testing_verify_pcd (&manager, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_region2_notify_observers (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = pcd_manager_add_observer (&manager.test.base, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_testing_verify_pcd (&manager, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_region1_notify_observers (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, false);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x10000);

	status = pcd_manager_add_observer (&manager.test.base, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = pcd_manager_flash_testing_verify_pcd (&manager, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_with_active (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, NULL, true);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = pcd_manager_flash_testing_verify_pcd2 (&manager, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_lower_id (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd2, NULL, true);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = pcd_manager_flash_testing_verify_pcd (&manager, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ID, status);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_same_id (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, NULL, true);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = pcd_manager_flash_testing_verify_pcd (&manager, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ID, status);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_different_platform_id (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, NULL, true);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = pcd_manager_flash_testing_verify_a_pcd (&manager, 0x20000, PCD3_DATA, PCD3_DATA_LEN,
		PCD3_SIGNATURE, PCD3_SIGNATURE_OFFSET, PCD3_HASH, 0);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ID, status);

	CuAssertPtrEquals (test, &manager.pcd1, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_no_clear_region2 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_NONE_PENDING, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_no_clear_region1 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, false);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_NONE_PENDING, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_extra_data_written (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	int offset;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	offset = pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = flash_master_mock_expect_write (&manager.flash_mock, 0x20000 + offset, data,
		sizeof (data));

	status |= pcd_manager_flash_testing_verify_pcd (&manager, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data,
		sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_null (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = manager.test.base.base.verify_pending_manifest (NULL);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_verify_error_region2 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = flash_master_mock_expect_xfer (&manager.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_verify_error_region1 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, false);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x10000);

	status = flash_master_mock_expect_xfer (&manager.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_verify_error_notify_observers (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = pcd_manager_add_observer (&manager.test.base, &manager.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&manager.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_verify_fail_region2 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = pcd_manager_flash_testing_verify_a_pcd (&manager, 0x20000, PCD_DATA, PCD_DATA_LEN,
		PCD_SIGNATURE, PCD_SIGNATURE_OFFSET, PCD_HASH, RSA_ENGINE_BAD_SIGNATURE);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_verify_fail_region1 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, false);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x10000);

	status = pcd_manager_flash_testing_verify_a_pcd (&manager, 0x10000, PCD_DATA, PCD_DATA_LEN,
		PCD_SIGNATURE, PCD_SIGNATURE_OFFSET, PCD_HASH, RSA_ENGINE_BAD_SIGNATURE);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_verify_fail_ecc_region2 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = pcd_manager_flash_testing_verify_a_pcd (&manager, 0x20000, PCD_DATA, PCD_DATA_LEN,
		PCD_SIGNATURE, PCD_SIGNATURE_OFFSET, PCD_HASH, ECC_ENGINE_BAD_SIGNATURE);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, ECC_ENGINE_BAD_SIGNATURE, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_verify_fail_ecc_region1 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, false);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x10000);

	status = pcd_manager_flash_testing_verify_a_pcd (&manager, 0x10000, PCD_DATA, PCD_DATA_LEN,
		PCD_SIGNATURE, PCD_SIGNATURE_OFFSET, PCD_HASH, ECC_ENGINE_BAD_SIGNATURE);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, ECC_ENGINE_BAD_SIGNATURE, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_verify_after_verify_error (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = flash_master_mock_expect_xfer (&manager.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_NONE_PENDING, status);

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_verify_after_verify_fail (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = pcd_manager_flash_testing_verify_a_pcd (&manager, 0x20000, PCD_DATA, PCD_DATA_LEN,
		PCD_SIGNATURE, PCD_SIGNATURE_OFFSET, PCD_HASH, RSA_ENGINE_BAD_SIGNATURE);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_NONE_PENDING, status);

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_write_after_verify (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = pcd_manager_flash_testing_verify_pcd (&manager, 0x20000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data,
		sizeof (data));
	CuAssertIntEquals (test, MANIFEST_MANAGER_NOT_CLEARED, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_write_after_verify_error (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	pcd_manager_flash_testing_write_new_pcd (test, &manager, 0x20000);

	status = flash_master_mock_expect_xfer (&manager.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data,
		sizeof (data));
	CuAssertIntEquals (test, MANIFEST_MANAGER_NOT_CLEARED, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_incomplete_pcd (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x20000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 2);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INCOMPLETE_UPDATE, status);

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_verify_pending_pcd_write_after_incomplete_pcd (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x20000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 2);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.verify_pending_manifest (&manager.test.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INCOMPLETE_UPDATE, status);

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data,
		sizeof (data));
	CuAssertIntEquals (test, MANIFEST_MANAGER_NOT_CLEARED, status);

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_all_manifests_region1 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, pcd_manager_flash_testing_verify_pcd, false);

	status = flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x10000);
	status |= flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x20000);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_all_manifests (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_all_manifests_region2 (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, pcd_manager_flash_testing_verify_pcd, true);

	status = flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x20000);
	status |= flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x10000);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_all_manifests (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_all_manifests_only_active (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd2, NULL, true);

	status = flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x20000);
	status |= flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x10000);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_all_manifests (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_all_manifests_only_pending (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL,
		pcd_manager_flash_testing_verify_pcd, true);

	status = flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x10000);
	status |= flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x20000);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_all_manifests (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_all_manifests_no_pcds (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000, NULL, NULL, true);

	status = flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x20000);
	status |= flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x10000);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_all_manifests (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_all_manifests_active_in_use (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	struct pcd *active;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, pcd_manager_flash_testing_verify_pcd2, true);

	active = manager.test.base.get_active_pcd (&manager.test.base);

	status = flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_all_manifests (&manager.test.base.base);
	CuAssertIntEquals (test, MANIFEST_MANAGER_ACTIVE_IN_USE, status);

	manager.test.base.free_pcd (&manager.test.base, active);

	active = manager.test.base.get_active_pcd (&manager.test.base);
	CuAssertPtrEquals (test, &manager.pcd2, active);
	manager.test.base.free_pcd (&manager.test.base, active);

	status = mock_validate (&manager.flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x10000);
	status |= flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x20000);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_all_manifests (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_all_manifests_during_update (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, pcd_manager_flash_testing_verify_pcd2, true);

	status = flash_master_mock_expect_erase_flash_verify (&manager.flash_mock, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_pending_region (&manager.test.base.base, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&manager.flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x10000);
	status |= flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x20000);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_all_manifests (&manager.test.base.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	status = manager.test.base.base.write_pending_data (&manager.test.base.base, data,
		sizeof (data));
	CuAssertIntEquals (test, MANIFEST_MANAGER_NOT_CLEARED, status);

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_all_manifests_null (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, pcd_manager_flash_testing_verify_pcd2, true);

	status = manager.test.base.base.clear_all_manifests (NULL);
	CuAssertIntEquals (test, MANIFEST_MANAGER_INVALID_ARGUMENT, status);

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_all_manifests_erase_pending_error (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, pcd_manager_flash_testing_verify_pcd2, true);

	status = flash_master_mock_expect_xfer (&manager.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_all_manifests (&manager.test.base.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, &manager.pcd2, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}

static void pcd_manager_flash_test_clear_all_manifests_erase_active_error (CuTest *test)
{
	struct pcd_manager_flash_testing manager;
	int status;

	TEST_START;

	pcd_manager_flash_testing_init (test, &manager, 0x10000, 0x20000,
		pcd_manager_flash_testing_verify_pcd, pcd_manager_flash_testing_verify_pcd2, true);

	status = flash_master_mock_expect_erase_flash (&manager.flash_mock, 0x10000);
	status |= flash_master_mock_expect_xfer (&manager.flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = manager.test.base.base.clear_all_manifests (&manager.test.base.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	CuAssertPtrEquals (test, NULL, manager.test.base.get_active_pcd (&manager.test.base));

	pcd_manager_flash_testing_validate_and_release (test, &manager);
}


CuSuite* get_pcd_manager_flash_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, pcd_manager_flash_test_init);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_init_region1);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_init_region2);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_init_activate_pending);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_init_null);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_init_region1_flash_error);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_init_region2_flash_error);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_init_pcd_bad_signature);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_init_pcd_bad_signature_ecc);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_init_bad_length);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_init_bad_magic_number);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_init_region1_pending_same_id);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_init_region1_pending_lower_id);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_init_region2_pending_same_id);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_init_region2_pending_different_platform_id);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_init_region2_pending_lower_id);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_get_active_pcd_null);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_activate_pending_pcd_region2_after_write);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_activate_pending_pcd_region1_after_write);
	SUITE_ADD_TEST (suite,
		pcd_manager_flash_test_activate_pending_pcd_region2_after_write_notify_observers);
	SUITE_ADD_TEST (suite,
		pcd_manager_flash_test_activate_pending_pcd_region1_after_write_notify_observers);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_activate_pending_pcd_no_pending_region2);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_activate_pending_pcd_no_pending_region1);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_activate_pending_pcd_no_pending_notify_observers);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_activate_pending_pcd_null);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_pending_region_region2);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_pending_region_region1);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_pending_region_invalidate_pending_region2);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_pending_region_invalidate_pending_region1);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_pending_region_null);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_pending_region_manifest_too_large);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_pending_region_erase_error_region2);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_pending_region_erase_error_region1);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_pending_no_pending_in_use_region2);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_pending_no_pending_in_use_region1);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_write_pending_data_region2);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_write_pending_data_region1);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_write_pending_data_multiple);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_write_pending_data_block_end);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_write_pending_data_null);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_write_pending_data_write_error);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_write_pending_data_write_after_error);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_write_pending_data_partial_write);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_write_pending_data_write_after_partial_write);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_write_pending_data_without_clear);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_write_pending_data_restart_write);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_write_pending_data_too_long);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_region2);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_region1);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_region2_notify_observers);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_region1_notify_observers);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_with_active);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_lower_id);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_same_id);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_different_platform_id);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_no_clear_region2);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_no_clear_region1);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_extra_data_written);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_null);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_verify_error_region2);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_verify_error_region1);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_verify_error_notify_observers);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_verify_fail_region2);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_verify_fail_region1);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_verify_fail_ecc_region2);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_verify_fail_ecc_region1);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_verify_after_verify_error);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_verify_after_verify_fail);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_write_after_verify);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_write_after_verify_error);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_incomplete_pcd);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_verify_pending_pcd_write_after_incomplete_pcd);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_all_manifests_region1);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_all_manifests_region2);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_all_manifests_only_active);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_all_manifests_only_pending);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_all_manifests_no_pcds);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_all_manifests_active_in_use);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_all_manifests_during_update);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_all_manifests_null);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_all_manifests_erase_pending_error);
	SUITE_ADD_TEST (suite, pcd_manager_flash_test_clear_all_manifests_erase_active_error);

	return suite;
}
