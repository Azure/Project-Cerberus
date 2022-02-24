// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "manifest/cfm/cfm_flash.h"
#include "manifest/cfm/cfm_format.h"
#include "testing/engines/hash_testing_engine.h"
#include "flash/flash.h"
#include "manifest_flash_v2_testing.h"
#include "cfm_testing.h"


static const char *SUITE = "cfm_flash";


/**
 * Dummy CFM for testing.
 */
const uint8_t CFM_DATA[] = {
	0x14,0x0b,0x92,0xa5,0x01,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x27,0x27,0x00,0x00,
	0x00,0xff,0x01,0x00,0x48,0x06,0x08,0x00,0x70,0xff,0x00,0x01,0x50,0x06,0x10,0x00,
	0x7a,0x70,0x00,0x02,0x60,0x06,0x44,0x00,0x71,0x70,0x00,0x03,0xa4,0x06,0x24,0x00,
	0x71,0x70,0x00,0x04,0xc8,0x06,0x44,0x00,0x72,0x70,0x00,0x05,0x0c,0x07,0x44,0x00,
	0x72,0x70,0x00,0x06,0x50,0x07,0x44,0x00,0x73,0x70,0x00,0x07,0x94,0x07,0x44,0x00,
	0x73,0x70,0x00,0x08,0xd8,0x07,0x24,0x00,0x74,0x70,0x00,0x09,0xfc,0x07,0x04,0x00,
	0x75,0x74,0x00,0x0a,0x00,0x08,0x1c,0x00,0x75,0x74,0x00,0x0b,0x1c,0x08,0x18,0x00,
	0x74,0x70,0x00,0x0c,0x34,0x08,0x04,0x00,0x75,0x74,0x00,0x0d,0x38,0x08,0x10,0x00,
	0x75,0x74,0x00,0x0e,0x48,0x08,0x0c,0x00,0x76,0x70,0x00,0x0f,0x54,0x08,0x0e,0x00,
	0x79,0x76,0x00,0x10,0x62,0x08,0x0c,0x00,0x79,0x76,0x00,0x11,0x6e,0x08,0x08,0x00,
	0x76,0x70,0x00,0x12,0x76,0x08,0x0e,0x00,0x79,0x76,0x00,0x13,0x84,0x08,0x08,0x00,
	0x77,0x70,0x00,0x14,0x8c,0x08,0x0e,0x00,0x79,0x77,0x00,0x15,0x9a,0x08,0x08,0x00,
	0x77,0x70,0x00,0x16,0xa2,0x08,0x0e,0x00,0x79,0x77,0x00,0x17,0xb0,0x08,0x08,0x00,
	0x78,0x70,0x00,0x18,0xb8,0x08,0x0e,0x00,0x79,0x78,0x00,0x19,0xc6,0x08,0x08,0x00,
	0x70,0xff,0x00,0x1a,0xce,0x08,0x10,0x00,0x7a,0x70,0x00,0x1b,0xde,0x08,0x34,0x00,
	0x71,0x70,0x00,0x1c,0x12,0x09,0x34,0x00,0x72,0x70,0x00,0x1d,0x46,0x09,0x44,0x00,
	0x73,0x70,0x00,0x1e,0x8a,0x09,0x34,0x00,0x74,0x70,0x00,0x1f,0xbe,0x09,0x04,0x00,
	0x75,0x74,0x00,0x20,0xc2,0x09,0x10,0x00,0x76,0x70,0x00,0x21,0xd2,0x09,0x0e,0x00,
	0x79,0x76,0x00,0x22,0xe0,0x09,0x08,0x00,0x77,0x70,0x00,0x23,0xe8,0x09,0x0e,0x00,
	0x79,0x77,0x00,0x24,0xf6,0x09,0x08,0x00,0x78,0x70,0x00,0x25,0xfe,0x09,0x0e,0x00,
	0x79,0x78,0x00,0x26,0x0c,0x0a,0x08,0x00,0x13,0xe9,0x1c,0x16,0x0e,0xcf,0xd2,0xbb,
	0x3a,0x86,0x83,0xb6,0x01,0xc4,0xba,0xcb,0x04,0xf0,0xa5,0x18,0x9b,0x97,0xd9,0x2d,
	0x67,0xf4,0x6d,0x69,0xea,0x1e,0x25,0x36,0xe8,0x57,0x2a,0x8e,0x2e,0x62,0x19,0xc1,
	0x75,0xcb,0x14,0x77,0x77,0x4b,0xfc,0xac,0xb4,0xa7,0xcd,0x12,0x43,0x44,0x4b,0xa7,
	0xf3,0xb1,0x1d,0xef,0x3e,0x1f,0xbb,0x07,0x2b,0xed,0x7a,0xf7,0x5e,0x3b,0x06,0x41,
	0x34,0x07,0xf0,0x43,0x00,0x70,0x34,0xcf,0x41,0x70,0xb5,0x61,0xa5,0xf2,0x16,0xce,
	0x74,0x1d,0x12,0x0b,0xcc,0xf1,0xca,0x3c,0x40,0xe8,0x08,0x0e,0xe9,0xd5,0x0f,0x4f,
	0x78,0x38,0xcb,0x03,0x25,0x03,0xfe,0xb2,0x7a,0x49,0x0b,0xcc,0x07,0xf3,0xb5,0x13,
	0xc9,0xfe,0xec,0xd0,0x46,0x63,0xe0,0x03,0xbd,0xff,0x06,0x76,0x6e,0x1c,0xc1,0xf3,
	0x45,0x1a,0xad,0x4b,0x90,0x14,0x4e,0xb6,0xad,0x83,0xf5,0x05,0xca,0x91,0x83,0xf5,
	0xe3,0x99,0xe4,0xee,0xa7,0x3d,0x13,0x0f,0x13,0x8d,0xad,0xbb,0x70,0x3c,0x40,0x52,
	0x07,0x61,0xc2,0xb2,0xf8,0xab,0x13,0x60,0x7e,0x54,0xbe,0x97,0x80,0x15,0x8e,0x05,
	0x76,0x5c,0xf8,0xf6,0x68,0x87,0x21,0xa5,0xc0,0xf4,0xe0,0x37,0xc3,0xe2,0x19,0xeb,
	0x7c,0xa0,0x33,0x2a,0x7b,0x88,0xc8,0x09,0x4b,0x51,0xed,0x80,0x38,0x35,0x11,0x19,
	0x2d,0x89,0x0c,0x8f,0x04,0xf5,0xf7,0x74,0x39,0xe1,0x04,0x32,0xbb,0x27,0x87,0xfe,
	0x97,0x4a,0x00,0x9b,0xf3,0x35,0xbc,0xbe,0x8f,0xea,0xa5,0xac,0xbd,0xcf,0xa7,0x75,
	0x92,0xe1,0x3c,0x61,0x5d,0x1a,0x91,0x62,0x31,0x78,0x10,0x0b,0xb3,0x96,0x44,0x3f,
	0x69,0x76,0x61,0x32,0x76,0xc8,0x2b,0xf5,0x33,0xff,0x8e,0x13,0x79,0x2d,0x2d,0xf3,
	0x72,0x4d,0x02,0x76,0xf7,0x55,0x5b,0x8c,0xd8,0x1f,0xe9,0x6d,0xc5,0x00,0xbc,0x43,
	0xe1,0xcd,0x58,0x00,0xbe,0xf9,0xd7,0x2b,0x3d,0x03,0x0b,0xdb,0x7e,0x86,0x0e,0x10,
	0xc5,0x22,0xe4,0x24,0x6b,0x30,0xbd,0x93,0x6a,0x65,0x1f,0x3b,0x69,0x40,0xcf,0x99,
	0x74,0x33,0x80,0xdf,0xcc,0xb2,0xf1,0xd3,0x62,0xe6,0xb3,0x41,0x83,0x9b,0xab,0xfb,
	0xf2,0x55,0x19,0xa1,0x76,0x1f,0x1d,0xeb,0x23,0x41,0xab,0xfa,0xb2,0x42,0x9b,0xf3,
	0x12,0x45,0xb7,0x8f,0xfc,0xe0,0xb7,0x4a,0x3c,0xe7,0xd8,0x51,0xd9,0x02,0x7d,0x69,
	0xab,0xfa,0x63,0x3d,0x7c,0x6f,0x35,0x6e,0xb2,0x9d,0x58,0xdf,0x74,0x5b,0xbf,0x59,
	0x87,0xee,0xf0,0xad,0x36,0x03,0x6f,0x49,0x33,0x46,0xbe,0x85,0x40,0xda,0x52,0xf7,
	0x59,0x43,0x02,0x09,0x4d,0xec,0xef,0x5d,0x42,0x57,0x65,0xbb,0xe1,0x94,0xb9,0x87,
	0xf3,0xb2,0x6f,0x2c,0xc5,0xb4,0x92,0x67,0xc0,0xd1,0x79,0x7a,0x5b,0x31,0x8f,0xc8,
	0x8c,0x49,0x06,0x63,0x7f,0xbc,0xeb,0xe8,0x56,0xef,0x38,0x92,0x49,0x63,0x71,0x60,
	0xf0,0xec,0x0e,0x57,0x74,0xeb,0x91,0xb2,0x1f,0xa2,0x7f,0x30,0xc7,0x4a,0xcf,0x56,
	0x4e,0x51,0xd9,0xe5,0x74,0x12,0x98,0x3b,0x93,0xc1,0x46,0xda,0xac,0x53,0x1a,0xff,
	0xc8,0x3c,0xcf,0xd0,0x41,0x7c,0x02,0x96,0xeb,0x5c,0x16,0x31,0xb7,0x8c,0xd5,0x27,
	0xe4,0x03,0x0b,0x67,0x93,0x88,0xf6,0x2c,0x5a,0xaa,0xc6,0x7c,0xf4,0x86,0x9f,0x1f,
	0x33,0x14,0xe6,0xed,0xe2,0xe8,0xcf,0xf2,0xbb,0x96,0xed,0x1f,0xbb,0x80,0x77,0x3d,
	0x83,0xfa,0xc7,0x0d,0xb4,0x61,0x06,0x31,0xbd,0xc5,0xb0,0x24,0x8b,0x05,0x2a,0xa7,
	0x13,0x16,0xff,0xa7,0x31,0xc5,0x2f,0xb8,0x40,0x34,0x28,0x4e,0xe6,0x7c,0xc2,0x19,
	0xfa,0x54,0x99,0xe9,0x7d,0xa9,0x9d,0x9a,0xf0,0x23,0xc6,0xde,0x58,0x3b,0x8e,0x03,
	0x9b,0x5f,0x67,0xa7,0xef,0x4c,0xe4,0xf1,0x78,0x33,0x2c,0x6d,0x3f,0x42,0x8b,0x5d,
	0x5d,0x83,0x9a,0x49,0xaf,0x09,0x70,0xa6,0x33,0xd5,0x46,0x93,0xe8,0x52,0x7a,0x5c,
	0x8c,0xaa,0x9d,0x84,0x7d,0x49,0x1d,0x25,0x25,0x71,0xe8,0x07,0x58,0x49,0xad,0x42,
	0xbb,0xc7,0xfa,0x91,0xa6,0xfc,0x61,0x93,0x0e,0xcd,0x89,0x5e,0xb4,0x22,0xce,0xe0,
	0xb8,0xae,0x62,0x57,0x6a,0x83,0x63,0x88,0xfc,0x40,0x76,0x6e,0xdc,0xc9,0x47,0xe8,
	0x57,0x57,0x65,0x17,0x0c,0xee,0x66,0x9c,0x47,0x35,0xa1,0x4c,0x94,0x1f,0x3d,0xc9,
	0x79,0x7f,0x74,0x55,0xe3,0xbd,0x43,0x56,0x77,0x82,0x6f,0x48,0xf8,0xb0,0x46,0x24,
	0xc1,0x34,0xc0,0x39,0xfa,0x03,0xbc,0x11,0x2d,0xdb,0x92,0x18,0xe7,0xac,0x50,0xfa,
	0x51,0x50,0x05,0x55,0x52,0x56,0x3c,0x45,0xe2,0xfb,0x03,0xca,0x48,0x44,0x24,0xd6,
	0xa0,0x48,0x72,0x68,0xe3,0xc8,0x7e,0x47,0x71,0x05,0x83,0xd7,0x8c,0xf0,0xe2,0xff,
	0xde,0x97,0x68,0x54,0x03,0x4f,0x4e,0x24,0xfe,0x8a,0x53,0xbc,0xcc,0xbb,0x15,0xdc,
	0x03,0x44,0x69,0xb5,0x66,0x94,0x88,0x1e,0x99,0x24,0x75,0x92,0x01,0x46,0x61,0x4e,
	0x87,0x5f,0xa3,0xb9,0xbc,0x33,0x82,0xb5,0xee,0x88,0xab,0xde,0x57,0x74,0x43,0x23,
	0x13,0x7b,0x60,0xac,0x3b,0xd7,0xfe,0xb4,0x20,0xc9,0x58,0xd6,0x4f,0xaf,0x08,0xf6,
	0x58,0xbb,0xc6,0xe1,0xe5,0x17,0x3e,0xd1,0x37,0x1a,0x72,0xe6,0x7b,0x18,0xd3,0x06,
	0xe8,0xf5,0x7a,0xbc,0x8e,0x61,0xe0,0xce,0x0f,0xa0,0xae,0x6b,0x69,0x26,0xe4,0x17,
	0x72,0x15,0xac,0x0e,0xa9,0x90,0xbc,0x9d,0x8e,0x66,0xc2,0xc5,0x68,0xb8,0x35,0xf3,
	0x59,0xc7,0xd1,0x68,0x7f,0x6c,0x1c,0xe7,0xce,0x37,0x4b,0x27,0x9f,0x7a,0x57,0x9c,
	0x58,0xec,0xff,0x64,0x9c,0x89,0xda,0xc1,0x2e,0xbb,0xd8,0xc7,0x24,0x67,0x81,0x68,
	0xc4,0x6f,0x78,0xd4,0x08,0x5c,0x71,0xdd,0xf2,0xda,0x8d,0x26,0xeb,0xd8,0x9b,0x7b,
	0x7f,0xb4,0x98,0x60,0x1e,0x85,0x1a,0xae,0x53,0xfe,0x61,0xad,0x59,0x6a,0xd2,0xb8,
	0x41,0xbc,0x62,0x6d,0x13,0x08,0x9d,0xd4,0x61,0x6c,0xd8,0x9c,0xc3,0xd0,0x6b,0xe1,
	0x16,0x67,0x8b,0xb3,0x83,0x99,0x82,0x1e,0xc3,0x11,0x9f,0xd7,0xdf,0x34,0x58,0x25,
	0x3c,0x80,0xfa,0xf6,0xdf,0xc0,0xa6,0x83,0xc2,0x0b,0xec,0xa1,0x71,0x31,0x4d,0xf6,
	0x7b,0xfc,0xea,0x99,0xe1,0xa0,0x40,0xad,0x57,0x28,0x48,0x8b,0x19,0xe0,0x3e,0x7f,
	0xfb,0xe8,0xa8,0x77,0x4a,0x64,0x10,0x61,0xbd,0xc6,0xb5,0x05,0x69,0x9e,0xc7,0x3f,
	0xaf,0x2a,0xa3,0xf2,0x07,0x8a,0xdd,0xb2,0x52,0xf9,0x02,0xb0,0x6a,0x0a,0xf8,0x1f,
	0x12,0xf6,0xd9,0xe1,0xf8,0xb6,0x0b,0x1f,0xec,0xb1,0xc3,0xfb,0x15,0xba,0xb8,0xa2,
	0x27,0xce,0xce,0x57,0x85,0x0a,0x93,0xc3,0x2c,0x10,0xf2,0x94,0x71,0xb5,0xc9,0xca,
	0x6e,0x11,0xd9,0xa9,0xb3,0x44,0x47,0xeb,0x50,0x1c,0x3b,0xca,0x1f,0xa5,0x4b,0x95,
	0xc5,0x48,0x08,0x5a,0x2d,0x48,0xb0,0x1e,0xd9,0x1e,0x17,0xfb,0x37,0x4e,0xad,0x55,
	0xb3,0xac,0xce,0x8c,0x58,0xc7,0x12,0xc6,0x96,0xa3,0x44,0xf9,0xf6,0xb7,0x46,0x89,
	0xf4,0xb2,0xb3,0xce,0xad,0xc3,0xad,0xd0,0xb8,0x87,0x27,0xd7,0xe3,0x2f,0xed,0x10,
	0x46,0x02,0x00,0x1d,0x37,0x27,0x10,0x4d,0x7e,0xf1,0xbd,0x8f,0x7e,0xfd,0x5d,0x4b,
	0x91,0x39,0x85,0x99,0x6b,0x45,0xdc,0x9a,0x43,0xb2,0x9f,0x9a,0xb0,0x3f,0xe8,0xe3,
	0x2d,0x09,0x8f,0xd8,0x25,0x04,0x4b,0x91,0x20,0xc9,0x58,0xd6,0x4f,0xaf,0x08,0xf6,
	0x58,0xbb,0xc6,0xe1,0xe5,0x17,0x3e,0xd1,0x37,0x1a,0x72,0xe6,0x7b,0x18,0xd3,0x06,
	0xe8,0xf5,0x7a,0xbc,0x8e,0x61,0xe0,0xce,0x90,0x79,0xc9,0x3e,0xed,0x3f,0x46,0xc7,
	0xe9,0x60,0x11,0xb6,0x72,0x3e,0xa5,0x34,0x05,0x28,0x53,0x77,0xde,0x79,0xe2,0xa5,
	0x3d,0xf5,0x4e,0xac,0x68,0x11,0xcf,0xb4,0x67,0x5a,0xee,0x86,0x0f,0x7d,0x0e,0x1a,
	0x10,0xb8,0x8d,0xd9,0x54,0x26,0xad,0x58,0xa8,0x9a,0x85,0x7d,0x58,0x77,0xe0,0x36,
	0x73,0x6b,0x52,0x7b,0x92,0x93,0xb7,0x8b,0x53,0x23,0xa9,0x2f,0xe8,0x37,0x4a,0xa8,
	0x6c,0x6e,0x22,0x4d,0xf3,0x95,0x34,0x7d,0xf9,0x54,0x8b,0xed,0x16,0x1f,0x5e,0x3a,
	0xb1,0xf9,0xb4,0x3d,0x9b,0x49,0xe8,0xc6,0x04,0x00,0x00,0x00,0x53,0x4b,0x55,0x31,
	0x01,0x00,0x00,0x0a,0x43,0x6f,0x6d,0x70,0x6f,0x6e,0x65,0x6e,0x74,0x31,0x00,0x00,
	0x00,0x02,0x00,0x00,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,
	0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,
	0xee,0xee,0xee,0xee,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0x01,0x00,0x00,0x00,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
	0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
	0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x02,0x40,0x00,0x00,0x11,0x11,0x11,0x11,
	0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
	0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
	0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
	0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x00,0x00,0x02,0x00,
	0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
	0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
	0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,
	0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,
	0x04,0x40,0x01,0x00,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,
	0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,
	0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,
	0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,
	0xcc,0xcc,0xcc,0xcc,0x01,0x02,0x00,0x02,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,
	0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,
	0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,
	0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,
	0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0x02,0x02,0x00,0x01,0xcc,0xcc,0xcc,0xcc,
	0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,
	0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0x01,0x02,0x00,0x00,
	0x80,0x00,0x02,0x05,0x00,0x00,0x00,0x00,0x00,0xff,0x00,0xff,0xff,0x00,0x00,0x00,
	0x54,0x65,0x73,0x74,0x31,0x54,0x65,0x73,0x74,0x32,0x00,0x00,0x80,0x04,0x01,0x05,
	0x00,0x00,0x00,0x00,0x00,0x00,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x22,0x00,
	0x00,0x00,0x00,0x00,0x01,0x04,0x00,0x00,0x80,0x01,0x01,0x02,0x00,0x00,0x00,0x00,
	0x00,0xff,0x00,0x00,0x65,0x43,0x00,0x00,0x00,0x01,0x01,0x02,0x00,0x00,0x00,0x00,
	0x10,0x11,0x00,0x00,0x01,0x09,0x70,0x6c,0x61,0x74,0x66,0x6f,0x72,0x6d,0x41,0x00,
	0x00,0x00,0x00,0x02,0x00,0x00,0x99,0x00,0x00,0x00,0x9a,0x00,0x00,0x00,0x04,0x01,
	0x00,0x00,0x9d,0x00,0x00,0x00,0x02,0x09,0x70,0x6c,0x61,0x74,0x66,0x6f,0x72,0x6d,
	0x42,0x00,0x00,0x00,0x03,0x01,0x00,0x00,0x55,0x00,0x00,0x00,0x01,0x09,0x70,0x6c,
	0x61,0x74,0x66,0x6f,0x72,0x6d,0x43,0x00,0x00,0x00,0x04,0x01,0x00,0x00,0x12,0x00,
	0x00,0x00,0x02,0x09,0x70,0x6c,0x61,0x74,0x66,0x6f,0x72,0x6d,0x45,0x00,0x00,0x00,
	0x00,0x01,0x00,0x00,0xab,0x00,0x00,0x00,0x00,0x09,0x70,0x6c,0x61,0x74,0x66,0x6f,
	0x72,0x6d,0x44,0x00,0x00,0x00,0x03,0x01,0x00,0x00,0x34,0x00,0x00,0x00,0x00,0x01,
	0x00,0x0a,0x43,0x6f,0x6d,0x70,0x6f,0x6e,0x65,0x6e,0x74,0x32,0x00,0x00,0x20,0x01,
	0x00,0x00,0xab,0xab,0xab,0xab,0xab,0xab,0xab,0xab,0xab,0xab,0xab,0xab,0xab,0xab,
	0xab,0xab,0xab,0xab,0xab,0xab,0xab,0xab,0xab,0xab,0xab,0xab,0xab,0xab,0xab,0xab,
	0xab,0xab,0xab,0xab,0xab,0xab,0xab,0xab,0xab,0xab,0xab,0xab,0xab,0xab,0xab,0xab,
	0xab,0xab,0x00,0x20,0x00,0x00,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,
	0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,
	0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,
	0x33,0x33,0x33,0x33,0x33,0x33,0x02,0x40,0x01,0x00,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
	0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
	0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
	0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
	0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0x01,0x05,0x20,0x01,0xee,0xee,
	0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,
	0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,
	0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0x01,0x03,
	0x00,0x00,0x80,0x04,0x01,0x03,0x00,0x00,0x00,0x00,0xff,0x0f,0xff,0x00,0x12,0x34,
	0x56,0x00,0x02,0x09,0x70,0x6c,0x61,0x74,0x66,0x6f,0x72,0x6d,0x31,0x00,0x00,0x00,
	0x05,0x01,0x00,0x00,0x12,0x00,0x00,0x00,0x00,0x09,0x70,0x6c,0x61,0x74,0x66,0x6f,
	0x72,0x6d,0x32,0x00,0x00,0x00,0x03,0x01,0x00,0x00,0x34,0x00,0x00,0x00,0x00,0x09,
	0x70,0x6c,0x61,0x74,0x66,0x6f,0x72,0x6d,0x33,0x00,0x00,0x00,0x02,0x01,0x00,0x00,
	0x56,0x00,0x00,0x00,0x37,0xde,0x00,0x6b,0xaa,0x03,0xa7,0x6d,0x16,0x75,0xb3,0x95,
	0x85,0x83,0xb2,0xcc,0xd8,0xba,0xa7,0xd0,0x97,0x46,0x1e,0xa4,0x9b,0x50,0xeb,0x03,
	0x02,0xec,0x81,0x22,0xb0,0x40,0x68,0x89,0xfa,0xc5,0x99,0x9b,0xc6,0x56,0x36,0xfa,
	0xa2,0x8e,0x03,0xb3,0xd5,0x4f,0x87,0xc6,0x81,0xd9,0x5f,0x8a,0xb8,0x46,0xd6,0x18,
	0x9c,0xcf,0x4b,0x08,0xed,0x8e,0xdd,0x4e,0xd0,0xd9,0xad,0xff,0x2f,0x78,0x73,0x3d,
	0x8f,0x8c,0xc9,0x6c,0xd0,0x80,0x2d,0x5c,0xa5,0x94,0x77,0xe6,0xa6,0xd4,0x2b,0xb5,
	0x74,0x4e,0xa7,0xe7,0xf9,0xbb,0x85,0x4d,0x44,0xda,0xc1,0x1b,0x3a,0x94,0xaf,0x36,
	0x90,0xe0,0x0b,0x85,0x6d,0x3c,0x32,0xa0,0x57,0x37,0x5b,0xb2,0xe0,0xa2,0x1b,0xf0,
	0xed,0xbe,0x60,0x24,0x25,0x15,0xbc,0x64,0xce,0x2d,0xf7,0x56,0x13,0xa0,0xbb,0xc6,
	0x60,0xb0,0xf2,0x88,0xe0,0x12,0xae,0xdb,0x3f,0x0d,0xf2,0x74,0x23,0x2d,0x81,0xdf,
	0x6b,0x31,0x05,0xdd,0x5f,0x09,0x9c,0x1c,0xee,0xf1,0x53,0xcf,0xd5,0x3a,0xa8,0x29,
	0x5d,0x8a,0xc8,0x4e,0xa6,0x62,0xba,0xd9,0x76,0x89,0x81,0x45,0x46,0x38,0x4a,0x62,
	0x20,0x18,0x93,0xca,0x70,0xa5,0xc3,0x19,0x42,0x81,0x98,0xd1,0xd2,0x29,0xcf,0x69,
	0x2b,0x10,0xdf,0x2a,0x7c,0x8b,0xaf,0x3d,0x60,0x9c,0x09,0x9d,0x54,0xf1,0x93,0x86,
	0x7e,0x8c,0x30,0x43,0x9e,0x86,0xe8,0x32,0x0b,0x52,0x78,0x76,0xc2,0x81,0x95,0xe9,
	0x57,0x99,0xfc,0x22,0xf6,0x10,0x46,0x28,0x62,0x7f,0x26,0x63,0x41,0xd8,0x1e,0x78,
	0xfd,0x4f,0xc4,0x80
};

/**
 * Length of the test CFM data.
 */
const uint32_t CFM_DATA_LEN = sizeof (CFM_DATA);

/**
 * CFM_DATA hash for testing.
 */
const uint8_t CFM_HASH[] = {
	0xc9,0x8f,0x9e,0x54,0x44,0xa9,0xf9,0xd7,0xb5,0x27,0xf7,0x12,0x16,0x8b,0x13,0xee,
	0xed,0xa1,0xd1,0x8a,0xd7,0xc4,0x1b,0x2c,0x48,0x8c,0x2f,0x05,0x42,0xfa,0x6b,0xb7
};

/*
* The platform identifier in the CFM data
*/
const char CFM_PLATFORM_ID[] = "SKU1";

/**
 * Components of the test CFM.
 */
const struct cfm_testing_data CFM_TESTING = {
	.manifest = {
		.raw = CFM_DATA,
		.length = sizeof (CFM_DATA),
		.hash = CFM_HASH,
		.hash_len = sizeof (CFM_HASH),
		.id = 0x1,
		.signature = CFM_DATA + (sizeof (CFM_DATA) - 256),
		.sig_len = 256,
		.sig_offset = (sizeof (CFM_DATA) - 256),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = CFM_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x618,
		.toc_hash = CFM_DATA + 0x628,
		.toc_hash_len = 32,
		.toc_hash_offset = 0x628,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 39,
		.toc_hashes = 39,
		.plat_id = CFM_DATA + 0x648,
		.plat_id_len = 0x8,
		.plat_id_str = CFM_PLATFORM_ID,
		.plat_id_str_len = sizeof (CFM_PLATFORM_ID) - 1,
		.plat_id_str_pad = 0,
		.plat_id_offset = 0x648,
		.plat_id_entry = 0,
		.plat_id_hash = 0
	},
	.component_device1_len = 0x10,
	.component_device1_offset = 0x650,
	.component_device1_entry = 1,
	.component_device1_hash = 1,
};

/**
 * Initial value for PMR 1 Device 1.
 */
static uint8_t PMR_1_DEVICE_1[] = {
	0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
	0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11
};

/**
 * Initial value for PMR 1 Device 1.
 */
static uint8_t PMR_2_DEVICE_1[] = {
	0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
	0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
	0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
	0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11
};

/**
 * Initial value for PMR 1.
 */
static uint8_t PMR_0_DEVICE_2[] = {
	0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,
	0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,
	0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33
};

/**
 * Supported digest for PMR 0 Device 1.
 */
static uint8_t PMR_DIGEST_0_DEVICE_1_1[] = {
	0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
	0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA
};

/**
 * Supported digest for PMR 0 Device 1.
 */
static uint8_t PMR_DIGEST_0_DEVICE_1_2[] = {
	0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,
	0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB
};

/**
 * Supported digest for PMR 2 Device 2.
 */
static uint8_t PMR_DIGEST_2_DEVICE_2[] = {
	0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,
	0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,
	0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,
	0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD
};

/**
 * Supported digest for PMR 4 Device 1.
 */
static uint8_t PMR_DIGEST_4_DEVICE_1[] = {
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC
};

/**
 * Supported measurement for PMR 1 Measurement 1 Device 1.
 */
static uint8_t MEASUREMENT_PMR_2_MEASUREMENT_2_DEVICE_1[] = {
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC
};

/**
 * Supported measurement for PMR 1 Measurement 2 Device 1.
 */
static uint8_t MEASUREMENT_PMR_1_MEASUREMENT_2_DEVICE_1[] = {
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC
};

/**
 * Second supported measurement for PMR 1 Measurement 2 Device 1.
 */
static uint8_t MEASUREMENT_PMR_1_MEASUREMENT_2_DEVICE_1_2[] = {
	0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,
	0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE
};

/**
 * Second supported measurement for PMR 1 Measurement 5 Device 2.
 */
static uint8_t MEASUREMENT_PMR_1_MEASUREMENT_5_DEVICE_2[] = {
	0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,
	0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,
	0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE
};

/**
 * Supported measurement for PMR 1 Measurement 2 Device 1.
 */
static uint8_t MEASUREMENT_DATA_PMR_1_MEASUREMENT_2_DEVICE_1[] = {
	0x54,0x65,0x73,0x74,0x31
};

/**
 * Bitmask for supported measurement for PMR 1 Measurement 2 Device 1.
 */
static uint8_t MEASUREMENT_DATA_PMR_1_MEASUREMENT_2_DEVICE_1_BITMASK[] = {
	0x00,0xFF,0x00,0xFF,0xFF
};

/**
 * Second supported measurement for PMR 1 Measurement 2 Device 1.
 */
static uint8_t MEASUREMENT_DATA_PMR_1_MEASUREMENT_2_DEVICE_1_2[] = {
	0x54,0x65,0x73,0x74,0x32
};

/**
 * Supported measurement for PMR 1 Measurement 2 Device 1, second check.
 */
static uint8_t MEASUREMENT_DATA_PMR_1_MEASUREMENT_2_DEVICE_1_CHECK_2[] = {
	0x00,0x00,0x22,0x00,0x00
};

/**
 * Bitmask for supported measurement for PMR 1 Measurement 2 Device 1, second check.
 */
static uint8_t MEASUREMENT_DATA_PMR_1_MEASUREMENT_2_DEVICE_1_BITMASK_CHECK_2[] = {
	0x00,0x00,0xFF,0x00,0x00
};

/**
 * Supported measurement for PMR 1 Measurement 4 Device 1.
 */
static uint8_t MEASUREMENT_DATA_PMR_1_MEASUREMENT_4_DEVICE_1[] = {
	0x65,0x43
};

/**
 * Bitmask for supported measurement for PMR 1 Measurement 4 Device 1.
 */
static uint8_t MEASUREMENT_DATA_PMR_1_MEASUREMENT_4_DEVICE_1_BITMASK[] = {
	0x00,0xFF
};

/**
 * Second supported measurement for PMR 1 Measurement 4 Device 1.
 */
static uint8_t MEASUREMENT_DATA_PMR_1_MEASUREMENT_4_DEVICE_1_2[] = {
	0x10,0x11
};

/**
 * Supported measurement for PMR 1 Measurement 3 Device 2.
 */
static uint8_t MEASUREMENT_DATA_PMR_1_MEASUREMENT_3_DEVICE_2[] = {
	0x12,0x34,0x56
};

/**
 * Bitmask for supported measurement for PMR 1 Measurement 3 Device 2.
 */
static uint8_t MEASUREMENT_DATA_PMR_1_MEASUREMENT_3_DEVICE_2_BITMASK[] = {
	0xFF,0x0F,0xFF
};

/**
 * Supported root CA digest for Device 1.
 */
static uint8_t ROOT_CA_DIGEST_0_DEVICE_1[] = {
	0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,
	0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE
};

/**
 * Second supported root CA digest for Device 1.
 */
static uint8_t ROOT_CA_DIGEST_1_DEVICE_1[] = {
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
};

/**
 * Supported root CA digest for Device 2.
 */
static uint8_t ROOT_CA_DIGEST_DEVICE_2[] = {
	0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,
	0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,
	0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB,0xAB
};

/*
* The platform identifier for allowable PFM for port 1 in Device 1.
*/
const char CFM_ALLOWABLE_PFM_1_PLATFORM_ID_DEVICE_1[] = "platformA";

/*
* The first allowable ID for allowable PFM for port 1 in Device 1.
*/
const uint32_t CFM_ALLOWABLE_PFM_1_ALLOWABLE_ID_1_DEVICE_1 = 0x00000099;

/*
* The second allowable ID for allowable PFM for port 1 in Device 1.
*/
const uint32_t CFM_ALLOWABLE_PFM_1_ALLOWABLE_ID_1_DEVICE_1_2 = 0x0000009a;

/*
* The allowable ID in second check for allowable PFM for port 1 in Device 1.
*/
const uint32_t CFM_ALLOWABLE_PFM_1_ALLOWABLE_ID_2_DEVICE_1 = 0x0000009d;

/*
* The platform identifier for allowable PFM for port 2 in Device 1.
*/
const char CFM_ALLOWABLE_PFM_2_PLATFORM_ID_DEVICE_1[] = "platformB";

/*
* The allowable ID for allowable PFM for port 2 in Device 1.
*/
const uint32_t CFM_ALLOWABLE_PFM_2_ALLOWABLE_ID_DEVICE_1 = 0x00000055;

/*
* The platform identifier for allowable PFM for port 2 in Device 2.
*/
const char CFM_ALLOWABLE_PFM_2_PLATFORM_ID_DEVICE_2[] = "platform1";

/*
* The allowable ID for allowable PFM for port 2 in Device 2.
*/
const uint32_t CFM_ALLOWABLE_PFM_2_ALLOWABLE_ID_DEVICE_2 = 0x00000012;

/*
* The platform identifier for allowable CFM 1 in Device 1.
*/
const char CFM_ALLOWABLE_CFM_1_PLATFORM_ID_DEVICE_1[] = "platformC";

/*
* The allowable ID for allowable CFM 1 in Device 1.
*/
const uint32_t CFM_ALLOWABLE_CFM_1_ALLOWABLE_ID_DEVICE_1 = 0x00000012;

/*
* The platform identifier for allowable CFM 2 in Device 1.
*/
const char CFM_ALLOWABLE_CFM_2_PLATFORM_ID_DEVICE_1[] = "platformE";

/*
* The allowable ID for allowable CFM 2 in Device 2.
*/
const uint32_t CFM_ALLOWABLE_CFM_2_ALLOWABLE_ID_DEVICE_2 = 0x000000ab;

/*
* The platform identifier for allowable CFM 0 in Device 2.
*/
const char CFM_ALLOWABLE_CFM_0_PLATFORM_ID_DEVICE_2[] = "platform2";

/*
* The allowable ID for allowable CFM 0 in Device 2.
*/
const uint32_t CFM_ALLOWABLE_CFM_0_ALLOWABLE_ID_DEVICE_2 = 0x00000034;

/*
* The platform identifier for allowable PCD in Device 1.
*/
const char CFM_ALLOWABLE_PCD_PLATFORM_ID_DEVICE_1[] = "platformD";

/*
* The allowable ID for allowable PCD in Device 2.
*/
const uint32_t CFM_ALLOWABLE_PCD_ALLOWABLE_ID_DEVICE_1 = 0x00000034;

/*
* The platform identifier for allowable PCD in Device 2.
*/
const char CFM_ALLOWABLE_PCD_PLATFORM_ID_DEVICE_2[] = "platform3";

/*
* The allowable ID for allowable PCD in Device 2.
*/
const uint32_t CFM_ALLOWABLE_PCD_ALLOWABLE_ID_DEVICE_2 = 0x00000056;

/**
 * Dummy CFM with only PMR digest elements for testing.
 */
const uint8_t CFM_ONLY_PMR_DIGEST_DATA[] = {
	0x04,0x02,0x92,0xa5,0x02,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x03,0x03,0x00,0x00,
	0x00,0xff,0x01,0x00,0xa8,0x00,0x08,0x00,0x70,0xff,0x00,0x01,0xb0,0x00,0x10,0x00,
	0x72,0x70,0x00,0x02,0xc0,0x00,0x44,0x00,0x13,0xe9,0x1c,0x16,0x0e,0xcf,0xd2,0xbb,
	0x3a,0x86,0x83,0xb6,0x01,0xc4,0xba,0xcb,0x04,0xf0,0xa5,0x18,0x9b,0x97,0xd9,0x2d,
	0x67,0xf4,0x6d,0x69,0xea,0x1e,0x25,0x36,0xe8,0x57,0x2a,0x8e,0x2e,0x62,0x19,0xc1,
	0x75,0xcb,0x14,0x77,0x77,0x4b,0xfc,0xac,0xb4,0xa7,0xcd,0x12,0x43,0x44,0x4b,0xa7,
	0xf3,0xb1,0x1d,0xef,0x3e,0x1f,0xbb,0x07,0x13,0x8d,0xad,0xbb,0x70,0x3c,0x40,0x52,
	0x07,0x61,0xc2,0xb2,0xf8,0xab,0x13,0x60,0x7e,0x54,0xbe,0x97,0x80,0x15,0x8e,0x05,
	0x76,0x5c,0xf8,0xf6,0x68,0x87,0x21,0xa5,0xa6,0x73,0x86,0xad,0xfc,0xd3,0xca,0x1e,
	0xcc,0xa1,0xbb,0x28,0x6d,0x66,0x29,0x50,0x15,0x7e,0x41,0xa4,0x6b,0xb2,0xab,0xe5,
	0xee,0x6c,0xec,0x42,0xfc,0xca,0x28,0x7f,0x04,0x00,0x00,0x00,0x53,0x4b,0x55,0x31,
	0x01,0x00,0x00,0x0a,0x43,0x6f,0x6d,0x70,0x6f,0x6e,0x65,0x6e,0x74,0x31,0x00,0x00,
	0x00,0x00,0x02,0x00,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
	0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
	0xaa,0xaa,0xaa,0xaa,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,
	0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,
	0xbb,0xbb,0xbb,0xbb,0x14,0xd7,0xe8,0xf4,0xff,0x29,0x74,0x62,0x56,0x32,0xaf,0xcc,
	0xd6,0x81,0xb4,0xcc,0x9a,0x59,0xd9,0x06,0x08,0x36,0xed,0xae,0xec,0x78,0x8e,0xc8,
	0xe0,0xd0,0x76,0x32,0xce,0x4a,0x12,0xac,0xb2,0x28,0xe0,0x85,0x2c,0x48,0xda,0x1c,
	0x1c,0x18,0x48,0x06,0xdb,0x86,0xae,0xf3,0x51,0x86,0x9d,0xa0,0xdf,0x1e,0xec,0x6f,
	0x34,0x35,0x84,0x4a,0xa5,0x1e,0xb3,0x77,0xf6,0x73,0x5d,0x08,0x88,0xfa,0xde,0x1a,
	0x4e,0xca,0xcb,0xb0,0x44,0xff,0x13,0x2f,0x8b,0x83,0xca,0x0e,0x9a,0xb4,0x66,0x67,
	0xec,0xdf,0xbc,0xf2,0x11,0x57,0x7e,0x23,0x5b,0x4e,0x52,0x26,0x74,0xa5,0xeb,0x76,
	0x7a,0x2a,0x08,0xd3,0x45,0x7c,0xac,0x0e,0x16,0x57,0x5e,0x5e,0x85,0xc5,0xe9,0x45,
	0x22,0x99,0x20,0xbc,0x7a,0xe4,0x2a,0x40,0xa8,0x32,0xae,0xfb,0xd4,0xe1,0x4a,0xca,
	0x8e,0x81,0x80,0x6f,0x5d,0xde,0xaf,0xa1,0x1f,0x0f,0x88,0x05,0x43,0xfc,0x05,0xad,
	0x8a,0xb4,0x5d,0xb7,0xf2,0x5a,0xe6,0x07,0x76,0xd3,0x1b,0x50,0x7a,0xb8,0x1d,0x1c,
	0xe8,0x03,0x16,0xb5,0x3c,0x73,0xed,0x03,0x42,0xdf,0x0d,0x93,0xb9,0xcd,0xd0,0x8e,
	0xf2,0xdb,0xa3,0xf7,0xce,0x9b,0x87,0x2a,0x32,0x08,0xfc,0xfd,0x45,0x83,0x6d,0xf9,
	0xed,0x6b,0xc8,0xe3,0x67,0xa9,0x49,0xac,0xd4,0x31,0x76,0xea,0xdc,0x9f,0x4b,0xe4,
	0xbf,0x8a,0x3d,0x8e,0x21,0x18,0xf0,0xda,0x54,0xa8,0xcc,0xb1,0x1b,0x0c,0x65,0x08,
	0xc6,0x68,0x4a,0x5e,0x81,0xc6,0x68,0x47,0xc4,0x67,0xad,0xea,0x25,0x1b,0xdf,0x8c,
	0x91,0x2b,0x2c,0x90
};

/**
 * Length of the test CFM data.
 */
const uint32_t CFM_ONLY_PMR_DIGEST_DATA_LEN = sizeof (CFM_ONLY_PMR_DIGEST_DATA);

/**
 * CFM_ONLY_PMR_DIGEST_DATA hash for testing.
 */
const uint8_t CFM_ONLY_PMR_DIGEST_HASH[] = {
	0x41,0xc4,0xbb,0xe6,0x2f,0x93,0xe4,0xdf,0xc1,0xa3,0x2e,0xa0,0x4f,0x63,0xf1,0x6c,
	0xe4,0x2b,0x17,0x2c,0x42,0x71,0xde,0x2f,0xd9,0x1c,0x04,0xac,0xa1,0x1c,0xbc,0x5d
};

/*
* The platform identifier in the CFM data
*/
const char CFM_ONLY_PMR_DIGEST_PLATFORM_ID[] = "SKU1";

/**
 * Components of the test CFM.
 */
const struct cfm_testing_data CFM_ONLY_PMR_DIGEST_TESTING = {
	.manifest = {
		.raw = CFM_ONLY_PMR_DIGEST_DATA,
		.length = sizeof (CFM_ONLY_PMR_DIGEST_DATA),
		.hash = CFM_ONLY_PMR_DIGEST_HASH,
		.hash_len = sizeof (CFM_ONLY_PMR_DIGEST_HASH),
		.id = 0x2,
		.signature = CFM_ONLY_PMR_DIGEST_DATA + (sizeof (CFM_ONLY_PMR_DIGEST_DATA) - 256),
		.sig_len = 256,
		.sig_offset = (sizeof (CFM_ONLY_PMR_DIGEST_DATA) - 256),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = CFM_ONLY_PMR_DIGEST_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x78,
		.toc_hash = CFM_ONLY_PMR_DIGEST_DATA + 0x88,
		.toc_hash_len = 32,
		.toc_hash_offset = 0x88,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 3,
		.toc_hashes = 3,
		.plat_id = CFM_ONLY_PMR_DIGEST_DATA + 0xa8,
		.plat_id_len = 0x8,
		.plat_id_str = CFM_ONLY_PMR_DIGEST_PLATFORM_ID,
		.plat_id_str_len = sizeof (CFM_ONLY_PMR_DIGEST_PLATFORM_ID) - 1,
		.plat_id_str_pad = 0,
		.plat_id_offset = 0xa8,
		.plat_id_entry = 0,
		.plat_id_hash = 0
	},
	.component_device1_len = 0x10,
	.component_device1_offset = 0xb0,
	.component_device1_entry = 1,
	.component_device1_hash = 1,
};

/**
 * Dummy CFM with only measurement elements for testing.
 */
const uint8_t CFM_ONLY_MEASUREMENT[] = {
	0x04,0x02,0x92,0xa5,0x03,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x03,0x03,0x00,0x00,
	0x00,0xff,0x01,0x00,0xa8,0x00,0x08,0x00,0x70,0xff,0x00,0x01,0xb0,0x00,0x10,0x00,
	0x73,0x70,0x00,0x02,0xc0,0x00,0x44,0x00,0x13,0xe9,0x1c,0x16,0x0e,0xcf,0xd2,0xbb,
	0x3a,0x86,0x83,0xb6,0x01,0xc4,0xba,0xcb,0x04,0xf0,0xa5,0x18,0x9b,0x97,0xd9,0x2d,
	0x67,0xf4,0x6d,0x69,0xea,0x1e,0x25,0x36,0xe8,0x57,0x2a,0x8e,0x2e,0x62,0x19,0xc1,
	0x75,0xcb,0x14,0x77,0x77,0x4b,0xfc,0xac,0xb4,0xa7,0xcd,0x12,0x43,0x44,0x4b,0xa7,
	0xf3,0xb1,0x1d,0xef,0x3e,0x1f,0xbb,0x07,0x39,0xe1,0x04,0x32,0xbb,0x27,0x87,0xfe,
	0x97,0x4a,0x00,0x9b,0xf3,0x35,0xbc,0xbe,0x8f,0xea,0xa5,0xac,0xbd,0xcf,0xa7,0x75,
	0x92,0xe1,0x3c,0x61,0x5d,0x1a,0x91,0x62,0x20,0x15,0x7e,0x9b,0xeb,0xf5,0x44,0x38,
	0xb8,0x1d,0x4a,0xb7,0xc2,0xea,0xa6,0x8a,0x95,0x3f,0x7e,0x39,0xbc,0x44,0xa2,0x0a,
	0x2d,0xde,0xfe,0xb9,0x79,0xe3,0x30,0xff,0x04,0x00,0x00,0x00,0x53,0x4b,0x55,0x31,
	0x01,0x00,0x00,0x0a,0x43,0x6f,0x6d,0x70,0x6f,0x6e,0x65,0x6e,0x74,0x31,0x00,0x00,
	0x01,0x02,0x00,0x02,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,
	0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,
	0xcc,0xcc,0xcc,0xcc,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,
	0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,
	0xee,0xee,0xee,0xee,0x05,0x3a,0x87,0x49,0xad,0x1b,0x05,0xb0,0xe3,0xb6,0xfc,0xef,
	0xfe,0x35,0x67,0xdb,0xec,0xb2,0x4d,0xce,0xaf,0x65,0xf9,0x2f,0xf7,0xc1,0xdf,0x37,
	0xf8,0x51,0x30,0x06,0x6e,0xae,0x17,0x64,0x39,0xe7,0xd4,0x90,0xf2,0x3e,0x03,0xbf,
	0xa2,0x0a,0xa8,0x70,0x17,0x64,0x5e,0x77,0xe0,0xae,0xc6,0xaf,0x65,0x28,0x11,0xc5,
	0xbc,0xea,0x97,0x2a,0xad,0xb3,0x32,0xd8,0x03,0x45,0x19,0x19,0x0c,0x0d,0x9c,0xed,
	0xa7,0x05,0x38,0x00,0xf4,0x33,0x56,0x2b,0x1e,0x73,0xfd,0xe6,0x62,0x92,0xed,0x65,
	0x97,0x2c,0x06,0xe0,0x16,0x91,0xc2,0x97,0xf0,0x32,0x34,0xcf,0xfd,0xd0,0x06,0x41,
	0x8d,0x0a,0xdd,0xf0,0x19,0x2c,0xd0,0x6e,0x2e,0x44,0x53,0x46,0x54,0xf0,0x0b,0x47,
	0xc8,0xe9,0x50,0x5f,0x2a,0x6c,0x20,0x07,0xf5,0xca,0x31,0x45,0x11,0x9b,0x8a,0x68,
	0x52,0xa7,0x80,0xb7,0xa9,0x08,0x6a,0x22,0xab,0xa2,0x1c,0x70,0x4e,0xbb,0x42,0x11,
	0xf5,0xdc,0xcf,0x45,0xa3,0x7f,0x2a,0x0d,0xac,0x52,0xb4,0x3f,0x16,0x65,0xbe,0x9d,
	0x78,0x7b,0x4e,0x9e,0x35,0x3f,0x87,0x80,0x73,0x50,0x25,0x8c,0x4c,0x76,0xb4,0x19,
	0x15,0x36,0xd9,0x9f,0x1b,0x83,0x87,0x19,0x00,0x71,0x97,0x30,0x4b,0x73,0xf9,0x22,
	0xad,0x0e,0x5b,0x51,0x9d,0xc3,0x34,0xf4,0xa9,0x8c,0x4a,0xf9,0x4b,0x39,0x23,0x9d,
	0xda,0x11,0xed,0x6c,0x6c,0xd5,0xb7,0x38,0x5b,0x63,0xca,0x28,0x16,0xfd,0x0e,0xe4,
	0x02,0x21,0x0a,0x8f,0xde,0x85,0x56,0x47,0x12,0xe4,0x86,0x94,0x11,0xb9,0xd1,0x5a,
	0x9e,0x1c,0x5c,0x87
};

/**
 * Length of the test CFM data.
 */
const uint32_t CFM_ONLY_MEASUREMENT_LEN = sizeof (CFM_ONLY_MEASUREMENT);

/**
 * CFM_ONLY_MEASUREMENT hash for testing.
 */
const uint8_t CFM_ONLY_MEASUREMENT_HASH[] = {
	0x98,0x8a,0x00,0x38,0x9e,0x72,0xcc,0x30,0x06,0x4b,0x80,0x13,0xfe,0xa8,0x82,0x75,
	0xe5,0xc7,0xab,0x72,0x9c,0x30,0xfe,0x8a,0x7e,0xc1,0xef,0x2c,0x86,0xa1,0x2c,0x62
};

/*
* The platform identifier in the CFM data
*/
const char CFM_ONLY_MEASUREMENT_PLATFORM_ID[] = "SKU1";

/**
 * Components of the test CFM.
 */
const struct cfm_testing_data CFM_ONLY_MEASUREMENT_TESTING = {
	.manifest = {
		.raw = CFM_ONLY_MEASUREMENT,
		.length = sizeof (CFM_ONLY_MEASUREMENT),
		.hash = CFM_ONLY_MEASUREMENT_HASH,
		.hash_len = sizeof (CFM_ONLY_MEASUREMENT_HASH),
		.id = 0x3,
		.signature = CFM_ONLY_MEASUREMENT + (sizeof (CFM_ONLY_MEASUREMENT) - 256),
		.sig_len = 256,
		.sig_offset = (sizeof (CFM_ONLY_MEASUREMENT) - 256),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = CFM_ONLY_MEASUREMENT + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x78,
		.toc_hash = CFM_ONLY_MEASUREMENT + 0x88,
		.toc_hash_len = 32,
		.toc_hash_offset = 0x88,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 3,
		.toc_hashes = 3,
		.plat_id = CFM_ONLY_MEASUREMENT + 0xa8,
		.plat_id_len = 0x8,
		.plat_id_str = CFM_ONLY_MEASUREMENT_PLATFORM_ID,
		.plat_id_str_len = sizeof (CFM_ONLY_MEASUREMENT_PLATFORM_ID) - 1,
		.plat_id_str_pad = 0,
		.plat_id_offset = 0xa8,
		.plat_id_entry = 0,
		.plat_id_hash = 0
	},
	.component_device1_len = 0x10,
	.component_device1_offset = 0xb0,
	.component_device1_entry = 1,
	.component_device1_hash = 1,
};

/**
 * Dummy CFM with only measurement data elements for testing.
 */
const uint8_t CFM_ONLY_MEASUREMENT_DATA[] = {
	0x48,0x02,0x92,0xa5,0x04,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x05,0x05,0x00,0x00,
	0x00,0xff,0x01,0x00,0xf8,0x00,0x08,0x00,0x70,0xff,0x00,0x01,0x00,0x01,0x10,0x00,
	0x74,0x70,0x00,0x02,0x10,0x01,0x04,0x00,0x75,0x74,0x00,0x03,0x14,0x01,0x1c,0x00,
	0x75,0x74,0x00,0x04,0x30,0x01,0x18,0x00,0x13,0xe9,0x1c,0x16,0x0e,0xcf,0xd2,0xbb,
	0x3a,0x86,0x83,0xb6,0x01,0xc4,0xba,0xcb,0x04,0xf0,0xa5,0x18,0x9b,0x97,0xd9,0x2d,
	0x67,0xf4,0x6d,0x69,0xea,0x1e,0x25,0x36,0xe8,0x57,0x2a,0x8e,0x2e,0x62,0x19,0xc1,
	0x75,0xcb,0x14,0x77,0x77,0x4b,0xfc,0xac,0xb4,0xa7,0xcd,0x12,0x43,0x44,0x4b,0xa7,
	0xf3,0xb1,0x1d,0xef,0x3e,0x1f,0xbb,0x07,0xd8,0x1f,0xe9,0x6d,0xc5,0x00,0xbc,0x43,
	0xe1,0xcd,0x58,0x00,0xbe,0xf9,0xd7,0x2b,0x3d,0x03,0x0b,0xdb,0x7e,0x86,0x0e,0x10,
	0xc5,0x22,0xe4,0x24,0x6b,0x30,0xbd,0x93,0x6a,0x65,0x1f,0x3b,0x69,0x40,0xcf,0x99,
	0x74,0x33,0x80,0xdf,0xcc,0xb2,0xf1,0xd3,0x62,0xe6,0xb3,0x41,0x83,0x9b,0xab,0xfb,
	0xf2,0x55,0x19,0xa1,0x76,0x1f,0x1d,0xeb,0x23,0x41,0xab,0xfa,0xb2,0x42,0x9b,0xf3,
	0x12,0x45,0xb7,0x8f,0xfc,0xe0,0xb7,0x4a,0x3c,0xe7,0xd8,0x51,0xd9,0x02,0x7d,0x69,
	0xab,0xfa,0x63,0x3d,0x7c,0x6f,0x35,0x6e,0xed,0x1d,0x2d,0xc2,0xb7,0xcf,0xb1,0xff,
	0xef,0x76,0x15,0x9e,0x3e,0x75,0x5e,0xac,0x82,0x83,0x5c,0xf3,0xf8,0x6e,0x59,0x5d,
	0x96,0xab,0xf6,0xed,0xd8,0xf0,0x75,0xb4,0x04,0x00,0x00,0x00,0x53,0x4b,0x55,0x31,
	0x01,0x00,0x00,0x0a,0x43,0x6f,0x6d,0x70,0x6f,0x6e,0x65,0x6e,0x74,0x31,0x00,0x00,
	0x01,0x02,0x00,0x00,0x80,0x00,0x02,0x05,0x00,0x00,0x00,0x00,0x00,0xff,0x00,0xff,
	0xff,0x00,0x00,0x00,0x54,0x65,0x73,0x74,0x31,0x54,0x65,0x73,0x74,0x32,0x00,0x00,
	0x80,0x04,0x01,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x22,0x00,0x00,0x00,0x00,0x00,0x5c,0xfb,0x55,0xc2,0x15,0x97,0x7a,0x7d,
	0x5a,0x0f,0xbb,0x6f,0xbc,0x51,0x83,0x09,0x77,0x61,0xee,0x2d,0x58,0x53,0x37,0xfb,
	0x49,0x13,0x81,0x6c,0xd3,0x5a,0xef,0x40,0x01,0x2d,0x08,0x15,0x9b,0x0d,0xa3,0x4e,
	0xea,0xdd,0x24,0x9c,0x90,0xe9,0x93,0xdb,0x73,0xa4,0x64,0x7a,0xc2,0x29,0xb7,0xbb,
	0x1b,0x21,0x05,0xeb,0x98,0x38,0xaf,0x8f,0xf0,0xf7,0xb5,0xcd,0x70,0xbb,0x7e,0x4d,
	0x75,0xe3,0xbe,0xc4,0xf9,0x84,0x0a,0xca,0x67,0xd7,0xff,0x18,0x98,0xbb,0x0d,0x7e,
	0x2d,0xe9,0x6b,0x64,0x85,0x2d,0x20,0x62,0xaf,0x49,0x2a,0x6f,0xae,0x55,0x00,0x45,
	0x61,0x3e,0x02,0x10,0x3f,0x44,0xeb,0x72,0x8c,0x3b,0x3a,0xbd,0x01,0x34,0x90,0x92,
	0xa4,0xb6,0xc4,0x0a,0x84,0x0b,0x03,0x78,0x2b,0xcc,0xd0,0xa2,0xae,0xd5,0x0b,0x31,
	0x58,0x85,0x59,0x87,0xe6,0xe2,0x69,0x30,0x26,0x5d,0x23,0xc4,0x0c,0x0e,0xe8,0xb1,
	0xdb,0x94,0x12,0xa2,0x96,0x6c,0x22,0x05,0x22,0x06,0xba,0x99,0x1e,0x7d,0x08,0x8d,
	0xc2,0xd9,0x1a,0x40,0x7e,0xc2,0x6a,0x2a,0x24,0x37,0x21,0xf2,0xda,0x6c,0xc5,0xd8,
	0x18,0x5f,0xdd,0x84,0xd1,0xf1,0x35,0x2b,0x8f,0xa4,0x9e,0xa4,0xaf,0x67,0x0d,0xaf,
	0x88,0xb3,0xb9,0x41,0x22,0x88,0x36,0x73,0x17,0x45,0x1c,0xf7,0x2b,0xa5,0x6a,0xb9,
	0xcc,0xcd,0x6c,0x58,0xa2,0x4d,0x8a,0x60,0x75,0x1a,0xe7,0x7f,0x9b,0x7a,0xec,0x06,
	0x1e,0x20,0x8b,0x9f,0xa2,0x80,0xfb,0x69,0x97,0x58,0xa9,0x09,0xff,0x4a,0x82,0xec,
	0x88,0xab,0xed,0x9e,0xab,0x58,0x14,0x76
};

/**
 * Length of the test CFM data.
 */
const uint32_t CFM_ONLY_MEASUREMENT_DATA_LEN = sizeof (CFM_ONLY_MEASUREMENT_DATA);

/**
 * CFM_ONLY_MEASUREMENT_DATA hash for testing.
 */
const uint8_t CFM_ONLY_MEASUREMENT_DATA_HASH[] = {
	0x56,0x76,0x68,0x66,0x23,0x62,0x35,0xae,0x81,0xaa,0xbb,0x41,0x34,0x88,0x33,0xa0,
	0xd1,0x1c,0xa5,0xdc,0x41,0x17,0xcb,0xdd,0xc5,0xb8,0x8c,0xb3,0xb1,0x67,0x2d,0xc8
};

/*
* The platform identifier in the CFM data
*/
const char CFM_ONLY_MEASUREMENT_DATA_PLATFORM_ID[] = "SKU1";

/**
 * Components of the test CFM.
 */
const struct cfm_testing_data CFM_ONLY_MEASUREMENT_DATA_TESTING = {
	.manifest = {
		.raw = CFM_ONLY_MEASUREMENT_DATA,
		.length = sizeof (CFM_ONLY_MEASUREMENT_DATA),
		.hash = CFM_ONLY_MEASUREMENT_DATA_HASH,
		.hash_len = sizeof (CFM_ONLY_MEASUREMENT_DATA_HASH),
		.id = 0x4,
		.signature = CFM_ONLY_MEASUREMENT_DATA + (sizeof (CFM_ONLY_MEASUREMENT_DATA) - 256),
		.sig_len = 256,
		.sig_offset = (sizeof (CFM_ONLY_MEASUREMENT_DATA) - 256),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = CFM_ONLY_MEASUREMENT_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0xc8,
		.toc_hash = CFM_ONLY_MEASUREMENT_DATA + 0xd8,
		.toc_hash_len = 32,
		.toc_hash_offset = 0xd8,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 5,
		.toc_hashes = 5,
		.plat_id = CFM_ONLY_MEASUREMENT_DATA + 0xf8,
		.plat_id_len = 0x8,
		.plat_id_str = CFM_ONLY_MEASUREMENT_DATA_PLATFORM_ID,
		.plat_id_str_len = sizeof (CFM_ONLY_MEASUREMENT_DATA_PLATFORM_ID) - 1,
		.plat_id_str_pad = 0,
		.plat_id_offset = 0xf8,
		.plat_id_entry = 0,
		.plat_id_hash = 0
	},
	.component_device1_len = 0x10,
	.component_device1_offset = 0x100,
	.component_device1_entry = 1,
	.component_device1_hash = 1,
};

/**
 * Dummy CFM with only allowable PFM elements for testing.
 */
const uint8_t CFM_ONLY_PFM_DATA[] = {
	0x32,0x02,0x92,0xa5,0x05,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x05,0x05,0x00,0x00,
	0x00,0xff,0x01,0x00,0xf8,0x00,0x08,0x00,0x70,0xff,0x00,0x01,0x00,0x01,0x10,0x00,
	0x76,0x70,0x00,0x02,0x10,0x01,0x0e,0x00,0x79,0x76,0x00,0x03,0x1e,0x01,0x0c,0x00,
	0x79,0x76,0x00,0x04,0x2a,0x01,0x08,0x00,0x13,0xe9,0x1c,0x16,0x0e,0xcf,0xd2,0xbb,
	0x3a,0x86,0x83,0xb6,0x01,0xc4,0xba,0xcb,0x04,0xf0,0xa5,0x18,0x9b,0x97,0xd9,0x2d,
	0x67,0xf4,0x6d,0x69,0xea,0x1e,0x25,0x36,0xe8,0x57,0x2a,0x8e,0x2e,0x62,0x19,0xc1,
	0x75,0xcb,0x14,0x77,0x77,0x4b,0xfc,0xac,0xb4,0xa7,0xcd,0x12,0x43,0x44,0x4b,0xa7,
	0xf3,0xb1,0x1d,0xef,0x3e,0x1f,0xbb,0x07,0x93,0xc1,0x46,0xda,0xac,0x53,0x1a,0xff,
	0xc8,0x3c,0xcf,0xd0,0x41,0x7c,0x02,0x96,0xeb,0x5c,0x16,0x31,0xb7,0x8c,0xd5,0x27,
	0xe4,0x03,0x0b,0x67,0x93,0x88,0xf6,0x2c,0x5a,0xaa,0xc6,0x7c,0xf4,0x86,0x9f,0x1f,
	0x33,0x14,0xe6,0xed,0xe2,0xe8,0xcf,0xf2,0xbb,0x96,0xed,0x1f,0xbb,0x80,0x77,0x3d,
	0x83,0xfa,0xc7,0x0d,0xb4,0x61,0x06,0x31,0xbd,0xc5,0xb0,0x24,0x8b,0x05,0x2a,0xa7,
	0x13,0x16,0xff,0xa7,0x31,0xc5,0x2f,0xb8,0x40,0x34,0x28,0x4e,0xe6,0x7c,0xc2,0x19,
	0xfa,0x54,0x99,0xe9,0x7d,0xa9,0x9d,0x9a,0x7a,0x2c,0x1a,0x46,0xd0,0xf3,0xef,0x96,
	0xfc,0x48,0x0c,0xba,0x96,0xfe,0xb0,0x0a,0x70,0x66,0x51,0x73,0x93,0x1e,0x11,0x00,
	0xe8,0x31,0x54,0x8b,0xef,0x4d,0xa9,0x7f,0x04,0x00,0x00,0x00,0x53,0x4b,0x55,0x31,
	0x01,0x00,0x00,0x0a,0x43,0x6f,0x6d,0x70,0x6f,0x6e,0x65,0x6e,0x74,0x31,0x00,0x00,
	0x01,0x09,0x70,0x6c,0x61,0x74,0x66,0x6f,0x72,0x6d,0x41,0x00,0x00,0x00,0x00,0x02,
	0x00,0x00,0x99,0x00,0x00,0x00,0x9a,0x00,0x00,0x00,0x04,0x01,0x00,0x00,0x9d,0x00,
	0x00,0x00,0x56,0xea,0x83,0x41,0xb4,0xc5,0x31,0x97,0x7a,0xa0,0x5a,0x02,0xaf,0xd5,
	0x5d,0xd3,0x50,0x0a,0x70,0xc9,0x46,0x0e,0x91,0xcc,0x5d,0x3d,0x5c,0xd6,0xb4,0x00,
	0xe3,0x4f,0xfb,0x06,0xdb,0xb7,0x0b,0xbd,0xc2,0x25,0xd3,0xf7,0x79,0x63,0x1b,0x16,
	0x57,0xb1,0xeb,0xa1,0x56,0x4f,0x4a,0x19,0x95,0xbd,0xeb,0xfe,0x1e,0x18,0x13,0xf9,
	0xb4,0xd4,0x51,0xe9,0x4a,0xda,0xb9,0x41,0x14,0xaa,0xce,0x94,0xd0,0xad,0xc2,0xe9,
	0x39,0x26,0x4a,0x50,0xa4,0x55,0xda,0x9b,0x2b,0xc6,0x65,0x3c,0x04,0xf5,0xce,0x41,
	0xcc,0x35,0x09,0xed,0xe0,0x6f,0x5f,0x1e,0xab,0x9b,0xee,0xa5,0x30,0xfb,0x98,0x4c,
	0x60,0x12,0x8c,0x6c,0xb4,0x23,0x1c,0x39,0xc4,0xc6,0x93,0xa6,0xf1,0xed,0x2b,0x57,
	0xd3,0x61,0xeb,0xb5,0x47,0x57,0x9c,0xc6,0x03,0x96,0x9a,0x6a,0x07,0x11,0xe1,0x99,
	0x66,0xdb,0x93,0x9f,0x65,0x08,0x3b,0x39,0xda,0x2f,0xfb,0xf6,0x87,0x85,0x82,0x23,
	0xd5,0xce,0x14,0x36,0xa4,0x42,0xdf,0x10,0xe8,0x83,0x3b,0xc3,0x4f,0x6f,0x2a,0x0b,
	0x8b,0x56,0x7d,0x70,0x1f,0x4f,0x18,0xe4,0x26,0x74,0x8b,0xf0,0x87,0xc6,0x00,0x8b,
	0x45,0x55,0xec,0x5a,0x9f,0x2a,0xee,0x54,0xb3,0xee,0xfa,0x13,0x3c,0x54,0x4c,0x6d,
	0x5d,0x2b,0x49,0x50,0x2b,0x37,0x89,0x1d,0x20,0x8b,0x6c,0x7a,0xfd,0x14,0xa8,0x71,
	0x15,0x40,0x16,0x8c,0x57,0xa3,0xeb,0x6e,0x60,0xc9,0x03,0x96,0xee,0x19,0xfd,0xac,
	0xca,0x92,0xdc,0x8c,0x55,0x33,0x5b,0x38,0x03,0xac,0x16,0x5f,0xf6,0xdf,0xff,0xb4,
	0xcf,0x5a
};

/**
 * Length of the test CFM data.
 */
const uint32_t CFM_ONLY_PFM_DATA_LEN = sizeof (CFM_ONLY_PFM_DATA);

/**
 * CFM_ONLY_PFM_DATA hash for testing.
 */
const uint8_t CFM_ONLY_PFM_HASH[] = {
	0x99,0xdc,0x20,0x08,0x06,0x63,0xd5,0xdb,0x19,0x88,0x0c,0x47,0xab,0x28,0x2f,0xcb,
	0xf2,0xa9,0x6b,0xd1,0xb3,0x20,0x96,0x78,0xd5,0xa3,0x9e,0x1b,0xc4,0x17,0xbc,0xb0
};

/*
* The platform identifier in the CFM data
*/
const char CFM_ONLY_PFM_PLATFORM_ID[] = "SKU1";

/**
 * Components of the test CFM.
 */
const struct cfm_testing_data CFM_ONLY_PFM_TESTING = {
	.manifest = {
		.raw = CFM_ONLY_PFM_DATA,
		.length = sizeof (CFM_ONLY_PFM_DATA),
		.hash = CFM_ONLY_PFM_HASH,
		.hash_len = sizeof (CFM_ONLY_PFM_HASH),
		.id = 0x5,
		.signature = CFM_ONLY_PFM_DATA + (sizeof (CFM_ONLY_PFM_DATA) - 256),
		.sig_len = 256,
		.sig_offset = (sizeof (CFM_ONLY_PFM_DATA) - 256),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = CFM_ONLY_PFM_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0xc8,
		.toc_hash = CFM_ONLY_PFM_DATA + 0xd8,
		.toc_hash_len = 32,
		.toc_hash_offset = 0xd8,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 5,
		.toc_hashes = 5,
		.plat_id = CFM_ONLY_PFM_DATA + 0xf8,
		.plat_id_len = 0x8,
		.plat_id_str = CFM_ONLY_PFM_PLATFORM_ID,
		.plat_id_str_len = sizeof (CFM_ONLY_PFM_PLATFORM_ID) - 1,
		.plat_id_str_pad = 0,
		.plat_id_offset = 0xf8,
		.plat_id_entry = 0,
		.plat_id_hash = 0
	},
	.component_device1_len = 0x10,
	.component_device1_offset = 0x100,
	.component_device1_entry = 1,
	.component_device1_hash = 1,
};

/**
 * Dummy CFM with only allowable CFM elements for testing.
 */
const uint8_t CFM_ONLY_CFM_DATA[] = {
	0xfe,0x01,0x92,0xa5,0x06,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x04,0x04,0x00,0x00,
	0x00,0xff,0x01,0x00,0xd0,0x00,0x08,0x00,0x70,0xff,0x00,0x01,0xd8,0x00,0x10,0x00,
	0x77,0x70,0x00,0x02,0xe8,0x00,0x0e,0x00,0x79,0x77,0x00,0x03,0xf6,0x00,0x08,0x00,
	0x13,0xe9,0x1c,0x16,0x0e,0xcf,0xd2,0xbb,0x3a,0x86,0x83,0xb6,0x01,0xc4,0xba,0xcb,
	0x04,0xf0,0xa5,0x18,0x9b,0x97,0xd9,0x2d,0x67,0xf4,0x6d,0x69,0xea,0x1e,0x25,0x36,
	0xe8,0x57,0x2a,0x8e,0x2e,0x62,0x19,0xc1,0x75,0xcb,0x14,0x77,0x77,0x4b,0xfc,0xac,
	0xb4,0xa7,0xcd,0x12,0x43,0x44,0x4b,0xa7,0xf3,0xb1,0x1d,0xef,0x3e,0x1f,0xbb,0x07,
	0x0e,0xcd,0x89,0x5e,0xb4,0x22,0xce,0xe0,0xb8,0xae,0x62,0x57,0x6a,0x83,0x63,0x88,
	0xfc,0x40,0x76,0x6e,0xdc,0xc9,0x47,0xe8,0x57,0x57,0x65,0x17,0x0c,0xee,0x66,0x9c,
	0x47,0x35,0xa1,0x4c,0x94,0x1f,0x3d,0xc9,0x79,0x7f,0x74,0x55,0xe3,0xbd,0x43,0x56,
	0x77,0x82,0x6f,0x48,0xf8,0xb0,0x46,0x24,0xc1,0x34,0xc0,0x39,0xfa,0x03,0xbc,0x11,
	0x5c,0x90,0x67,0x0e,0x08,0x19,0x31,0xb9,0xb6,0xeb,0xb8,0x92,0xb6,0x4b,0xd9,0x9b,
	0xe1,0x9c,0x96,0x5a,0x97,0x7a,0x28,0xce,0x6c,0xc9,0x52,0xcf,0xb4,0x68,0x0c,0xfd,
	0x04,0x00,0x00,0x00,0x53,0x4b,0x55,0x31,0x01,0x00,0x00,0x0a,0x43,0x6f,0x6d,0x70,
	0x6f,0x6e,0x65,0x6e,0x74,0x31,0x00,0x00,0x01,0x09,0x70,0x6c,0x61,0x74,0x66,0x6f,
	0x72,0x6d,0x43,0x00,0x00,0x00,0x04,0x01,0x00,0x00,0x12,0x00,0x00,0x00,0x82,0x8c,
	0xe3,0xdd,0x9b,0xb0,0x7b,0xd1,0xf6,0xf9,0x02,0x88,0x04,0xd7,0xf7,0x07,0x81,0x40,
	0x52,0xb5,0x30,0x1e,0x65,0xc6,0x68,0xec,0xb6,0xe8,0x7c,0x6f,0xe6,0x21,0x5c,0x3c,
	0xa1,0xef,0xbf,0x8f,0xa3,0xb4,0xcf,0xe3,0x6b,0x82,0xa3,0xe9,0x17,0x36,0x0e,0x20,
	0x36,0xa5,0xf6,0x2f,0x32,0xa3,0xb9,0x67,0xf6,0x7c,0xe2,0xce,0x26,0x12,0x59,0x27,
	0x3b,0x8d,0x74,0xbd,0xa7,0x17,0xbd,0x2a,0x30,0x43,0x1e,0x08,0x3e,0xd4,0xf1,0xfa,
	0x72,0x16,0x49,0x91,0xbb,0xe9,0xd1,0xfe,0x1e,0x7a,0x08,0xe0,0x47,0x77,0xec,0x5c,
	0x27,0xbe,0x55,0x4e,0x8d,0xf1,0x1f,0xfe,0x25,0x4c,0xa8,0xdc,0x3f,0x3c,0x7a,0x07,
	0x66,0x6e,0xa0,0x0d,0xe9,0xdb,0x4a,0xeb,0xe2,0xb6,0x51,0x63,0x1a,0x65,0x3c,0xba,
	0x9d,0xce,0x77,0xc4,0xf2,0xe0,0x5a,0x21,0x4f,0x5d,0x95,0x84,0x3a,0x05,0x30,0x53,
	0xc2,0xfa,0x24,0x9f,0xb0,0xce,0xc7,0xbe,0x64,0xfc,0x10,0xeb,0xda,0xe8,0xed,0xca,
	0x25,0xaf,0xfd,0x48,0x47,0xf6,0xf4,0x74,0x13,0x15,0xbd,0x5c,0xdc,0xb4,0x4a,0x40,
	0xf2,0xcf,0xbf,0xeb,0x03,0xad,0x51,0xbd,0x92,0xe2,0x47,0x48,0x79,0xe3,0x0f,0x7e,
	0x9c,0x7f,0x6a,0x13,0x16,0xc5,0xb9,0x53,0xca,0xe3,0xae,0xe1,0x88,0xb2,0xb0,0xe1,
	0xd5,0x6c,0xc8,0xf4,0x2b,0xfe,0x81,0xe9,0xb2,0x61,0x82,0x2d,0x71,0xaa,0x58,0x4f,
	0xbe,0x7a,0xfb,0x36,0x38,0x71,0xde,0x34,0x36,0x73,0x77,0xed,0xd3,0x0f,0x76,0x58,
	0xa8,0x05,0x92,0x6a,0xdc,0xae,0x3a,0x9f,0xf3,0xd5,0x98,0x60,0x1b,0xef
};

/**
 * Length of the test CFM data.
 */
const uint32_t CFM_ONLY_CFM_DATA_LEN = sizeof (CFM_ONLY_CFM_DATA);

/**
 * CFM_ONLY_CFM_DATA hash for testing.
 */
const uint8_t CFM_ONLY_CFM_HASH[] = {
	0x7e,0x3e,0x18,0x4a,0x94,0x9b,0x3e,0x13,0x77,0x23,0x05,0xf5,0x20,0x52,0x7d,0x90,
	0x32,0xf3,0x7e,0xa7,0x87,0x4e,0x80,0xd5,0x4f,0x80,0xfd,0xbc,0x35,0x61,0xfb,0x85
};

/*
* The platform identifier in the CFM data
*/
const char CFM_ONLY_CFM_PLATFORM_ID[] = "SKU1";

/**
 * Components of the test CFM.
 */
const struct cfm_testing_data CFM_ONLY_CFM_TESTING = {
	.manifest = {
		.raw = CFM_ONLY_CFM_DATA,
		.length = sizeof (CFM_ONLY_CFM_DATA),
		.hash = CFM_ONLY_CFM_HASH,
		.hash_len = sizeof (CFM_ONLY_CFM_HASH),
		.id = 0x6,
		.signature = CFM_ONLY_CFM_DATA + (sizeof (CFM_ONLY_CFM_DATA) - 256),
		.sig_len = 256,
		.sig_offset = (sizeof (CFM_ONLY_CFM_DATA) - 256),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = CFM_ONLY_CFM_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0xa0,
		.toc_hash = CFM_ONLY_CFM_DATA + 0xb0,
		.toc_hash_len = 32,
		.toc_hash_offset = 0xb0,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 4,
		.toc_hashes = 4,
		.plat_id = CFM_ONLY_CFM_DATA + 0xd0,
		.plat_id_len = 0x8,
		.plat_id_str = CFM_ONLY_CFM_PLATFORM_ID,
		.plat_id_str_len = sizeof (CFM_ONLY_CFM_PLATFORM_ID) - 1,
		.plat_id_str_pad = 0,
		.plat_id_offset = 0xd0,
		.plat_id_entry = 0,
		.plat_id_hash = 0
	},
	.component_device1_len = 0x10,
	.component_device1_offset = 0xd8,
	.component_device1_entry = 1,
	.component_device1_hash = 1,
};

/**
 * Dummy CFM with only allowable PCD elements for testing.
 */
const uint8_t CFM_ONLY_PCD_DATA[] = {
	0xfe,0x01,0x92,0xa5,0x07,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x04,0x04,0x00,0x00,
	0x00,0xff,0x01,0x00,0xd0,0x00,0x08,0x00,0x70,0xff,0x00,0x01,0xd8,0x00,0x10,0x00,
	0x78,0x70,0x00,0x02,0xe8,0x00,0x0e,0x00,0x79,0x78,0x00,0x03,0xf6,0x00,0x08,0x00,
	0x13,0xe9,0x1c,0x16,0x0e,0xcf,0xd2,0xbb,0x3a,0x86,0x83,0xb6,0x01,0xc4,0xba,0xcb,
	0x04,0xf0,0xa5,0x18,0x9b,0x97,0xd9,0x2d,0x67,0xf4,0x6d,0x69,0xea,0x1e,0x25,0x36,
	0xe8,0x57,0x2a,0x8e,0x2e,0x62,0x19,0xc1,0x75,0xcb,0x14,0x77,0x77,0x4b,0xfc,0xac,
	0xb4,0xa7,0xcd,0x12,0x43,0x44,0x4b,0xa7,0xf3,0xb1,0x1d,0xef,0x3e,0x1f,0xbb,0x07,
	0x99,0x24,0x75,0x92,0x01,0x46,0x61,0x4e,0x87,0x5f,0xa3,0xb9,0xbc,0x33,0x82,0xb5,
	0xee,0x88,0xab,0xde,0x57,0x74,0x43,0x23,0x13,0x7b,0x60,0xac,0x3b,0xd7,0xfe,0xb4,
	0x20,0xc9,0x58,0xd6,0x4f,0xaf,0x08,0xf6,0x58,0xbb,0xc6,0xe1,0xe5,0x17,0x3e,0xd1,
	0x37,0x1a,0x72,0xe6,0x7b,0x18,0xd3,0x06,0xe8,0xf5,0x7a,0xbc,0x8e,0x61,0xe0,0xce,
	0x03,0xe4,0x19,0x30,0x1a,0xd1,0xbd,0xe9,0x27,0x28,0xe7,0x00,0xd4,0x3a,0xd3,0xdc,
	0x22,0xe5,0x2c,0xd5,0x07,0x25,0xa6,0xce,0x35,0xea,0x64,0x32,0x3a,0x70,0xdb,0xd8,
	0x04,0x00,0x00,0x00,0x53,0x4b,0x55,0x31,0x01,0x00,0x00,0x0a,0x43,0x6f,0x6d,0x70,
	0x6f,0x6e,0x65,0x6e,0x74,0x31,0x00,0x00,0x00,0x09,0x70,0x6c,0x61,0x74,0x66,0x6f,
	0x72,0x6d,0x44,0x00,0x00,0x00,0x03,0x01,0x00,0x00,0x34,0x00,0x00,0x00,0x57,0xe8,
	0x08,0x4c,0xfc,0xe1,0x21,0x03,0x74,0xd7,0x04,0x6b,0x6d,0x47,0xb2,0x4e,0x3a,0x61,
	0x4a,0xec,0x23,0xcd,0xb0,0x70,0x55,0xe7,0xe3,0xf4,0xce,0xe5,0x35,0xe6,0xfd,0xfb,
	0xa1,0xff,0x2b,0xbf,0xce,0xf7,0x3c,0x95,0x4b,0xb3,0xed,0x95,0x30,0xc2,0xe7,0x82,
	0xaf,0xf0,0x9c,0x79,0xea,0x37,0xe3,0x7b,0x08,0xc5,0x27,0x3e,0xda,0x3d,0x96,0x0a,
	0x16,0x26,0x06,0xf5,0x62,0x5f,0x35,0x40,0x7c,0x7b,0xcd,0x63,0x6a,0x5e,0x2a,0x14,
	0x87,0xed,0x4e,0x70,0x08,0xa0,0x3e,0x9d,0xe4,0x1d,0x6c,0x3b,0xcb,0xe6,0x9f,0x95,
	0xe8,0xae,0xe9,0x47,0x40,0xdb,0x0d,0x0b,0x49,0xa1,0xc4,0x08,0x5e,0xb9,0xb8,0x3e,
	0x36,0x8b,0xac,0xaa,0x62,0xfd,0xea,0x25,0x9d,0xff,0x73,0x98,0x67,0x85,0x26,0x92,
	0x66,0x9b,0x41,0x08,0xeb,0xb5,0x21,0x28,0x4c,0x52,0x90,0xc5,0x4e,0xca,0xac,0x75,
	0x75,0xaf,0xd0,0xaf,0xd8,0x74,0x59,0x5f,0x3b,0xc7,0x6f,0xbe,0x46,0x33,0x7b,0x52,
	0x07,0x5b,0x5d,0xb0,0xc9,0x20,0x80,0x4d,0x14,0x6b,0xb7,0x08,0x8b,0xd3,0x50,0x82,
	0xa4,0xdb,0xb9,0xae,0xf5,0x2d,0x2f,0xf5,0x45,0x81,0x60,0xb7,0xf7,0xf5,0x3d,0xb7,
	0xb7,0x81,0xcd,0x88,0x25,0xa4,0xb5,0xc3,0x2d,0x4d,0x4e,0xd9,0x76,0x7c,0x52,0xe2,
	0x2a,0xa6,0x88,0xf1,0x00,0xc4,0xb5,0x23,0x9e,0xab,0xb5,0xbc,0xad,0x8b,0xfc,0xbe,
	0xb2,0x8b,0x5c,0x89,0x82,0x1c,0x14,0x58,0x71,0x66,0x96,0x8a,0x6e,0x23,0x4e,0xa0,
	0xcf,0x94,0x2a,0xc2,0x65,0x6d,0x6d,0x96,0x1e,0xa0,0xed,0x5f,0x18,0x7c
};

/**
 * Length of the test CFM data.
 */
const uint32_t CFM_ONLY_PCD_DATA_LEN = sizeof (CFM_ONLY_PCD_DATA);

/**
 * CFM_ONLY_PCD_DATA hash for testing.
 */
const uint8_t CFM_ONLY_PCD_HASH[] = {
	0x88,0xec,0xf5,0xcb,0xaa,0x28,0x89,0xe7,0x4b,0x84,0x06,0x41,0xfe,0xfe,0x40,0xc3,
	0xa2,0x14,0x16,0x25,0xcd,0xe8,0x04,0x9e,0x6f,0x30,0x37,0x7f,0x2c,0xc9,0xb3,0x6f
};

/*
* The platform identifier in the CFM data
*/
const char CFM_ONLY_PCD_PLATFORM_ID[] = "SKU1";

/**
 * Components of the test CFM.
 */
const struct cfm_testing_data CFM_ONLY_PCD_TESTING = {
	.manifest = {
		.raw = CFM_ONLY_PCD_DATA,
		.length = sizeof (CFM_ONLY_PCD_DATA),
		.hash = CFM_ONLY_PCD_HASH,
		.hash_len = sizeof (CFM_ONLY_PCD_HASH),
		.id = 0x7,
		.signature = CFM_ONLY_PCD_DATA + (sizeof (CFM_ONLY_PCD_DATA) - 256),
		.sig_len = 256,
		.sig_offset = (sizeof (CFM_ONLY_PCD_DATA) - 256),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = CFM_ONLY_PCD_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0xa0,
		.toc_hash = CFM_ONLY_PCD_DATA + 0xb0,
		.toc_hash_len = 32,
		.toc_hash_offset = 0xb0,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 4,
		.toc_hashes = 4,
		.plat_id = CFM_ONLY_PCD_DATA + 0xd0,
		.plat_id_len = 0x8,
		.plat_id_str = CFM_ONLY_PCD_PLATFORM_ID,
		.plat_id_str_len = sizeof (CFM_ONLY_PCD_PLATFORM_ID) - 1,
		.plat_id_str_pad = 0,
		.plat_id_offset = 0xd0,
		.plat_id_entry = 0,
		.plat_id_hash = 0
	},
	.component_device1_len = 0x10,
	.component_device1_offset = 0xd8,
	.component_device1_entry = 1,
	.component_device1_hash = 1,
};

/**
 * Empty CFM for testing.
 */
const uint8_t CFM_EMPTY_DATA[] = {
	0x60,0x01,0x92,0xa5,0x20,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x01,0x01,0x00,0x00,
	0x00,0xff,0x01,0x00,0x58,0x00,0x08,0x00,0x13,0xe9,0x1c,0x16,0x0e,0xcf,0xd2,0xbb,
	0x3a,0x86,0x83,0xb6,0x01,0xc4,0xba,0xcb,0x04,0xf0,0xa5,0x18,0x9b,0x97,0xd9,0x2d,
	0x67,0xf4,0x6d,0x69,0xea,0x1e,0x25,0x36,0xdc,0x10,0x83,0x7f,0x37,0xb5,0x77,0xd9,
	0x7e,0x1b,0xb5,0xf2,0xbf,0x58,0xf4,0xd7,0xa2,0x05,0xf2,0xc9,0x76,0xcb,0x32,0x0e,
	0xa2,0xd3,0xbe,0x32,0xbe,0x76,0x0c,0x0b,0x04,0x00,0x00,0x00,0x53,0x4b,0x55,0x31,
	0x68,0xd8,0x2d,0xaf,0x40,0xc3,0x69,0x3f,0xc6,0x4d,0xe3,0xe1,0x64,0xa7,0x07,0x4a,
	0xc8,0x4c,0x1c,0x6f,0xc3,0xdd,0x30,0xac,0x59,0x98,0xd4,0xa8,0xdc,0xe3,0xa9,0x1b,
	0x41,0xa5,0xe8,0x96,0xa9,0xf7,0x05,0xc1,0x68,0xc8,0x9b,0xa3,0xc6,0x76,0x9f,0xa7,
	0x72,0x3e,0x98,0xb8,0x7a,0x7f,0xe0,0x38,0x80,0x51,0xb8,0x96,0x7c,0x1f,0x7a,0xfb,
	0x60,0x59,0x33,0x62,0x15,0x57,0x0a,0xaa,0xec,0x0f,0x6d,0x7e,0x08,0x4b,0x09,0x18,
	0xc5,0x67,0x65,0x18,0x16,0x0a,0x21,0x08,0x47,0x68,0x6b,0x8c,0x4e,0x34,0x3c,0x93,
	0x4f,0xc1,0x78,0x57,0xf1,0x5b,0xcc,0xa5,0x16,0x36,0x11,0x51,0xc0,0xea,0x0f,0x43,
	0xb5,0x0d,0xac,0x6b,0x17,0x14,0x0c,0x33,0x40,0x20,0x41,0x82,0x7c,0xe5,0xb4,0x7a,
	0x73,0x66,0x0d,0x08,0xc7,0xef,0x08,0x01,0xb0,0x64,0x80,0x30,0xeb,0x62,0x1f,0x5e,
	0x2a,0x01,0x10,0xb4,0xd0,0xc8,0xf9,0x0f,0x9a,0x17,0x3f,0x26,0xd1,0x7a,0x7a,0xa0,
	0x5a,0x0a,0xca,0x0b,0x7a,0x4a,0x92,0xaa,0xb8,0xb4,0xa4,0xa4,0x89,0xe9,0x4a,0x59,
	0xfb,0x10,0x77,0x2a,0xcc,0x13,0x73,0x53,0xb4,0x34,0x20,0xbf,0xc0,0x22,0x41,0xc9,
	0x57,0x63,0x79,0x4d,0xb5,0x1c,0x60,0xbd,0x2d,0x43,0x2b,0x95,0xc5,0x8c,0xa1,0x64,
	0x54,0xd4,0xe2,0x4c,0xcd,0x9e,0xa0,0x69,0xe6,0xf0,0x25,0xcb,0x0b,0x80,0xae,0x5b,
	0xc6,0xfb,0xda,0x42,0x47,0xc4,0xd8,0xa1,0x45,0x12,0xe1,0x90,0x11,0xa2,0x29,0x18,
	0xfa,0xb4,0x52,0x83,0x98,0x74,0xc4,0x01,0xdf,0xc1,0x2b,0x87,0x71,0x3d,0x65,0x2e
};

/**
 * Length of the testing empty CFM.
 */
const uint32_t CFM_EMPTY_DATA_LEN = sizeof (CFM_EMPTY_DATA);

/**
 * CFM_DATA_EMPTY hash for testing.
 */
const uint8_t CFM_EMPTY_HASH[] = {
	0xc2,0x87,0x78,0x87,0x85,0x73,0x97,0xac,0x9d,0x39,0xeb,0x8b,0xa6,0x95,0x25,0xff,
	0xb5,0xc7,0xe2,0x20,0x4e,0x65,0x0f,0x1b,0x1e,0x6b,0x3d,0x13,0x3c,0x48,0xe6,0x29
};

/**
 * The platform ID for the empty CFM.
 */
const char CFM_EMPTY_PLATFORM_ID[] = "SKU1";

/**
 * Components of the test empty CFM.
 */
const struct cfm_testing_data CFM_EMPTY_TESTING = {
	.manifest = {
		.raw = CFM_EMPTY_DATA,
		.length = sizeof (CFM_EMPTY_DATA),
		.hash = CFM_EMPTY_HASH,
		.hash_len = sizeof (CFM_EMPTY_HASH),
		.id = 0x20,
		.signature = CFM_EMPTY_DATA + (sizeof (CFM_EMPTY_DATA) - 256),
		.sig_len = 256,
		.sig_offset = (sizeof (CFM_EMPTY_DATA) - 256),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = CFM_EMPTY_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x0044,
		.toc_hash = CFM_EMPTY_DATA + 0x0038,
		.toc_hash_len = 32,
		.toc_hash_offset = 0x0038,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 1,
		.toc_hashes = 1,
		.plat_id = CFM_EMPTY_DATA + 0x0058,
		.plat_id_len = 0x008,
		.plat_id_str = CFM_EMPTY_PLATFORM_ID,
		.plat_id_str_len = sizeof (CFM_EMPTY_PLATFORM_ID) - 1,
		.plat_id_str_pad = 0,
		.plat_id_offset = 0x0058,
		.plat_id_entry = 0,
		.plat_id_hash = 0
	},
	.component_device1_len = 0,
	.component_device1_offset = 0,
	.component_device1_entry = -1,
	.component_device1_hash = -1,
};

/**
 * Dependencies for testing CFMs.
 */
struct cfm_flash_testing {
	struct manifest_flash_v2_testing manifest;			/**< Common dependencies for manifest testing. */
	struct cfm_flash test;								/**< CFM instance under test. */
};


/**
 * Initialize common CFM testing dependencies.
 *
 * @param test The testing framework.
 * @param cfm The testing components to initialize.
 * @param address The base address for the CFM data.
 */
static void cfm_flash_testing_init_dependencies (CuTest *test, struct cfm_flash_testing *cfm,
	uint32_t address)
{
	manifest_flash_v2_testing_init_dependencies (test, &cfm->manifest, address);
}

/**
 * Release test dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param cfm The testing components to release.
 */
void cfm_flash_testing_validate_and_release_dependencies (CuTest *test,
	struct cfm_flash_testing *cfm)
{
	manifest_flash_v2_testing_validate_and_release_dependencies (test, &cfm->manifest);
}

/**
 * Initialize CFM for testing.
 *
 * @param test The testing framework.
 * @param cfm The testing components to initialize.
 * @param address The base address for the CFM data.
 */
static void cfm_flash_testing_init (CuTest *test, struct cfm_flash_testing *cfm,
	uint32_t address)
{
	int status;

	cfm_flash_testing_init_dependencies (test, cfm, address);
	manifest_flash_v2_testing_init_common (test, &cfm->manifest, 0x1000);

	status = cfm_flash_init (&cfm->test, &cfm->manifest.flash.base, &cfm->manifest.hash.base,
		address, cfm->manifest.signature, sizeof (cfm->manifest.signature),
		cfm->manifest.platform_id, sizeof (cfm->manifest.platform_id));
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&cfm->manifest.flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&cfm->manifest.verification.mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param cfm The testing components to release.
 */
static void cfm_flash_testing_validate_and_release (CuTest *test, struct cfm_flash_testing *cfm)
{
	cfm_flash_release (&cfm->test);

	cfm_flash_testing_validate_and_release_dependencies (test, cfm);
}

/**
 * Set up expectations for verifying a CFM on flash.
 *
 * @param test The testing framework.
 * @param cfm The testing components.
 * @param testing_data Container with testing data.
 * @param sig_result Result of the signature verification call.
 */
static void cfm_flash_testing_verify_cfm (CuTest *test, struct cfm_flash_testing *cfm,
	const struct cfm_testing_data *testing_data, int sig_result)
{
	manifest_flash_v2_testing_verify_manifest (test, &cfm->manifest, &testing_data->manifest,
		sig_result);
}

/**
 * Initialize a CFM for testing.  Run verification to load the CFM information.
 *
 * @param test The testing framework.
 * @param cfm The testing components to initialize.
 * @param address The base address for the CFM data.
 * @param testing_data Container with testing data.
 * @param sig_result Result of the signature verification call.
 */
static void cfm_flash_testing_init_and_verify (CuTest *test, struct cfm_flash_testing *cfm,
	uint32_t address, const struct cfm_testing_data *testing_data, int sig_result)
{
	int status;

	cfm_flash_testing_init (test, cfm, address);
	cfm_flash_testing_verify_cfm (test, cfm, testing_data, sig_result);

	status = cfm->test.base.base.verify (&cfm->test.base.base, &cfm->manifest.hash.base,
		&cfm->manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, sig_result, status);

	status = mock_validate (&cfm->manifest.flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&cfm->manifest.verification.mock);
	CuAssertIntEquals (test, 0, status);
}


/*******************
 * Test cases
 *******************/

static void cfm_flash_test_init (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_dependencies (test, &cfm, 0x10000);
	manifest_flash_v2_testing_init_common (test, &cfm.manifest, 0x1000);

	status = cfm_flash_init (&cfm.test, &cfm.manifest.flash.base, &cfm.manifest.hash.base,
		0x10000, cfm.manifest.signature, sizeof (cfm.manifest.signature),
		cfm.manifest.platform_id, sizeof (cfm.manifest.platform_id));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, cfm.test.base.base.verify);
	CuAssertPtrNotNull (test, cfm.test.base.base.get_id);
	CuAssertPtrNotNull (test, cfm.test.base.base.get_platform_id);
	CuAssertPtrNotNull (test, cfm.test.base.base.free_platform_id);
	CuAssertPtrNotNull (test, cfm.test.base.base.get_hash);
	CuAssertPtrNotNull (test, cfm.test.base.base.get_signature);
	CuAssertPtrNotNull (test, cfm.test.base.base.is_empty);

	CuAssertPtrNotNull (test, cfm.test.base.get_component_pmr);
	CuAssertPtrNotNull (test, cfm.test.base.free_component_pmr_digest);
	CuAssertPtrNotNull (test, cfm.test.base.get_component_pmr_digest);
	CuAssertPtrNotNull (test, cfm.test.base.buffer_supported_components);
	CuAssertPtrNotNull (test, cfm.test.base.get_component_device);
	CuAssertPtrNotNull (test, cfm.test.base.free_measurement);
	CuAssertPtrNotNull (test, cfm.test.base.get_next_measurement);
	CuAssertPtrNotNull (test, cfm.test.base.free_measurement_data);
	CuAssertPtrNotNull (test, cfm.test.base.get_next_measurement_data);
	CuAssertPtrNotNull (test, cfm.test.base.free_root_ca_digest);
	CuAssertPtrNotNull (test, cfm.test.base.get_root_ca_digest);
	CuAssertPtrNotNull (test, cfm.test.base.free_manifest);
	CuAssertPtrNotNull (test, cfm.test.base.get_next_pfm);
	CuAssertPtrNotNull (test, cfm.test.base.get_next_cfm);
	CuAssertPtrNotNull (test, cfm.test.base.get_pcd);

	CuAssertIntEquals (test, 0x10000, manifest_flash_get_addr (&cfm.test.base_flash));
	CuAssertPtrEquals (test, &cfm.manifest.flash,
		manifest_flash_get_flash (&cfm.test.base_flash));

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_init_null (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_dependencies (test, &cfm, 0x10000);

	status = cfm_flash_init (NULL, &cfm.manifest.flash.base, &cfm.manifest.hash.base, 0x10000,
		cfm.manifest.signature, sizeof (cfm.manifest.signature), cfm.manifest.platform_id,
		sizeof (cfm.manifest.platform_id));
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm_flash_init (&cfm.test, NULL, &cfm.manifest.hash.base, 0x10000,
		cfm.manifest.signature, sizeof (cfm.manifest.signature), cfm.manifest.platform_id,
		sizeof (cfm.manifest.platform_id));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = cfm_flash_init (&cfm.test, &cfm.manifest.flash.base, &cfm.manifest.hash.base,
		0x10000, NULL, sizeof (cfm.manifest.signature), cfm.manifest.platform_id,
		sizeof (cfm.manifest.platform_id));
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm_flash_init (&cfm.test, &cfm.manifest.flash.base, &cfm.manifest.hash.base,
		0x10000, cfm.manifest.signature, sizeof (cfm.manifest.signature), NULL,
		sizeof (cfm.manifest.platform_id));
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	cfm_flash_testing_validate_and_release_dependencies (test, &cfm);
}

static void cfm_flash_test_init_manifest_flash_init_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_dependencies (test, &cfm, 0x10001);
	manifest_flash_v2_testing_init_common (test, &cfm.manifest, 0x1000);

	status = cfm_flash_init (&cfm.test, &cfm.manifest.flash.base, &cfm.manifest.hash.base,
		0x10001, cfm.manifest.signature, sizeof (cfm.manifest.signature),
		cfm.manifest.platform_id, sizeof (cfm.manifest.platform_id));
	CuAssertIntEquals (test, MANIFEST_STORAGE_NOT_ALIGNED, status);

	cfm_flash_testing_validate_and_release_dependencies (test, &cfm);
}

static void cfm_flash_test_release_null (CuTest *test)
{
	TEST_START;

	cfm_flash_release (NULL);
}

static void cfm_flash_test_verify (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	cfm_flash_testing_verify_cfm (test, &cfm, &CFM_TESTING, 0);

	status = cfm.test.base.base.verify (&cfm.test.base.base, &cfm.manifest.hash.base,
		&cfm.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_verify_only_pmr_digest (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	cfm_flash_testing_verify_cfm (test, &cfm, &CFM_ONLY_PMR_DIGEST_TESTING, 0);

	status = cfm.test.base.base.verify (&cfm.test.base.base, &cfm.manifest.hash.base,
		&cfm.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_verify_only_measurement (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	cfm_flash_testing_verify_cfm (test, &cfm, &CFM_ONLY_MEASUREMENT_TESTING, 0);

	status = cfm.test.base.base.verify (&cfm.test.base.base, &cfm.manifest.hash.base,
		&cfm.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_verify_only_measurement_data (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	cfm_flash_testing_verify_cfm (test, &cfm, &CFM_ONLY_MEASUREMENT_DATA_TESTING, 0);

	status = cfm.test.base.base.verify (&cfm.test.base.base, &cfm.manifest.hash.base,
		&cfm.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_verify_only_allowable_pfm (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	cfm_flash_testing_verify_cfm (test, &cfm, &CFM_ONLY_PFM_TESTING, 0);

	status = cfm.test.base.base.verify (&cfm.test.base.base, &cfm.manifest.hash.base,
		&cfm.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_verify_only_allowable_cfm (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	cfm_flash_testing_verify_cfm (test, &cfm, &CFM_ONLY_CFM_TESTING, 0);

	status = cfm.test.base.base.verify (&cfm.test.base.base, &cfm.manifest.hash.base,
		&cfm.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_verify_only_allowable_pcd (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	cfm_flash_testing_verify_cfm (test, &cfm, &CFM_ONLY_PCD_TESTING, 0);

	status = cfm.test.base.base.verify (&cfm.test.base.base, &cfm.manifest.hash.base,
		&cfm.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_verify_null (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = cfm.test.base.base.verify (NULL, &cfm.manifest.hash.base,
		&cfm.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.base.verify (&cfm.test.base.base, NULL,
		&cfm.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = cfm.test.base.base.verify (&cfm.test.base.base, &cfm.manifest.hash.base, NULL,
		NULL, 0);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_verify_bad_magic_number (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;
	uint8_t cfm_bad_data[MANIFEST_V2_HEADER_SIZE];

	TEST_START;

	memcpy (cfm_bad_data, CFM_TESTING.manifest.raw, sizeof (cfm_bad_data));
	cfm_bad_data[2] ^= 0x55;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, 0, MOCK_ARG (cfm.manifest.addr), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&cfm.manifest.flash.mock, 1, cfm_bad_data,
		MANIFEST_V2_HEADER_SIZE, 2);
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.base.verify (&cfm.test.base.base, &cfm.manifest.hash.base,
		&cfm.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_id (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;
	uint32_t id;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	status = cfm.test.base.base.get_id (&cfm.test.base.base, &id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, id);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_id_null (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;
	uint32_t id;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	status = cfm.test.base.base.get_id (NULL, &id);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.base.get_id (&cfm.test.base.base, NULL);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_id_verify_never_run (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;
	uint32_t id;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = cfm.test.base.base.get_id (&cfm.test.base.base, &id);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_hash (CuTest *test)
{
	struct cfm_flash_testing cfm;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	/* Read manifest header. */
	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, 0, MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&cfm.manifest.flash.mock, 1, CFM_TESTING.manifest.raw,
		MANIFEST_V2_HEADER_SIZE, 2);

	status |= flash_mock_expect_verify_flash (&cfm.manifest.flash, 0x10000,
		CFM_TESTING.manifest.raw, CFM_DATA_LEN - CFM_TESTING.manifest.sig_len);

	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.base.get_hash (&cfm.test.base.base, &cfm.manifest.hash.base,
		hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (CFM_TESTING.manifest.hash, hash_out,
		CFM_TESTING.manifest.hash_len);
	CuAssertIntEquals (test, 0, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_hash_after_verify (CuTest *test)
{
	struct cfm_flash_testing cfm;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	status = cfm.test.base.base.get_hash (&cfm.test.base.base, &cfm.manifest.hash.base,
		hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (CFM_TESTING.manifest.hash, hash_out,
		CFM_TESTING.manifest.hash_len);
	CuAssertIntEquals (test, 0, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_hash_null (CuTest *test)
{
	struct cfm_flash_testing cfm;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = cfm.test.base.base.get_hash (NULL, &cfm.manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.base.get_hash (&cfm.test.base.base, NULL, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = cfm.test.base.base.get_hash (&cfm.test.base.base, &cfm.manifest.hash.base, NULL,
		sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_hash_bad_magic_num (CuTest *test)
{
	struct cfm_flash_testing cfm;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;
	uint8_t cfm_bad_data[CFM_TESTING.manifest.sig_offset];

	TEST_START;

	memcpy (cfm_bad_data, CFM_TESTING.manifest.raw, sizeof (cfm_bad_data));
	cfm_bad_data[2] ^= 0x55;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, 0, MOCK_ARG (cfm.manifest.addr), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&cfm.manifest.flash.mock, 1, cfm_bad_data,
		MANIFEST_V2_HEADER_SIZE, 2);
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.base.get_hash (&cfm.test.base.base, &cfm.manifest.hash.base,
		hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_signature (CuTest *test)
{
	struct cfm_flash_testing cfm;
	uint8_t sig_out[CFM_TESTING.manifest.sig_len];
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, 0, MOCK_ARG (cfm.manifest.addr), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&cfm.manifest.flash.mock, 1, CFM_TESTING.manifest.raw,
		MANIFEST_V2_HEADER_SIZE, 2);

	status |= mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, 0, MOCK_ARG (cfm.manifest.addr + CFM_TESTING.manifest.sig_offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (CFM_TESTING.manifest.sig_len));
	status |= mock_expect_output (&cfm.manifest.flash.mock, 1, CFM_TESTING.manifest.signature,
		CFM_TESTING.manifest.sig_len, 2);

	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.base.get_signature (&cfm.test.base.base, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, CFM_TESTING.manifest.sig_len, status);

	status = testing_validate_array (CFM_TESTING.manifest.signature, sig_out,
		CFM_TESTING.manifest.sig_len);
	CuAssertIntEquals (test, 0, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_signature_after_verify (CuTest *test)
{
	struct cfm_flash_testing cfm;
	uint8_t sig_out[CFM_TESTING.manifest.sig_len];
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	status = cfm.test.base.base.get_signature (&cfm.test.base.base, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, CFM_TESTING.manifest.sig_len, status);

	status = testing_validate_array (CFM_TESTING.manifest.signature, sig_out,
		CFM_TESTING.manifest.sig_len);
	CuAssertIntEquals (test, 0, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_signature_null (CuTest *test)
{
	struct cfm_flash_testing cfm;
	uint8_t sig_out[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = cfm.test.base.base.get_signature (NULL, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.base.get_signature (&cfm.test.base.base, NULL, sizeof (sig_out));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_signature_bad_magic_number (CuTest *test)
{
	struct cfm_flash_testing cfm;
	uint8_t sig_out[SHA256_HASH_LENGTH];
	int status;
	uint8_t cfm_bad_data[MANIFEST_V2_HEADER_SIZE];

	TEST_START;

	memcpy (cfm_bad_data, CFM_TESTING.manifest.raw, sizeof (cfm_bad_data));
	cfm_bad_data[2] ^= 0x55;

	cfm_flash_testing_init (test, &cfm, 0x10000);



	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, 0, MOCK_ARG (cfm.manifest.addr), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&cfm.manifest.flash.mock, 1, cfm_bad_data,
		MANIFEST_V2_HEADER_SIZE, 2);

	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.base.get_signature (&cfm.test.base.base, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_platform_id (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;
	char buffer[32];
	char *id = buffer;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	status = cfm.test.base.base.get_platform_id (&cfm.test.base.base, &id, sizeof (buffer));
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, buffer, id);
	CuAssertStrEquals (test, "SKU1", id);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_platform_id_manifest_allocation (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;
	char *id = NULL;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	status = cfm.test.base.base.get_platform_id (&cfm.test.base.base, &id, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, id);
	CuAssertStrEquals (test, "SKU1", id);

	cfm.test.base.base.free_platform_id (&cfm.test.base.base, id);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_platform_id_null (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;
	char *id = NULL;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	status = cfm.test.base.base.get_platform_id (NULL, &id, 0);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.base.get_platform_id (&cfm.test.base.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_platform_id_verify_never_run (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;
	char buffer[32];
	char *id = buffer;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = cfm.test.base.base.get_platform_id (&cfm.test.base.base, &id, sizeof (buffer));
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_is_empty (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	status = cfm.test.base.base.is_empty (&cfm.test.base.base);
	CuAssertIntEquals (test, 0, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_is_empty_empty (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_EMPTY_TESTING, 0);

	status = cfm.test.base.base.is_empty (&cfm.test.base.base);
	CuAssertIntEquals (test, 1, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_is_empty_null (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_EMPTY_TESTING, 0);

	status = cfm.test.base.base.is_empty (NULL);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_is_empty_verify_never_run (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = cfm.test.base.base.is_empty (&cfm.test.base.base);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr (CuTest *test)
{
	struct cfm_pmr pmr;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 3, 2, 3,
		0x6a4, 0x24, 0x24, 0);

	status = cfm.test.base.get_component_pmr (&cfm.test.base, "Component1", 1, &pmr);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, pmr.pmr_id);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, pmr.initial_value_len);

	status = testing_validate_array (PMR_1_DEVICE_1, pmr.initial_value, sizeof (PMR_1_DEVICE_1));
	CuAssertIntEquals (test, 0, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_second_component (CuTest *test)
{
	struct cfm_pmr pmr;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 26, 2, 26,
		0x8ce, 0x10, 0x10, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		27, 38);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 28, 27, 28,
		0x912, 0x34, 0x34, 0);

	status = cfm.test.base.get_component_pmr (&cfm.test.base, "Component2", 0, &pmr);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, pmr.pmr_id);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, pmr.initial_value_len);

	status = testing_validate_array (PMR_0_DEVICE_2, pmr.initial_value,	sizeof (PMR_0_DEVICE_2));
	CuAssertIntEquals (test, 0, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_second_pmr (CuTest *test)
{
	struct cfm_pmr pmr;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 3, 2, 3,
		0x6a4, 0x24, 0x24, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest, 4,
		26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 4, 4, 4,
		0x6c8, 0x44, 0x44, 0);

	status = cfm.test.base.get_component_pmr (&cfm.test.base, "Component1", 2, &pmr);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, pmr.pmr_id);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, pmr.initial_value_len);

	status = testing_validate_array (PMR_2_DEVICE_1, pmr.initial_value, sizeof (PMR_2_DEVICE_1));
	CuAssertIntEquals (test, 0, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_null (CuTest *test)
{
	struct cfm_pmr pmr;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	status = cfm.test.base.get_component_pmr (NULL, "Component1", 0, &pmr);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.get_component_pmr (&cfm.test.base, NULL, 0, &pmr);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.get_component_pmr (&cfm.test.base, "Component1", 0, NULL);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_verify_never_run (CuTest *test)
{
	struct cfm_pmr pmr;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = cfm.test.base.get_component_pmr (&cfm.test.base, "Component1", 0, &pmr);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_component_read_fail (CuTest *test)
{
	struct cfm_pmr pmr;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x08));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_component_pmr (&cfm.test.base, "Component1", 0, &pmr);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_component_not_found (CuTest *test)
{
	struct cfm_pmr pmr;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 26, 2,
		26, 0x8ce, 0x10, 0x10, 0);

	status = flash_mock_expect_verify_flash (&cfm.manifest.flash,
		cfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET,
		CFM_TESTING.manifest.raw + MANIFEST_V2_TOC_ENTRY_OFFSET, MANIFEST_V2_TOC_ENTRY_SIZE * 27);
	CuAssertIntEquals (test, 0, status);

	for (int i = 27; i < CFM_TESTING.manifest.toc_entries; ++i) {
		status |= mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
			&cfm.manifest.flash, 0,
			MOCK_ARG (cfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET +
				i * MANIFEST_V2_TOC_ENTRY_SIZE), MOCK_ARG_NOT_NULL,
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&cfm.manifest.flash.mock, 1,
			(struct manifest_toc_entry*) (CFM_TESTING.manifest.raw +
				MANIFEST_V2_TOC_ENTRY_OFFSET + MANIFEST_V2_TOC_ENTRY_SIZE * i),
				MANIFEST_V2_TOC_ENTRY_SIZE, 2);
	}
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_component_pmr (&cfm.test.base, "Component3", 0, &pmr);
	CuAssertIntEquals (test, MANIFEST_ELEMENT_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_component_has_no_pmr (CuTest *test)
{
	struct cfm_pmr pmr;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_ONLY_MEASUREMENT_DATA_TESTING,	0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_DATA_TESTING.manifest,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_entry, 0,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_hash,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_offset,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_len,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_DATA_TESTING.manifest, 2, 4);

	status = cfm.test.base.get_component_pmr (&cfm.test.base, "Component1", 0, &pmr);
	CuAssertIntEquals (test, CFM_PMR_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_get_num_pmr_fail (CuTest *test)
{
	struct cfm_pmr pmr;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	status = flash_mock_expect_verify_flash (&cfm.manifest.flash, cfm.manifest.addr +
		MANIFEST_V2_TOC_ENTRY_OFFSET, CFM_TESTING.manifest.raw + MANIFEST_V2_TOC_ENTRY_OFFSET,
		MANIFEST_V2_TOC_ENTRY_SIZE * 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY,
		MOCK_ARG (cfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET +
			2 * MANIFEST_V2_TOC_ENTRY_SIZE), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_component_pmr (&cfm.test.base, "Component1", 0, &pmr);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_pmr_read_fail (CuTest *test)
{
	struct cfm_pmr pmr;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x10));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_component_pmr (&cfm.test.base, "Component1", 0, &pmr);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_pmr_not_found (CuTest *test)
{
	struct cfm_pmr pmr;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 3, 2, 3,
		0x6a4, 0x24, 0x24, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest, 4,
		26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 4, 4, 4,
		0x6c8, 0x44, 0x44, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest, 5,
		26);

	status = cfm.test.base.get_component_pmr (&cfm.test.base, "Component1", 3, &pmr);
	CuAssertIntEquals (test, CFM_PMR_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_digest (CuTest *test)
{
	struct cfm_pmr_digest pmr_digest;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 5, 2, 5,
		0x70c, 0x44, sizeof (struct cfm_pmr_digest_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 5, 5, 5,
		0x70c, 0x44, 0x44 - sizeof (struct cfm_pmr_digest_element),
		sizeof (struct cfm_pmr_digest_element));

	status = cfm.test.base.get_component_pmr_digest (&cfm.test.base, "Component1", 0, &pmr_digest);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, pmr_digest.pmr_id);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, pmr_digest.digests.hash_len);
	CuAssertIntEquals (test, 2, pmr_digest.digests.digest_count);

	status = testing_validate_array (PMR_DIGEST_0_DEVICE_1_1, pmr_digest.digests.digests,
		sizeof (PMR_DIGEST_0_DEVICE_1_1));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PMR_DIGEST_0_DEVICE_1_2, pmr_digest.digests.digests +
		sizeof (PMR_DIGEST_0_DEVICE_1_1), sizeof (PMR_DIGEST_0_DEVICE_1_2));
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_component_pmr_digest (&cfm.test.base, &pmr_digest);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_digest_second_component (CuTest *test)
{
	struct cfm_pmr_digest pmr_digest;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 26, 2,
		26, 0x8ce, 0x10, 0x10, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		27, 38);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 29, 27, 29,
		0x946, 0x44, sizeof (struct cfm_pmr_digest_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 29, 29, 29,
		0x946, 0x44, 0x44 - sizeof (struct cfm_pmr_digest_element),
		sizeof (struct cfm_pmr_digest_element));

	status = cfm.test.base.get_component_pmr_digest (&cfm.test.base, "Component2", 2, &pmr_digest);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, pmr_digest.pmr_id);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, pmr_digest.digests.hash_len);
	CuAssertIntEquals (test, 1, pmr_digest.digests.digest_count);

	status = testing_validate_array (PMR_DIGEST_2_DEVICE_2, pmr_digest.digests.digests,
		sizeof (PMR_DIGEST_2_DEVICE_2));
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_component_pmr_digest (&cfm.test.base, &pmr_digest);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_digest_second_digest (CuTest *test)
{
	struct cfm_pmr_digest pmr_digest;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,	5, 2, 5,
		0x70c, 0x44, sizeof (struct cfm_pmr_digest_element), 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		6, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 6, 6, 6,
		0x750, 0x44, sizeof (struct cfm_pmr_digest_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 6, 6, 6,
		0x750, 0x44, 0x44 - sizeof (struct cfm_pmr_digest_element),
		sizeof (struct cfm_pmr_digest_element));

	status = cfm.test.base.get_component_pmr_digest (&cfm.test.base, "Component1", 4, &pmr_digest);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 4, pmr_digest.pmr_id);
	CuAssertIntEquals (test, SHA512_HASH_LENGTH, pmr_digest.digests.hash_len);
	CuAssertIntEquals (test, 1, pmr_digest.digests.digest_count);

	status = testing_validate_array (PMR_DIGEST_4_DEVICE_1, pmr_digest.digests.digests,
		sizeof (PMR_DIGEST_4_DEVICE_1));
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_component_pmr_digest (&cfm.test.base, &pmr_digest);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_digest_null (CuTest *test)
{
	struct cfm_pmr_digest pmr_digest;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	status = cfm.test.base.get_component_pmr_digest (NULL, "Component1", 0, &pmr_digest);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.get_component_pmr_digest (&cfm.test.base, NULL, 0, &pmr_digest);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.get_component_pmr_digest (&cfm.test.base, "Component1", 0, NULL);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_digest_verify_never_run (CuTest *test)
{
	struct cfm_pmr_digest pmr_digest;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = cfm.test.base.get_component_pmr_digest (&cfm.test.base, "Component1", 0, &pmr_digest);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_digest_component_read_fail (CuTest *test)
{
	struct cfm_pmr_digest pmr_digest;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x08));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_component_pmr_digest (&cfm.test.base, "Component1", 0, &pmr_digest);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_digest_component_not_found (CuTest *test)
{
	struct cfm_pmr_digest pmr_digest;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 26, 2,
		26, 0x8ce, 0x10, 0x10, 0);

	status = flash_mock_expect_verify_flash (&cfm.manifest.flash,
		cfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET,
		CFM_TESTING.manifest.raw + MANIFEST_V2_TOC_ENTRY_OFFSET, MANIFEST_V2_TOC_ENTRY_SIZE * 27);
	CuAssertIntEquals (test, 0, status);

	for (int i = 27; i < CFM_TESTING.manifest.toc_entries; ++i) {
		status |= mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
			&cfm.manifest.flash, 0,
			MOCK_ARG (cfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET +
				i * MANIFEST_V2_TOC_ENTRY_SIZE), MOCK_ARG_NOT_NULL,
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&cfm.manifest.flash.mock, 1,
			(struct manifest_toc_entry*) (CFM_TESTING.manifest.raw +
				MANIFEST_V2_TOC_ENTRY_OFFSET + MANIFEST_V2_TOC_ENTRY_SIZE * i),
				MANIFEST_V2_TOC_ENTRY_SIZE, 2);
	}
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_component_pmr_digest (&cfm.test.base, "Component3", 0, &pmr_digest);
	CuAssertIntEquals (test, MANIFEST_ELEMENT_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_digest_component_has_no_pmr_digest (CuTest *test)
{
	struct cfm_pmr_digest pmr_digest;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_ONLY_MEASUREMENT_DATA_TESTING,	0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_DATA_TESTING.manifest,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_entry, 0,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_hash,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_offset,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_len,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_DATA_TESTING.manifest, 2, 4);

	status = cfm.test.base.get_component_pmr_digest (&cfm.test.base, "Component1", 0, &pmr_digest);
	CuAssertIntEquals (test, CFM_PMR_DIGEST_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_digest_get_num_pmr_digest_fail (CuTest *test)
{
	struct cfm_pmr_digest pmr_digest;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	status = flash_mock_expect_verify_flash (&cfm.manifest.flash, cfm.manifest.addr +
		MANIFEST_V2_TOC_ENTRY_OFFSET, CFM_TESTING.manifest.raw + MANIFEST_V2_TOC_ENTRY_OFFSET,
		MANIFEST_V2_TOC_ENTRY_SIZE * 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY,
		MOCK_ARG (cfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET +
			2 * MANIFEST_V2_TOC_ENTRY_SIZE), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_component_pmr_digest (&cfm.test.base, "Component1", 0, &pmr_digest);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_digest_pmr_digest_read_fail (CuTest *test)
{
	struct cfm_pmr_digest pmr_digest;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x10));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_component_pmr_digest (&cfm.test.base, "Component1", 0, &pmr_digest);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_digest_pmr_not_found (CuTest *test)
{
	struct cfm_pmr_digest pmr_digest;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,	5, 2, 5,
		0x70c, 0x44, sizeof (struct cfm_pmr_digest_element), 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest, 6,
		26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 6, 6, 6,
		0x750, 0x44, sizeof (struct cfm_pmr_digest_element), 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest, 7,
		26);

	status = cfm.test.base.get_component_pmr_digest (&cfm.test.base, "Component1", 1, &pmr_digest);
	CuAssertIntEquals (test, CFM_PMR_DIGEST_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_digest_digests_read_fail (CuTest *test)
{
	struct cfm_pmr_digest pmr_digest;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 5, 2, 5,
		0x70c, 0x44, sizeof (struct cfm_pmr_digest_element), 0);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x28));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_component_pmr_digest (&cfm.test.base, "Component1", 0, &pmr_digest);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_free_component_pmr_digest_null (CuTest *test)
{
	struct cfm_flash_testing cfm;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	cfm.test.base.free_component_pmr_digest (&cfm.test.base, NULL);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_buffer_supported_components (CuTest *test)
{
	struct cfm_flash_testing cfm;
	uint8_t components[4096];
	size_t components_len = sizeof (components);
	const char *component1 = "Component1";
	const char *component2 = "Component2";
	size_t component1_len = strlen (component1) + 1;
	size_t component2_len = strlen (component2) + 1;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 26, 2,
		26, 0x8ce, 0x10, 0x10, 0);

	status = flash_mock_expect_verify_flash (&cfm.manifest.flash,
		cfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET,
		CFM_TESTING.manifest.raw + MANIFEST_V2_TOC_ENTRY_OFFSET, MANIFEST_V2_TOC_ENTRY_SIZE * 27);
	CuAssertIntEquals (test, 0, status);

	for (int i = 27; i < CFM_TESTING.manifest.toc_entries; ++i) {
		status |= mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
			&cfm.manifest.flash, 0,
			MOCK_ARG (cfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET +
				i * MANIFEST_V2_TOC_ENTRY_SIZE), MOCK_ARG_NOT_NULL,
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&cfm.manifest.flash.mock, 1,
			(struct manifest_toc_entry*) (CFM_TESTING.manifest.raw +
				MANIFEST_V2_TOC_ENTRY_OFFSET + MANIFEST_V2_TOC_ENTRY_SIZE * i),
				MANIFEST_V2_TOC_ENTRY_SIZE, 2);
	}
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.buffer_supported_components (&cfm.test.base, 0, components_len,
		components);
	CuAssertIntEquals (test, component1_len + component2_len, status);
	CuAssertStrEquals (test, component1, (const char*) components);
	CuAssertStrEquals (test, component2, (const char*) &components[component1_len]);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_buffer_supported_components_offset_nonzero (CuTest *test)
{
	struct cfm_flash_testing cfm;
	uint8_t components[4096];
	const char *component1 = "Component1";
	const char *component2 = "Component2";
	size_t component1_len = strlen (component1) + 1;
	size_t component2_len = strlen (component2) + 1;
	size_t components_len = component1_len;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	status = cfm.test.base.buffer_supported_components (&cfm.test.base, 0, components_len,
		components);
	CuAssertIntEquals (test, component1_len, status);
	CuAssertStrEquals (test, component1, (const char*) components);

	components_len = component2_len;

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 26, 2,
		26, 0x8ce, 0x10, 0x10, 0);

	status = cfm.test.base.buffer_supported_components (&cfm.test.base, component1_len,
		components_len, components);
	CuAssertIntEquals (test, component2_len, status);
	CuAssertStrEquals (test, component2, (const char*) components);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_buffer_supported_components_offset_too_large (CuTest *test)
{
	struct cfm_flash_testing cfm;
	uint8_t components[4096];
	size_t components_len = sizeof (components);
	const char *component1 = "Component1";
	const char *component2 = "Component2";
	size_t component1_len = strlen (component1) + 1;
	size_t component2_len = strlen (component2) + 1;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 26, 2,
		26, 0x8ce, 0x10, 0x10, 0);

	status = flash_mock_expect_verify_flash (&cfm.manifest.flash,
		cfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET,
		CFM_TESTING.manifest.raw + MANIFEST_V2_TOC_ENTRY_OFFSET, MANIFEST_V2_TOC_ENTRY_SIZE * 27);
	CuAssertIntEquals (test, 0, status);

	for (int i = 27; i < CFM_TESTING.manifest.toc_entries; ++i) {
		status |= mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
			&cfm.manifest.flash, 0,
			MOCK_ARG (cfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET +
				i * MANIFEST_V2_TOC_ENTRY_SIZE), MOCK_ARG_NOT_NULL,
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&cfm.manifest.flash.mock, 1,
			(struct manifest_toc_entry*) (CFM_TESTING.manifest.raw +
				MANIFEST_V2_TOC_ENTRY_OFFSET + MANIFEST_V2_TOC_ENTRY_SIZE * i),
				MANIFEST_V2_TOC_ENTRY_SIZE, 2);
	}
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.buffer_supported_components (&cfm.test.base,
		component1_len + component2_len, components_len, components);
	CuAssertIntEquals (test, MANIFEST_ELEMENT_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_buffer_supported_components_null (CuTest *test)
{
	struct cfm_flash_testing cfm;
	uint8_t components[4096];
	size_t components_len = sizeof (components);
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	status = cfm.test.base.buffer_supported_components (NULL, 0, components_len, components);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.buffer_supported_components (&cfm.test.base, 0, components_len, NULL);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.buffer_supported_components (&cfm.test.base, 0, 0, components);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_buffer_supported_components_verify_never_run (CuTest *test)
{
	struct cfm_flash_testing cfm;
	uint8_t components[4096];
	size_t components_len = sizeof (components);
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = cfm.test.base.buffer_supported_components (&cfm.test.base, 0, components_len,
		components);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_buffer_supported_components_component_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	uint8_t components[4096];
	size_t components_len = sizeof (components);
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x08));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.buffer_supported_components (&cfm.test.base, 0, components_len,
		components);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_device (CuTest *test)
{
	struct cfm_component_device component;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 5, 2, 5,
		0x70c, 0x44, sizeof (struct cfm_pmr_digest_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 6, 6, 6,
		0x750, 0x44, sizeof (struct cfm_pmr_digest_element), 0);

	status = cfm.test.base.get_component_device (&cfm.test.base, "Component1", &component);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, component.cert_slot);
	CuAssertIntEquals (test, 0, component.attestation_protocol);
	CuAssertStrEquals (test, "Component1", (const char*) component.type);
	CuAssertIntEquals (test, 0, component.pmr_id_list[0]);
	CuAssertIntEquals (test, 4, component.pmr_id_list[1]);
	CuAssertIntEquals (test, 2, component.num_pmr_digest);

	cfm.test.base.free_component_device (&cfm.test.base, &component);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_device_second_component (CuTest *test)
{
	struct cfm_component_device component;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 26, 2, 26,
		0x8ce, 0x10, 0x10, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		27, 38);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 29, 27, 29,
		0x946, 0x44, sizeof (struct cfm_pmr_digest_element), 0);

	status = cfm.test.base.get_component_device (&cfm.test.base, "Component2", &component);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, component.cert_slot);
	CuAssertIntEquals (test, 1, component.attestation_protocol);
	CuAssertStrEquals (test, "Component2", (const char*) component.type);
	CuAssertIntEquals (test, 2, component.pmr_id_list[0]);
	CuAssertIntEquals (test, 1, component.num_pmr_digest);

	cfm.test.base.free_component_device (&cfm.test.base, &component);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_device_null (CuTest *test)
{
	struct cfm_component_device component;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	status = cfm.test.base.get_component_device (NULL, "Component1", &component);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.get_component_device (&cfm.test.base, NULL, &component);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.get_component_device (&cfm.test.base, "Component1", NULL);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_device_component_read_fail (CuTest *test)
{
	struct cfm_component_device component;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x08));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_component_device (&cfm.test.base, "Component1", &component);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_device_get_num_pmr_digest_fail (CuTest *test)
{
	struct cfm_component_device component;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x10));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_component_device (&cfm.test.base, "Component1", &component);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_device_pmr_digest_read_fail (CuTest *test)
{
	struct cfm_component_device component;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		26);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x10));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_component_device (&cfm.test.base, "Component1", &component);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_device_component_not_found (CuTest *test)
{
	struct cfm_component_device component;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 26, 2,
		26, 0x8ce, 0x10, 0x10, 0);

	status = flash_mock_expect_verify_flash (&cfm.manifest.flash,
		cfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET,
		CFM_TESTING.manifest.raw + MANIFEST_V2_TOC_ENTRY_OFFSET, MANIFEST_V2_TOC_ENTRY_SIZE * 27);
	CuAssertIntEquals (test, 0, status);

	for (int i = 27; i < CFM_TESTING.manifest.toc_entries; ++i) {
		status |= mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
			&cfm.manifest.flash, 0,
			MOCK_ARG (cfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET +
				i * MANIFEST_V2_TOC_ENTRY_SIZE), MOCK_ARG_NOT_NULL,
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&cfm.manifest.flash.mock, 1,
			(struct manifest_toc_entry*) (CFM_TESTING.manifest.raw +
				MANIFEST_V2_TOC_ENTRY_OFFSET + MANIFEST_V2_TOC_ENTRY_SIZE * i),
				MANIFEST_V2_TOC_ENTRY_SIZE, 2);
	}
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_component_device (&cfm.test.base, "Component3", &component);
	CuAssertIntEquals (test, MANIFEST_ELEMENT_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_device_verify_never_run (CuTest *test)
{
	struct cfm_component_device component;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = cfm.test.base.get_component_device (&cfm.test.base, "Component1", &component);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_free_component_device_null (CuTest *test)
{
	struct cfm_flash_testing cfm;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	cfm.test.base.free_component_device (&cfm.test.base, NULL);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement pmr_measurement;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 7, 2, 7,
		0x794, 0x44, sizeof (struct cfm_measurement_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 7, 7, 7,
		0x794, 0x44, 0x44 - sizeof (struct cfm_measurement_element),
		sizeof (struct cfm_measurement_element));

	status = cfm.test.base.get_next_measurement (&cfm.test.base, "Component1", &pmr_measurement,
		true);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, pmr_measurement.pmr_id);
	CuAssertIntEquals (test, 2, pmr_measurement.measurement_id);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, pmr_measurement.digests.hash_len);
	CuAssertIntEquals (test, 2, pmr_measurement.digests.digest_count);

	status = testing_validate_array (MEASUREMENT_PMR_1_MEASUREMENT_2_DEVICE_1,
		pmr_measurement.digests.digests, sizeof (MEASUREMENT_PMR_1_MEASUREMENT_2_DEVICE_1));
	status |= testing_validate_array (MEASUREMENT_PMR_1_MEASUREMENT_2_DEVICE_1_2,
		pmr_measurement.digests.digests + sizeof (MEASUREMENT_PMR_1_MEASUREMENT_2_DEVICE_1),
		sizeof (MEASUREMENT_PMR_1_MEASUREMENT_2_DEVICE_1_2));
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_measurement (&cfm.test.base, &pmr_measurement);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_second_measurement (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement pmr_measurement;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 7, 2, 7,
		0x794, 0x44, sizeof (struct cfm_measurement_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 7, 7, 7,
		0x794, 0x44, 0x44 - sizeof (struct cfm_measurement_element),
		sizeof (struct cfm_measurement_element));

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest, 8,
		26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 8, 8, 8,
		0x7d8, 0x24, sizeof (struct cfm_measurement_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 8, 8, 8,
		0x7d8, 0x24, 0x24 - sizeof (struct cfm_measurement_element),
		sizeof (struct cfm_measurement_element));

	status = cfm.test.base.get_next_measurement (&cfm.test.base, "Component1", &pmr_measurement,
		true);
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_measurement (&cfm.test.base, &pmr_measurement);

	status = cfm.test.base.get_next_measurement (&cfm.test.base, "Component1", &pmr_measurement,
		false);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, pmr_measurement.pmr_id);
	CuAssertIntEquals (test, 2, pmr_measurement.measurement_id);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, pmr_measurement.digests.hash_len);
	CuAssertIntEquals (test, 1, pmr_measurement.digests.digest_count);

	status = testing_validate_array (MEASUREMENT_PMR_2_MEASUREMENT_2_DEVICE_1,
		pmr_measurement.digests.digests, sizeof (MEASUREMENT_PMR_2_MEASUREMENT_2_DEVICE_1));
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_measurement (&cfm.test.base, &pmr_measurement);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_no_more_measurements (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement pmr_measurement;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 7, 2, 7,
		0x794, 0x44, sizeof (struct cfm_measurement_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 7, 7, 7,
		0x794, 0x44, 0x44 - sizeof (struct cfm_measurement_element),
		sizeof (struct cfm_measurement_element));

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest, 8,
		26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 8, 8, 8,
		0x7d8, 0x24, sizeof (struct cfm_measurement_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 8, 8, 8,
		0x7d8, 0x24, 0x24 - sizeof (struct cfm_measurement_element),
		sizeof (struct cfm_measurement_element));

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest, 9,
		26);

	status = cfm.test.base.get_next_measurement (&cfm.test.base, "Component1", &pmr_measurement,
		true);
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_measurement (&cfm.test.base, &pmr_measurement);

	status = cfm.test.base.get_next_measurement (&cfm.test.base, "Component1", &pmr_measurement,
		false);
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_measurement (&cfm.test.base, &pmr_measurement);

	status = cfm.test.base.get_next_measurement (&cfm.test.base, "Component1", &pmr_measurement,
		false);
	CuAssertIntEquals (test, CFM_MEASUREMENT_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_second_component (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement pmr_measurement;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 26, 2,
		26, 0x8ce, 0x10, 0x10, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		27, 38);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 30, 27, 30,
		0x98a, 0x34, sizeof (struct cfm_measurement_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 30, 30, 30,
		0x98a, 0x34, 0x34 - sizeof (struct cfm_measurement_element),
		sizeof (struct cfm_measurement_element));

	status = cfm.test.base.get_next_measurement (&cfm.test.base, "Component2", &pmr_measurement,
		true);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, pmr_measurement.pmr_id);
	CuAssertIntEquals (test, 5, pmr_measurement.measurement_id);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, pmr_measurement.digests.hash_len);
	CuAssertIntEquals (test, 1, pmr_measurement.digests.digest_count);

	status = testing_validate_array (MEASUREMENT_PMR_1_MEASUREMENT_5_DEVICE_2,
		pmr_measurement.digests.digests, sizeof (MEASUREMENT_PMR_1_MEASUREMENT_5_DEVICE_2));
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_measurement (&cfm.test.base, &pmr_measurement);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_null (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement pmr_measurement;
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = cfm.test.base.get_next_measurement (NULL, "Component1", &pmr_measurement, true);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.get_next_measurement (&cfm.test.base, NULL, &pmr_measurement, true);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.get_next_measurement (&cfm.test.base, "Component1", NULL, true);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_verify_never_run (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement pmr_measurement;
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = cfm.test.base.get_next_measurement (&cfm.test.base, "Component1", &pmr_measurement,
		true);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_component_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement pmr_measurement;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x08));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement (&cfm.test.base, "Component1", &pmr_measurement,
		true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_component_not_found (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement pmr_measurement;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 26, 2,
		26, 0x8ce, 0x10, 0x10, 0);

	status = flash_mock_expect_verify_flash (&cfm.manifest.flash,
		cfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET,
		CFM_TESTING.manifest.raw + MANIFEST_V2_TOC_ENTRY_OFFSET, MANIFEST_V2_TOC_ENTRY_SIZE * 27);
	CuAssertIntEquals (test, 0, status);

	for (int i = 27; i < CFM_TESTING.manifest.toc_entries; ++i) {
		status |= mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
			&cfm.manifest.flash, 0,
			MOCK_ARG (cfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET +
				i * MANIFEST_V2_TOC_ENTRY_SIZE), MOCK_ARG_NOT_NULL,
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&cfm.manifest.flash.mock, 1,
			(struct manifest_toc_entry*) (CFM_TESTING.manifest.raw +
				MANIFEST_V2_TOC_ENTRY_OFFSET + MANIFEST_V2_TOC_ENTRY_SIZE * i),
				MANIFEST_V2_TOC_ENTRY_SIZE, 2);
	}
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement (&cfm.test.base, "Component3", &pmr_measurement,
		true);
	CuAssertIntEquals (test, MANIFEST_ELEMENT_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_component_has_no_measurements (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement pmr_measurement;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_ONLY_MEASUREMENT_DATA_TESTING,	0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_DATA_TESTING.manifest,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_entry, 0,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_hash,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_offset,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_len,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_DATA_TESTING.manifest, 2, 4);

	status = cfm.test.base.get_next_measurement (&cfm.test.base, "Component1", &pmr_measurement,
		true);
	CuAssertIntEquals (test, CFM_MEASUREMENT_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_get_num_measurements_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement pmr_measurement;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	status = flash_mock_expect_verify_flash (&cfm.manifest.flash, cfm.manifest.addr +
		MANIFEST_V2_TOC_ENTRY_OFFSET, CFM_TESTING.manifest.raw + MANIFEST_V2_TOC_ENTRY_OFFSET,
		MANIFEST_V2_TOC_ENTRY_SIZE * 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY,
		MOCK_ARG (cfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET +
			2 * MANIFEST_V2_TOC_ENTRY_SIZE), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement (&cfm.test.base, "Component1", &pmr_measurement,
		true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_measurement_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement pmr_measurement;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x10));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement (&cfm.test.base, "Component1", &pmr_measurement,
		true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_digests_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement pmr_measurement;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 7, 2, 7,
		0x794, 0x44, sizeof (struct cfm_measurement_element), 0);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x38));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement (&cfm.test.base, "Component1", &pmr_measurement,
		true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_free_measurement_null (CuTest *test)
{
	struct cfm_flash_testing cfm;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	cfm.test.base.free_measurement (&cfm.test.base, NULL);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_data (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_data measurement_data;
	struct cfm_allowable_data *allowable_data_ptr;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 9, 2, 9,
		0x7fc, 0x4, 0x4, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		10, 12);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 10, 10, 10,
		0x800, 0x1c, sizeof (struct cfm_allowable_data_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 10, 10, 10,
		0x800, 0x1c, 5, sizeof (struct cfm_allowable_data_element));
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 10, 10, 10,
		0x800, 0x1c, 10, sizeof (struct cfm_allowable_data_element) + 8);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 11, 11, 11,
		0x81c, 0x18, sizeof (struct cfm_allowable_data_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 11, 11, 11,
		0x81c, 0x18, 5, sizeof (struct cfm_allowable_data_element));
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 11, 11, 11,
		0x81c, 0x18, 5, sizeof (struct cfm_allowable_data_element) + 8);

	status = cfm.test.base.get_next_measurement_data (&cfm.test.base, "Component1",
		&measurement_data, true);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, measurement_data.pmr_id);
	CuAssertIntEquals (test, 2, measurement_data.measurement_id);
	CuAssertIntEquals (test, 2, measurement_data.check_count);

	allowable_data_ptr = measurement_data.check;

	CuAssertIntEquals (test, 0, allowable_data_ptr->check);
	CuAssertIntEquals (test, 5, allowable_data_ptr->data_len);
	CuAssertIntEquals (test, 2, allowable_data_ptr->data_count);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_2_DEVICE_1_BITMASK,
		allowable_data_ptr->bitmask, allowable_data_ptr->data_len);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_2_DEVICE_1,
		allowable_data_ptr->allowable_data,	allowable_data_ptr->data_len);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_2_DEVICE_1_2,
		allowable_data_ptr->allowable_data + allowable_data_ptr->data_len,
		allowable_data_ptr->data_len);

	allowable_data_ptr = &measurement_data.check[1];

	CuAssertIntEquals (test, 4, allowable_data_ptr->check);
	CuAssertIntEquals (test, 5, allowable_data_ptr->data_len);
	CuAssertIntEquals (test, 1, allowable_data_ptr->data_count);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_2_DEVICE_1_BITMASK_CHECK_2,
		allowable_data_ptr->bitmask, allowable_data_ptr->data_len);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_2_DEVICE_1_CHECK_2,
		allowable_data_ptr->allowable_data,	allowable_data_ptr->data_len);

	cfm.test.base.free_measurement_data (&cfm.test.base, &measurement_data);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_data_second_measurement_data (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_data measurement_data;
	struct cfm_allowable_data *allowable_data_ptr;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 9, 2, 9,
		0x7fc, 0x4, 0x4, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		10,	12);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 10, 10, 10,
		0x800, 0x1c, sizeof (struct cfm_allowable_data_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 10, 10, 10,
		0x800, 0x1c, 5, sizeof (struct cfm_allowable_data_element));
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 10, 10, 10,
		0x800, 0x1c, 10, sizeof (struct cfm_allowable_data_element) + 8);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 11, 11, 11,
		0x81c, 0x18, sizeof (struct cfm_allowable_data_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 11, 11, 11,
		0x81c, 0x18, 5, sizeof (struct cfm_allowable_data_element));
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 11, 11, 11,
		0x81c, 0x18, 5, sizeof (struct cfm_allowable_data_element) + 8);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		12,	26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 12, 12, 12,
		0x834, 0x4, 0x4, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		13,	15);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 13, 13, 13,
		0x838, 0x10, sizeof (struct cfm_allowable_data_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 13, 13, 13,
		0x838, 0x10, 2, sizeof (struct cfm_allowable_data_element));
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 13, 13, 13,
		0x838, 0x10, 2, sizeof (struct cfm_allowable_data_element) + 4);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 14, 14, 14,
		0x848, 0xc, sizeof (struct cfm_allowable_data_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 14, 14, 14,
		0x848, 0xc, 2, sizeof (struct cfm_allowable_data_element));

	status = cfm.test.base.get_next_measurement_data (&cfm.test.base, "Component1",
		&measurement_data, true);
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_measurement_data (&cfm.test.base, &measurement_data);

	status = cfm.test.base.get_next_measurement_data (&cfm.test.base, "Component1",
		&measurement_data, false);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, measurement_data.pmr_id);
	CuAssertIntEquals (test, 4, measurement_data.measurement_id);
	CuAssertIntEquals (test, 2, measurement_data.check_count);

	allowable_data_ptr = measurement_data.check;

	CuAssertIntEquals (test, 1, allowable_data_ptr->check);
	CuAssertIntEquals (test, 2, allowable_data_ptr->data_len);
	CuAssertIntEquals (test, 1, allowable_data_ptr->data_count);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_4_DEVICE_1_BITMASK,
		allowable_data_ptr->bitmask, allowable_data_ptr->data_len);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_4_DEVICE_1,
		allowable_data_ptr->allowable_data,	allowable_data_ptr->data_len);

	allowable_data_ptr = &measurement_data.check[1];

	CuAssertIntEquals (test, 1, allowable_data_ptr->check);
	CuAssertIntEquals (test, 2, allowable_data_ptr->data_len);
	CuAssertIntEquals (test, 1, allowable_data_ptr->data_count);
	CuAssertPtrEquals (test, NULL, (void*) allowable_data_ptr->bitmask);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_4_DEVICE_1_2,
		allowable_data_ptr->allowable_data,	allowable_data_ptr->data_len);

	cfm.test.base.free_measurement_data (&cfm.test.base, &measurement_data);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_data_no_more_measurement_data (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_data measurement_data;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 9, 2, 9,
		0x7fc, 0x4, 0x4, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		10,	12);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 10, 10, 10,
		0x800, 0x1c, sizeof (struct cfm_allowable_data_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 10, 10, 10,
		0x800, 0x1c, 5, sizeof (struct cfm_allowable_data_element));
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 10, 10, 10,
		0x800, 0x1c, 10, sizeof (struct cfm_allowable_data_element) + 8);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 11, 11, 11,
		0x81c, 0x18, sizeof (struct cfm_allowable_data_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 11, 11, 11,
		0x81c, 0x18, 5, sizeof (struct cfm_allowable_data_element));
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 11, 11, 11,
		0x81c, 0x18, 5, sizeof (struct cfm_allowable_data_element) + 8);
	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		12,	26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 12, 12, 12,
		0x834, 0x4, 0x4, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		13,	15);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 13, 13, 13,
		0x838, 0x10, sizeof (struct cfm_allowable_data_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 13, 13, 13,
		0x838, 0x10, 2, sizeof (struct cfm_allowable_data_element));
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 13, 13, 13,
		0x838, 0x10, 2, sizeof (struct cfm_allowable_data_element) + 4);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 14, 14, 14,
		0x848, 0xc, sizeof (struct cfm_allowable_data_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 14, 14, 14,
		0x848, 0xc, 2, sizeof (struct cfm_allowable_data_element));

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		15, 26);

	status = cfm.test.base.get_next_measurement_data (&cfm.test.base, "Component1",
		&measurement_data, true);
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_measurement_data (&cfm.test.base, &measurement_data);

	status = cfm.test.base.get_next_measurement_data (&cfm.test.base, "Component1",
		&measurement_data, false);
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_measurement_data (&cfm.test.base, &measurement_data);

	status = cfm.test.base.get_next_measurement_data (&cfm.test.base, "Component1",
		&measurement_data, false);
	CuAssertIntEquals (test, CFM_MEASUREMENT_DATA_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_data_second_component (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_data measurement_data;
	struct cfm_allowable_data *allowable_data_ptr;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 26, 2,
		26, 0x8ce, 0x10, 0x10, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		27, 38);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 31, 27, 31,
		0x9be, 0x4, 0x4, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		32,	33);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 32, 32, 32,
		0x9c2, 0x10, sizeof (struct cfm_allowable_data_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 32, 32, 32,
		0x9c2, 0x10, 3, sizeof (struct cfm_allowable_data_element));
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 32, 32, 32,
		0x9c2, 0x10, 3, sizeof (struct cfm_allowable_data_element) + 4);

	status = cfm.test.base.get_next_measurement_data (&cfm.test.base, "Component2",
		&measurement_data, true);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, measurement_data.pmr_id);
	CuAssertIntEquals (test, 3, measurement_data.measurement_id);
	CuAssertIntEquals (test, 1, measurement_data.check_count);

	allowable_data_ptr = measurement_data.check;

	CuAssertIntEquals (test, 4, allowable_data_ptr->check);
	CuAssertIntEquals (test, 3, allowable_data_ptr->data_len);
	CuAssertIntEquals (test, 1, allowable_data_ptr->data_count);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_3_DEVICE_2_BITMASK,
		allowable_data_ptr->bitmask, allowable_data_ptr->data_len);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_3_DEVICE_2,
		allowable_data_ptr->allowable_data, allowable_data_ptr->data_len);

	cfm.test.base.free_measurement_data (&cfm.test.base, &measurement_data);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_data_single_check (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_data measurement_data;
	struct cfm_allowable_data *allowable_data_ptr;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 26, 2,
		26, 0x8ce, 0x10, 0x10, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		27, 38);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 31, 27, 31,
		0x9be, 0x4, 0x4, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		32,	33);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 32, 32, 32,
		0x9c2, 0x10, sizeof (struct cfm_allowable_data_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 32, 32, 32,
		0x9c2, 0x10, 3, sizeof (struct cfm_allowable_data_element));
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 32, 32, 32,
		0x9c2, 0x10, 3, sizeof (struct cfm_allowable_data_element) + 4);

	status = cfm.test.base.get_next_measurement_data (&cfm.test.base, "Component2",
		&measurement_data, true);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, measurement_data.pmr_id);
	CuAssertIntEquals (test, 3, measurement_data.measurement_id);
	CuAssertIntEquals (test, 1, measurement_data.check_count);

	allowable_data_ptr = measurement_data.check;

	CuAssertIntEquals (test, 4, allowable_data_ptr->check);
	CuAssertIntEquals (test, 3, allowable_data_ptr->data_len);
	CuAssertIntEquals (test, 1, allowable_data_ptr->data_count);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_3_DEVICE_2_BITMASK,
		allowable_data_ptr->bitmask, allowable_data_ptr->data_len);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_3_DEVICE_2,
		allowable_data_ptr->allowable_data, allowable_data_ptr->data_len);

	cfm.test.base.free_measurement_data (&cfm.test.base, &measurement_data);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_data_single_allowable_data (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_data measurement_data;
	struct cfm_allowable_data *allowable_data_ptr;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 9, 2, 9,
		0x7fc, 0x4, 0x4, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		10,	12);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 10, 10, 10,
		0x800, 0x1c, sizeof (struct cfm_allowable_data_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 10, 10, 10,
		0x800, 0x1c, 5, sizeof (struct cfm_allowable_data_element));
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 10, 10, 10,
		0x800, 0x1c, 10, sizeof (struct cfm_allowable_data_element) + 8);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 11, 11, 11,
		0x81c, 0x18, sizeof (struct cfm_allowable_data_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 11, 11, 11,
		0x81c, 0x18, 5, sizeof (struct cfm_allowable_data_element));
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 11, 11, 11,
		0x81c, 0x18, 5, sizeof (struct cfm_allowable_data_element) + 8);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		12,	26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 12, 12, 12,
		0x834, 0x4, 0x4, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		13,	15);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 13, 13, 13,
		0x838, 0x10, sizeof (struct cfm_allowable_data_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 13, 13, 13,
		0x838, 0x10, 2, sizeof (struct cfm_allowable_data_element));
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 13, 13, 13,
		0x838, 0x10, 2, sizeof (struct cfm_allowable_data_element) + 4);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 14, 14, 14,
		0x848, 0xc, sizeof (struct cfm_allowable_data_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 14, 14, 14,
		0x848, 0xc, 2, sizeof (struct cfm_allowable_data_element));

	status = cfm.test.base.get_next_measurement_data (&cfm.test.base, "Component1",
		&measurement_data, true);
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_measurement_data (&cfm.test.base, &measurement_data);

	status = cfm.test.base.get_next_measurement_data (&cfm.test.base, "Component1",
		&measurement_data, false);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, measurement_data.pmr_id);
	CuAssertIntEquals (test, 4, measurement_data.measurement_id);
	CuAssertIntEquals (test, 2, measurement_data.check_count);

	allowable_data_ptr = measurement_data.check;

	CuAssertIntEquals (test, 1, allowable_data_ptr->check);
	CuAssertIntEquals (test, 2, allowable_data_ptr->data_len);
	CuAssertIntEquals (test, 1, allowable_data_ptr->data_count);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_4_DEVICE_1_BITMASK,
		allowable_data_ptr->bitmask, allowable_data_ptr->data_len);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_4_DEVICE_1,
		allowable_data_ptr->allowable_data,	allowable_data_ptr->data_len);

	allowable_data_ptr = &measurement_data.check[1];

	CuAssertIntEquals (test, 1, allowable_data_ptr->check);
	CuAssertIntEquals (test, 2, allowable_data_ptr->data_len);
	CuAssertIntEquals (test, 1, allowable_data_ptr->data_count);
	CuAssertPtrEquals (test, NULL, (void*) allowable_data_ptr->bitmask);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_4_DEVICE_1_2,
		allowable_data_ptr->allowable_data,	allowable_data_ptr->data_len);

	cfm.test.base.free_measurement_data (&cfm.test.base, &measurement_data);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_data_no_bitmask (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_data measurement_data;
	struct cfm_allowable_data *allowable_data_ptr;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 9, 2, 9,
		0x7fc, 0x4, 0x4, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		10,	12);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 10, 10, 10,
		0x800, 0x1c, sizeof (struct cfm_allowable_data_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 10, 10, 10,
		0x800, 0x1c, 5, sizeof (struct cfm_allowable_data_element));
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 10, 10, 10,
		0x800, 0x1c, 10, sizeof (struct cfm_allowable_data_element) + 8);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 11, 11, 11,
		0x81c, 0x18, sizeof (struct cfm_allowable_data_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 11, 11, 11,
		0x81c, 0x18, 5, sizeof (struct cfm_allowable_data_element));
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 11, 11, 11,
		0x81c, 0x18, 5, sizeof (struct cfm_allowable_data_element) + 8);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		12,	26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 12, 12, 12,
		0x834, 0x4, 0x4, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		13,	15);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 13, 13, 13,
		0x838, 0x10, sizeof (struct cfm_allowable_data_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 13, 13, 13,
		0x838, 0x10, 2, sizeof (struct cfm_allowable_data_element));
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 13, 13, 13,
		0x838, 0x10, 2, sizeof (struct cfm_allowable_data_element) + 4);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 14, 14, 14,
		0x848, 0xc, sizeof (struct cfm_allowable_data_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 14, 14, 14,
		0x848, 0xc, 2, sizeof (struct cfm_allowable_data_element));

	status = cfm.test.base.get_next_measurement_data (&cfm.test.base, "Component1",
		&measurement_data, true);
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_measurement_data (&cfm.test.base, &measurement_data);

	status = cfm.test.base.get_next_measurement_data (&cfm.test.base, "Component1",
		&measurement_data, false);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, measurement_data.pmr_id);
	CuAssertIntEquals (test, 4, measurement_data.measurement_id);
	CuAssertIntEquals (test, 2, measurement_data.check_count);

	allowable_data_ptr = measurement_data.check;

	CuAssertIntEquals (test, 1, allowable_data_ptr->check);
	CuAssertIntEquals (test, 2, allowable_data_ptr->data_len);
	CuAssertIntEquals (test, 1, allowable_data_ptr->data_count);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_4_DEVICE_1_BITMASK,
		allowable_data_ptr->bitmask, allowable_data_ptr->data_len);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_4_DEVICE_1,
		allowable_data_ptr->allowable_data,	allowable_data_ptr->data_len);

	allowable_data_ptr = &measurement_data.check[1];

	CuAssertIntEquals (test, 1, allowable_data_ptr->check);
	CuAssertIntEquals (test, 2, allowable_data_ptr->data_len);
	CuAssertIntEquals (test, 1, allowable_data_ptr->data_count);
	CuAssertPtrEquals (test, NULL, (void*) allowable_data_ptr->bitmask);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_4_DEVICE_1_2,
		allowable_data_ptr->allowable_data,	allowable_data_ptr->data_len);

	cfm.test.base.free_measurement_data (&cfm.test.base, &measurement_data);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_data_null (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_data measurement_data;
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = cfm.test.base.get_next_measurement_data (NULL, "Component1", &measurement_data, true);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.get_next_measurement_data (&cfm.test.base, NULL, &measurement_data,
		true);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.get_next_measurement_data (&cfm.test.base, "Component1", NULL, true);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_data_verify_never_run (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_data measurement_data;
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = cfm.test.base.get_next_measurement_data (&cfm.test.base, "Component1",
		&measurement_data, true);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_data_component_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_data measurement_data;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x08));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_data (&cfm.test.base, "Component1",
		&measurement_data, true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_data_component_not_found (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_data measurement_data;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 26, 2,
		26, 0x8ce, 0x10, 0x10, 0);

	status = flash_mock_expect_verify_flash (&cfm.manifest.flash,
		cfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET,
		CFM_TESTING.manifest.raw + MANIFEST_V2_TOC_ENTRY_OFFSET, MANIFEST_V2_TOC_ENTRY_SIZE * 27);
	CuAssertIntEquals (test, 0, status);

	for (int i = 27; i < CFM_TESTING.manifest.toc_entries; ++i) {
		status |= mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
			&cfm.manifest.flash, 0,
			MOCK_ARG (cfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET +
				i * MANIFEST_V2_TOC_ENTRY_SIZE), MOCK_ARG_NOT_NULL,
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&cfm.manifest.flash.mock, 1,
			(struct manifest_toc_entry*) (CFM_TESTING.manifest.raw +
				MANIFEST_V2_TOC_ENTRY_OFFSET + MANIFEST_V2_TOC_ENTRY_SIZE * i),
				MANIFEST_V2_TOC_ENTRY_SIZE, 2);
	}
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_data (&cfm.test.base, "Component3",
		&measurement_data, true);
	CuAssertIntEquals (test, MANIFEST_ELEMENT_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_data_component_has_no_measurement_data (
	CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_data measurement_data;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_ONLY_MEASUREMENT_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_TESTING.manifest,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_entry, 0,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_hash,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_offset,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_len,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_TESTING.manifest, 2, 2);

	status = cfm.test.base.get_next_measurement_data (&cfm.test.base, "Component1",
		&measurement_data, true);
	CuAssertIntEquals (test, CFM_MEASUREMENT_DATA_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_data_get_num_measurement_data_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_data measurement_data;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	status = flash_mock_expect_verify_flash (&cfm.manifest.flash, cfm.manifest.addr +
		MANIFEST_V2_TOC_ENTRY_OFFSET, CFM_TESTING.manifest.raw + MANIFEST_V2_TOC_ENTRY_OFFSET,
		MANIFEST_V2_TOC_ENTRY_SIZE * 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY,
		MOCK_ARG (cfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET +
			2 * MANIFEST_V2_TOC_ENTRY_SIZE), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_data (&cfm.test.base, "Component1",
		&measurement_data, true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_data_measurement_data_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_data measurement_data;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x10));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_data (&cfm.test.base, "Component1",
		&measurement_data, true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_data_get_num_allowable_data_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_data measurement_data;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 9, 2, 9,
		0x7fc, 0x4, 0x4, 0);

	status = flash_mock_expect_verify_flash (&cfm.manifest.flash, cfm.manifest.addr +
		MANIFEST_V2_TOC_ENTRY_OFFSET, CFM_TESTING.manifest.raw + MANIFEST_V2_TOC_ENTRY_OFFSET,
		MANIFEST_V2_TOC_ENTRY_SIZE * 10);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY,
		MOCK_ARG (cfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET +
			10 * MANIFEST_V2_TOC_ENTRY_SIZE), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_data (&cfm.test.base, "Component1",
		&measurement_data, true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_data_allowable_data_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_data measurement_data;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 9, 2, 9,
		0x7fc, 0x4, 0x4, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		10, 12);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x50));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_data (&cfm.test.base, "Component1",
		&measurement_data, true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_data_bitmask_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_data measurement_data;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 9, 2, 9,
		0x7fc, 0x4, 0x4, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		10, 12);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 10, 10, 10,
		0x800, 0x1c, sizeof (struct cfm_allowable_data_element), 0);
	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x50));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_data (&cfm.test.base, "Component1",
		&measurement_data, true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_data_allowable_data_buffer_read_fail (
	CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_data measurement_data;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 9, 2, 9,
		0x7fc, 0x4, 0x4, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		10, 12);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 10, 10, 10,
		0x800, 0x1c, sizeof (struct cfm_allowable_data_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 10, 10, 10,
		0x800, 0x1c, 5, sizeof (struct cfm_allowable_data_element));
	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x50));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_data (&cfm.test.base, "Component1",
		&measurement_data, true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_free_measurement_data_null (CuTest *test)
{
	struct cfm_flash_testing cfm;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	cfm.test.base.free_measurement_data (&cfm.test.base, NULL);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_root_ca_digest (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_root_ca_digests root_ca_digest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 2, 2, 2,
		0x660, 0x44, sizeof (struct cfm_root_ca_digests_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 2, 2, 2,
		0x660, 0x44, 0x44 - sizeof (struct cfm_root_ca_digests_element),
		sizeof (struct cfm_root_ca_digests_element));

	status = cfm.test.base.get_root_ca_digest (&cfm.test.base, "Component1", &root_ca_digest);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, root_ca_digest.digests.hash_len);
	CuAssertIntEquals (test, 2, root_ca_digest.digests.digest_count);

	status = testing_validate_array (ROOT_CA_DIGEST_0_DEVICE_1, root_ca_digest.digests.digests,
		sizeof (ROOT_CA_DIGEST_0_DEVICE_1));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ROOT_CA_DIGEST_1_DEVICE_1,
		root_ca_digest.digests.digests + SHA256_HASH_LENGTH, sizeof (ROOT_CA_DIGEST_1_DEVICE_1));
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_root_ca_digest (&cfm.test.base, &root_ca_digest);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_root_ca_digest_second_component (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_root_ca_digests root_ca_digest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 26, 2, 26,
		0x8ce, 0x10, 0x10, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		27, 38);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 27, 27, 27,
		0x8de, 0x34, sizeof (struct cfm_root_ca_digests_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 27, 27, 27,
		0x8de, 0x34, 0x34 - sizeof (struct cfm_root_ca_digests_element),
		sizeof (struct cfm_root_ca_digests_element));

	status = cfm.test.base.get_root_ca_digest (&cfm.test.base, "Component2", &root_ca_digest);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, root_ca_digest.digests.hash_len);
	CuAssertIntEquals (test, 1, root_ca_digest.digests.digest_count);

	status = testing_validate_array (ROOT_CA_DIGEST_DEVICE_2, root_ca_digest.digests.digests,
		sizeof (ROOT_CA_DIGEST_DEVICE_2));
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_root_ca_digest (&cfm.test.base, &root_ca_digest);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_root_ca_digest_null (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_root_ca_digests root_ca_digest;
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = cfm.test.base.get_root_ca_digest (NULL, "Component1", &root_ca_digest);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.get_root_ca_digest (&cfm.test.base, NULL, &root_ca_digest);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.get_root_ca_digest (&cfm.test.base, "Component1", NULL);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_root_ca_digest_verify_never_run (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_root_ca_digests root_ca_digest;
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = cfm.test.base.get_root_ca_digest (&cfm.test.base, "Component1", &root_ca_digest);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_root_ca_digest_component_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_root_ca_digests root_ca_digest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x08));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_root_ca_digest (&cfm.test.base, "Component1", &root_ca_digest);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_root_ca_digest_component_not_found (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_root_ca_digests root_ca_digest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 26, 2, 26,
		0x8ce, 0x10, 0x10, 0);

	status = flash_mock_expect_verify_flash (&cfm.manifest.flash,
		cfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET,
		CFM_TESTING.manifest.raw + MANIFEST_V2_TOC_ENTRY_OFFSET, MANIFEST_V2_TOC_ENTRY_SIZE * 27);
	CuAssertIntEquals (test, 0, status);

	for (int i = 27; i < CFM_TESTING.manifest.toc_entries; ++i) {
		status |= mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
			&cfm.manifest.flash, 0,
			MOCK_ARG (cfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET +
				i * MANIFEST_V2_TOC_ENTRY_SIZE), MOCK_ARG_NOT_NULL,
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&cfm.manifest.flash.mock, 1,
			(struct manifest_toc_entry*) (CFM_TESTING.manifest.raw +
				MANIFEST_V2_TOC_ENTRY_OFFSET + MANIFEST_V2_TOC_ENTRY_SIZE * i),
				MANIFEST_V2_TOC_ENTRY_SIZE, 2);
	}
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_root_ca_digest (&cfm.test.base, "Component3", &root_ca_digest);
	CuAssertIntEquals (test, MANIFEST_ELEMENT_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_root_ca_digest_component_has_no_root_ca_digest (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_root_ca_digests root_ca_digest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_ONLY_MEASUREMENT_DATA_TESTING,	0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_DATA_TESTING.manifest,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_entry, 0,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_hash,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_offset,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_len,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_DATA_TESTING.manifest, 2, 4);

	status = cfm.test.base.get_root_ca_digest (&cfm.test.base, "Component1", &root_ca_digest);
	CuAssertIntEquals (test, CFM_ROOT_CA_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_root_ca_digest_component_get_num_root_ca_digest_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_root_ca_digests root_ca_digest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	status = flash_mock_expect_verify_flash (&cfm.manifest.flash, cfm.manifest.addr +
		MANIFEST_V2_TOC_ENTRY_OFFSET, CFM_TESTING.manifest.raw + MANIFEST_V2_TOC_ENTRY_OFFSET,
		MANIFEST_V2_TOC_ENTRY_SIZE * 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY,
		MOCK_ARG (cfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET +
			2 * MANIFEST_V2_TOC_ENTRY_SIZE), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_root_ca_digest (&cfm.test.base, "Component1", &root_ca_digest);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_root_ca_digest_root_ca_digest_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_root_ca_digests root_ca_digest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x10));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_root_ca_digest (&cfm.test.base, "Component1", &root_ca_digest);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_root_ca_digest_digests_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_root_ca_digests root_ca_digest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 2, 2, 2,
		0x660, 0x44, sizeof (struct cfm_root_ca_digests_element), 0);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x10));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_root_ca_digest (&cfm.test.base, "Component1", &root_ca_digest);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_free_root_ca_digest_null (CuTest *test)
{
	struct cfm_flash_testing cfm;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	cfm.test.base.free_root_ca_digest (&cfm.test.base, NULL);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_pfm (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	struct cfm_allowable_id *manifest_check_ptr;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 15, 2, 15,
		0x854, 0xe, 0xe, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		16, 18);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 16, 16, 16,
		0x862, 0xc, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 16, 16, 16,
		0x862, 0xc, 0xc - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 17, 17, 17,
		0x86e, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 17, 17, 17,
		0x86e, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	status = cfm.test.base.get_next_pfm (&cfm.test.base, "Component1", &manifest, true);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, manifest.manifest_index);
	CuAssertIntEquals (test, 2, manifest.check_count);
	CuAssertStrEquals (test, CFM_ALLOWABLE_PFM_1_PLATFORM_ID_DEVICE_1, manifest.platform_id);

	CuAssertIntEquals (test, 0, manifest.check->check);
	CuAssertIntEquals (test, 2, manifest.check->id_count);
	CuAssertIntEquals (test, CFM_ALLOWABLE_PFM_1_ALLOWABLE_ID_1_DEVICE_1,
		manifest.check->allowable_id[0]);
	CuAssertIntEquals (test, CFM_ALLOWABLE_PFM_1_ALLOWABLE_ID_1_DEVICE_1_2,
		manifest.check->allowable_id[1]);

	manifest_check_ptr = &manifest.check[1];

	CuAssertIntEquals (test, 4, manifest_check_ptr->check);
	CuAssertIntEquals (test, 1, manifest_check_ptr->id_count);
	CuAssertIntEquals (test, CFM_ALLOWABLE_PFM_1_ALLOWABLE_ID_2_DEVICE_1,
		manifest_check_ptr->allowable_id[0]);

	cfm.test.base.free_manifest (&cfm.test.base, &manifest);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_pfm_second_pfm (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 15, 2, 15,
		0x854, 0xe, 0xe, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		16, 18);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 16, 16, 16,
		0x862, 0xc, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 16, 16, 16,
		0x862, 0xc, 0xc - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 17, 17, 17,
		0x86e, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 17, 17, 17,
		0x86e, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		18, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 18, 18, 18,
		0x876, 0xe, 0xe, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		19, 20);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 19, 19, 19,
		0x884, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 19, 19, 19,
		0x884, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	status = cfm.test.base.get_next_pfm (&cfm.test.base, "Component1", &manifest, true);
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_manifest (&cfm.test.base, &manifest);

	status = cfm.test.base.get_next_pfm (&cfm.test.base, "Component1", &manifest, false);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, manifest.manifest_index);
	CuAssertIntEquals (test, 1, manifest.check_count);
	CuAssertStrEquals (test, CFM_ALLOWABLE_PFM_2_PLATFORM_ID_DEVICE_1, manifest.platform_id);

	CuAssertIntEquals (test, 3, manifest.check->check);
	CuAssertIntEquals (test, 1, manifest.check->id_count);
	CuAssertIntEquals (test, CFM_ALLOWABLE_PFM_2_ALLOWABLE_ID_DEVICE_1,
		manifest.check->allowable_id[0]);

	cfm.test.base.free_manifest (&cfm.test.base, &manifest);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_pfm_no_more_pfm (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 15, 2, 15,
		0x854, 0xe, 0xe, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		16, 18);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 16, 16, 16,
		0x862, 0xc, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 16, 16, 16,
		0x862, 0xc, 0xc - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 17, 17, 17,
		0x86e, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 17, 17, 17,
		0x86e, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		18, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 18, 18, 18,
		0x876, 0xe, 0xe, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		19, 20);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 19, 19, 19,
		0x884, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 19, 19, 19,
		0x884, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		20, 26);

	status = cfm.test.base.get_next_pfm (&cfm.test.base, "Component1", &manifest, true);
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_manifest (&cfm.test.base, &manifest);

	status = cfm.test.base.get_next_pfm (&cfm.test.base, "Component1", &manifest, false);
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_manifest (&cfm.test.base, &manifest);

	status = cfm.test.base.get_next_pfm (&cfm.test.base, "Component1", &manifest, false);
	CuAssertIntEquals (test, CFM_ELEMENT_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_pfm_second_component (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 26, 2, 26,
		0x8ce, 0x10, 0x10, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		27, 38);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 33, 27, 33,
		0x9d2, 0xe, 0xe, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		34, 35);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 34, 34, 34,
		0x9e0, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 34, 34, 34,
		0x9e0, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	status = cfm.test.base.get_next_pfm (&cfm.test.base, "Component2", &manifest, true);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, manifest.manifest_index);
	CuAssertIntEquals (test, 1, manifest.check_count);
	CuAssertStrEquals (test, CFM_ALLOWABLE_PFM_2_PLATFORM_ID_DEVICE_2, manifest.platform_id);

	CuAssertIntEquals (test, 5, manifest.check->check);
	CuAssertIntEquals (test, 1, manifest.check->id_count);
	CuAssertIntEquals (test, CFM_ALLOWABLE_PFM_2_ALLOWABLE_ID_DEVICE_2,
		manifest.check->allowable_id[0]);

	cfm.test.base.free_manifest (&cfm.test.base, &manifest);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_pfm_single_check (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 26, 2, 26,
		0x8ce, 0x10, 0x10, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		27, 38);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 33, 27, 33,
		0x9d2, 0xe, 0xe, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		34, 35);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 34, 34, 34,
		0x9e0, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 34, 34, 34,
		0x9e0, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	status = cfm.test.base.get_next_pfm (&cfm.test.base, "Component2", &manifest, true);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, manifest.manifest_index);
	CuAssertIntEquals (test, 1, manifest.check_count);
	CuAssertStrEquals (test, CFM_ALLOWABLE_PFM_2_PLATFORM_ID_DEVICE_2, manifest.platform_id);

	CuAssertIntEquals (test, 5, manifest.check->check);
	CuAssertIntEquals (test, 1, manifest.check->id_count);
	CuAssertIntEquals (test, CFM_ALLOWABLE_PFM_2_ALLOWABLE_ID_DEVICE_2,
		manifest.check->allowable_id[0]);

	cfm.test.base.free_manifest (&cfm.test.base, &manifest);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_pfm_single_id (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 26, 2, 26,
		0x8ce, 0x10, 0x10, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		27, 38);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 33, 27, 33,
		0x9d2, 0xe, 0xe, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		34, 35);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 34, 34, 34,
		0x9e0, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 34, 34, 34,
		0x9e0, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	status = cfm.test.base.get_next_pfm (&cfm.test.base, "Component2", &manifest, true);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, manifest.manifest_index);
	CuAssertIntEquals (test, 1, manifest.check_count);
	CuAssertStrEquals (test, CFM_ALLOWABLE_PFM_2_PLATFORM_ID_DEVICE_2, manifest.platform_id);

	CuAssertIntEquals (test, 5, manifest.check->check);
	CuAssertIntEquals (test, 1, manifest.check->id_count);
	CuAssertIntEquals (test, CFM_ALLOWABLE_PFM_2_ALLOWABLE_ID_DEVICE_2,
		manifest.check->allowable_id[0]);

	cfm.test.base.free_manifest (&cfm.test.base, &manifest);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_pfm_null (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	status = cfm.test.base.get_next_pfm (NULL, "Component2", &manifest, true);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.get_next_pfm (&cfm.test.base, NULL, &manifest, true);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.get_next_pfm (&cfm.test.base, "Component2", NULL, true);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_pfm_verify_never_run (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = cfm.test.base.get_next_pfm (&cfm.test.base, "Component1", &manifest, true);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_pfm_component_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x08));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_pfm (&cfm.test.base, "Component1", &manifest, true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_pfm_component_not_found (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 26, 2,
		26, 0x8ce, 0x10, 0x10, 0);

	status = flash_mock_expect_verify_flash (&cfm.manifest.flash,
		cfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET,
		CFM_TESTING.manifest.raw + MANIFEST_V2_TOC_ENTRY_OFFSET, MANIFEST_V2_TOC_ENTRY_SIZE * 27);
	CuAssertIntEquals (test, 0, status);

	for (int i = 27; i < CFM_TESTING.manifest.toc_entries; ++i) {
		status |= mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
			&cfm.manifest.flash, 0,
			MOCK_ARG (cfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET +
				i * MANIFEST_V2_TOC_ENTRY_SIZE), MOCK_ARG_NOT_NULL,
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&cfm.manifest.flash.mock, 1,
			(struct manifest_toc_entry*) (CFM_TESTING.manifest.raw +
				MANIFEST_V2_TOC_ENTRY_OFFSET + MANIFEST_V2_TOC_ENTRY_SIZE * i),
				MANIFEST_V2_TOC_ENTRY_SIZE, 2);
	}
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_pfm (&cfm.test.base, "Component3", &manifest, true);
	CuAssertIntEquals (test, MANIFEST_ELEMENT_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_pfm_component_has_no_allowable_pfm (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_ONLY_MEASUREMENT_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_TESTING.manifest,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_entry, 0,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_hash,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_offset,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_len,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_TESTING.manifest, 2, 2);

	status = cfm.test.base.get_next_pfm (&cfm.test.base, "Component1", &manifest, true);
	CuAssertIntEquals (test, CFM_ELEMENT_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_pfm_get_num_allowable_pfm_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	status = flash_mock_expect_verify_flash (&cfm.manifest.flash, cfm.manifest.addr +
		MANIFEST_V2_TOC_ENTRY_OFFSET, CFM_TESTING.manifest.raw + MANIFEST_V2_TOC_ENTRY_OFFSET,
		MANIFEST_V2_TOC_ENTRY_SIZE * 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY,
		MOCK_ARG (cfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET +
			2 * MANIFEST_V2_TOC_ENTRY_SIZE), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_pfm (&cfm.test.base, "Component1", &manifest, true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_pfm_allowable_pfm_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x10));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_pfm (&cfm.test.base, "Component1", &manifest, true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_pfm_get_num_allowable_id_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 15, 2, 15,
		0x854, 0xe, 0xe, 0);

	status = flash_mock_expect_verify_flash (&cfm.manifest.flash, cfm.manifest.addr +
		MANIFEST_V2_TOC_ENTRY_OFFSET, CFM_TESTING.manifest.raw + MANIFEST_V2_TOC_ENTRY_OFFSET,
		MANIFEST_V2_TOC_ENTRY_SIZE * 16);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY,
		MOCK_ARG (cfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET +
			16 * MANIFEST_V2_TOC_ENTRY_SIZE), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_pfm (&cfm.test.base, "Component1", &manifest, true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_pfm_allowable_id_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 15, 2, 15,
		0x854, 0xe, 0xe, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		16, 18);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x80));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_pfm (&cfm.test.base, "Component1", &manifest, true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_pfm_allowable_id_ids_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 15, 2, 15,
		0x854, 0xe, 0xe, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		16, 18);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 16, 16, 16,
		0x862, 0xc, sizeof (struct cfm_allowable_id_element), 0);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x80));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_pfm (&cfm.test.base, "Component1", &manifest, true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_cfm (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 20, 2, 20,
		0x88c, 0xe, 0xe, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		21, 22);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 21, 21, 21,
		0x89a, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 21, 21, 21,
		0x89a, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	status = cfm.test.base.get_next_cfm (&cfm.test.base, "Component1", &manifest, true);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, manifest.manifest_index);
	CuAssertIntEquals (test, 1, manifest.check_count);
	CuAssertStrEquals (test, CFM_ALLOWABLE_CFM_1_PLATFORM_ID_DEVICE_1, manifest.platform_id);

	CuAssertIntEquals (test, 4, manifest.check->check);
	CuAssertIntEquals (test, 1, manifest.check->id_count);
	CuAssertIntEquals (test, CFM_ALLOWABLE_CFM_1_ALLOWABLE_ID_DEVICE_1,
		manifest.check->allowable_id[0]);

	cfm.test.base.free_manifest (&cfm.test.base, &manifest);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_cfm_second_cfm (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 20, 2, 20,
		0x88c, 0xe, 0xe, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		21, 22);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 21, 21, 21,
		0x89a, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 21, 21, 21,
		0x89a, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		22, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 22, 22, 22,
		0x8a2, 0xe, 0xe, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		23, 24);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 23, 23, 23,
		0x8b0, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 23, 23, 23,
		0x8b0, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	status = cfm.test.base.get_next_cfm (&cfm.test.base, "Component1", &manifest, true);
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_manifest (&cfm.test.base, &manifest);

	status = cfm.test.base.get_next_cfm (&cfm.test.base, "Component1", &manifest, false);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, manifest.manifest_index);
	CuAssertIntEquals (test, 1, manifest.check_count);
	CuAssertStrEquals (test, CFM_ALLOWABLE_CFM_2_PLATFORM_ID_DEVICE_1, manifest.platform_id);

	CuAssertIntEquals (test, 0, manifest.check->check);
	CuAssertIntEquals (test, 1, manifest.check->id_count);
	CuAssertIntEquals (test, CFM_ALLOWABLE_CFM_2_ALLOWABLE_ID_DEVICE_2,
		manifest.check->allowable_id[0]);

	cfm.test.base.free_manifest (&cfm.test.base, &manifest);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_cfm_no_more_cfm (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 20, 2, 20,
		0x88c, 0xe, 0xe, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		21, 22);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 21, 21, 21,
		0x89a, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 21, 21, 21,
		0x89a, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		22, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 22, 22, 22,
		0x8a2, 0xe, 0xe, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		23, 24);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 23, 23, 23,
		0x8b0, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 23, 23, 23,
		0x8b0, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		24, 26);

	status = cfm.test.base.get_next_cfm (&cfm.test.base, "Component1", &manifest, true);
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_manifest (&cfm.test.base, &manifest);

	status = cfm.test.base.get_next_cfm (&cfm.test.base, "Component1", &manifest, false);
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_manifest (&cfm.test.base, &manifest);

	status = cfm.test.base.get_next_cfm (&cfm.test.base, "Component1", &manifest, false);
	CuAssertIntEquals (test, CFM_ELEMENT_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_cfm_second_component (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 26, 2, 26,
		0x8ce, 0x10, 0x10, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		27, 38);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 35, 27, 35,
		0x9e8, 0xe, 0xe, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		36, 37);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 36, 36, 36,
		0x9f6, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 36, 36, 36,
		0x9f6, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	status = cfm.test.base.get_next_cfm (&cfm.test.base, "Component2", &manifest, true);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, manifest.manifest_index);
	CuAssertIntEquals (test, 1, manifest.check_count);
	CuAssertStrEquals (test, CFM_ALLOWABLE_CFM_0_PLATFORM_ID_DEVICE_2, manifest.platform_id);

	CuAssertIntEquals (test, 3, manifest.check->check);
	CuAssertIntEquals (test, 1, manifest.check->id_count);
	CuAssertIntEquals (test, CFM_ALLOWABLE_CFM_0_ALLOWABLE_ID_DEVICE_2,
		manifest.check->allowable_id[0]);

	cfm.test.base.free_manifest (&cfm.test.base, &manifest);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_cfm_single_check (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 26, 2, 26,
		0x8ce, 0x10, 0x10, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		27, 38);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 35, 27, 35,
		0x9e8, 0xe, 0xe, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		36, 37);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 36, 36, 36,
		0x9f6, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 36, 36, 36,
		0x9f6, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	status = cfm.test.base.get_next_cfm (&cfm.test.base, "Component2", &manifest, true);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, manifest.manifest_index);
	CuAssertIntEquals (test, 1, manifest.check_count);
	CuAssertStrEquals (test, CFM_ALLOWABLE_CFM_0_PLATFORM_ID_DEVICE_2, manifest.platform_id);

	CuAssertIntEquals (test, 3, manifest.check->check);
	CuAssertIntEquals (test, 1, manifest.check->id_count);
	CuAssertIntEquals (test, CFM_ALLOWABLE_CFM_0_ALLOWABLE_ID_DEVICE_2,
		manifest.check->allowable_id[0]);

	cfm.test.base.free_manifest (&cfm.test.base, &manifest);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_cfm_single_id (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 26, 2, 26,
		0x8ce, 0x10, 0x10, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		27, 38);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 35, 27, 35,
		0x9e8, 0xe, 0xe, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		36, 37);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 36, 36, 36,
		0x9f6, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 36, 36, 36,
		0x9f6, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	status = cfm.test.base.get_next_cfm (&cfm.test.base, "Component2", &manifest, true);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, manifest.manifest_index);
	CuAssertIntEquals (test, 1, manifest.check_count);
	CuAssertStrEquals (test, CFM_ALLOWABLE_CFM_0_PLATFORM_ID_DEVICE_2, manifest.platform_id);

	CuAssertIntEquals (test, 3, manifest.check->check);
	CuAssertIntEquals (test, 1, manifest.check->id_count);
	CuAssertIntEquals (test, CFM_ALLOWABLE_CFM_0_ALLOWABLE_ID_DEVICE_2,
		manifest.check->allowable_id[0]);

	cfm.test.base.free_manifest (&cfm.test.base, &manifest);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_cfm_null (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	status = cfm.test.base.get_next_cfm (NULL, "Component2", &manifest, true);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.get_next_cfm (&cfm.test.base, NULL, &manifest, true);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.get_next_cfm (&cfm.test.base, "Component2", NULL, true);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_cfm_verify_never_run (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = cfm.test.base.get_next_cfm (&cfm.test.base, "Component1", &manifest, true);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_cfm_component_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x08));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_cfm (&cfm.test.base, "Component1", &manifest, true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_cfm_component_not_found (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 26, 2, 26,
		0x8ce, 0x10, 0x10, 0);

	status = flash_mock_expect_verify_flash (&cfm.manifest.flash,
		cfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET,
		CFM_TESTING.manifest.raw + MANIFEST_V2_TOC_ENTRY_OFFSET, MANIFEST_V2_TOC_ENTRY_SIZE * 27);
	CuAssertIntEquals (test, 0, status);

	for (int i = 27; i < CFM_TESTING.manifest.toc_entries; ++i) {
		status |= mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
			&cfm.manifest.flash, 0,
			MOCK_ARG (cfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET +
				i * MANIFEST_V2_TOC_ENTRY_SIZE), MOCK_ARG_NOT_NULL,
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&cfm.manifest.flash.mock, 1,
			(struct manifest_toc_entry*) (CFM_TESTING.manifest.raw +
				MANIFEST_V2_TOC_ENTRY_OFFSET + MANIFEST_V2_TOC_ENTRY_SIZE * i),
				MANIFEST_V2_TOC_ENTRY_SIZE, 2);
	}
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_cfm (&cfm.test.base, "Component3", &manifest, true);
	CuAssertIntEquals (test, MANIFEST_ELEMENT_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_cfm_component_has_no_allowable_cfm (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_ONLY_MEASUREMENT_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_TESTING.manifest,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_entry, 0,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_hash,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_offset,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_len,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_TESTING.manifest, 2, 2);

	status = cfm.test.base.get_next_cfm (&cfm.test.base, "Component1", &manifest, true);
	CuAssertIntEquals (test, CFM_ELEMENT_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_cfm_get_num_allowable_cfm_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	status = flash_mock_expect_verify_flash (&cfm.manifest.flash, cfm.manifest.addr +
		MANIFEST_V2_TOC_ENTRY_OFFSET, CFM_TESTING.manifest.raw + MANIFEST_V2_TOC_ENTRY_OFFSET,
		MANIFEST_V2_TOC_ENTRY_SIZE * 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY,
		MOCK_ARG (cfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET +
			2 * MANIFEST_V2_TOC_ENTRY_SIZE), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_cfm (&cfm.test.base, "Component1", &manifest, true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_cfm_allowable_cfm_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x10));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_cfm (&cfm.test.base, "Component1", &manifest, true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_cfm_get_num_allowable_id_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 20, 2, 20,
		0x88c, 0xe, 0xe, 0);

	status = flash_mock_expect_verify_flash (&cfm.manifest.flash, cfm.manifest.addr +
		MANIFEST_V2_TOC_ENTRY_OFFSET, CFM_TESTING.manifest.raw + MANIFEST_V2_TOC_ENTRY_OFFSET,
		MANIFEST_V2_TOC_ENTRY_SIZE * 21);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY,
		MOCK_ARG (cfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET +
			21 * MANIFEST_V2_TOC_ENTRY_SIZE), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_cfm (&cfm.test.base, "Component1", &manifest, true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_cfm_allowable_id_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 20, 2, 20,
		0x88c, 0xe, 0xe, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		21, 22);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0xa8));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_cfm (&cfm.test.base, "Component1", &manifest, true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_cfm_allowable_id_ids_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 20, 2, 20,
		0x88c, 0xe, 0xe, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		21, 22);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 21, 21, 21,
		0x89a, 0x8, sizeof (struct cfm_allowable_id_element), 0);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0xa8));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_cfm (&cfm.test.base, "Component1", &manifest, true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_pcd (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 24, 2, 24,
		0x8b8, 0xe, 0xe, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		25, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 25, 25, 25,
		0x8c6, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 25, 25, 25,
		0x8c6, 0x8, 0x8 -sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	status = cfm.test.base.get_pcd (&cfm.test.base, "Component1", &manifest);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, manifest.manifest_index);
	CuAssertIntEquals (test, 1, manifest.check_count);
	CuAssertStrEquals (test, CFM_ALLOWABLE_PCD_PLATFORM_ID_DEVICE_1, manifest.platform_id);

	CuAssertIntEquals (test, 3, manifest.check->check);
	CuAssertIntEquals (test, 1, manifest.check->id_count);
	CuAssertIntEquals (test, CFM_ALLOWABLE_PCD_ALLOWABLE_ID_DEVICE_1,
		manifest.check->allowable_id[0]);

	cfm.test.base.free_manifest (&cfm.test.base, &manifest);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_pcd_second_component (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 26, 2, 26,
		0x8ce, 0x10, 0x10, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		27, 38);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 37, 27, 37,
		0x9fe, 0xe, 0xe, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		38, 38);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 38, 38, 38,
		0xa0c, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 38, 38, 38,
		0xa0c, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	status = cfm.test.base.get_pcd (&cfm.test.base, "Component2", &manifest);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, manifest.manifest_index);
	CuAssertIntEquals (test, 1, manifest.check_count);
	CuAssertStrEquals (test, CFM_ALLOWABLE_PCD_PLATFORM_ID_DEVICE_2, manifest.platform_id);

	CuAssertIntEquals (test, 2, manifest.check->check);
	CuAssertIntEquals (test, 1, manifest.check->id_count);
	CuAssertIntEquals (test, CFM_ALLOWABLE_PCD_ALLOWABLE_ID_DEVICE_2,
		manifest.check->allowable_id[0]);

	cfm.test.base.free_manifest (&cfm.test.base, &manifest);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_pcd_single_check (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 26, 2, 26,
		0x8ce, 0x10, 0x10, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		27, 38);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 37, 27, 37,
		0x9fe, 0xe, 0xe, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		38, 38);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 38, 38, 38,
		0xa0c, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 38, 38, 38,
		0xa0c, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	status = cfm.test.base.get_pcd (&cfm.test.base, "Component2", &manifest);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, manifest.manifest_index);
	CuAssertIntEquals (test, 1, manifest.check_count);
	CuAssertStrEquals (test, CFM_ALLOWABLE_PCD_PLATFORM_ID_DEVICE_2, manifest.platform_id);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 2, manifest.check->check);
	CuAssertIntEquals (test, 1, manifest.check->id_count);
	CuAssertIntEquals (test, CFM_ALLOWABLE_PCD_ALLOWABLE_ID_DEVICE_2,
		manifest.check->allowable_id[0]);

	cfm.test.base.free_manifest (&cfm.test.base, &manifest);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_pcd_single_id (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 26, 2, 26,
		0x8ce, 0x10, 0x10, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		27, 38);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 37, 27, 37,
		0x9fe, 0xe, 0xe, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		38, 38);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 38, 38, 38,
		0xa0c, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 38, 38, 38,
		0xa0c, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	status = cfm.test.base.get_pcd (&cfm.test.base, "Component2", &manifest);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, manifest.manifest_index);
	CuAssertIntEquals (test, 1, manifest.check_count);
	CuAssertStrEquals (test, CFM_ALLOWABLE_PCD_PLATFORM_ID_DEVICE_2, manifest.platform_id);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 2, manifest.check->check);
	CuAssertIntEquals (test, 1, manifest.check->id_count);
	CuAssertIntEquals (test, CFM_ALLOWABLE_PCD_ALLOWABLE_ID_DEVICE_2,
		manifest.check->allowable_id[0]);

	cfm.test.base.free_manifest (&cfm.test.base, &manifest);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_pcd_null (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	status = cfm.test.base.get_pcd (NULL, "Component2", &manifest);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.get_pcd (&cfm.test.base, NULL, &manifest);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.get_pcd (&cfm.test.base, "Component2", NULL);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_pcd_verify_never_run (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = cfm.test.base.get_pcd (&cfm.test.base, "Component1", &manifest);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_pcd_component_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x08));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_pcd (&cfm.test.base, "Component1", &manifest);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_pcd_component_not_found (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 26, 2,
		26, 0x8ce, 0x10, 0x10, 0);

	status = flash_mock_expect_verify_flash (&cfm.manifest.flash,
		cfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET,
		CFM_TESTING.manifest.raw + MANIFEST_V2_TOC_ENTRY_OFFSET, MANIFEST_V2_TOC_ENTRY_SIZE * 27);
	CuAssertIntEquals (test, 0, status);

	for (int i = 27; i < CFM_TESTING.manifest.toc_entries; ++i) {
		status |= mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
			&cfm.manifest.flash, 0,
			MOCK_ARG (cfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET +
				i * MANIFEST_V2_TOC_ENTRY_SIZE), MOCK_ARG_NOT_NULL,
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&cfm.manifest.flash.mock, 1,
			(struct manifest_toc_entry*) (CFM_TESTING.manifest.raw +
				MANIFEST_V2_TOC_ENTRY_OFFSET + MANIFEST_V2_TOC_ENTRY_SIZE * i),
				MANIFEST_V2_TOC_ENTRY_SIZE, 2);
	}
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_pcd (&cfm.test.base, "Component3", &manifest);
	CuAssertIntEquals (test, MANIFEST_ELEMENT_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_pcd_component_has_no_allowable_pcd (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_ONLY_MEASUREMENT_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_TESTING.manifest,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_entry, 0,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_hash,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_offset,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_len,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_TESTING.manifest, 2, 2);

	status = cfm.test.base.get_pcd (&cfm.test.base, "Component1", &manifest);
	CuAssertIntEquals (test, CFM_ELEMENT_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_pcd_get_num_allowable_pcd_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	status = flash_mock_expect_verify_flash (&cfm.manifest.flash, cfm.manifest.addr +
		MANIFEST_V2_TOC_ENTRY_OFFSET, CFM_TESTING.manifest.raw + MANIFEST_V2_TOC_ENTRY_OFFSET,
		MANIFEST_V2_TOC_ENTRY_SIZE * 2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY,
		MOCK_ARG (cfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET +
			2 * MANIFEST_V2_TOC_ENTRY_SIZE), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_pcd (&cfm.test.base, "Component1", &manifest);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_pcd_allowable_pcd_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x10));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_pcd (&cfm.test.base, "Component1", &manifest);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_pcd_get_num_allowable_id_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 24, 2, 24,
		0x8b8, 0xe, 0xe, 0);

	status = flash_mock_expect_verify_flash (&cfm.manifest.flash, cfm.manifest.addr +
		MANIFEST_V2_TOC_ENTRY_OFFSET, CFM_TESTING.manifest.raw + MANIFEST_V2_TOC_ENTRY_OFFSET,
		MANIFEST_V2_TOC_ENTRY_SIZE * 25);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY,
		MOCK_ARG (cfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET +
			25 * MANIFEST_V2_TOC_ENTRY_SIZE), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_pcd (&cfm.test.base, "Component1", &manifest);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_pcd_allowable_id_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 24, 2, 24,
		0x8b8, 0xe, 0xe, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		25, 26);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0xc8));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_pcd (&cfm.test.base, "Component1", &manifest);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_pcd_allowable_id_ids_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 24, 2, 24,
		0x8b8, 0xe, 0xe, 0);

	manifest_flash_v2_testing_get_num_child_elements (test, &cfm.manifest, &CFM_TESTING.manifest,
		25, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 25, 25, 25,
		0x8c6, 0x8, sizeof (struct cfm_allowable_id_element), 0);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0xc8));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_pcd (&cfm.test.base, "Component1", &manifest);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_free_manifest_null (CuTest *test)
{
	struct cfm_flash_testing cfm;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0);

	cfm.test.base.free_manifest (&cfm.test.base, NULL);

	cfm_flash_testing_validate_and_release (test, &cfm);
}


TEST_SUITE_START (cfm_flash);

TEST (cfm_flash_test_init);
TEST (cfm_flash_test_init_null);
TEST (cfm_flash_test_init_manifest_flash_init_fail);
TEST (cfm_flash_test_release_null);
TEST (cfm_flash_test_verify);
TEST (cfm_flash_test_verify_only_pmr_digest);
TEST (cfm_flash_test_verify_only_measurement);
TEST (cfm_flash_test_verify_only_measurement_data);
TEST (cfm_flash_test_verify_only_allowable_pfm);
TEST (cfm_flash_test_verify_only_allowable_cfm);
TEST (cfm_flash_test_verify_only_allowable_pcd);
TEST (cfm_flash_test_verify_null);
TEST (cfm_flash_test_verify_bad_magic_number);
TEST (cfm_flash_test_get_id);
TEST (cfm_flash_test_get_id_null);
TEST (cfm_flash_test_get_id_verify_never_run);
TEST (cfm_flash_test_get_hash);
TEST (cfm_flash_test_get_hash_after_verify);
TEST (cfm_flash_test_get_hash_null);
TEST (cfm_flash_test_get_hash_bad_magic_num);
TEST (cfm_flash_test_get_signature);
TEST (cfm_flash_test_get_signature_after_verify);
TEST (cfm_flash_test_get_signature_null);
TEST (cfm_flash_test_get_signature_bad_magic_number);
TEST (cfm_flash_test_get_platform_id);
TEST (cfm_flash_test_get_platform_id_manifest_allocation);
TEST (cfm_flash_test_get_platform_id_null);
TEST (cfm_flash_test_get_platform_id_verify_never_run);
TEST (cfm_flash_test_is_empty);
TEST (cfm_flash_test_is_empty_empty);
TEST (cfm_flash_test_is_empty_null);
TEST (cfm_flash_test_is_empty_verify_never_run);
TEST (cfm_flash_test_get_component_pmr);
TEST (cfm_flash_test_get_component_pmr_second_component);
TEST (cfm_flash_test_get_component_pmr_second_pmr);
TEST (cfm_flash_test_get_component_pmr_null);
TEST (cfm_flash_test_get_component_pmr_verify_never_run);
TEST (cfm_flash_test_get_component_pmr_component_read_fail);
TEST (cfm_flash_test_get_component_pmr_component_not_found);
TEST (cfm_flash_test_get_component_pmr_component_has_no_pmr);
TEST (cfm_flash_test_get_component_pmr_get_num_pmr_fail);
TEST (cfm_flash_test_get_component_pmr_pmr_read_fail);
TEST (cfm_flash_test_get_component_pmr_pmr_not_found);
TEST (cfm_flash_test_get_component_pmr_digest);
TEST (cfm_flash_test_get_component_pmr_digest_second_component);
TEST (cfm_flash_test_get_component_pmr_digest_second_digest);
TEST (cfm_flash_test_get_component_pmr_digest_null);
TEST (cfm_flash_test_get_component_pmr_digest_verify_never_run);
TEST (cfm_flash_test_get_component_pmr_digest_component_read_fail);
TEST (cfm_flash_test_get_component_pmr_digest_component_not_found);
TEST (cfm_flash_test_get_component_pmr_digest_component_has_no_pmr_digest);
TEST (cfm_flash_test_get_component_pmr_digest_get_num_pmr_digest_fail);
TEST (cfm_flash_test_get_component_pmr_digest_pmr_digest_read_fail);
TEST (cfm_flash_test_get_component_pmr_digest_pmr_not_found);
TEST (cfm_flash_test_get_component_pmr_digest_digests_read_fail);
TEST (cfm_flash_test_free_component_pmr_digest_null);
TEST (cfm_flash_test_buffer_supported_components);
TEST (cfm_flash_test_buffer_supported_components_offset_nonzero);
TEST (cfm_flash_test_buffer_supported_components_offset_too_large);
TEST (cfm_flash_test_buffer_supported_components_null);
TEST (cfm_flash_test_buffer_supported_components_verify_never_run);
TEST (cfm_flash_test_buffer_supported_components_component_read_fail);
TEST (cfm_flash_test_get_component_device);
TEST (cfm_flash_test_get_component_device_second_component);
TEST (cfm_flash_test_get_component_device_null);
TEST (cfm_flash_test_get_component_device_component_read_fail);
TEST (cfm_flash_test_get_component_device_get_num_pmr_digest_fail);
TEST (cfm_flash_test_get_component_device_pmr_digest_read_fail);
TEST (cfm_flash_test_get_component_device_component_not_found);
TEST (cfm_flash_test_get_component_device_verify_never_run);
TEST (cfm_flash_test_free_component_device_null);
TEST (cfm_flash_test_get_next_measurement);
TEST (cfm_flash_test_get_next_measurement_second_measurement);
TEST (cfm_flash_test_get_next_measurement_no_more_measurements);
TEST (cfm_flash_test_get_next_measurement_second_component);
TEST (cfm_flash_test_get_next_measurement_null);
TEST (cfm_flash_test_get_next_measurement_verify_never_run);
TEST (cfm_flash_test_get_next_measurement_component_read_fail);
TEST (cfm_flash_test_get_next_measurement_component_not_found);
TEST (cfm_flash_test_get_next_measurement_component_has_no_measurements);
TEST (cfm_flash_test_get_next_measurement_get_num_measurements_fail);
TEST (cfm_flash_test_get_next_measurement_measurement_read_fail);
TEST (cfm_flash_test_get_next_measurement_digests_read_fail);
TEST (cfm_flash_test_free_measurement_null);
TEST (cfm_flash_test_get_next_measurement_data);
TEST (cfm_flash_test_get_next_measurement_data_second_measurement_data);
TEST (cfm_flash_test_get_next_measurement_data_no_more_measurement_data);
TEST (cfm_flash_test_get_next_measurement_data_second_component);
TEST (cfm_flash_test_get_next_measurement_data_single_check);
TEST (cfm_flash_test_get_next_measurement_data_single_allowable_data);
TEST (cfm_flash_test_get_next_measurement_data_no_bitmask);
TEST (cfm_flash_test_get_next_measurement_data_null);
TEST (cfm_flash_test_get_next_measurement_data_verify_never_run);
TEST (cfm_flash_test_get_next_measurement_data_component_read_fail);
TEST (cfm_flash_test_get_next_measurement_data_component_not_found);
TEST (cfm_flash_test_get_next_measurement_data_component_has_no_measurement_data);
TEST (cfm_flash_test_get_next_measurement_data_get_num_measurement_data_fail);
TEST (cfm_flash_test_get_next_measurement_data_measurement_data_read_fail);
TEST (cfm_flash_test_get_next_measurement_data_get_num_allowable_data_fail);
TEST (cfm_flash_test_get_next_measurement_data_allowable_data_read_fail);
TEST (cfm_flash_test_get_next_measurement_data_bitmask_read_fail);
TEST (cfm_flash_test_get_next_measurement_data_allowable_data_buffer_read_fail);
TEST (cfm_flash_test_free_measurement_data_null);
TEST (cfm_flash_test_get_root_ca_digest);
TEST (cfm_flash_test_get_root_ca_digest_second_component);
TEST (cfm_flash_test_get_root_ca_digest_null);
TEST (cfm_flash_test_get_root_ca_digest_verify_never_run);
TEST (cfm_flash_test_get_root_ca_digest_component_read_fail);
TEST (cfm_flash_test_get_root_ca_digest_component_not_found);
TEST (cfm_flash_test_get_root_ca_digest_component_has_no_root_ca_digest);
TEST (cfm_flash_test_get_root_ca_digest_component_get_num_root_ca_digest_fail);
TEST (cfm_flash_test_get_root_ca_digest_root_ca_digest_read_fail);
TEST (cfm_flash_test_get_root_ca_digest_digests_read_fail);
TEST (cfm_flash_test_free_root_ca_digest_null);
TEST (cfm_flash_test_get_next_pfm);
TEST (cfm_flash_test_get_next_pfm_second_pfm);
TEST (cfm_flash_test_get_next_pfm_no_more_pfm);
TEST (cfm_flash_test_get_next_pfm_second_component);
TEST (cfm_flash_test_get_next_pfm_single_check);
TEST (cfm_flash_test_get_next_pfm_single_id);
TEST (cfm_flash_test_get_next_pfm_null);
TEST (cfm_flash_test_get_next_pfm_verify_never_run);
TEST (cfm_flash_test_get_next_pfm_component_read_fail);
TEST (cfm_flash_test_get_next_pfm_component_not_found);
TEST (cfm_flash_test_get_next_pfm_component_has_no_allowable_pfm);
TEST (cfm_flash_test_get_next_pfm_get_num_allowable_pfm_fail);
TEST (cfm_flash_test_get_next_pfm_allowable_pfm_read_fail);
TEST (cfm_flash_test_get_next_pfm_get_num_allowable_id_fail);
TEST (cfm_flash_test_get_next_pfm_allowable_id_read_fail);
TEST (cfm_flash_test_get_next_pfm_allowable_id_ids_read_fail);
TEST (cfm_flash_test_get_next_cfm);
TEST (cfm_flash_test_get_next_cfm_second_cfm);
TEST (cfm_flash_test_get_next_cfm_no_more_cfm);
TEST (cfm_flash_test_get_next_cfm_second_component);
TEST (cfm_flash_test_get_next_cfm_single_check);
TEST (cfm_flash_test_get_next_cfm_single_id);
TEST (cfm_flash_test_get_next_cfm_null);
TEST (cfm_flash_test_get_next_cfm_verify_never_run);
TEST (cfm_flash_test_get_next_cfm_component_read_fail);
TEST (cfm_flash_test_get_next_cfm_component_not_found);
TEST (cfm_flash_test_get_next_cfm_component_has_no_allowable_cfm);
TEST (cfm_flash_test_get_next_cfm_get_num_allowable_cfm_fail);
TEST (cfm_flash_test_get_next_cfm_allowable_cfm_read_fail);
TEST (cfm_flash_test_get_next_cfm_get_num_allowable_id_fail);
TEST (cfm_flash_test_get_next_cfm_allowable_id_read_fail);
TEST (cfm_flash_test_get_next_cfm_allowable_id_ids_read_fail);
TEST (cfm_flash_test_get_pcd);
TEST (cfm_flash_test_get_pcd_second_component);
TEST (cfm_flash_test_get_pcd_single_check);
TEST (cfm_flash_test_get_pcd_single_id);
TEST (cfm_flash_test_get_pcd_null);
TEST (cfm_flash_test_get_pcd_verify_never_run);
TEST (cfm_flash_test_get_pcd_component_read_fail);
TEST (cfm_flash_test_get_pcd_component_not_found);
TEST (cfm_flash_test_get_pcd_component_has_no_allowable_pcd);
TEST (cfm_flash_test_get_pcd_get_num_allowable_pcd_fail);
TEST (cfm_flash_test_get_pcd_allowable_pcd_read_fail);
TEST (cfm_flash_test_get_pcd_get_num_allowable_id_fail);
TEST (cfm_flash_test_get_pcd_allowable_id_read_fail);
TEST (cfm_flash_test_get_pcd_allowable_id_ids_read_fail);
TEST (cfm_flash_test_free_manifest_null);

TEST_SUITE_END;
