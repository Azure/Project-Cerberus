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
 *
 * CFM file: cfm.xml
 * CFM component file(s): cfm_component.xml, cfm_component2.xml
 *
 * python3 cfm_generator.py cfm_generator.config
 * to_array.sh <output cfm bin>
 */
const uint8_t CFM_DATA[] = {
	0xc8,0x0a,0x92,0xa5,0x01,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x27,0x27,0x00,0x00,
	0x00,0xff,0x01,0x00,0x48,0x06,0x08,0x00,0x70,0xff,0x00,0x01,0x50,0x06,0x08,0x00,
	0x7a,0x70,0x00,0x02,0x58,0x06,0x44,0x00,0x71,0x70,0x00,0x03,0x9c,0x06,0x24,0x00,
	0x71,0x70,0x00,0x04,0xc0,0x06,0x24,0x00,0x72,0x70,0x00,0x05,0xe4,0x06,0x44,0x00,
	0x72,0x70,0x00,0x06,0x28,0x07,0x24,0x00,0x73,0x70,0x00,0x07,0x4c,0x07,0x48,0x00,
	0x73,0x70,0x00,0x08,0x94,0x07,0x28,0x00,0x74,0x70,0x00,0x09,0xbc,0x07,0x04,0x00,
	0x75,0x74,0x00,0x0a,0xc0,0x07,0x24,0x00,0x75,0x74,0x00,0x0b,0xe4,0x07,0x18,0x00,
	0x74,0x70,0x00,0x0c,0xfc,0x07,0x04,0x00,0x75,0x74,0x00,0x0d,0x00,0x08,0x10,0x00,
	0x75,0x74,0x00,0x0e,0x10,0x08,0x0c,0x00,0x76,0x70,0x00,0x0f,0x1c,0x08,0x0e,0x00,
	0x79,0x76,0x00,0x10,0x2a,0x08,0x0c,0x00,0x79,0x76,0x00,0x11,0x36,0x08,0x08,0x00,
	0x76,0x70,0x00,0x12,0x3e,0x08,0x0e,0x00,0x79,0x76,0x00,0x13,0x4c,0x08,0x08,0x00,
	0x77,0x70,0x00,0x14,0x54,0x08,0x0e,0x00,0x79,0x77,0x00,0x15,0x62,0x08,0x08,0x00,
	0x77,0x70,0x00,0x16,0x6a,0x08,0x0e,0x00,0x79,0x77,0x00,0x17,0x78,0x08,0x08,0x00,
	0x78,0x70,0x00,0x18,0x80,0x08,0x0e,0x00,0x79,0x78,0x00,0x19,0x8e,0x08,0x08,0x00,
	0x70,0xff,0x00,0x1a,0x96,0x08,0x08,0x00,0x7a,0x70,0x00,0x1b,0x9e,0x08,0x34,0x00,
	0x71,0x70,0x00,0x1c,0xd2,0x08,0x34,0x00,0x72,0x70,0x00,0x1d,0x06,0x09,0x34,0x00,
	0x73,0x70,0x00,0x1e,0x3a,0x09,0x38,0x00,0x74,0x70,0x00,0x1f,0x72,0x09,0x04,0x00,
	0x75,0x74,0x00,0x20,0x76,0x09,0x10,0x00,0x76,0x70,0x00,0x21,0x86,0x09,0x0e,0x00,
	0x79,0x76,0x00,0x22,0x94,0x09,0x08,0x00,0x77,0x70,0x00,0x23,0x9c,0x09,0x0e,0x00,
	0x79,0x77,0x00,0x24,0xaa,0x09,0x08,0x00,0x78,0x70,0x00,0x25,0xb2,0x09,0x0e,0x00,
	0x79,0x78,0x00,0x26,0xc0,0x09,0x08,0x00,0x13,0xe9,0x1c,0x16,0x0e,0xcf,0xd2,0xbb,
	0x3a,0x86,0x83,0xb6,0x01,0xc4,0xba,0xcb,0x04,0xf0,0xa5,0x18,0x9b,0x97,0xd9,0x2d,
	0x67,0xf4,0x6d,0x69,0xea,0x1e,0x25,0x36,0x72,0xe6,0x77,0x03,0xde,0xc7,0x73,0xfc,
	0x1b,0x50,0x02,0x03,0x82,0xaa,0xce,0x5e,0x43,0x16,0x5c,0x81,0x62,0xea,0x7d,0x4c,
	0x50,0xa9,0xec,0x6e,0x79,0x7f,0xfc,0x0c,0x43,0x29,0x60,0x32,0x64,0xa8,0xe3,0x2c,
	0x1b,0x2c,0x17,0x88,0x5c,0xae,0xf9,0xdb,0x50,0x65,0x7f,0xa8,0x8b,0x4d,0x03,0xf2,
	0x40,0xb4,0x54,0x40,0xf2,0xb3,0xbb,0x7c,0x40,0xe8,0x08,0x0e,0xe9,0xd5,0x0f,0x4f,
	0x78,0x38,0xcb,0x03,0x25,0x03,0xfe,0xb2,0x7a,0x49,0x0b,0xcc,0x07,0xf3,0xb5,0x13,
	0xc9,0xfe,0xec,0xd0,0x46,0x63,0xe0,0x03,0x75,0x71,0x4a,0x2d,0xc2,0x17,0x80,0x27,
	0xe9,0x2a,0x00,0x70,0xad,0xde,0xf6,0xe6,0xee,0x0f,0x94,0x87,0xd4,0x1c,0x36,0x35,
	0x0d,0x8c,0x48,0x33,0x00,0x30,0x73,0x00,0x47,0x23,0xe5,0x32,0x3c,0x50,0xf0,0x3f,
	0xe3,0xf6,0x2e,0x82,0xc8,0xbd,0xfa,0x7a,0x34,0xf0,0xb2,0x6b,0xc0,0xe0,0xbc,0x3f,
	0x29,0xfd,0x55,0x63,0x5f,0x8e,0x23,0x99,0x99,0x9f,0xed,0xf5,0xae,0xb1,0xf8,0x06,
	0x2e,0x1c,0xfe,0x56,0xe1,0xc7,0x38,0xd3,0x14,0x38,0xfe,0xef,0xdd,0x7a,0xe5,0x65,
	0x0e,0x8d,0x03,0x68,0xcc,0x99,0x10,0x15,0x05,0xc8,0x45,0xd3,0x98,0x59,0xdb,0x80,
	0x91,0xfa,0x91,0xfe,0x24,0x19,0xf4,0xf6,0xb4,0x08,0xc4,0x4c,0xb7,0x3d,0x61,0x26,
	0x0a,0x37,0x59,0x49,0xee,0x2d,0x83,0x20,0x6b,0xf6,0x56,0x21,0x07,0x2e,0x48,0x78,
	0x87,0x31,0xac,0x06,0x54,0x03,0x35,0x85,0x28,0x03,0x5e,0xa9,0x15,0x16,0x3d,0x76,
	0xaa,0x9e,0x01,0x5c,0x4f,0x43,0xde,0xff,0xd8,0x1f,0xe9,0x6d,0xc5,0x00,0xbc,0x43,
	0xe1,0xcd,0x58,0x00,0xbe,0xf9,0xd7,0x2b,0x3d,0x03,0x0b,0xdb,0x7e,0x86,0x0e,0x10,
	0xc5,0x22,0xe4,0x24,0x6b,0x30,0xbd,0x93,0x25,0x22,0xc6,0x6f,0xcb,0xb2,0x59,0xbe,
	0xa4,0x5a,0x21,0x1d,0x24,0xac,0xa8,0x47,0x97,0x61,0xc8,0x12,0x33,0xca,0x61,0x96,
	0x82,0xd4,0xc0,0xb3,0xbd,0xd9,0x13,0x6d,0x0f,0x1f,0xbf,0xc6,0x3c,0xa7,0x33,0x59,
	0xff,0x30,0x06,0x6e,0x8d,0x1e,0x10,0x30,0xd3,0xc5,0xa9,0x45,0x19,0xcc,0xc5,0x84,
	0x9c,0x83,0x4e,0xf1,0x47,0xcf,0x74,0x01,0xb2,0x9d,0x58,0xdf,0x74,0x5b,0xbf,0x59,
	0x87,0xee,0xf0,0xad,0x36,0x03,0x6f,0x49,0x33,0x46,0xbe,0x85,0x40,0xda,0x52,0xf7,
	0x59,0x43,0x02,0x09,0x4d,0xec,0xef,0x5d,0xed,0x9d,0xa8,0x06,0xdd,0x01,0x3f,0x0a,
	0x1e,0x97,0xce,0xbb,0x4d,0xb2,0xf0,0xee,0x1c,0x3b,0xd9,0x64,0x78,0x79,0xb7,0xb8,
	0x23,0x24,0x64,0xbc,0x74,0xe1,0x82,0xb6,0x36,0x95,0x14,0x00,0x39,0x81,0x80,0x2f,
	0xd4,0x7a,0x4e,0xd6,0x41,0xf8,0xfd,0xee,0xd9,0xa8,0xb5,0x34,0xed,0x47,0x5b,0x11,
	0x22,0x31,0xda,0xe4,0x57,0xca,0x13,0x97,0x93,0xc1,0x46,0xda,0xac,0x53,0x1a,0xff,
	0xc8,0x3c,0xcf,0xd0,0x41,0x7c,0x02,0x96,0xeb,0x5c,0x16,0x31,0xb7,0x8c,0xd5,0x27,
	0xe4,0x03,0x0b,0x67,0x93,0x88,0xf6,0x2c,0x86,0x07,0x5f,0x31,0x94,0x83,0x43,0x84,
	0x78,0xf7,0xbf,0xf0,0x8b,0xda,0x22,0x99,0xe7,0x2e,0xf2,0xca,0xc9,0xff,0xce,0x1c,
	0x95,0x6a,0x8f,0x55,0x34,0x06,0x30,0xe1,0xbd,0xc5,0xb0,0x24,0x8b,0x05,0x2a,0xa7,
	0x13,0x16,0xff,0xa7,0x31,0xc5,0x2f,0xb8,0x40,0x34,0x28,0x4e,0xe6,0x7c,0xc2,0x19,
	0xfa,0x54,0x99,0xe9,0x7d,0xa9,0x9d,0x9a,0xf0,0x23,0xc6,0xde,0x58,0x3b,0x8e,0x03,
	0x9b,0x5f,0x67,0xa7,0xef,0x4c,0xe4,0xf1,0x78,0x33,0x2c,0x6d,0x3f,0x42,0x8b,0x5d,
	0x5d,0x83,0x9a,0x49,0xaf,0x09,0x70,0xa6,0x33,0xd5,0x46,0x93,0xe8,0x52,0x7a,0x5c,
	0x8c,0xaa,0x9d,0x84,0x7d,0x49,0x1d,0x25,0x25,0x71,0xe8,0x07,0x58,0x49,0xad,0x42,
	0xbb,0xc7,0xfa,0x91,0xa6,0xfc,0x61,0x93,0x0e,0xcd,0x89,0x5e,0xb4,0x22,0xce,0xe0,
	0xb8,0xae,0x62,0x57,0x6a,0x83,0x63,0x88,0xfc,0x40,0x76,0x6e,0xdc,0xc9,0x47,0xe8,
	0x57,0x57,0x65,0x17,0x0c,0xee,0x66,0x9c,0x56,0x66,0xe4,0x15,0x16,0x23,0xa9,0xc6,
	0xa2,0x86,0x11,0xf5,0x30,0x9c,0xcc,0x56,0xeb,0x54,0x0d,0xce,0x75,0x29,0xa3,0x60,
	0x05,0x5d,0x46,0xce,0x24,0x86,0x35,0x8f,0x2d,0xdb,0x92,0x18,0xe7,0xac,0x50,0xfa,
	0x51,0x50,0x05,0x55,0x52,0x56,0x3c,0x45,0xe2,0xfb,0x03,0xca,0x48,0x44,0x24,0xd6,
	0xa0,0x48,0x72,0x68,0xe3,0xc8,0x7e,0x47,0x71,0x05,0x83,0xd7,0x8c,0xf0,0xe2,0xff,
	0xde,0x97,0x68,0x54,0x03,0x4f,0x4e,0x24,0xfe,0x8a,0x53,0xbc,0xcc,0xbb,0x15,0xdc,
	0x03,0x44,0x69,0xb5,0x66,0x94,0x88,0x1e,0x99,0x24,0x75,0x92,0x01,0x46,0x61,0x4e,
	0x87,0x5f,0xa3,0xb9,0xbc,0x33,0x82,0xb5,0xee,0x88,0xab,0xde,0x57,0x74,0x43,0x23,
	0x13,0x7b,0x60,0xac,0x3b,0xd7,0xfe,0xb4,0x20,0xc9,0x58,0xd6,0x4f,0xaf,0x08,0xf6,
	0x58,0xbb,0xc6,0xe1,0xe5,0x17,0x3e,0xd1,0x37,0x1a,0x72,0xe6,0x7b,0x18,0xd3,0x06,
	0xe8,0xf5,0x7a,0xbc,0x8e,0x61,0xe0,0xce,0xea,0x6b,0x1c,0xf5,0x2d,0x0f,0x58,0x37,
	0x35,0xe6,0x50,0x77,0xc8,0x47,0xb0,0x3f,0xa2,0x97,0xb0,0x08,0x23,0xfc,0x4b,0xfd,
	0x4e,0x62,0xae,0x11,0x19,0x09,0xc8,0x89,0xea,0xf6,0x48,0x3a,0x72,0x32,0xe0,0xaa,
	0x66,0xeb,0xcf,0x06,0x06,0x7e,0x30,0xa9,0xc9,0x30,0x7e,0x07,0x7a,0xa1,0x50,0x06,
	0x18,0x83,0x53,0x26,0x9a,0xf1,0xb4,0x37,0xcb,0x0f,0x52,0x4e,0x0b,0xdd,0xe3,0x4c,
	0x88,0x6d,0x51,0xd5,0x38,0x1f,0x86,0x91,0x2c,0xe5,0x40,0xd2,0x2c,0xd2,0x88,0x3f,
	0x10,0x6e,0x4e,0x8d,0x5c,0xc4,0x7c,0x99,0x75,0xe6,0x67,0x64,0x74,0x11,0x43,0xff,
	0x26,0xeb,0x2a,0xf1,0x96,0xd3,0x8d,0x64,0x8d,0x6f,0xa1,0xa9,0xe1,0x66,0x79,0xd6,
	0x4a,0x55,0xcb,0xce,0xa6,0x2c,0x63,0x64,0x93,0xbf,0x78,0x89,0x13,0xe5,0xef,0xb6,
	0x80,0x5f,0x76,0x97,0x31,0x78,0xef,0x00,0x36,0xe1,0x1e,0xc6,0x12,0x0e,0x8e,0x59,
	0x14,0x31,0xfd,0x7f,0xa1,0xaa,0xb7,0xcd,0xbd,0xc6,0xb5,0x05,0x69,0x9e,0xc7,0x3f,
	0xaf,0x2a,0xa3,0xf2,0x07,0x8a,0xdd,0xb2,0x52,0xf9,0x02,0xb0,0x6a,0x0a,0xf8,0x1f,
	0x12,0xf6,0xd9,0xe1,0xf8,0xb6,0x0b,0x1f,0xcb,0x33,0x71,0x9c,0x21,0x7a,0x29,0x39,
	0xb2,0x48,0x44,0xbe,0x16,0x95,0xd9,0x71,0x8d,0x0c,0x7a,0x0b,0x6e,0xca,0x1e,0x0b,
	0x23,0x4d,0x4f,0x5d,0xca,0x0b,0x76,0x8f,0x50,0x1c,0x3b,0xca,0x1f,0xa5,0x4b,0x95,
	0xc5,0x48,0x08,0x5a,0x2d,0x48,0xb0,0x1e,0xd9,0x1e,0x17,0xfb,0x37,0x4e,0xad,0x55,
	0xb3,0xac,0xce,0x8c,0x58,0xc7,0x12,0xc6,0x71,0x09,0x60,0x86,0x22,0x23,0xd4,0x09,
	0xd8,0x64,0x0e,0x25,0xc5,0x8a,0x5c,0x8d,0x7b,0xa0,0x6b,0xf7,0x64,0xe1,0x11,0x55,
	0xd0,0x8c,0x22,0x0b,0x91,0x97,0xaf,0xcf,0x7e,0xf1,0xbd,0x8f,0x7e,0xfd,0x5d,0x4b,
	0x91,0x39,0x85,0x99,0x6b,0x45,0xdc,0x9a,0x43,0xb2,0x9f,0x9a,0xb0,0x3f,0xe8,0xe3,
	0x2d,0x09,0x8f,0xd8,0x25,0x04,0x4b,0x91,0x20,0xc9,0x58,0xd6,0x4f,0xaf,0x08,0xf6,
	0x58,0xbb,0xc6,0xe1,0xe5,0x17,0x3e,0xd1,0x37,0x1a,0x72,0xe6,0x7b,0x18,0xd3,0x06,
	0xe8,0xf5,0x7a,0xbc,0x8e,0x61,0xe0,0xce,0x90,0x79,0xc9,0x3e,0xed,0x3f,0x46,0xc7,
	0xe9,0x60,0x11,0xb6,0x72,0x3e,0xa5,0x34,0x05,0x28,0x53,0x77,0xde,0x79,0xe2,0xa5,
	0x3d,0xf5,0x4e,0xac,0x68,0x11,0xcf,0xb4,0x16,0x18,0x83,0x8b,0x6d,0xbb,0xc2,0x41,
	0x3a,0xc3,0xfe,0x41,0x19,0x46,0x75,0xaf,0x5f,0xb1,0x95,0x19,0xfb,0x91,0x15,0x15,
	0xc8,0xdc,0xda,0x9b,0x3d,0xe2,0xa5,0xe3,0x85,0x41,0xf2,0xc6,0xa4,0xee,0x6e,0xe5,
	0x92,0x19,0x65,0x86,0x64,0x4f,0xbd,0x25,0xfd,0x01,0x7e,0x05,0x09,0x24,0x3e,0xfc,
	0x48,0xbf,0xfc,0xbd,0x36,0x9e,0x19,0xf7,0x04,0x00,0x00,0x00,0x53,0x4b,0x55,0x31,
	0x01,0x00,0x01,0x00,0x03,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0xee,0xee,0xee,0xee,
	0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,
	0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x01,0x00,0x00,0x00,
	0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
	0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
	0x02,0x00,0x00,0x00,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,
	0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,
	0x22,0x22,0x22,0x22,0x00,0x02,0x00,0x00,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
	0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
	0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,
	0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,
	0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0x04,0x01,0x00,0x00,0xcc,0xcc,0xcc,0xcc,
	0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,
	0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0x01,0x02,0x01,0x00,
	0x00,0x00,0x02,0x00,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
	0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
	0xdd,0xdd,0xdd,0xdd,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,
	0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,
	0xee,0xee,0xee,0xee,0x02,0x02,0x01,0x00,0x00,0x00,0x01,0x00,0xcc,0xcc,0xcc,0xcc,
	0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,
	0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0x01,0x02,0x00,0x00,
	0x80,0x02,0x06,0x00,0x00,0xff,0x00,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x05,0x00,
	0x54,0x65,0x73,0x74,0x31,0x00,0x00,0x00,0x00,0x00,0x05,0x00,0x54,0x65,0x73,0x74,
	0x32,0x00,0x00,0x00,0x04,0x01,0x05,0x00,0x00,0x00,0xff,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x05,0x00,0x00,0x00,0x22,0x00,0x00,0x00,0x00,0x00,0x01,0x04,0x00,0x00,
	0x01,0x01,0x02,0x00,0x00,0xff,0x00,0x00,0x00,0x00,0x02,0x00,0x65,0x43,0x00,0x00,
	0x81,0x01,0x00,0x00,0x00,0x00,0x02,0x00,0x10,0x11,0x00,0x00,0x01,0x09,0x70,0x6c,
	0x61,0x74,0x66,0x6f,0x72,0x6d,0x41,0x00,0x00,0x00,0x80,0x02,0x00,0x00,0x99,0x00,
	0x00,0x00,0x9a,0x00,0x00,0x00,0x04,0x01,0x00,0x00,0x9d,0x00,0x00,0x00,0x02,0x09,
	0x70,0x6c,0x61,0x74,0x66,0x6f,0x72,0x6d,0x42,0x00,0x00,0x00,0x03,0x01,0x00,0x00,
	0x55,0x00,0x00,0x00,0x01,0x09,0x70,0x6c,0x61,0x74,0x66,0x6f,0x72,0x6d,0x43,0x00,
	0x00,0x00,0x84,0x01,0x00,0x00,0x12,0x00,0x00,0x00,0x02,0x09,0x70,0x6c,0x61,0x74,
	0x66,0x6f,0x72,0x6d,0x45,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0xab,0x00,0x00,0x00,
	0x00,0x09,0x70,0x6c,0x61,0x74,0x66,0x6f,0x72,0x6d,0x44,0x00,0x00,0x00,0x03,0x01,
	0x00,0x00,0x34,0x00,0x00,0x00,0x00,0x01,0x0a,0x00,0x04,0x00,0x00,0x00,0x01,0x00,
	0x00,0x00,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,
	0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,
	0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,
	0xee,0xee,0x00,0x00,0x00,0x00,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,
	0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,
	0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,
	0x33,0x33,0x33,0x33,0x33,0x33,0x02,0x01,0x00,0x00,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,
	0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,
	0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,
	0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0x01,0x05,0x01,0x00,0x00,0x00,
	0x01,0x00,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
	0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
	0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
	0xdd,0xdd,0x01,0x03,0x00,0x00,0x04,0x01,0x03,0x00,0xff,0x0f,0xff,0x00,0x00,0x00,
	0x03,0x00,0x12,0x34,0x56,0x00,0x02,0x09,0x70,0x6c,0x61,0x74,0x66,0x6f,0x72,0x6d,
	0x31,0x00,0x00,0x00,0x85,0x01,0x00,0x00,0x14,0x00,0x00,0x00,0x00,0x09,0x70,0x6c,
	0x61,0x74,0x66,0x6f,0x72,0x6d,0x32,0x00,0x00,0x00,0x03,0x01,0x00,0x00,0x34,0x00,
	0x00,0x00,0x00,0x09,0x70,0x6c,0x61,0x74,0x66,0x6f,0x72,0x6d,0x33,0x00,0x00,0x00,
	0x82,0x01,0x00,0x00,0x56,0x00,0x00,0x00,0x76,0x3f,0x20,0xaa,0x46,0x2a,0xf2,0xcc,
	0xf5,0x57,0xb3,0x78,0x26,0xf3,0x50,0xef,0xb9,0xcd,0x4b,0x30,0x9d,0xc6,0xc7,0x3e,
	0x84,0xee,0x9f,0xfc,0xae,0x05,0x03,0xd1,0xe9,0xe4,0xb3,0x56,0xd4,0x74,0xf0,0x86,
	0x1e,0x6b,0xdb,0xe7,0xfd,0x14,0x81,0x7b,0xd5,0x1d,0x26,0xa7,0x2d,0xbd,0xa7,0x81,
	0x5f,0x2f,0x4a,0x04,0x9d,0x9f,0x8a,0x45,0xa3,0xde,0x1a,0x83,0x27,0x56,0x67,0x17,
	0x57,0x53,0xaf,0xb9,0xf1,0x18,0x8c,0x15,0x0d,0x13,0x7e,0x2e,0x0c,0x8a,0x84,0x4b,
	0xbf,0x56,0xc6,0xa2,0xad,0x64,0x39,0xdd,0xea,0x43,0xc8,0xe8,0xe4,0x00,0x8b,0xce,
	0x8f,0xe7,0x38,0xc3,0x50,0xe0,0x6c,0x18,0xd8,0x12,0x9d,0x69,0x52,0xec,0xd0,0xd3,
	0x34,0x03,0x81,0x12,0x44,0x6a,0x12,0x98,0x36,0x8e,0xbc,0x7f,0xd1,0xa8,0x32,0x55,
	0x14,0x2f,0x5b,0xa5,0x34,0x91,0x4b,0x4a,0x92,0xe3,0x5e,0xc0,0x3c,0x19,0x0d,0xed,
	0x11,0x32,0xca,0x09,0x34,0xdc,0x24,0x75,0x3a,0xff,0xca,0xb5,0xa6,0x29,0x6a,0x65,
	0x9b,0xa7,0xbe,0x30,0xb6,0xb1,0xe3,0x48,0x93,0xae,0x50,0xee,0x0f,0xf9,0x20,0xd2,
	0x10,0x27,0x96,0x80,0x2e,0xb5,0x4f,0x03,0x59,0xcd,0xa8,0x6c,0x7e,0xd3,0x41,0x0a,
	0x7d,0x91,0x00,0x6c,0x8e,0x70,0x31,0x68,0x7f,0x75,0x6b,0xca,0xad,0x4f,0xf3,0x8c,
	0xc3,0xb0,0xd2,0x30,0x25,0xd0,0xf9,0x28,0xad,0xbf,0x8d,0xcb,0xda,0xbd,0x34,0x75,
	0x42,0x51,0x98,0x3e,0xed,0xe5,0x8a,0xc3,0xbb,0xa3,0x53,0xce,0xaa,0xa8,0x59,0x6c,
	0x77,0x14,0x88,0x1c,0xdc,0x34,0xb7,0xa4
};

/**
 * Length of the test CFM data.
 */
const uint32_t CFM_DATA_LEN = sizeof (CFM_DATA);

/**
 * CFM_DATA hash for testing.
 *
 * head -c -256 <file> | openssl dgst -sha256 -binary | to_array.sh -
 */
const uint8_t CFM_HASH[] = {
	0x14,0xe1,0x8d,0x2a,0x9b,0x4b,0x55,0xd4,0x7f,0x37,0x44,0x98,0x62,0x9f,0x8b,0x06,
	0x55,0x80,0x68,0x3d,0x7e,0xb8,0x3d,0x6e,0xd0,0x6b,0x01,0x03,0xa8,0x3f,0xe2,0x51
};

/**
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
	.component_device1_len = 0x08,
	.component_device1_offset = 0x650,
	.component_device1_entry = 1,
	.component_device1_hash = 1,
	.component_device2_len = 0x08,
	.component_device2_offset = 0x896,
	.component_device2_entry = 26,
	.component_device2_hash = 26,
};

/**
 * Initial value for PMR 1 Device 1.
 */
static uint8_t PMR_1_DEVICE_1[] = {
	0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
	0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11
};

/**
 * Initial value for PMR 2 Device 1.
 */
static uint8_t PMR_2_DEVICE_1[] = {
	0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,
	0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22
};

/**
 * Initial value for PMR 0 Device 2.
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
	0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,
	0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,
	0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB
};

/**
 * Supported digest for PMR 4 Device 1.
 */
static uint8_t PMR_DIGEST_4_DEVICE_1[] = {
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC
};

/**
 * Supported measurement for PMR 2 Measurement 2 Device 1.
 */
static uint8_t MEASUREMENT_PMR_2_MEASUREMENT_2_DEVICE_1[] = {
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
	0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC
};

/**
 * Supported measurement for PMR 1 Measurement 2 Device 1.
 */
static uint8_t MEASUREMENT_PMR_1_MEASUREMENT_2_DEVICE_1[] = {
	0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,
	0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD
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
	0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,
	0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,
	0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD
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
	0x00,0xFF,0x00,0xFF,0xFF,0x00
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
 * Supported measurement for PMR 1 Measurement 4, Device 1.
 */
static uint8_t MEASUREMENT_DATA_PMR_1_MEASUREMENT_4_DEVICE_1[] = {
	0x65,0x43
};

/**
 * Bitmask for supported measurement for PMR 1 Measurement 4, Device 1.
 */
static uint8_t MEASUREMENT_DATA_PMR_1_MEASUREMENT_4_DEVICE_1_BITMASK[] = {
	0x00,0xFF
};

/**
 * Second supported measurement for PMR 1 Measurement 4, Device 1.
 */
static uint8_t MEASUREMENT_DATA_PMR_1_MEASUREMENT_4_DEVICE_1_2[] = {
	0x10,0x11
};

/**
 * Supported measurement for PMR 1 Measurement 3, Device 2.
 */
static uint8_t MEASUREMENT_DATA_PMR_1_MEASUREMENT_3_DEVICE_2[] = {
	0x12,0x34,0x56
};

/**
 * Bitmask for supported measurement for PMR 1 Measurement 3, Device 2.
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
	0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,
	0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,
	0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE
};

/*
* The platform identifier for allowable PFM for port 1 in Device 1.
*/
const char CFM_ALLOWABLE_PFM_1_PLATFORM_ID_DEVICE_1[] = "platformA";

/*
* The first allowable ID for allowable PFM for port 1 in Device 1.
*/
const uint32_t CFM_ALLOWABLE_PFM_1_ALLOWABLE_ID_1_DEVICE_1 = 0x99000000;

/*
* The second allowable ID for allowable PFM for port 1 in Device 1.
*/
const uint32_t CFM_ALLOWABLE_PFM_1_ALLOWABLE_ID_1_DEVICE_1_2 = 0x9a000000;

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
const uint32_t CFM_ALLOWABLE_PFM_2_ALLOWABLE_ID_DEVICE_2 = 0x14000000;

/*
* The platform identifier for allowable CFM 1 in Device 1.
*/
const char CFM_ALLOWABLE_CFM_1_PLATFORM_ID_DEVICE_1[] = "platformC";

/*
* The allowable ID for allowable CFM 1 in Device 1.
*/
const uint32_t CFM_ALLOWABLE_CFM_1_ALLOWABLE_ID_DEVICE_1 = 0x12000000;

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
const uint32_t CFM_ALLOWABLE_PCD_ALLOWABLE_ID_DEVICE_2 = 0x56000000;

/**
 * Dummy CFM with only a PMR digest element for testing.
 *
 * CFM file: cfm.xml
 * CFM component file(s): cfm_component_only_pmr_digest.xml
 *
 * python3 cfm_generator.py cfm_generator.config
 * to_array.sh <output cfm bin>
 */
const uint8_t CFM_ONLY_PMR_DIGEST_DATA[] = {
	0xfc,0x01,0x92,0xa5,0x02,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x03,0x03,0x00,0x00,
	0x00,0xff,0x01,0x00,0xa8,0x00,0x08,0x00,0x70,0xff,0x00,0x01,0xb0,0x00,0x08,0x00,
	0x72,0x70,0x00,0x02,0xb8,0x00,0x44,0x00,0x13,0xe9,0x1c,0x16,0x0e,0xcf,0xd2,0xbb,
	0x3a,0x86,0x83,0xb6,0x01,0xc4,0xba,0xcb,0x04,0xf0,0xa5,0x18,0x9b,0x97,0xd9,0x2d,
	0x67,0xf4,0x6d,0x69,0xea,0x1e,0x25,0x36,0x72,0xe6,0x77,0x03,0xde,0xc7,0x73,0xfc,
	0x1b,0x50,0x02,0x03,0x82,0xaa,0xce,0x5e,0x43,0x16,0x5c,0x81,0x62,0xea,0x7d,0x4c,
	0x50,0xa9,0xec,0x6e,0x79,0x7f,0xfc,0x0c,0x47,0x23,0xe5,0x32,0x3c,0x50,0xf0,0x3f,
	0xe3,0xf6,0x2e,0x82,0xc8,0xbd,0xfa,0x7a,0x34,0xf0,0xb2,0x6b,0xc0,0xe0,0xbc,0x3f,
	0x29,0xfd,0x55,0x63,0x5f,0x8e,0x23,0x99,0xd8,0x54,0xf5,0xd6,0x8e,0xb9,0xf2,0xd9,
	0xbf,0x7b,0x1e,0x7e,0x11,0x37,0x80,0x4e,0xa1,0xb2,0xcd,0x9a,0xf1,0xc2,0xf3,0x79,
	0xbf,0x9f,0x93,0x0a,0xd2,0x9a,0x85,0x1a,0x04,0x00,0x00,0x00,0x53,0x4b,0x55,0x31,
	0x01,0x00,0x01,0x00,0x03,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0xaa,0xaa,0xaa,0xaa,
	0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
	0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xbb,0xbb,0xbb,0xbb,
	0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,
	0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xb3,0xb7,0x1c,0xb6,
	0x69,0x38,0xee,0xea,0x02,0xe8,0xc1,0xd0,0x48,0xcd,0x5e,0xf6,0x33,0x06,0xc8,0x33,
	0xe3,0xb5,0x50,0x6e,0x91,0x23,0x08,0xf8,0x79,0x58,0xca,0xc8,0x16,0xae,0xee,0x72,
	0x27,0x4e,0x06,0x9d,0x05,0xae,0x51,0x47,0xf6,0x1c,0x29,0x3f,0x13,0xb9,0xc0,0x78,
	0x14,0x81,0x64,0xa2,0xab,0x00,0x18,0xd1,0xa2,0x76,0xe8,0xc7,0x79,0x52,0x01,0xfb,
	0x10,0x7b,0xc7,0x5f,0x0d,0x44,0x59,0x28,0x88,0x8f,0xb1,0xb6,0xa8,0xed,0xf4,0xa4,
	0x3e,0x29,0x66,0x5a,0xc5,0xe7,0xae,0xd2,0xbd,0x26,0xf7,0x57,0xab,0xc0,0x49,0x92,
	0x40,0x32,0xda,0x96,0xd8,0x13,0x8a,0x0a,0x7e,0x6c,0x3b,0x05,0x60,0x9e,0x0e,0x4d,
	0x39,0x0f,0x1d,0x92,0xd8,0xf2,0xf4,0xf5,0xb9,0xc3,0x50,0xc4,0x47,0xdf,0x1e,0x6a,
	0x04,0x43,0xf9,0x02,0xaf,0x5c,0x2b,0x98,0x28,0x25,0x8b,0x33,0x11,0x52,0xf2,0xda,
	0x11,0xa4,0xad,0x7e,0xf2,0x50,0x61,0x96,0xa1,0x3c,0xeb,0xfe,0x59,0x5e,0x5b,0x0d,
	0x95,0x37,0xe5,0x08,0xd0,0xb7,0x84,0x0a,0xde,0x55,0xde,0xd1,0xe3,0x7e,0x42,0x54,
	0xc6,0xdd,0xf5,0x7f,0x08,0x1d,0xa3,0x13,0xea,0x09,0xb5,0x33,0xa7,0xb7,0x97,0x45,
	0x0f,0xcf,0xd8,0x65,0xbf,0x65,0x32,0x82,0xf0,0x13,0x48,0x14,0x58,0x88,0xe5,0x0f,
	0xb2,0xe1,0x54,0xc4,0xdb,0xac,0xdd,0xad,0xa6,0x86,0x31,0x40,0xba,0x20,0x85,0x49,
	0x6f,0xa3,0xe3,0xb6,0x24,0x1e,0xa7,0x5d,0x64,0xff,0x70,0x58,0xb3,0x04,0x7f,0x99,
	0xdc,0x24,0xd8,0xef,0x76,0x0b,0x93,0xdd,0x70,0xe5,0x86,0xa3
};

/**
 * Length of the testing only PMR digest CFM.
 */
const uint32_t CFM_ONLY_PMR_DIGEST_DATA_LEN = sizeof (CFM_ONLY_PMR_DIGEST_DATA);

/**
 * CFM_ONLY_PMR_DIGEST_DATA hash for testing.
 *
 * head -c -256 <file> | openssl dgst -sha256 -binary | to_array.sh -
 */
const uint8_t CFM_ONLY_PMR_DIGEST_HASH[] = {
	0xcd,0xda,0x29,0xff,0xc5,0x64,0xf2,0x44,0x0f,0xbd,0xc6,0x70,0x1f,0x53,0xd3,0xcc,
	0xef,0xc2,0x71,0x6b,0x6c,0x77,0x85,0x0f,0xf2,0xfa,0x81,0x7a,0xee,0xf5,0xcc,0xd8
};

/*
* The platform ID for the only PMR digest CFM.
*/
const char CFM_ONLY_PMR_DIGEST_PLATFORM_ID[] = "SKU1";

/**
 * Components of the test only PMR digest CFM.
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
	.component_device1_len = 0x08,
	.component_device1_offset = 0xb0,
	.component_device1_entry = 1,
	.component_device1_hash = 1,
};

/**
 * Dummy CFM with only a measurement element for testing.
 *
 * CFM file: cfm.xml
 * CFM component file(s): cfm_component_only_measurement.xml
 *
 * python3 cfm_generator.py cfm_generator.config
 * to_array.sh <output cfm bin>
 */
const uint8_t CFM_ONLY_MEASUREMENT[] = {
	0x40,0x02,0x92,0xa5,0x03,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x03,0x03,0x00,0x00,
	0x00,0xff,0x01,0x00,0xa8,0x00,0x08,0x00,0x70,0xff,0x00,0x01,0xb0,0x00,0x08,0x00,
	0x73,0x70,0x00,0x02,0xb8,0x00,0x88,0x00,0x13,0xe9,0x1c,0x16,0x0e,0xcf,0xd2,0xbb,
	0x3a,0x86,0x83,0xb6,0x01,0xc4,0xba,0xcb,0x04,0xf0,0xa5,0x18,0x9b,0x97,0xd9,0x2d,
	0x67,0xf4,0x6d,0x69,0xea,0x1e,0x25,0x36,0xe5,0xaa,0x9b,0xc4,0x0f,0xb8,0xde,0xab,
	0xb5,0x34,0xa9,0xc8,0xe8,0xf3,0x4e,0xdb,0x00,0x55,0xce,0x7a,0x46,0xa4,0xd5,0xa6,
	0x3e,0xed,0x21,0x79,0x78,0xf6,0xb3,0xd2,0xc3,0xa9,0x65,0x39,0x45,0x94,0x39,0xdd,
	0xa1,0xdb,0x4e,0x07,0xce,0xdd,0x98,0x7c,0x79,0x5d,0x6b,0x6c,0x20,0x37,0xde,0xe4,
	0xe0,0xdf,0xef,0xd3,0xef,0xe6,0x15,0x33,0xe6,0x5d,0xc8,0x1a,0xba,0x6c,0x92,0x1d,
	0xa1,0xb3,0x91,0x8d,0x95,0x47,0xa3,0x62,0x63,0xe3,0x88,0xdf,0x18,0x98,0xae,0x10,
	0x7d,0x29,0xea,0x15,0x20,0xb2,0xa7,0x59,0x04,0x00,0x00,0x00,0x53,0x4b,0x55,0x31,
	0x01,0x00,0x10,0x00,0x03,0x00,0x00,0x00,0x01,0x02,0x01,0x00,0x00,0x00,0x02,0x00,
	0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,
	0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,
	0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,
	0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,
	0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,
	0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,
	0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,
	0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,
	0x35,0x6f,0x4c,0x84,0xde,0x19,0x85,0x59,0x3c,0xf5,0x52,0xca,0x4f,0x9d,0xf6,0x92,
	0xb2,0xd2,0x9f,0xc1,0x4c,0xbb,0x2b,0x2d,0x67,0x81,0x07,0xe6,0xaf,0xcc,0x23,0x9f,
	0xf0,0xa8,0xcf,0x33,0xb0,0x44,0x4b,0xa1,0xeb,0xb2,0x3f,0x0c,0x67,0xcc,0xac,0x44,
	0xe3,0xa2,0x51,0x68,0xcb,0xed,0x7e,0x7e,0xe9,0x6a,0x0f,0xac,0x0e,0x0b,0xaf,0xba,
	0x3d,0x89,0x8b,0xea,0x46,0x95,0x2f,0xbd,0x85,0x06,0x68,0xd9,0xd1,0x15,0xd4,0xb9,
	0xe1,0xd4,0x46,0x16,0xa3,0xb5,0xa5,0x13,0x97,0x86,0x84,0xce,0x05,0x16,0x5c,0x53,
	0xf1,0x0c,0xf9,0x31,0xd5,0xac,0x74,0x53,0xc2,0x8f,0x5b,0xb1,0xba,0xa5,0x3f,0xfa,
	0xe2,0x4e,0x94,0xd5,0xdc,0xeb,0xcb,0x94,0x84,0x3e,0x17,0x0a,0xf4,0x10,0x4d,0x4b,
	0xf7,0x23,0xd4,0xcc,0x36,0x91,0xfe,0x76,0x73,0x14,0x0a,0x24,0x74,0xb3,0x51,0x14,
	0x9a,0x25,0xca,0xe8,0x23,0xe1,0xfa,0xf0,0x5b,0xf7,0x25,0x96,0x7a,0xfd,0x05,0xe7,
	0xe5,0x7b,0x35,0x5c,0x57,0xd1,0x58,0x83,0x3b,0xc1,0x4a,0x1b,0x7b,0xa3,0x44,0x6f,
	0x28,0x21,0x71,0xff,0xf4,0xd1,0x9e,0xb9,0xff,0xe2,0x41,0x0c,0xef,0xe5,0x54,0x25,
	0x7e,0x59,0x0e,0x8d,0x41,0xaa,0x77,0x53,0x27,0x0d,0xd3,0x27,0x20,0xc7,0x28,0x58,
	0xdf,0x40,0xdb,0xaa,0x1a,0x79,0xcd,0x1d,0x43,0xb0,0x9d,0xde,0x38,0xc4,0x0f,0x83,
	0xa4,0xec,0xf4,0xd7,0x44,0x0a,0x04,0xa9,0xa0,0xb5,0x7f,0x53,0xe7,0x96,0xb4,0x43,
	0xa5,0x11,0x7a,0xce,0x35,0x0e,0xb5,0x0e,0xdd,0xdd,0xb7,0x30,0x89,0xd5,0x15,0x82
};

/**
 * Length of the testing only measurement CFM.
 */
const uint32_t CFM_ONLY_MEASUREMENT_LEN = sizeof (CFM_ONLY_MEASUREMENT);

/**
 * CFM_ONLY_MEASUREMENT hash for testing.
 *
 * head -c -256 <file> | openssl dgst -sha256 -binary | to_array.sh -
 */
const uint8_t CFM_ONLY_MEASUREMENT_HASH[] = {
	0x7e,0x5b,0x0d,0xc8,0x9a,0x3f,0x01,0x2f,0x34,0x01,0xd7,0x9a,0x38,0x2f,0x75,0x26,
	0x5b,0xab,0x1a,0xcd,0x53,0x77,0xf8,0xc0,0x36,0x6a,0x9e,0x8b,0x54,0x90,0x8a,0x44
};

/*
* The platform ID for the only measurement CFM.
*/
const char CFM_ONLY_MEASUREMENT_PLATFORM_ID[] = "SKU1";

/**
 * Components of the test only measurement CFM.
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
	.component_device1_len = 0x8,
	.component_device1_offset = 0xb0,
	.component_device1_entry = 1,
	.component_device1_hash = 1,
};

/**
 * Dummy CFM with only a measurement data element for testing.
 *
 * CFM file: cfm.xml
 * CFM component file(s): cfm_component_only_measurement_data.xml
 *
 * python3 cfm_generator.py cfm_generator.config
 * to_array.sh <output cfm bin>
 */
const uint8_t CFM_ONLY_MEASUREMENT_DATA[] = {
	0x48,0x02,0x92,0xa5,0x03,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x05,0x05,0x00,0x00,
	0x00,0xff,0x01,0x00,0xf8,0x00,0x08,0x00,0x70,0xff,0x00,0x01,0x00,0x01,0x08,0x00,
	0x74,0x70,0x00,0x02,0x08,0x01,0x04,0x00,0x75,0x74,0x00,0x03,0x0c,0x01,0x24,0x00,
	0x75,0x74,0x00,0x04,0x30,0x01,0x18,0x00,0x13,0xe9,0x1c,0x16,0x0e,0xcf,0xd2,0xbb,
	0x3a,0x86,0x83,0xb6,0x01,0xc4,0xba,0xcb,0x04,0xf0,0xa5,0x18,0x9b,0x97,0xd9,0x2d,
	0x67,0xf4,0x6d,0x69,0xea,0x1e,0x25,0x36,0x72,0xe6,0x77,0x03,0xde,0xc7,0x73,0xfc,
	0x1b,0x50,0x02,0x03,0x82,0xaa,0xce,0x5e,0x43,0x16,0x5c,0x81,0x62,0xea,0x7d,0x4c,
	0x50,0xa9,0xec,0x6e,0x79,0x7f,0xfc,0x0c,0xd8,0x1f,0xe9,0x6d,0xc5,0x00,0xbc,0x43,
	0xe1,0xcd,0x58,0x00,0xbe,0xf9,0xd7,0x2b,0x3d,0x03,0x0b,0xdb,0x7e,0x86,0x0e,0x10,
	0xc5,0x22,0xe4,0x24,0x6b,0x30,0xbd,0x93,0xe3,0xf7,0xed,0xf9,0x28,0x02,0x84,0xca,
	0x9e,0xef,0x40,0xe2,0xea,0x27,0x95,0x54,0xf0,0x76,0x8b,0xb8,0x08,0x2f,0x05,0x98,
	0x30,0xcb,0x86,0x61,0x3d,0x31,0x67,0x2f,0x0f,0x1f,0xbf,0xc6,0x3c,0xa7,0x33,0x59,
	0xff,0x30,0x06,0x6e,0x8d,0x1e,0x10,0x30,0xd3,0xc5,0xa9,0x45,0x19,0xcc,0xc5,0x84,
	0x9c,0x83,0x4e,0xf1,0x47,0xcf,0x74,0x01,0xd5,0x6a,0x3e,0xc1,0xe1,0xa2,0x88,0x3d,
	0x09,0x19,0x57,0xcd,0xf0,0x3d,0x21,0xca,0xdf,0x80,0x59,0x48,0xd9,0x9f,0x6e,0x12,
	0x5c,0x1d,0x92,0xdd,0x79,0xca,0xd5,0x4c,0x04,0x00,0x00,0x00,0x53,0x4b,0x55,0x31,
	0x01,0x00,0x01,0x00,0x03,0x00,0x00,0x00,0x01,0x02,0x00,0x00,0x80,0x02,0x05,0x00,
	0x00,0xff,0x00,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x05,0x00,0x54,0x65,0x73,0x74,
	0x31,0x00,0x00,0x00,0x00,0x00,0x05,0x00,0x54,0x65,0x73,0x74,0x32,0x00,0x00,0x00,
	0x04,0x01,0x05,0x00,0x00,0x00,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x05,0x00,
	0x00,0x00,0x22,0x00,0x00,0x00,0x00,0x00,0x41,0x67,0x49,0xd4,0x92,0xa1,0x1b,0x3b,
	0x1c,0xad,0x5f,0xc0,0x26,0x00,0xcb,0xd1,0xad,0x27,0x69,0x01,0xfa,0x27,0x77,0x60,
	0x03,0xb3,0xff,0x09,0xea,0xf4,0xe3,0xfc,0x75,0xfa,0x6b,0x01,0xa4,0x6b,0x29,0x09,
	0x67,0xbb,0x32,0x6c,0x9c,0x6a,0xe3,0x51,0x7d,0x74,0x3a,0xf6,0xe9,0xe1,0xf3,0x58,
	0x66,0x96,0xfd,0xfd,0x74,0xa1,0x79,0x83,0x3d,0x75,0xa4,0xf2,0xf9,0xea,0x84,0xda,
	0xcc,0x26,0x49,0x20,0xdd,0xd7,0x97,0xfe,0xfe,0x80,0x48,0xa5,0x03,0x60,0x4b,0x89,
	0xad,0x05,0x7e,0x3e,0xe7,0x41,0x7e,0x69,0xf1,0x0d,0x98,0xe3,0x1a,0xe6,0x59,0x6e,
	0xc3,0x8a,0x50,0x18,0x46,0xa6,0xbf,0x26,0xfb,0x5e,0x20,0x5b,0xf2,0xb2,0xca,0xfd,
	0xc7,0x29,0xc0,0x90,0x75,0xd8,0x44,0x07,0x96,0x63,0x20,0x47,0xae,0xe6,0x7f,0x57,
	0x5a,0x59,0x53,0x82,0x25,0x03,0x3a,0x27,0x7a,0xb4,0x86,0x6d,0xe3,0x35,0x10,0xc9,
	0x2c,0x67,0xa9,0x09,0xeb,0x88,0x03,0x57,0x18,0x54,0xcd,0xa3,0x54,0xd6,0xd0,0xe4,
	0x0e,0x13,0x91,0x3e,0xfd,0xae,0x8e,0x33,0xaf,0xff,0x04,0x06,0x2c,0x1a,0xd6,0x74,
	0x9f,0x6c,0x52,0xf6,0x8a,0xd0,0x01,0xe2,0x6b,0x04,0xfd,0x34,0x59,0x2c,0x0a,0x26,
	0x5b,0xa5,0x7b,0x93,0xa4,0xde,0x1a,0xfc,0x69,0x10,0xb2,0x54,0x2a,0xa7,0xc0,0x02,
	0x1c,0xe6,0x7d,0xf1,0xa8,0x07,0x89,0x24,0xee,0xf0,0x03,0xcd,0x68,0xb4,0x43,0xdc,
	0x29,0x15,0x5d,0x72,0xa0,0xed,0x51,0xfc,0x59,0x60,0x4c,0x36,0x77,0x7b,0x9e,0x21,
	0x36,0x20,0x0c,0x80,0x61,0xf0,0xa7,0x04
};

/**
 * Length of the only measurement data CFM.
 */
const uint32_t CFM_ONLY_MEASUREMENT_DATA_LEN = sizeof (CFM_ONLY_MEASUREMENT_DATA);

/**
 * CFM_ONLY_MEASUREMENT_DATA hash for testing.
 *
 * head -c -256 <file> | openssl dgst -sha256 -binary | to_array.sh -
 */
const uint8_t CFM_ONLY_MEASUREMENT_DATA_HASH[] = {
	0x2f,0xf3,0x39,0x00,0xbf,0x3d,0x36,0x69,0xee,0x0b,0x51,0x61,0xe5,0x07,0x63,0x6a,
	0xc9,0xf3,0xb6,0x75,0xcb,0xa5,0x33,0x68,0x30,0x41,0xfe,0x11,0x3b,0x49,0xfb,0x8f
};

/*
* The platform ID for the only measurement data CFM.
*/
const char CFM_ONLY_MEASUREMENT_DATA_PLATFORM_ID[] = "SKU1";

/**
 * Components of the only measurement data CFM.
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
	.component_device1_len = 0x08,
	.component_device1_offset = 0x100,
	.component_device1_entry = 1,
	.component_device1_hash = 1,
};

/**
 * Dummy CFM with only an allowable PFM element for testing.
 *
 * CFM file: cfm.xml
 * CFM component file(s): cfm_component_only_pfm.xml
 *
 * python3 cfm_generator.py cfm_generator.config
 * to_array.sh <output cfm bin>
 */
const uint8_t CFM_ONLY_PFM_DATA[] = {
	0x2a,0x02,0x92,0xa5,0x05,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x05,0x05,0x00,0x00,
	0x00,0xff,0x01,0x00,0xf8,0x00,0x08,0x00,0x70,0xff,0x00,0x01,0x00,0x01,0x08,0x00,
	0x76,0x70,0x00,0x02,0x08,0x01,0x0e,0x00,0x79,0x76,0x00,0x03,0x16,0x01,0x0c,0x00,
	0x79,0x76,0x00,0x04,0x22,0x01,0x08,0x00,0x13,0xe9,0x1c,0x16,0x0e,0xcf,0xd2,0xbb,
	0x3a,0x86,0x83,0xb6,0x01,0xc4,0xba,0xcb,0x04,0xf0,0xa5,0x18,0x9b,0x97,0xd9,0x2d,
	0x67,0xf4,0x6d,0x69,0xea,0x1e,0x25,0x36,0x72,0xe6,0x77,0x03,0xde,0xc7,0x73,0xfc,
	0x1b,0x50,0x02,0x03,0x82,0xaa,0xce,0x5e,0x43,0x16,0x5c,0x81,0x62,0xea,0x7d,0x4c,
	0x50,0xa9,0xec,0x6e,0x79,0x7f,0xfc,0x0c,0x93,0xc1,0x46,0xda,0xac,0x53,0x1a,0xff,
	0xc8,0x3c,0xcf,0xd0,0x41,0x7c,0x02,0x96,0xeb,0x5c,0x16,0x31,0xb7,0x8c,0xd5,0x27,
	0xe4,0x03,0x0b,0x67,0x93,0x88,0xf6,0x2c,0x5a,0xaa,0xc6,0x7c,0xf4,0x86,0x9f,0x1f,
	0x33,0x14,0xe6,0xed,0xe2,0xe8,0xcf,0xf2,0xbb,0x96,0xed,0x1f,0xbb,0x80,0x77,0x3d,
	0x83,0xfa,0xc7,0x0d,0xb4,0x61,0x06,0x31,0xbd,0xc5,0xb0,0x24,0x8b,0x05,0x2a,0xa7,
	0x13,0x16,0xff,0xa7,0x31,0xc5,0x2f,0xb8,0x40,0x34,0x28,0x4e,0xe6,0x7c,0xc2,0x19,
	0xfa,0x54,0x99,0xe9,0x7d,0xa9,0x9d,0x9a,0x96,0x1d,0x81,0x0b,0x33,0xa0,0x82,0x10,
	0x57,0xf6,0x07,0x62,0x59,0x64,0x79,0xb9,0x40,0xf5,0x3f,0xd2,0x41,0xc9,0xe1,0x51,
	0x42,0x7a,0xb8,0x82,0xe9,0x7c,0x2e,0xea,0x04,0x00,0x00,0x00,0x53,0x4b,0x55,0x31,
	0x01,0x00,0x01,0x00,0x03,0x00,0x00,0x00,0x01,0x09,0x70,0x6c,0x61,0x74,0x66,0x6f,
	0x72,0x6d,0x41,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x99,0x00,0x00,0x00,0x9a,0x00,
	0x00,0x00,0x04,0x01,0x00,0x00,0x9d,0x00,0x00,0x00,0x7f,0x9a,0x14,0x35,0xef,0xbe,
	0xe1,0xfb,0xd0,0xa7,0xf8,0x5f,0x6f,0xb2,0x63,0x1b,0xe7,0x67,0x16,0xe4,0x1c,0xa2,
	0x86,0x4a,0xdd,0x25,0xdb,0x85,0xfe,0x54,0xd4,0x9d,0xa0,0x46,0x98,0x97,0xff,0xa7,
	0xb4,0x86,0xdb,0xe2,0xad,0x68,0x63,0x95,0x64,0xbb,0x67,0x09,0xe4,0x91,0x4d,0x04,
	0xee,0x26,0xd8,0x43,0x61,0xa9,0x68,0x57,0x81,0xf5,0xe1,0x55,0xb4,0x1a,0xd3,0x11,
	0x72,0x21,0xc2,0x5a,0xd8,0x10,0x72,0x32,0x45,0x31,0x5a,0x4d,0x7a,0x2d,0x0a,0xaa,
	0xaa,0x16,0x8b,0x9d,0xf9,0xab,0x94,0x54,0x41,0x03,0xe3,0xd0,0x7b,0x8d,0x71,0xc0,
	0xfd,0xb8,0x79,0x36,0xdd,0x42,0xf4,0x55,0xbb,0xbd,0x18,0x4e,0xef,0x4c,0x5e,0xca,
	0x23,0x3c,0xa5,0x08,0x2b,0x93,0x71,0x2f,0x31,0x67,0x3c,0xb3,0xd0,0x28,0x6d,0x33,
	0x6e,0xa6,0xad,0xef,0x90,0x7d,0x07,0x1f,0x72,0x1e,0xe6,0x3e,0x60,0x3b,0x93,0xf6,
	0xa6,0xfb,0x7b,0x55,0x5e,0xd6,0x4b,0x3b,0x5a,0x7d,0xca,0x69,0xeb,0x30,0x7a,0x4e,
	0x8c,0x17,0x04,0x53,0x65,0x8d,0xc6,0x8d,0x84,0xe0,0x0d,0xe9,0x81,0x01,0x3c,0x34,
	0xcc,0x79,0x9c,0x15,0x88,0xf0,0x68,0x52,0x0c,0xf9,0x48,0xfb,0x3c,0x83,0xcc,0xd9,
	0xb8,0x96,0x14,0x99,0x99,0xcb,0xda,0x62,0x97,0x0f,0x61,0xf7,0x2d,0x3f,0xa8,0x7f,
	0x4d,0xc7,0x1f,0xe5,0x5a,0x20,0x98,0x21,0x9f,0xd6,0xd5,0xd8,0xb4,0x21,0xe1,0x3d,
	0xf5,0x36,0xb0,0xa5,0x3e,0x44,0xb0,0x6f,0x7e,0x12,0x06,0x3e,0x68,0x13,0x0b,0x72,
	0x7d,0x07,0xdd,0x7b,0x5e,0xab,0x01,0x5b,0x7d,0xcb
};

/**
 * Length of the testing only PFM CFM.
 */
const uint32_t CFM_ONLY_PFM_DATA_LEN = sizeof (CFM_ONLY_PFM_DATA);

/**
 * CFM_ONLY_PFM_DATA hash for testing.
 *
 * head -c -256 <file> | openssl dgst -sha256 -binary | to_array.sh -
 */
const uint8_t CFM_ONLY_PFM_HASH[] = {
	0x30,0xf2,0x91,0x08,0x33,0x79,0x1c,0x39,0xc7,0xa6,0xc8,0x58,0xc3,0x03,0xae,0xd3,
	0x5d,0xc3,0x40,0xf8,0x6d,0x33,0xd7,0xaf,0xdd,0x99,0xb2,0xee,0xfd,0x32,0x82,0xad
};

/*
* The platform ID for the only PFM CFM.
*/
const char CFM_ONLY_PFM_PLATFORM_ID[] = "SKU1";

/**
 * Components of the only PFM CFM.
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
	.component_device1_len = 0x08,
	.component_device1_offset = 0x100,
	.component_device1_entry = 1,
	.component_device1_hash = 1,
};

/**
 * Dummy CFM with only an allowable CFM element for testing.
 *
 * CFM file: cfm.xml
 * CFM component file(s): cfm_component_only_cfm.xml
 *
 * python3 cfm_generator.py cfm_generator.config
 * to_array.sh <output cfm bin>
 */
const uint8_t CFM_ONLY_CFM_DATA[] = {
	0xf6,0x01,0x92,0xa5,0x06,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x04,0x04,0x00,0x00,
	0x00,0xff,0x01,0x00,0xd0,0x00,0x08,0x00,0x70,0xff,0x00,0x01,0xd8,0x00,0x08,0x00,
	0x77,0x70,0x00,0x02,0xe0,0x00,0x0e,0x00,0x79,0x77,0x00,0x03,0xee,0x00,0x08,0x00,
	0x13,0xe9,0x1c,0x16,0x0e,0xcf,0xd2,0xbb,0x3a,0x86,0x83,0xb6,0x01,0xc4,0xba,0xcb,
	0x04,0xf0,0xa5,0x18,0x9b,0x97,0xd9,0x2d,0x67,0xf4,0x6d,0x69,0xea,0x1e,0x25,0x36,
	0x72,0xe6,0x77,0x03,0xde,0xc7,0x73,0xfc,0x1b,0x50,0x02,0x03,0x82,0xaa,0xce,0x5e,
	0x43,0x16,0x5c,0x81,0x62,0xea,0x7d,0x4c,0x50,0xa9,0xec,0x6e,0x79,0x7f,0xfc,0x0c,
	0x0e,0xcd,0x89,0x5e,0xb4,0x22,0xce,0xe0,0xb8,0xae,0x62,0x57,0x6a,0x83,0x63,0x88,
	0xfc,0x40,0x76,0x6e,0xdc,0xc9,0x47,0xe8,0x57,0x57,0x65,0x17,0x0c,0xee,0x66,0x9c,
	0x47,0x35,0xa1,0x4c,0x94,0x1f,0x3d,0xc9,0x79,0x7f,0x74,0x55,0xe3,0xbd,0x43,0x56,
	0x77,0x82,0x6f,0x48,0xf8,0xb0,0x46,0x24,0xc1,0x34,0xc0,0x39,0xfa,0x03,0xbc,0x11,
	0x6b,0x70,0x63,0xdb,0x58,0x69,0x1a,0xc5,0x6f,0xfa,0x5c,0x70,0xd4,0x62,0xe1,0xcd,
	0x2a,0x54,0xfa,0x18,0xf2,0x13,0x8f,0x5c,0x21,0x18,0x7c,0x3e,0x4d,0x5a,0xba,0x9e,
	0x04,0x00,0x00,0x00,0x53,0x4b,0x55,0x31,0x01,0x00,0x01,0x00,0x03,0x00,0x00,0x00,
	0x01,0x09,0x70,0x6c,0x61,0x74,0x66,0x6f,0x72,0x6d,0x43,0x00,0x00,0x00,0x04,0x01,
	0x00,0x00,0x12,0x00,0x00,0x00,0x6f,0xa8,0x41,0x09,0x26,0x7e,0xd5,0xcc,0x71,0xd6,
	0x4c,0xe6,0xfd,0x57,0xc5,0xc9,0xa5,0x08,0x53,0x15,0xe7,0x8c,0xaa,0xb5,0x6a,0x30,
	0xb8,0xd2,0x10,0xbb,0x10,0x81,0x5f,0x0a,0xf6,0xd1,0x48,0xb2,0x2d,0x72,0x0b,0x39,
	0x8b,0x18,0xf2,0x8f,0xc9,0xcb,0x1e,0xc4,0x7a,0x4c,0x63,0x97,0x5f,0x72,0x96,0x20,
	0x9b,0xaa,0xa9,0xbc,0x7e,0x47,0x93,0xe8,0xb4,0xc2,0x1b,0x1d,0x42,0xab,0xb9,0x29,
	0xba,0x23,0xc6,0x9b,0xd7,0xbd,0x5b,0xf6,0x4b,0x6b,0xe4,0x95,0xec,0x28,0xcc,0xd5,
	0xa7,0xa8,0xf6,0xe1,0x1e,0x58,0xea,0x8d,0xa1,0x6a,0x97,0x94,0xc6,0xf3,0xf5,0x51,
	0x11,0xbd,0x18,0xfe,0x04,0x40,0xd5,0x4f,0x6b,0xc3,0x1a,0xa3,0xaf,0x52,0x5b,0x6f,
	0xcc,0x5d,0xcd,0x1b,0xb7,0x30,0x56,0x9c,0x9c,0x14,0x34,0x37,0xae,0xc0,0x33,0x2b,
	0xe3,0x4e,0xe8,0xe7,0x5f,0x41,0xb7,0x6d,0x10,0x5d,0x0e,0xdd,0x4e,0xcd,0xc1,0x27,
	0x8b,0x24,0x24,0xda,0x19,0x4e,0x0c,0x68,0xf6,0xf2,0x8a,0x8c,0xc4,0x84,0x6e,0xdb,
	0x97,0x8c,0x0f,0x34,0xd1,0xc5,0xef,0x4d,0x23,0x12,0x76,0x3f,0xe1,0xb8,0x9a,0xbb,
	0xbc,0x5c,0x32,0x14,0x2d,0x84,0x98,0xf3,0xaa,0xe7,0x83,0xe9,0x79,0xaf,0x85,0x8c,
	0xc2,0xdc,0xa8,0xc0,0x0f,0xd0,0x74,0x0f,0xbc,0xad,0x97,0x84,0x1a,0xaa,0x0e,0x56,
	0xa4,0x6c,0xd8,0x71,0x3f,0x31,0xa5,0x9f,0x51,0x80,0xfb,0x7c,0xde,0xc0,0x5a,0xe5,
	0x98,0x6d,0x45,0x82,0x71,0xe9,0x27,0xeb,0xd0,0x04,0x62,0x3d,0xcb,0x58,0xa9,0xb5,
	0xd4,0x23,0xb1,0xd1,0x63,0x15
};

/**
 * Length of the testing only CFM CFM.
 */
const uint32_t CFM_ONLY_CFM_DATA_LEN = sizeof (CFM_ONLY_CFM_DATA);

/**
 * CFM_ONLY_CFM_DATA hash for testing.
 */
const uint8_t CFM_ONLY_CFM_HASH[] = {
	0x52,0xbe,0x5d,0x89,0x15,0x72,0x64,0x88,0x3f,0xe6,0x4a,0xbc,0x8a,0x49,0x0e,0x99,
	0x2a,0xc1,0xac,0xb4,0xaf,0x84,0xf3,0x8f,0x8b,0x32,0x57,0xf0,0xac,0x61,0xfd,0xd9
};

/*
* The platform ID for the only CFM CFM.
*/
const char CFM_ONLY_CFM_PLATFORM_ID[] = "SKU1";

/**
 * Components of the test only CFM CFM.
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
	.component_device1_len = 0x08,
	.component_device1_offset = 0xd8,
	.component_device1_entry = 1,
	.component_device1_hash = 1,
};

/**
 * Dummy CFM with only an allowable PCD element for testing.
 *
 * CFM file: cfm.xml
 * CFM component file(s): cfm_component_only_pcd.xml
 *
 * python3 cfm_generator.py cfm_generator.config
 * to_array.sh <output cfm bin>
 */
const uint8_t CFM_ONLY_PCD_DATA[] = {
	0xf6,0x01,0x92,0xa5,0x01,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x04,0x04,0x00,0x00,
	0x00,0xff,0x01,0x00,0xd0,0x00,0x08,0x00,0x70,0xff,0x00,0x01,0xd8,0x00,0x08,0x00,
	0x78,0x70,0x00,0x02,0xe0,0x00,0x0e,0x00,0x79,0x78,0x00,0x03,0xee,0x00,0x08,0x00,
	0x13,0xe9,0x1c,0x16,0x0e,0xcf,0xd2,0xbb,0x3a,0x86,0x83,0xb6,0x01,0xc4,0xba,0xcb,
	0x04,0xf0,0xa5,0x18,0x9b,0x97,0xd9,0x2d,0x67,0xf4,0x6d,0x69,0xea,0x1e,0x25,0x36,
	0x80,0x5f,0xd6,0xed,0x15,0xe5,0x5d,0xf8,0x77,0xb0,0x66,0x60,0xfe,0xb5,0x48,0x69,
	0x12,0x77,0xdf,0x02,0x3b,0x61,0x66,0xb0,0x7f,0xd6,0x61,0xb9,0x9d,0x92,0x00,0x8b,
	0x99,0x24,0x75,0x92,0x01,0x46,0x61,0x4e,0x87,0x5f,0xa3,0xb9,0xbc,0x33,0x82,0xb5,
	0xee,0x88,0xab,0xde,0x57,0x74,0x43,0x23,0x13,0x7b,0x60,0xac,0x3b,0xd7,0xfe,0xb4,
	0x20,0xc9,0x58,0xd6,0x4f,0xaf,0x08,0xf6,0x58,0xbb,0xc6,0xe1,0xe5,0x17,0x3e,0xd1,
	0x37,0x1a,0x72,0xe6,0x7b,0x18,0xd3,0x06,0xe8,0xf5,0x7a,0xbc,0x8e,0x61,0xe0,0xce,
	0x5d,0x1b,0xe9,0x27,0xce,0x45,0xd1,0xcd,0xd3,0x95,0x45,0x95,0x07,0xa9,0x9e,0xd9,
	0xaf,0xe2,0x8f,0x4e,0xe6,0x28,0x98,0x25,0x68,0x53,0xd3,0xe4,0xc1,0x76,0x19,0x57,
	0x04,0x00,0x00,0x00,0x53,0x4b,0x55,0x31,0x01,0x00,0x10,0x00,0x00,0x00,0x00,0x00,
	0x00,0x09,0x70,0x6c,0x61,0x74,0x66,0x6f,0x72,0x6d,0x44,0x00,0x00,0x00,0x03,0x01,
	0x00,0x00,0x34,0x00,0x00,0x00,0x4c,0xb7,0x3f,0x68,0x63,0xfc,0x82,0xfe,0xec,0x45,
	0x43,0xdb,0xe2,0x85,0x08,0x56,0x0e,0xcf,0x90,0x4c,0x3f,0x13,0xa2,0x79,0x5a,0x90,
	0x4f,0x4c,0x00,0xb8,0x4c,0xe8,0x29,0xa6,0x89,0x72,0xec,0x68,0x75,0xf2,0xeb,0xe3,
	0x19,0x1a,0x94,0x6e,0x4f,0x60,0x62,0xe9,0xd7,0xa9,0xf7,0xec,0xac,0xb6,0x27,0xe3,
	0xe1,0xc0,0x1e,0x3c,0x9b,0x70,0xac,0x4b,0x57,0x40,0x64,0xae,0x2b,0x42,0x77,0x93,
	0x50,0x39,0xd9,0x1e,0xbe,0xda,0x5e,0xd4,0x01,0x16,0x49,0x28,0xc6,0xd1,0xbd,0x4a,
	0xba,0x03,0x10,0x25,0x96,0x76,0xfa,0xf1,0x77,0xb9,0x7e,0x6e,0x95,0xf2,0xe6,0x2d,
	0xcd,0xef,0x80,0xd2,0x9a,0xff,0x25,0x09,0x47,0xf3,0x18,0x53,0x8f,0x17,0xf1,0xf3,
	0x48,0xd1,0x7f,0x1d,0x8f,0xa8,0xd5,0xa6,0x9b,0xff,0x5b,0x5d,0xe2,0x50,0x35,0xd3,
	0xe8,0x59,0xee,0x16,0x37,0x80,0xe8,0xf8,0xf6,0x44,0x42,0x31,0x48,0x0a,0x62,0x30,
	0xe4,0x3f,0xf0,0xc0,0xac,0xa5,0x9d,0xd5,0x85,0xe6,0x88,0xdc,0x0f,0xae,0x43,0x35,
	0x40,0x08,0xd3,0xde,0x1d,0xbf,0x8e,0x07,0xa3,0x05,0x86,0x73,0x05,0x5c,0x93,0xf8,
	0xb3,0x44,0x70,0xc0,0x69,0x99,0x5b,0xff,0xc1,0x4d,0x54,0x2d,0xa3,0xd3,0x8c,0x66,
	0x05,0x12,0xaa,0x91,0xeb,0x0c,0xd7,0xb3,0xb4,0x4e,0xea,0xca,0x83,0x08,0x27,0xde,
	0xa9,0x4a,0xf1,0x65,0x94,0xf2,0x13,0x63,0x15,0xe7,0xa7,0x47,0x84,0xee,0x80,0x8e,
	0x52,0xe0,0x6f,0xbf,0xff,0xa8,0x43,0x0d,0x78,0xe2,0x6a,0xe6,0x55,0x00,0x88,0x7f,
	0x3a,0xaa,0x25,0x07,0x09,0xe0
};

/**
 * Length of the testing no PCD CFM.
 */
const uint32_t CFM_ONLY_PCD_DATA_LEN = sizeof (CFM_ONLY_PCD_DATA);

/**
 * CFM_ONLY_PCD_DATA hash for testing.
 *
 * head -c -256 <file> | openssl dgst -sha256 -binary | to_array.sh -
 */
const uint8_t CFM_ONLY_PCD_HASH[] = {
	0xe8,0x49,0x6b,0x4a,0xfe,0x3a,0x56,0xc7,0xfc,0x9e,0x0a,0xea,0x7a,0xa4,0xdc,0x44,
	0x3e,0xc5,0x2a,0x11,0x6f,0x65,0x48,0xe2,0xc1,0x8a,0x48,0x8a,0xe1,0x54,0x8b,0x32
};

/*
* The platform ID for the only PCD CFM.
*/
const char CFM_ONLY_PCD_PLATFORM_ID[] = "SKU1";

/**
 * Components of the test only PCD CFM.
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
	.component_device1_len = 0x08,
	.component_device1_offset = 0xd8,
	.component_device1_entry = 1,
	.component_device1_hash = 1,
};

/**
 * Empty CFM for testing.
 *
 * CFM file: cfm_empty.xml
 * CFM component file(s):
 *
 * python3 cfm_generator.py cfm_generator.config
 * to_array.sh <output cfm bin>
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
 * CFM with measurement data elements before measurement elements for testing.
 *
 * CFM file: cfm.xml
 * CFM component file(s): cfm_component_measurement_data_first.xml
 *
 * python3 cfm_generator.py cfm_generator.config
 * to_array.sh <output cfm bin>
 */
const uint8_t CFM_MEASUREMENT_DATA_FIRST_DATA[] = {
	0xc8,0x0a,0x92,0xa5,0x01,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x27,0x27,0x00,0x00,
	0x00,0xff,0x01,0x00,0x48,0x06,0x08,0x00,0x70,0xff,0x00,0x01,0x50,0x06,0x08,0x00,
	0x7a,0x70,0x00,0x02,0x58,0x06,0x44,0x00,0x71,0x70,0x00,0x03,0x9c,0x06,0x24,0x00,
	0x71,0x70,0x00,0x04,0xc0,0x06,0x24,0x00,0x72,0x70,0x00,0x05,0xe4,0x06,0x44,0x00,
	0x72,0x70,0x00,0x06,0x28,0x07,0x24,0x00,0x74,0x70,0x00,0x07,0x4c,0x07,0x04,0x00,
	0x75,0x74,0x00,0x08,0x50,0x07,0x24,0x00,0x75,0x74,0x00,0x09,0x74,0x07,0x18,0x00,
	0x74,0x70,0x00,0x0a,0x8c,0x07,0x04,0x00,0x75,0x74,0x00,0x0b,0x90,0x07,0x10,0x00,
	0x75,0x74,0x00,0x0c,0xa0,0x07,0x0c,0x00,0x73,0x70,0x00,0x0d,0xac,0x07,0x48,0x00,
	0x73,0x70,0x00,0x0e,0xf4,0x07,0x28,0x00,0x76,0x70,0x00,0x0f,0x1c,0x08,0x0e,0x00,
	0x79,0x76,0x00,0x10,0x2a,0x08,0x0c,0x00,0x79,0x76,0x00,0x11,0x36,0x08,0x08,0x00,
	0x76,0x70,0x00,0x12,0x3e,0x08,0x0e,0x00,0x79,0x76,0x00,0x13,0x4c,0x08,0x08,0x00,
	0x77,0x70,0x00,0x14,0x54,0x08,0x0e,0x00,0x79,0x77,0x00,0x15,0x62,0x08,0x08,0x00,
	0x77,0x70,0x00,0x16,0x6a,0x08,0x0e,0x00,0x79,0x77,0x00,0x17,0x78,0x08,0x08,0x00,
	0x78,0x70,0x00,0x18,0x80,0x08,0x0e,0x00,0x79,0x78,0x00,0x19,0x8e,0x08,0x08,0x00,
	0x70,0xff,0x00,0x1a,0x96,0x08,0x08,0x00,0x7a,0x70,0x00,0x1b,0x9e,0x08,0x34,0x00,
	0x71,0x70,0x00,0x1c,0xd2,0x08,0x34,0x00,0x72,0x70,0x00,0x1d,0x06,0x09,0x34,0x00,
	0x74,0x70,0x00,0x1e,0x3a,0x09,0x04,0x00,0x75,0x74,0x00,0x1f,0x3e,0x09,0x10,0x00,
	0x73,0x70,0x00,0x20,0x4e,0x09,0x38,0x00,0x76,0x70,0x00,0x21,0x86,0x09,0x0e,0x00,
	0x79,0x76,0x00,0x22,0x94,0x09,0x08,0x00,0x77,0x70,0x00,0x23,0x9c,0x09,0x0e,0x00,
	0x79,0x77,0x00,0x24,0xaa,0x09,0x08,0x00,0x78,0x70,0x00,0x25,0xb2,0x09,0x0e,0x00,
	0x79,0x78,0x00,0x26,0xc0,0x09,0x08,0x00,0x13,0xe9,0x1c,0x16,0x0e,0xcf,0xd2,0xbb,
	0x3a,0x86,0x83,0xb6,0x01,0xc4,0xba,0xcb,0x04,0xf0,0xa5,0x18,0x9b,0x97,0xd9,0x2d,
	0x67,0xf4,0x6d,0x69,0xea,0x1e,0x25,0x36,0x72,0xe6,0x77,0x03,0xde,0xc7,0x73,0xfc,
	0x1b,0x50,0x02,0x03,0x82,0xaa,0xce,0x5e,0x43,0x16,0x5c,0x81,0x62,0xea,0x7d,0x4c,
	0x50,0xa9,0xec,0x6e,0x79,0x7f,0xfc,0x0c,0x43,0x29,0x60,0x32,0x64,0xa8,0xe3,0x2c,
	0x1b,0x2c,0x17,0x88,0x5c,0xae,0xf9,0xdb,0x50,0x65,0x7f,0xa8,0x8b,0x4d,0x03,0xf2,
	0x40,0xb4,0x54,0x40,0xf2,0xb3,0xbb,0x7c,0x40,0xe8,0x08,0x0e,0xe9,0xd5,0x0f,0x4f,
	0x78,0x38,0xcb,0x03,0x25,0x03,0xfe,0xb2,0x7a,0x49,0x0b,0xcc,0x07,0xf3,0xb5,0x13,
	0xc9,0xfe,0xec,0xd0,0x46,0x63,0xe0,0x03,0x75,0x71,0x4a,0x2d,0xc2,0x17,0x80,0x27,
	0xe9,0x2a,0x00,0x70,0xad,0xde,0xf6,0xe6,0xee,0x0f,0x94,0x87,0xd4,0x1c,0x36,0x35,
	0x0d,0x8c,0x48,0x33,0x00,0x30,0x73,0x00,0x47,0x23,0xe5,0x32,0x3c,0x50,0xf0,0x3f,
	0xe3,0xf6,0x2e,0x82,0xc8,0xbd,0xfa,0x7a,0x34,0xf0,0xb2,0x6b,0xc0,0xe0,0xbc,0x3f,
	0x29,0xfd,0x55,0x63,0x5f,0x8e,0x23,0x99,0x99,0x9f,0xed,0xf5,0xae,0xb1,0xf8,0x06,
	0x2e,0x1c,0xfe,0x56,0xe1,0xc7,0x38,0xd3,0x14,0x38,0xfe,0xef,0xdd,0x7a,0xe5,0x65,
	0x0e,0x8d,0x03,0x68,0xcc,0x99,0x10,0x15,0xd8,0x1f,0xe9,0x6d,0xc5,0x00,0xbc,0x43,
	0xe1,0xcd,0x58,0x00,0xbe,0xf9,0xd7,0x2b,0x3d,0x03,0x0b,0xdb,0x7e,0x86,0x0e,0x10,
	0xc5,0x22,0xe4,0x24,0x6b,0x30,0xbd,0x93,0x25,0x22,0xc6,0x6f,0xcb,0xb2,0x59,0xbe,
	0xa4,0x5a,0x21,0x1d,0x24,0xac,0xa8,0x47,0x97,0x61,0xc8,0x12,0x33,0xca,0x61,0x96,
	0x82,0xd4,0xc0,0xb3,0xbd,0xd9,0x13,0x6d,0x0f,0x1f,0xbf,0xc6,0x3c,0xa7,0x33,0x59,
	0xff,0x30,0x06,0x6e,0x8d,0x1e,0x10,0x30,0xd3,0xc5,0xa9,0x45,0x19,0xcc,0xc5,0x84,
	0x9c,0x83,0x4e,0xf1,0x47,0xcf,0x74,0x01,0xb2,0x9d,0x58,0xdf,0x74,0x5b,0xbf,0x59,
	0x87,0xee,0xf0,0xad,0x36,0x03,0x6f,0x49,0x33,0x46,0xbe,0x85,0x40,0xda,0x52,0xf7,
	0x59,0x43,0x02,0x09,0x4d,0xec,0xef,0x5d,0xed,0x9d,0xa8,0x06,0xdd,0x01,0x3f,0x0a,
	0x1e,0x97,0xce,0xbb,0x4d,0xb2,0xf0,0xee,0x1c,0x3b,0xd9,0x64,0x78,0x79,0xb7,0xb8,
	0x23,0x24,0x64,0xbc,0x74,0xe1,0x82,0xb6,0x36,0x95,0x14,0x00,0x39,0x81,0x80,0x2f,
	0xd4,0x7a,0x4e,0xd6,0x41,0xf8,0xfd,0xee,0xd9,0xa8,0xb5,0x34,0xed,0x47,0x5b,0x11,
	0x22,0x31,0xda,0xe4,0x57,0xca,0x13,0x97,0x05,0xc8,0x45,0xd3,0x98,0x59,0xdb,0x80,
	0x91,0xfa,0x91,0xfe,0x24,0x19,0xf4,0xf6,0xb4,0x08,0xc4,0x4c,0xb7,0x3d,0x61,0x26,
	0x0a,0x37,0x59,0x49,0xee,0x2d,0x83,0x20,0x6b,0xf6,0x56,0x21,0x07,0x2e,0x48,0x78,
	0x87,0x31,0xac,0x06,0x54,0x03,0x35,0x85,0x28,0x03,0x5e,0xa9,0x15,0x16,0x3d,0x76,
	0xaa,0x9e,0x01,0x5c,0x4f,0x43,0xde,0xff,0x93,0xc1,0x46,0xda,0xac,0x53,0x1a,0xff,
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
	0x57,0x57,0x65,0x17,0x0c,0xee,0x66,0x9c,0x56,0x66,0xe4,0x15,0x16,0x23,0xa9,0xc6,
	0xa2,0x86,0x11,0xf5,0x30,0x9c,0xcc,0x56,0xeb,0x54,0x0d,0xce,0x75,0x29,0xa3,0x60,
	0x05,0x5d,0x46,0xce,0x24,0x86,0x35,0x8f,0x2d,0xdb,0x92,0x18,0xe7,0xac,0x50,0xfa,
	0x51,0x50,0x05,0x55,0x52,0x56,0x3c,0x45,0xe2,0xfb,0x03,0xca,0x48,0x44,0x24,0xd6,
	0xa0,0x48,0x72,0x68,0xe3,0xc8,0x7e,0x47,0x71,0x05,0x83,0xd7,0x8c,0xf0,0xe2,0xff,
	0xde,0x97,0x68,0x54,0x03,0x4f,0x4e,0x24,0xfe,0x8a,0x53,0xbc,0xcc,0xbb,0x15,0xdc,
	0x03,0x44,0x69,0xb5,0x66,0x94,0x88,0x1e,0x99,0x24,0x75,0x92,0x01,0x46,0x61,0x4e,
	0x87,0x5f,0xa3,0xb9,0xbc,0x33,0x82,0xb5,0xee,0x88,0xab,0xde,0x57,0x74,0x43,0x23,
	0x13,0x7b,0x60,0xac,0x3b,0xd7,0xfe,0xb4,0x20,0xc9,0x58,0xd6,0x4f,0xaf,0x08,0xf6,
	0x58,0xbb,0xc6,0xe1,0xe5,0x17,0x3e,0xd1,0x37,0x1a,0x72,0xe6,0x7b,0x18,0xd3,0x06,
	0xe8,0xf5,0x7a,0xbc,0x8e,0x61,0xe0,0xce,0xea,0x6b,0x1c,0xf5,0x2d,0x0f,0x58,0x37,
	0x35,0xe6,0x50,0x77,0xc8,0x47,0xb0,0x3f,0xa2,0x97,0xb0,0x08,0x23,0xfc,0x4b,0xfd,
	0x4e,0x62,0xae,0x11,0x19,0x09,0xc8,0x89,0xea,0xf6,0x48,0x3a,0x72,0x32,0xe0,0xaa,
	0x66,0xeb,0xcf,0x06,0x06,0x7e,0x30,0xa9,0xc9,0x30,0x7e,0x07,0x7a,0xa1,0x50,0x06,
	0x18,0x83,0x53,0x26,0x9a,0xf1,0xb4,0x37,0xcb,0x0f,0x52,0x4e,0x0b,0xdd,0xe3,0x4c,
	0x88,0x6d,0x51,0xd5,0x38,0x1f,0x86,0x91,0x2c,0xe5,0x40,0xd2,0x2c,0xd2,0x88,0x3f,
	0x10,0x6e,0x4e,0x8d,0x5c,0xc4,0x7c,0x99,0x75,0xe6,0x67,0x64,0x74,0x11,0x43,0xff,
	0x26,0xeb,0x2a,0xf1,0x96,0xd3,0x8d,0x64,0x8d,0x6f,0xa1,0xa9,0xe1,0x66,0x79,0xd6,
	0x4a,0x55,0xcb,0xce,0xa6,0x2c,0x63,0x64,0xbd,0xc6,0xb5,0x05,0x69,0x9e,0xc7,0x3f,
	0xaf,0x2a,0xa3,0xf2,0x07,0x8a,0xdd,0xb2,0x52,0xf9,0x02,0xb0,0x6a,0x0a,0xf8,0x1f,
	0x12,0xf6,0xd9,0xe1,0xf8,0xb6,0x0b,0x1f,0xcb,0x33,0x71,0x9c,0x21,0x7a,0x29,0x39,
	0xb2,0x48,0x44,0xbe,0x16,0x95,0xd9,0x71,0x8d,0x0c,0x7a,0x0b,0x6e,0xca,0x1e,0x0b,
	0x23,0x4d,0x4f,0x5d,0xca,0x0b,0x76,0x8f,0x93,0xbf,0x78,0x89,0x13,0xe5,0xef,0xb6,
	0x80,0x5f,0x76,0x97,0x31,0x78,0xef,0x00,0x36,0xe1,0x1e,0xc6,0x12,0x0e,0x8e,0x59,
	0x14,0x31,0xfd,0x7f,0xa1,0xaa,0xb7,0xcd,0x50,0x1c,0x3b,0xca,0x1f,0xa5,0x4b,0x95,
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
	0x73,0x6b,0x52,0x7b,0x92,0x93,0xb7,0x8b,0x03,0xfe,0x79,0xa8,0x81,0x5c,0xcd,0xb8,
	0x39,0xef,0x6d,0xba,0x66,0xe7,0x46,0xc8,0xd9,0xc4,0x8f,0x77,0x16,0xad,0x25,0x50,
	0x15,0x92,0x56,0xba,0x9f,0x5f,0x19,0xf3,0x04,0x00,0x00,0x00,0x53,0x4b,0x55,0x31,
	0x01,0x00,0x01,0x00,0x03,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0xee,0xee,0xee,0xee,
	0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,
	0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x01,0x00,0x00,0x00,
	0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
	0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
	0x02,0x00,0x00,0x00,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,
	0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,
	0x22,0x22,0x22,0x22,0x00,0x02,0x00,0x00,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
	0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
	0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,
	0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,
	0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0x04,0x01,0x00,0x00,0xcc,0xcc,0xcc,0xcc,
	0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,
	0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0x01,0x02,0x00,0x00,
	0x80,0x02,0x06,0x00,0x00,0xff,0x00,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x05,0x00,
	0x54,0x65,0x73,0x74,0x31,0x00,0x00,0x00,0x00,0x00,0x05,0x00,0x54,0x65,0x73,0x74,
	0x32,0x00,0x00,0x00,0x04,0x01,0x05,0x00,0x00,0x00,0xff,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x05,0x00,0x00,0x00,0x22,0x00,0x00,0x00,0x00,0x00,0x01,0x04,0x00,0x00,
	0x01,0x01,0x02,0x00,0x00,0xff,0x00,0x00,0x00,0x00,0x02,0x00,0x65,0x43,0x00,0x00,
	0x81,0x01,0x00,0x00,0x00,0x00,0x02,0x00,0x10,0x11,0x00,0x00,0x01,0x02,0x01,0x00,
	0x00,0x00,0x02,0x00,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
	0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
	0xdd,0xdd,0xdd,0xdd,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,
	0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,
	0xee,0xee,0xee,0xee,0x02,0x02,0x01,0x00,0x00,0x00,0x01,0x00,0xcc,0xcc,0xcc,0xcc,
	0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,
	0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0x01,0x09,0x70,0x6c,
	0x61,0x74,0x66,0x6f,0x72,0x6d,0x41,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x99,0x00,
	0x00,0x00,0x9a,0x00,0x00,0x00,0x04,0x01,0x00,0x00,0x9d,0x00,0x00,0x00,0x02,0x09,
	0x70,0x6c,0x61,0x74,0x66,0x6f,0x72,0x6d,0x42,0x00,0x00,0x00,0x03,0x01,0x00,0x00,
	0x55,0x00,0x00,0x00,0x01,0x09,0x70,0x6c,0x61,0x74,0x66,0x6f,0x72,0x6d,0x43,0x00,
	0x00,0x00,0x84,0x01,0x00,0x00,0x12,0x00,0x00,0x00,0x02,0x09,0x70,0x6c,0x61,0x74,
	0x66,0x6f,0x72,0x6d,0x45,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0xab,0x00,0x00,0x00,
	0x00,0x09,0x70,0x6c,0x61,0x74,0x66,0x6f,0x72,0x6d,0x44,0x00,0x00,0x00,0x03,0x01,
	0x00,0x00,0x34,0x00,0x00,0x00,0x00,0x01,0x0a,0x00,0x04,0x00,0x00,0x00,0x01,0x00,
	0x00,0x00,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,
	0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,
	0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,
	0xee,0xee,0x00,0x00,0x00,0x00,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,
	0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,
	0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,
	0x33,0x33,0x33,0x33,0x33,0x33,0x02,0x01,0x00,0x00,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,
	0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,
	0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,
	0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0x01,0x03,0x00,0x00,0x04,0x01,
	0x03,0x00,0xff,0x0f,0xff,0x00,0x00,0x00,0x03,0x00,0x12,0x34,0x56,0x00,0x01,0x05,
	0x01,0x00,0x00,0x00,0x01,0x00,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
	0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
	0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
	0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0x02,0x09,0x70,0x6c,0x61,0x74,0x66,0x6f,0x72,0x6d,
	0x31,0x00,0x00,0x00,0x05,0x01,0x00,0x00,0x12,0x00,0x00,0x00,0x00,0x09,0x70,0x6c,
	0x61,0x74,0x66,0x6f,0x72,0x6d,0x32,0x00,0x00,0x00,0x03,0x01,0x00,0x00,0x34,0x00,
	0x00,0x00,0x00,0x09,0x70,0x6c,0x61,0x74,0x66,0x6f,0x72,0x6d,0x33,0x00,0x00,0x00,
	0x02,0x01,0x00,0x00,0x56,0x00,0x00,0x00,0xad,0xb1,0x07,0x1d,0x8b,0x32,0x71,0x03,
	0xd6,0x0c,0x78,0x0d,0xc6,0x33,0x84,0x1e,0x24,0xe6,0x23,0x87,0x8e,0xf5,0x28,0x1c,
	0x33,0x84,0x42,0xb0,0x19,0x67,0x65,0x44,0x7a,0xcb,0x84,0xc1,0x2a,0xd3,0xec,0x4c,
	0x42,0x76,0x1d,0xe3,0x09,0xa8,0xcc,0xbb,0x4c,0xae,0xae,0x7e,0xaf,0x4b,0xcf,0xbb,
	0xf5,0xdc,0xed,0xe0,0xc4,0xde,0xb6,0xde,0x98,0x98,0x63,0x1b,0x56,0xc7,0x51,0xfd,
	0x34,0x52,0x9c,0xfa,0xc9,0x1b,0x85,0x7c,0x6e,0xd3,0x0a,0x7d,0xd6,0xae,0x5e,0x14,
	0xb2,0x6c,0xa4,0xa3,0xa8,0x13,0xca,0x09,0xa2,0x4e,0x63,0x48,0x00,0x99,0x87,0xb8,
	0xa7,0xb1,0xad,0x21,0x07,0xc6,0x19,0xd9,0x86,0xb8,0xde,0x8c,0xaa,0xc9,0x90,0x1d,
	0x8c,0x90,0xd8,0x82,0xf4,0x7d,0xfe,0xfb,0xc8,0x58,0xc5,0x7c,0xcd,0x7a,0x67,0x4d,
	0xc9,0xa9,0x0b,0x46,0xe9,0x41,0x25,0xa8,0xbe,0x6e,0x46,0xdc,0xa5,0x82,0xd9,0xbe,
	0x69,0xd6,0x81,0x5d,0xd2,0x0a,0x2b,0xcf,0x88,0x79,0x2d,0xfc,0x52,0x8e,0x2b,0x9b,
	0xff,0x4a,0x8a,0x08,0x99,0xb0,0xfc,0xca,0xe1,0x21,0x08,0x0d,0xc1,0x10,0x06,0x58,
	0x5b,0x45,0x9b,0xa8,0x8c,0x09,0x22,0x91,0x06,0x4d,0xc2,0x4f,0xab,0x85,0x48,0x06,
	0xd9,0x5a,0xb3,0xcc,0x15,0x25,0x1e,0xac,0x88,0x5f,0x37,0xfa,0xb0,0x20,0x63,0xb2,
	0x5b,0xc9,0x32,0xc9,0x34,0x67,0x85,0x48,0x23,0x60,0xe8,0x95,0x53,0x5d,0x26,0xc2,
	0xa7,0xe3,0xd0,0xa6,0x11,0x35,0xc1,0xb8,0x2b,0x35,0x61,0xad,0xc6,0xbb,0x73,0x62,
	0xe0,0x8c,0x91,0x81,0xb0,0x5d,0xf6,0xb2
};

/**
 * Length of the test CFM data.
 */
const uint32_t CFM_MEASUREMENT_DATA_FIRST_DATA_LEN = sizeof (CFM_MEASUREMENT_DATA_FIRST_DATA);

/**
 * CFM with measurement data elements before measurement elements hash for testing.
 *
 * head -c -256 <file> | openssl dgst -sha256 -binary | to_array.sh -
 */
const uint8_t CFM_MEASUREMENT_DATA_FIRST_HASH[] = {
	0xa9,0x57,0x41,0x10,0xe9,0x4d,0x82,0xbd,0xf7,0x20,0x31,0x71,0x6c,0x68,0x7a,0x6d,
	0xde,0xd0,0x3d,0x27,0xae,0x1f,0x29,0xf8,0xbf,0xcb,0xb8,0x31,0x61,0xff,0x53,0x39
};

/**
 * The platform identifier in the CFM data
 */
const char CFM_MEASUREMENT_DATA_FIRST_PLATFORM_ID[] = "SKU1";

/**
 * Components of the test CFM.
 */
const struct cfm_testing_data CFM_MEASUREMENT_DATA_FIRST_TESTING = {
	.manifest = {
		.raw = CFM_MEASUREMENT_DATA_FIRST_DATA,
		.length = sizeof (CFM_MEASUREMENT_DATA_FIRST_DATA),
		.hash = CFM_MEASUREMENT_DATA_FIRST_HASH,
		.hash_len = sizeof (CFM_MEASUREMENT_DATA_FIRST_HASH),
		.id = 0x1,
		.signature =
			CFM_MEASUREMENT_DATA_FIRST_DATA + (sizeof (CFM_MEASUREMENT_DATA_FIRST_DATA) - 256),
		.sig_len = 256,
		.sig_offset = (sizeof (CFM_MEASUREMENT_DATA_FIRST_DATA) - 256),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = CFM_MEASUREMENT_DATA_FIRST_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x618,
		.toc_hash = CFM_MEASUREMENT_DATA_FIRST_DATA + 0x628,
		.toc_hash_len = 32,
		.toc_hash_offset = 0x628,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 39,
		.toc_hashes = 39,
		.plat_id = CFM_MEASUREMENT_DATA_FIRST_DATA + 0x648,
		.plat_id_len = 0x8,
		.plat_id_str = CFM_MEASUREMENT_DATA_FIRST_PLATFORM_ID,
		.plat_id_str_len = sizeof (CFM_MEASUREMENT_DATA_FIRST_PLATFORM_ID) - 1,
		.plat_id_str_pad = 0,
		.plat_id_offset = 0x648,
		.plat_id_entry = 0,
		.plat_id_hash = 0
	},
	.component_device1_len = 0x08,
	.component_device1_offset = 0x650,
	.component_device1_entry = 1,
	.component_device1_hash = 1,
	.component_device2_len = 0x08,
	.component_device2_offset = 0x896,
	.component_device2_entry = 26,
	.component_device2_hash = 26,
};

/**
 * CFM with non-zero version sets for testing.
 *
 * CFM file: cfm.xml
 * CFM component file(s): cfm_component.xml, cfm_component2.xml
 *
 * python3 cfm_generator.py cfm_generator.config
 * to_array.sh <output cfm bin>
 */
const uint8_t CFM_NONZERO_VERSION_SET_DATA[] = {
	0xc8,0x0a,0x92,0xa5,0x01,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x27,0x27,0x00,0x00,
	0x00,0xff,0x01,0x00,0x48,0x06,0x08,0x00,0x70,0xff,0x00,0x01,0x50,0x06,0x08,0x00,
	0x7a,0x70,0x00,0x02,0x58,0x06,0x44,0x00,0x71,0x70,0x00,0x03,0x9c,0x06,0x24,0x00,
	0x71,0x70,0x00,0x04,0xc0,0x06,0x24,0x00,0x72,0x70,0x00,0x05,0xe4,0x06,0x44,0x00,
	0x72,0x70,0x00,0x06,0x28,0x07,0x24,0x00,0x73,0x70,0x00,0x07,0x4c,0x07,0x48,0x00,
	0x73,0x70,0x00,0x08,0x94,0x07,0x28,0x00,0x74,0x70,0x00,0x09,0xbc,0x07,0x04,0x00,
	0x75,0x74,0x00,0x0a,0xc0,0x07,0x24,0x00,0x75,0x74,0x00,0x0b,0xe4,0x07,0x18,0x00,
	0x74,0x70,0x00,0x0c,0xfc,0x07,0x04,0x00,0x75,0x74,0x00,0x0d,0x00,0x08,0x10,0x00,
	0x75,0x74,0x00,0x0e,0x10,0x08,0x0c,0x00,0x76,0x70,0x00,0x0f,0x1c,0x08,0x0e,0x00,
	0x79,0x76,0x00,0x10,0x2a,0x08,0x0c,0x00,0x79,0x76,0x00,0x11,0x36,0x08,0x08,0x00,
	0x76,0x70,0x00,0x12,0x3e,0x08,0x0e,0x00,0x79,0x76,0x00,0x13,0x4c,0x08,0x08,0x00,
	0x77,0x70,0x00,0x14,0x54,0x08,0x0e,0x00,0x79,0x77,0x00,0x15,0x62,0x08,0x08,0x00,
	0x77,0x70,0x00,0x16,0x6a,0x08,0x0e,0x00,0x79,0x77,0x00,0x17,0x78,0x08,0x08,0x00,
	0x78,0x70,0x00,0x18,0x80,0x08,0x0e,0x00,0x79,0x78,0x00,0x19,0x8e,0x08,0x08,0x00,
	0x70,0xff,0x00,0x1a,0x96,0x08,0x08,0x00,0x7a,0x70,0x00,0x1b,0x9e,0x08,0x34,0x00,
	0x71,0x70,0x00,0x1c,0xd2,0x08,0x34,0x00,0x72,0x70,0x00,0x1d,0x06,0x09,0x34,0x00,
	0x73,0x70,0x00,0x1e,0x3a,0x09,0x38,0x00,0x74,0x70,0x00,0x1f,0x72,0x09,0x04,0x00,
	0x75,0x74,0x00,0x20,0x76,0x09,0x10,0x00,0x76,0x70,0x00,0x21,0x86,0x09,0x0e,0x00,
	0x79,0x76,0x00,0x22,0x94,0x09,0x08,0x00,0x77,0x70,0x00,0x23,0x9c,0x09,0x0e,0x00,
	0x79,0x77,0x00,0x24,0xaa,0x09,0x08,0x00,0x78,0x70,0x00,0x25,0xb2,0x09,0x0e,0x00,
	0x79,0x78,0x00,0x26,0xc0,0x09,0x08,0x00,0x13,0xe9,0x1c,0x16,0x0e,0xcf,0xd2,0xbb,
	0x3a,0x86,0x83,0xb6,0x01,0xc4,0xba,0xcb,0x04,0xf0,0xa5,0x18,0x9b,0x97,0xd9,0x2d,
	0x67,0xf4,0x6d,0x69,0xea,0x1e,0x25,0x36,0x72,0xe6,0x77,0x03,0xde,0xc7,0x73,0xfc,
	0x1b,0x50,0x02,0x03,0x82,0xaa,0xce,0x5e,0x43,0x16,0x5c,0x81,0x62,0xea,0x7d,0x4c,
	0x50,0xa9,0xec,0x6e,0x79,0x7f,0xfc,0x0c,0x43,0x29,0x60,0x32,0x64,0xa8,0xe3,0x2c,
	0x1b,0x2c,0x17,0x88,0x5c,0xae,0xf9,0xdb,0x50,0x65,0x7f,0xa8,0x8b,0x4d,0x03,0xf2,
	0x40,0xb4,0x54,0x40,0xf2,0xb3,0xbb,0x7c,0x40,0xe8,0x08,0x0e,0xe9,0xd5,0x0f,0x4f,
	0x78,0x38,0xcb,0x03,0x25,0x03,0xfe,0xb2,0x7a,0x49,0x0b,0xcc,0x07,0xf3,0xb5,0x13,
	0xc9,0xfe,0xec,0xd0,0x46,0x63,0xe0,0x03,0x75,0x71,0x4a,0x2d,0xc2,0x17,0x80,0x27,
	0xe9,0x2a,0x00,0x70,0xad,0xde,0xf6,0xe6,0xee,0x0f,0x94,0x87,0xd4,0x1c,0x36,0x35,
	0x0d,0x8c,0x48,0x33,0x00,0x30,0x73,0x00,0x47,0x23,0xe5,0x32,0x3c,0x50,0xf0,0x3f,
	0xe3,0xf6,0x2e,0x82,0xc8,0xbd,0xfa,0x7a,0x34,0xf0,0xb2,0x6b,0xc0,0xe0,0xbc,0x3f,
	0x29,0xfd,0x55,0x63,0x5f,0x8e,0x23,0x99,0x99,0x9f,0xed,0xf5,0xae,0xb1,0xf8,0x06,
	0x2e,0x1c,0xfe,0x56,0xe1,0xc7,0x38,0xd3,0x14,0x38,0xfe,0xef,0xdd,0x7a,0xe5,0x65,
	0x0e,0x8d,0x03,0x68,0xcc,0x99,0x10,0x15,0x8f,0x1d,0xbf,0x47,0x48,0xa9,0x7e,0xe7,
	0x3e,0x21,0x96,0x9c,0xf6,0x02,0xd7,0xc3,0xbf,0xef,0xdb,0x7c,0xe5,0x8c,0x1c,0x45,
	0xd2,0x88,0xe5,0x29,0x43,0xb3,0x9b,0x9d,0x2f,0xad,0x34,0x37,0xd4,0x41,0x30,0xa4,
	0x6e,0x22,0x48,0xd7,0xe1,0x5c,0xf9,0x77,0x6c,0x1e,0x22,0x52,0x0d,0x99,0xb0,0x17,
	0x81,0x81,0x67,0x1f,0xfc,0x16,0xf1,0x6b,0xd8,0x1f,0xe9,0x6d,0xc5,0x00,0xbc,0x43,
	0xe1,0xcd,0x58,0x00,0xbe,0xf9,0xd7,0x2b,0x3d,0x03,0x0b,0xdb,0x7e,0x86,0x0e,0x10,
	0xc5,0x22,0xe4,0x24,0x6b,0x30,0xbd,0x93,0xb7,0x0e,0x13,0x9f,0xd3,0x84,0xff,0x10,
	0x5d,0x37,0x7f,0xd2,0xbf,0xe3,0x6c,0x74,0x38,0xdd,0x73,0x09,0x3a,0xfc,0xad,0xe3,
	0x0c,0x22,0x38,0x91,0xed,0x19,0xe2,0xa1,0x57,0xb6,0xd5,0xe2,0x0c,0xc1,0xbb,0x91,
	0xc3,0x77,0x5b,0x59,0x87,0x7f,0x2d,0xcc,0xd5,0x61,0xb3,0x3d,0xdb,0x87,0x8d,0x64,
	0x91,0x3f,0x70,0x4f,0xb7,0x2c,0x94,0x9a,0xb2,0x9d,0x58,0xdf,0x74,0x5b,0xbf,0x59,
	0x87,0xee,0xf0,0xad,0x36,0x03,0x6f,0x49,0x33,0x46,0xbe,0x85,0x40,0xda,0x52,0xf7,
	0x59,0x43,0x02,0x09,0x4d,0xec,0xef,0x5d,0x13,0xba,0x6e,0x98,0xba,0x9b,0x5e,0x01,
	0xd1,0xc8,0x56,0xc6,0x03,0xf1,0x77,0x9b,0xf7,0x15,0xd8,0xcd,0x94,0x21,0xc9,0xb3,
	0x6d,0x9d,0xf4,0x27,0x2f,0xfe,0xde,0x8d,0x59,0x1b,0xa4,0xfe,0x1d,0x68,0x2b,0xe2,
	0xd0,0x6c,0x7d,0x0a,0xb0,0xcd,0xbe,0x43,0x8a,0xd1,0x09,0x67,0xa8,0x2f,0x68,0xe4,
	0xad,0x76,0xb0,0x94,0x2d,0x2b,0x38,0x0e,0x93,0xc1,0x46,0xda,0xac,0x53,0x1a,0xff,
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
	0x57,0x57,0x65,0x17,0x0c,0xee,0x66,0x9c,0x56,0x66,0xe4,0x15,0x16,0x23,0xa9,0xc6,
	0xa2,0x86,0x11,0xf5,0x30,0x9c,0xcc,0x56,0xeb,0x54,0x0d,0xce,0x75,0x29,0xa3,0x60,
	0x05,0x5d,0x46,0xce,0x24,0x86,0x35,0x8f,0x2d,0xdb,0x92,0x18,0xe7,0xac,0x50,0xfa,
	0x51,0x50,0x05,0x55,0x52,0x56,0x3c,0x45,0xe2,0xfb,0x03,0xca,0x48,0x44,0x24,0xd6,
	0xa0,0x48,0x72,0x68,0xe3,0xc8,0x7e,0x47,0x71,0x05,0x83,0xd7,0x8c,0xf0,0xe2,0xff,
	0xde,0x97,0x68,0x54,0x03,0x4f,0x4e,0x24,0xfe,0x8a,0x53,0xbc,0xcc,0xbb,0x15,0xdc,
	0x03,0x44,0x69,0xb5,0x66,0x94,0x88,0x1e,0x99,0x24,0x75,0x92,0x01,0x46,0x61,0x4e,
	0x87,0x5f,0xa3,0xb9,0xbc,0x33,0x82,0xb5,0xee,0x88,0xab,0xde,0x57,0x74,0x43,0x23,
	0x13,0x7b,0x60,0xac,0x3b,0xd7,0xfe,0xb4,0x20,0xc9,0x58,0xd6,0x4f,0xaf,0x08,0xf6,
	0x58,0xbb,0xc6,0xe1,0xe5,0x17,0x3e,0xd1,0x37,0x1a,0x72,0xe6,0x7b,0x18,0xd3,0x06,
	0xe8,0xf5,0x7a,0xbc,0x8e,0x61,0xe0,0xce,0xea,0x6b,0x1c,0xf5,0x2d,0x0f,0x58,0x37,
	0x35,0xe6,0x50,0x77,0xc8,0x47,0xb0,0x3f,0xa2,0x97,0xb0,0x08,0x23,0xfc,0x4b,0xfd,
	0x4e,0x62,0xae,0x11,0x19,0x09,0xc8,0x89,0xea,0xf6,0x48,0x3a,0x72,0x32,0xe0,0xaa,
	0x66,0xeb,0xcf,0x06,0x06,0x7e,0x30,0xa9,0xc9,0x30,0x7e,0x07,0x7a,0xa1,0x50,0x06,
	0x18,0x83,0x53,0x26,0x9a,0xf1,0xb4,0x37,0xcb,0x0f,0x52,0x4e,0x0b,0xdd,0xe3,0x4c,
	0x88,0x6d,0x51,0xd5,0x38,0x1f,0x86,0x91,0x2c,0xe5,0x40,0xd2,0x2c,0xd2,0x88,0x3f,
	0x10,0x6e,0x4e,0x8d,0x5c,0xc4,0x7c,0x99,0x75,0xe6,0x67,0x64,0x74,0x11,0x43,0xff,
	0x26,0xeb,0x2a,0xf1,0x96,0xd3,0x8d,0x64,0x8d,0x6f,0xa1,0xa9,0xe1,0x66,0x79,0xd6,
	0x4a,0x55,0xcb,0xce,0xa6,0x2c,0x63,0x64,0xa2,0x32,0x19,0x98,0x0a,0x7a,0x02,0x82,
	0x2c,0xa6,0xf0,0x9e,0x70,0x48,0xcd,0x04,0x9a,0x14,0x1d,0x36,0x7e,0x55,0x62,0x75,
	0xb2,0x3a,0x17,0x84,0xfa,0x43,0x3b,0x96,0xbd,0xc6,0xb5,0x05,0x69,0x9e,0xc7,0x3f,
	0xaf,0x2a,0xa3,0xf2,0x07,0x8a,0xdd,0xb2,0x52,0xf9,0x02,0xb0,0x6a,0x0a,0xf8,0x1f,
	0x12,0xf6,0xd9,0xe1,0xf8,0xb6,0x0b,0x1f,0x35,0x53,0x8f,0x76,0x54,0x07,0xa5,0x77,
	0x5e,0x54,0x09,0xc4,0x21,0x14,0xc7,0xd8,0xbd,0xf4,0xcc,0xc1,0xd6,0x1c,0xac,0x91,
	0x32,0x09,0x01,0x15,0x4e,0xb7,0x05,0x97,0x50,0x1c,0x3b,0xca,0x1f,0xa5,0x4b,0x95,
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
	0x73,0x6b,0x52,0x7b,0x92,0x93,0xb7,0x8b,0x7d,0xb9,0x97,0x86,0x47,0x0f,0x70,0x38,
	0x96,0x2a,0x35,0xbd,0x77,0x03,0xf4,0x84,0x47,0x3e,0xf0,0xa7,0x47,0x86,0xe3,0x1e,
	0x3d,0x93,0xd0,0xbf,0x54,0xbb,0xed,0x85,0x04,0x00,0x00,0x00,0x53,0x4b,0x55,0x31,
	0x01,0x00,0x01,0x00,0x03,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0xee,0xee,0xee,0xee,
	0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,
	0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x01,0x00,0x00,0x00,
	0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
	0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
	0x02,0x00,0x00,0x00,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,
	0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,
	0x22,0x22,0x22,0x22,0x00,0x02,0x00,0x00,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
	0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
	0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,
	0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,
	0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0x04,0x01,0x00,0x00,0xcc,0xcc,0xcc,0xcc,
	0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,
	0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0x01,0x02,0x01,0x00,
	0x04,0x00,0x02,0x00,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
	0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
	0xdd,0xdd,0xdd,0xdd,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,
	0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,
	0xee,0xee,0xee,0xee,0x02,0x02,0x01,0x00,0x04,0x00,0x01,0x00,0xcc,0xcc,0xcc,0xcc,
	0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,
	0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0x01,0x02,0x00,0x00,
	0x80,0x02,0x06,0x00,0x00,0xff,0x00,0xff,0xff,0x00,0x00,0x00,0x02,0x00,0x05,0x00,
	0x54,0x65,0x73,0x74,0x31,0x00,0x00,0x00,0x02,0x00,0x05,0x00,0x54,0x65,0x73,0x74,
	0x32,0x00,0x00,0x00,0x04,0x01,0x05,0x00,0x00,0x00,0xff,0x00,0x00,0x00,0x00,0x00,
	0x02,0x00,0x05,0x00,0x00,0x00,0x22,0x00,0x00,0x00,0x00,0x00,0x01,0x04,0x00,0x00,
	0x01,0x01,0x02,0x00,0x00,0xff,0x00,0x00,0x02,0x00,0x02,0x00,0x65,0x43,0x00,0x00,
	0x81,0x01,0x00,0x00,0x02,0x00,0x02,0x00,0x10,0x11,0x00,0x00,0x01,0x09,0x70,0x6c,
	0x61,0x74,0x66,0x6f,0x72,0x6d,0x41,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x99,0x00,
	0x00,0x00,0x9a,0x00,0x00,0x00,0x04,0x01,0x00,0x00,0x9d,0x00,0x00,0x00,0x02,0x09,
	0x70,0x6c,0x61,0x74,0x66,0x6f,0x72,0x6d,0x42,0x00,0x00,0x00,0x03,0x01,0x00,0x00,
	0x55,0x00,0x00,0x00,0x01,0x09,0x70,0x6c,0x61,0x74,0x66,0x6f,0x72,0x6d,0x43,0x00,
	0x00,0x00,0x84,0x01,0x00,0x00,0x12,0x00,0x00,0x00,0x02,0x09,0x70,0x6c,0x61,0x74,
	0x66,0x6f,0x72,0x6d,0x45,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0xab,0x00,0x00,0x00,
	0x00,0x09,0x70,0x6c,0x61,0x74,0x66,0x6f,0x72,0x6d,0x44,0x00,0x00,0x00,0x03,0x01,
	0x00,0x00,0x34,0x00,0x00,0x00,0x00,0x01,0x0a,0x00,0x04,0x00,0x00,0x00,0x01,0x00,
	0x00,0x00,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,
	0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,
	0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,0xee,
	0xee,0xee,0x00,0x00,0x00,0x00,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,
	0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,
	0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,
	0x33,0x33,0x33,0x33,0x33,0x33,0x02,0x01,0x00,0x00,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,
	0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,
	0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,
	0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0x01,0x05,0x01,0x00,0x04,0x00,
	0x01,0x00,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
	0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
	0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
	0xdd,0xdd,0x01,0x03,0x00,0x00,0x04,0x01,0x03,0x00,0xff,0x0f,0xff,0x00,0x02,0x00,
	0x03,0x00,0x12,0x34,0x56,0x00,0x02,0x09,0x70,0x6c,0x61,0x74,0x66,0x6f,0x72,0x6d,
	0x31,0x00,0x00,0x00,0x05,0x01,0x00,0x00,0x12,0x00,0x00,0x00,0x00,0x09,0x70,0x6c,
	0x61,0x74,0x66,0x6f,0x72,0x6d,0x32,0x00,0x00,0x00,0x03,0x01,0x00,0x00,0x34,0x00,
	0x00,0x00,0x00,0x09,0x70,0x6c,0x61,0x74,0x66,0x6f,0x72,0x6d,0x33,0x00,0x00,0x00,
	0x02,0x01,0x00,0x00,0x56,0x00,0x00,0x00,0x11,0x0a,0x6e,0x83,0x2e,0x5a,0xbd,0x24,
	0x6b,0x60,0x0c,0xb9,0x22,0x2b,0x6f,0x58,0x0f,0xab,0x21,0x43,0x85,0x0d,0x18,0xa6,
	0x15,0x1a,0x6b,0xd9,0x1b,0xfe,0x46,0x5a,0xbf,0x20,0xae,0xb0,0x4e,0x6f,0x1d,0x18,
	0x11,0x5f,0x17,0x43,0x6a,0x89,0x7d,0xa7,0x80,0x59,0x15,0xfa,0x85,0x1a,0x77,0x7e,
	0x75,0x65,0xfe,0xcf,0x82,0x09,0x8d,0x3d,0x46,0xb1,0xb1,0x2c,0xf7,0x6d,0x5a,0x6f,
	0x76,0x68,0xa2,0x7b,0x7f,0x9b,0xc8,0x75,0x66,0x88,0x26,0x79,0xd3,0xb7,0x7a,0x0f,
	0x4b,0xe8,0xc8,0x53,0x0a,0x70,0xad,0xfc,0xe8,0xee,0x92,0xd6,0x59,0xd5,0xfc,0xf6,
	0xab,0xdd,0xa4,0x6b,0xb8,0xaa,0x91,0xb0,0x20,0x1e,0x2d,0xa2,0x98,0x8e,0x8e,0xf7,
	0x93,0x7d,0xdb,0x87,0x7c,0x6a,0x03,0x8b,0x15,0x39,0x31,0x6a,0xad,0x2b,0x30,0x74,
	0xa9,0xfd,0x37,0x98,0x37,0xdc,0xac,0x2c,0x83,0xb8,0x67,0xe8,0x15,0x41,0x5f,0x37,
	0xc0,0x31,0x7c,0x9a,0x2d,0xfc,0x28,0x5d,0x84,0x57,0x35,0x49,0xc0,0x99,0xf2,0xb0,
	0x19,0x07,0xef,0x91,0x19,0x1b,0xbf,0x71,0x8f,0x77,0x65,0xd2,0xf6,0x42,0x6d,0xd6,
	0x44,0x93,0xdb,0x47,0xa6,0xe2,0x8d,0xb1,0x18,0xe1,0xd3,0x4f,0x92,0xce,0x5b,0x5e,
	0xb0,0x3c,0xdd,0x5b,0x0a,0xea,0xae,0x8d,0xf1,0x39,0x39,0xfe,0x47,0xd9,0x6f,0x34,
	0x44,0x00,0x02,0xb8,0x5e,0xf1,0x3f,0x80,0x33,0xe9,0x58,0x39,0x4b,0xb2,0xed,0x0c,
	0xb8,0xf0,0x93,0x91,0x51,0x2b,0xb0,0x19,0xf2,0xd1,0x5b,0x86,0x12,0x14,0xa3,0x7e,
	0xe5,0x66,0x37,0x38,0x24,0x4d,0xd0,0x2a
};

/**
 * Length of the test CFM data.
 */
const uint32_t CFM_NONZERO_VERSION_SET_LEN = sizeof (CFM_NONZERO_VERSION_SET_DATA);
/**
 * CFM with non-zero version sets for testing hash for testing.
 *
 * head -c -256 <file> | openssl dgst -sha256 -binary | to_array.sh -
 */
const uint8_t CFM_NONZERO_VERSION_SET_HASH[] = {
	0xa3,0x55,0x4a,0x6c,0x4c,0xbf,0x78,0x70,0x70,0xa8,0xd9,0xc8,0xc7,0x10,0xd9,0x35,
	0x9f,0x28,0x75,0x6b,0x65,0x04,0x1a,0xa2,0xfe,0xc3,0xa8,0x16,0x10,0xe4,0xe1,0x82
};
/**
 * The platform identifier in the CFM data
 */
const char CFM_NONZERO_VERSION_SET_PLATFORM_ID[] = "SKU1";
/**
 * Components of the test CFM.
 */
const struct cfm_testing_data CFM_NONZERO_VERSION_SET_TESTING = {
	.manifest = {
		.raw = CFM_NONZERO_VERSION_SET_DATA,
		.length = sizeof (CFM_NONZERO_VERSION_SET_DATA),
		.hash = CFM_NONZERO_VERSION_SET_HASH,
		.hash_len = sizeof (CFM_NONZERO_VERSION_SET_HASH),
		.id = 0x1,
		.signature =
			CFM_NONZERO_VERSION_SET_DATA + (sizeof (CFM_NONZERO_VERSION_SET_DATA) - 256),
		.sig_len = 256,
		.sig_offset = (sizeof (CFM_NONZERO_VERSION_SET_DATA) - 256),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = CFM_NONZERO_VERSION_SET_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x618,
		.toc_hash = CFM_NONZERO_VERSION_SET_DATA + 0x628,
		.toc_hash_len = 32,
		.toc_hash_offset = 0x628,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 39,
		.toc_hashes = 39,
		.plat_id = CFM_NONZERO_VERSION_SET_DATA + 0x648,
		.plat_id_len = 0x8,
		.plat_id_str = CFM_NONZERO_VERSION_SET_PLATFORM_ID,
		.plat_id_str_len = sizeof (CFM_NONZERO_VERSION_SET_PLATFORM_ID) - 1,
		.plat_id_str_pad = 0,
		.plat_id_offset = 0x648,
		.plat_id_entry = 0,
		.plat_id_hash = 0
	},
	.component_device1_len = 0x08,
	.component_device1_offset = 0x650,
	.component_device1_entry = 1,
	.component_device1_hash = 1,
	.component_device2_len = 0x08,
	.component_device2_offset = 0x896,
	.component_device2_entry = 26,
	.component_device2_hash = 26,
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
 * Initialize CFM for testing with mocked hash engine.
 *
 * @param test The testing framework.
 * @param cfm The testing components to initialize.
 * @param address The base address for the CFM data.
 */
static void cfm_flash_testing_init_mocked_hash (CuTest *test, struct cfm_flash_testing *cfm,
	uint32_t address)
{
	int status;

	cfm_flash_testing_init_dependencies (test, cfm, address);
	manifest_flash_v2_testing_init_common (test, &cfm->manifest, 0x1000);

	status = cfm_flash_init (&cfm->test, &cfm->manifest.flash.base, &cfm->manifest.hash_mock.base,
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
 * Set up expectations for verifying a CFM on flash with mocked hash engine.
 *
 * @param test The testing framework.
 * @param cfm The testing components.
 * @param testing_data Container with testing data.
 * @param sig_result Result of the signature verification call.
 * @param hash_result Result of the call to finalize the manifest hash.
 */
static void cfm_flash_testing_verify_cfm_mocked_hash (CuTest *test, struct cfm_flash_testing *cfm,
	const struct cfm_testing_data *testing_data, int sig_result, int hash_result)
{
	manifest_flash_v2_testing_verify_manifest_mocked_hash (test, &cfm->manifest,
		&testing_data->manifest, sig_result, hash_result);
}

/**
 * Initialize a CFM for testing.  Run verification to load the CFM information.
 *
 * @param test The testing framework.
 * @param cfm The testing components to initialize.
 * @param address The base address for the CFM data.
 * @param testing_data Container with testing data.
 * @param sig_result Result of the signature verification call.
 * @param use_mock true to use the mock hash engine.
 * @param hash_result Result of the final hash call when using the mock hash engine.
 */
static void cfm_flash_testing_init_and_verify (CuTest *test, struct cfm_flash_testing *cfm,
	uint32_t address, const struct cfm_testing_data *testing_data, int sig_result, bool use_mock,
	int hash_result)
{
	struct hash_engine *hash =
		(!use_mock) ? &cfm->manifest.hash.base : &cfm->manifest.hash_mock.base;
	int status;

	if (!use_mock) {
		cfm_flash_testing_init (test, cfm, address);
		cfm_flash_testing_verify_cfm (test, cfm, testing_data, sig_result);
	}
	else {
		cfm_flash_testing_init_mocked_hash (test, cfm, address);
		cfm_flash_testing_verify_cfm_mocked_hash (test, cfm, testing_data, sig_result, hash_result);
	}

	status = cfm->test.base.base.verify (&cfm->test.base.base, hash,
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
	CuAssertPtrNotNull (test, cfm.test.base.get_next_measurement_or_measurement_data);
	CuAssertPtrNotNull (test, cfm.test.base.free_measurement_container);
	CuAssertPtrNotNull (test, cfm.test.base.free_root_ca_digest);
	CuAssertPtrNotNull (test, cfm.test.base.get_root_ca_digest);
	CuAssertPtrNotNull (test, cfm.test.base.free_manifest);
	CuAssertPtrNotNull (test, cfm.test.base.get_next_pfm);
	CuAssertPtrNotNull (test, cfm.test.base.get_next_cfm);
	CuAssertPtrNotNull (test, cfm.test.base.get_pcd);

	CuAssertIntEquals (test, 0x10000, manifest_flash_get_addr (&cfm.test.base_flash));
	CuAssertPtrEquals (test, &cfm.manifest.flash,
		(void*) manifest_flash_get_flash (&cfm.test.base_flash));

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

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

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

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

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

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

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

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

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

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

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

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

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

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

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

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	status = cfm.test.base.base.is_empty (&cfm.test.base.base);
	CuAssertIntEquals (test, 0, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_is_empty_empty (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_EMPTY_TESTING, 0, false, 0);

	status = cfm.test.base.base.is_empty (&cfm.test.base.base);
	CuAssertIntEquals (test, 1, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_is_empty_null (CuTest *test)
{
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_EMPTY_TESTING, 0, false, 0);

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

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 3, 2, 3,
		0x69c, 0x24, 0x24, 0);

	status = cfm.test.base.get_component_pmr (&cfm.test.base, 3, 1, &pmr);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, pmr.pmr_id);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, pmr.initial_value_len);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, pmr.hash_type);

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

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device2_entry, 2, CFM_TESTING.component_device2_hash,
		CFM_TESTING.component_device2_offset, CFM_TESTING.component_device2_len,
		CFM_TESTING.component_device2_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		27, 38);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 28, 27, 28,
		0x8d2, 0x34, 0x34, 0);

	status = cfm.test.base.get_component_pmr (&cfm.test.base, 4, 0, &pmr);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, pmr.pmr_id);
	CuAssertIntEquals (test, SHA384_HASH_LENGTH, pmr.initial_value_len);
	CuAssertIntEquals (test, HASH_TYPE_SHA384, pmr.hash_type);

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

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 3, 2, 3,
		0x69c, 0x24, 0x24, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 4,
		26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 4, 4, 4,
		0x6c0, 0x24, 0x24, 0);

	status = cfm.test.base.get_component_pmr (&cfm.test.base, 3, 2, &pmr);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, pmr.pmr_id);
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, pmr.initial_value_len);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, pmr.hash_type);

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

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	status = cfm.test.base.get_component_pmr (NULL, 3, 0, &pmr);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.get_component_pmr (&cfm.test.base, 3, 0, NULL);
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

	status = cfm.test.base.get_component_pmr (&cfm.test.base, 3, 0, &pmr);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_component_read_fail (CuTest *test)
{
	struct cfm_pmr pmr;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x08));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_component_pmr (&cfm.test.base, 3, 0, &pmr);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_component_not_found (CuTest *test)
{
	struct cfm_pmr pmr;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device2_entry, 2, CFM_TESTING.component_device2_hash,
		CFM_TESTING.component_device2_offset, CFM_TESTING.component_device2_len,
		CFM_TESTING.component_device2_len, 0);

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

	status = cfm.test.base.get_component_pmr (&cfm.test.base, 5, 0, &pmr);
	CuAssertIntEquals (test, MANIFEST_ELEMENT_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_component_has_no_pmr (CuTest *test)
{
	struct cfm_pmr pmr;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_ONLY_MEASUREMENT_DATA_TESTING,	0,
		false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_DATA_TESTING.manifest,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_entry, 0,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_hash,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_offset,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_len,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_DATA_TESTING.manifest, 2, 4);

	status = cfm.test.base.get_component_pmr (&cfm.test.base, 3, 0, &pmr);
	CuAssertIntEquals (test, CFM_PMR_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_get_num_pmr_fail (CuTest *test)
{
	struct cfm_pmr pmr;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

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

	status = cfm.test.base.get_component_pmr (&cfm.test.base, 3, 0, &pmr);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_pmr_read_fail (CuTest *test)
{
	struct cfm_pmr pmr;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x10));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_component_pmr (&cfm.test.base, 3, 0, &pmr);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_pmr_not_found (CuTest *test)
{
	struct cfm_pmr pmr;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 3, 2, 3,
		0x69c, 0x24, 0x24, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 4,
		26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 4, 4, 4,
		0x6c0, 0x24, 0x24, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 5,
		26);

	status = cfm.test.base.get_component_pmr (&cfm.test.base, 3, 3, &pmr);
	CuAssertIntEquals (test, CFM_PMR_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_digest (CuTest *test)
{
	struct cfm_pmr_digest pmr_digest;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 5, 2, 5,
		0x6e4, 0x44, sizeof (struct cfm_pmr_digest_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 5, 5, 5,
		0x6e4, 0x44, 0x44 - sizeof (struct cfm_pmr_digest_element),
		sizeof (struct cfm_pmr_digest_element));

	status = cfm.test.base.get_component_pmr_digest (&cfm.test.base, 3, 0, &pmr_digest);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, pmr_digest.pmr_id);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, pmr_digest.digests.hash_type);
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

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device2_entry, 2, CFM_TESTING.component_device2_hash,
		CFM_TESTING.component_device2_offset, CFM_TESTING.component_device2_len,
		CFM_TESTING.component_device2_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		27, 38);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 29, 27, 29,
		0x906, 0x34, sizeof (struct cfm_pmr_digest_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 29, 29, 29,
		0x906, 0x34, 0x34 - sizeof (struct cfm_pmr_digest_element),
		sizeof (struct cfm_pmr_digest_element));

	status = cfm.test.base.get_component_pmr_digest (&cfm.test.base, 4, 2, &pmr_digest);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, pmr_digest.pmr_id);
	CuAssertIntEquals (test, HASH_TYPE_SHA384, pmr_digest.digests.hash_type);
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

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,	5, 2, 5,
		0x6e4, 0x44, sizeof (struct cfm_pmr_digest_element), 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		6, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 6, 6, 6,
		0x728, 0x24, sizeof (struct cfm_pmr_digest_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 6, 6, 6,
		0x728, 0x24, 0x24 - sizeof (struct cfm_pmr_digest_element),
		sizeof (struct cfm_pmr_digest_element));

	status = cfm.test.base.get_component_pmr_digest (&cfm.test.base, 3, 4, &pmr_digest);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 4, pmr_digest.pmr_id);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, pmr_digest.digests.hash_type);
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

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	status = cfm.test.base.get_component_pmr_digest (NULL, 3, 0, &pmr_digest);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.get_component_pmr_digest (&cfm.test.base, 3, 0, NULL);
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

	status = cfm.test.base.get_component_pmr_digest (&cfm.test.base, 3, 0, &pmr_digest);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_digest_component_read_fail (CuTest *test)
{
	struct cfm_pmr_digest pmr_digest;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x08));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_component_pmr_digest (&cfm.test.base, 3, 0, &pmr_digest);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_digest_component_not_found (CuTest *test)
{
	struct cfm_pmr_digest pmr_digest;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device2_entry, 2, CFM_TESTING.component_device2_hash,
		CFM_TESTING.component_device2_offset, CFM_TESTING.component_device2_len,
		CFM_TESTING.component_device2_len, 0);

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

	status = cfm.test.base.get_component_pmr_digest (&cfm.test.base, 5, 0, &pmr_digest);
	CuAssertIntEquals (test, MANIFEST_ELEMENT_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_digest_component_has_no_pmr_digest (CuTest *test)
{
	struct cfm_pmr_digest pmr_digest;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_ONLY_MEASUREMENT_DATA_TESTING,	0,
		false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_DATA_TESTING.manifest,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_entry, 0,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_hash,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_offset,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_len,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_DATA_TESTING.manifest, 2, 4);

	status = cfm.test.base.get_component_pmr_digest (&cfm.test.base, 3, 0, &pmr_digest);
	CuAssertIntEquals (test, CFM_PMR_DIGEST_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_digest_get_num_pmr_digest_fail (CuTest *test)
{
	struct cfm_pmr_digest pmr_digest;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

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

	status = cfm.test.base.get_component_pmr_digest (&cfm.test.base, 3, 0, &pmr_digest);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_digest_pmr_digest_read_fail (CuTest *test)
{
	struct cfm_pmr_digest pmr_digest;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x10));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_component_pmr_digest (&cfm.test.base, 3, 0, &pmr_digest);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_digest_pmr_not_found (CuTest *test)
{
	struct cfm_pmr_digest pmr_digest;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,	5, 2, 5,
		0x6e4, 0x44, sizeof (struct cfm_pmr_digest_element), 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 6,
		26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 6, 6, 6,
		0x728, 0x24, sizeof (struct cfm_pmr_digest_element), 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 7,
		26);

	status = cfm.test.base.get_component_pmr_digest (&cfm.test.base, 3, 1, &pmr_digest);
	CuAssertIntEquals (test, CFM_PMR_DIGEST_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_digest_digests_read_fail (CuTest *test)
{
	struct cfm_pmr_digest pmr_digest;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 5, 2, 5,
		0x6e4, 0x44, sizeof (struct cfm_pmr_digest_element), 0);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x28));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_component_pmr_digest (&cfm.test.base, 3, 0, &pmr_digest);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_digest_invalid_hash_type (CuTest *test)
{
	struct cfm_pmr_digest pmr_digest;
	struct cfm_flash_testing cfm;
	int status;
	struct manifest_toc_entry component_entry;
	struct cfm_component_device_element bad_data;
	struct cfm_component_device_element *bad_data_ptr = &bad_data;

	TEST_START;

	component_entry.type_id = CFM_COMPONENT_DEVICE;
	component_entry.parent = 0xff;
	component_entry.format = 0;
	component_entry.hash_id = CFM_TESTING.component_device1_entry;
	component_entry.offset = CFM_TESTING.component_device1_offset;
	component_entry.length = CFM_TESTING.component_device1_len;

	bad_data_ptr->attestation_protocol = 0;
	bad_data_ptr->cert_slot = 1;
	bad_data_ptr->transcript_hash_type = HASH_TYPE_SHA256;
	bad_data_ptr->measurement_hash_type = 7;
	bad_data_ptr->reserved = 0;
	bad_data_ptr->reserved2 = 0;
	bad_data_ptr->component_id = 3;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, true, 0);

	manifest_flash_v2_testing_read_element_mocked_hash_bad_entry (test, &cfm.manifest,
		&CFM_TESTING.manifest, component_entry.hash_id, 0, component_entry.hash_id,
		component_entry.offset, component_entry.length, component_entry.length, 0, &component_entry,
		(uint8_t*) bad_data_ptr);

	status = cfm.test.base.get_component_pmr_digest (&cfm.test.base, 3, 1, &pmr_digest);
	CuAssertIntEquals (test, CFM_INVALID_MEASUREMENT_HASH_TYPE, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_pmr_digest_malformed_pmr_digest (CuTest *test)
{
	struct cfm_pmr_digest pmr_digest;
	struct cfm_flash_testing cfm;
	int status;
	struct manifest_toc_entry bad_entry;
	uint8_t bad_data[3];

	TEST_START;

	bad_entry.type_id = CFM_PMR_DIGEST;
	bad_entry.parent = CFM_COMPONENT_DEVICE;
	bad_entry.format = 0;
	bad_entry.hash_id = 5;
	bad_entry.offset = 0x6e4;
	bad_entry.length = sizeof (bad_data);

	memset (bad_data, 0x66, sizeof (bad_data));

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, true, 0);

	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_TESTING.manifest, 2, 26);

	manifest_flash_v2_testing_read_element_mocked_hash_bad_entry (test, &cfm.manifest,
		&CFM_TESTING.manifest, bad_entry.hash_id, 2, bad_entry.hash_id, bad_entry.offset,
		bad_entry.length, bad_entry.length, 0, &bad_entry, NULL);

	status = cfm.test.base.get_component_pmr_digest (&cfm.test.base, 3, 0, &pmr_digest);
	CuAssertIntEquals (test, CFM_MALFORMED_PMR_DIGEST_ENTRY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_free_component_pmr_digest_null (CuTest *test)
{
	struct cfm_flash_testing cfm;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	cfm.test.base.free_component_pmr_digest (&cfm.test.base, NULL);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_buffer_supported_components (CuTest *test)
{
	struct cfm_flash_testing cfm;
	uint32_t components[4096 / sizeof (uint32_t)];
	size_t components_len = sizeof (components);
	uint32_t component1 = 3;
	uint32_t component2 = 4;
	size_t component_len = sizeof (component1);
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device2_entry, 2, CFM_TESTING.component_device2_hash,
		CFM_TESTING.component_device2_offset, CFM_TESTING.component_device2_len,
		CFM_TESTING.component_device2_len, 0);

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
		(uint8_t*) components);
	CuAssertIntEquals (test, component_len * 2, status);
	CuAssertIntEquals (test, component1, components[0]);
	CuAssertIntEquals (test, component2, components[1]);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_buffer_supported_components_offset_nonzero (CuTest *test)
{
	struct cfm_flash_testing cfm;
	uint32_t components[4096 / sizeof (uint32_t)];
	uint32_t component1 = 3;
	uint32_t component2 = 4;
	size_t component_len = sizeof (component1);
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	status = cfm.test.base.buffer_supported_components (&cfm.test.base, 0, component_len,
		(uint8_t*) components);
	CuAssertIntEquals (test, component_len, status);
	CuAssertIntEquals (test, component1, components[0]);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device2_entry, 2, CFM_TESTING.component_device2_hash,
		CFM_TESTING.component_device2_offset, CFM_TESTING.component_device2_len,
		CFM_TESTING.component_device2_len, 0);

	status = cfm.test.base.buffer_supported_components (&cfm.test.base, component_len,
		component_len, (uint8_t*) &components[1]);
	CuAssertIntEquals (test, component_len, status);
	CuAssertIntEquals (test, component2, components[1]);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_buffer_supported_components_offset_too_large (CuTest *test)
{
	struct cfm_flash_testing cfm;
	uint32_t components[2];
	size_t components_len = sizeof (components);
	size_t component_len = sizeof (uint32_t);
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device2_entry, 2, CFM_TESTING.component_device2_hash,
		CFM_TESTING.component_device2_offset, CFM_TESTING.component_device2_len,
		CFM_TESTING.component_device2_len, 0);

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

	status = cfm.test.base.buffer_supported_components (&cfm.test.base, component_len * 2,
		components_len, (uint8_t*) components);
	CuAssertIntEquals (test, MANIFEST_ELEMENT_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_buffer_supported_components_offset_not_word_aligned (CuTest *test)
{
	struct cfm_flash_testing cfm;
	uint32_t components[4096 / sizeof (uint32_t)];
	uint32_t component1 = 3;
	size_t component_len = sizeof (component1);
	size_t offset = component_len - 1; // offset inside of the component
	int status;

	TEST_START;

	components[0] = 0;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	status = cfm.test.base.buffer_supported_components (&cfm.test.base, 0, offset,
		(uint8_t*) components);
	CuAssertIntEquals (test, offset, status);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	status = cfm.test.base.buffer_supported_components (&cfm.test.base, offset,
		component_len - offset, (uint8_t*) &components[offset]);
	CuAssertIntEquals (test, component_len - offset, status);
	CuAssertIntEquals (test, component1, components[0]);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_buffer_supported_components_offset_in_second_component (CuTest *test)
{
	struct cfm_flash_testing cfm;
	uint32_t components[4096 / sizeof (uint32_t)];
	uint32_t component1 = 3;
	uint32_t component2 = 4;
	size_t component_len = sizeof (component1);
	size_t components_len = 2 * component_len;
	size_t offset = component_len + 1; // offset inside of the second component
	int status = 0;

	TEST_START;

	components[0] = 0;
	components[1] = 0;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device2_entry, 2, CFM_TESTING.component_device2_hash,
		CFM_TESTING.component_device2_offset, CFM_TESTING.component_device2_len,
		CFM_TESTING.component_device2_len, 0);

	status = cfm.test.base.buffer_supported_components (&cfm.test.base, 0, offset,
		(uint8_t*) components);
	CuAssertIntEquals (test, offset, status);
	CuAssertIntEquals (test, component1, components[0]);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device2_entry, 2, CFM_TESTING.component_device2_hash,
		CFM_TESTING.component_device2_offset, CFM_TESTING.component_device2_len,
		CFM_TESTING.component_device2_len, 0);

	status = cfm.test.base.buffer_supported_components (&cfm.test.base, offset,
		components_len - offset, (uint8_t*) &components[offset]);
	CuAssertIntEquals (test, components_len - offset, status);
	CuAssertIntEquals (test, component2, components[1]);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_buffer_supported_components_null (CuTest *test)
{
	struct cfm_flash_testing cfm;
	uint32_t components[2];
	size_t components_len = sizeof (components);
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	status = cfm.test.base.buffer_supported_components (NULL, 0, components_len,
		(uint8_t*) components);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.buffer_supported_components (&cfm.test.base, 0, components_len, NULL);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.buffer_supported_components (&cfm.test.base, 0, 0,
		(uint8_t*) components);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_buffer_supported_components_verify_never_run (CuTest *test)
{
	struct cfm_flash_testing cfm;
	uint32_t components[2];
	size_t components_len = sizeof (components);
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = cfm.test.base.buffer_supported_components (&cfm.test.base, 0, components_len,
		(uint8_t*) components);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_buffer_supported_components_component_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	uint32_t components[2];
	size_t components_len = sizeof (components);
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x08));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.buffer_supported_components (&cfm.test.base, 0, components_len,
		(uint8_t*) components);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_buffer_supported_components_malformed_component_device (CuTest *test)
{
	struct cfm_flash_testing cfm;
	uint32_t components[4096 / sizeof (uint32_t)];
	size_t components_len = sizeof (components);
	int status;
	struct manifest_toc_entry bad_entry;
	uint8_t bad_data[3];

	TEST_START;

	bad_entry.type_id = CFM_COMPONENT_DEVICE;
	bad_entry.parent = 0xff;
	bad_entry.format = 0;
	bad_entry.hash_id = CFM_TESTING.component_device1_hash;
	bad_entry.offset = CFM_TESTING.component_device1_offset;
	bad_entry.length = sizeof (bad_data);

	memset (bad_data, 0x66, sizeof (bad_data));

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, true, 0);

	manifest_flash_v2_testing_read_element_mocked_hash_bad_entry (test, &cfm.manifest,
		&CFM_TESTING.manifest, CFM_TESTING.component_device1_entry, 0,
		CFM_TESTING.component_device1_hash, CFM_TESTING.component_device1_offset, bad_entry.length,
		bad_entry.length, 0, &bad_entry, NULL);

	status = cfm.test.base.buffer_supported_components (&cfm.test.base, 0, components_len,
		(uint8_t*) components);
	CuAssertIntEquals (test, CFM_MALFORMED_COMPONENT_DEVICE_ENTRY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_device (CuTest *test)
{
	struct cfm_component_device component;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 5, 2, 5,
		0x6e4, 0x44, sizeof (struct cfm_pmr_digest_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 6, 6, 6,
		0x728, 0x24, sizeof (struct cfm_pmr_digest_element), 0);

	status = cfm.test.base.get_component_device (&cfm.test.base, 3, &component);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, component.cert_slot);
	CuAssertIntEquals (test, 0, component.attestation_protocol);
	CuAssertIntEquals (test, HASH_TYPE_SHA384, component.transcript_hash_type);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, component.measurement_hash_type);
	CuAssertIntEquals (test, 3, component.component_id);
	CuAssertIntEquals (test, 0, component.pmr_id_list[0]);
	CuAssertIntEquals (test, 4, component.pmr_id_list[1]);
	CuAssertIntEquals (test, 2, component.num_pmr_ids);

	cfm.test.base.free_component_device (&cfm.test.base, &component);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_device_second_component (CuTest *test)
{
	struct cfm_component_device component;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device2_entry, 2, CFM_TESTING.component_device2_hash,
		CFM_TESTING.component_device2_offset, CFM_TESTING.component_device2_len,
		CFM_TESTING.component_device2_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		27, 38);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 29, 27, 29,
		0x906, 0x34, sizeof (struct cfm_pmr_digest_element), 0);

	status = cfm.test.base.get_component_device (&cfm.test.base, 4, &component);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, component.cert_slot);
	CuAssertIntEquals (test, 1, component.attestation_protocol);
	CuAssertIntEquals (test, HASH_TYPE_SHA512, component.transcript_hash_type);
	CuAssertIntEquals (test, HASH_TYPE_SHA384, component.measurement_hash_type);
	CuAssertIntEquals (test, 4, component.component_id);
	CuAssertIntEquals (test, 2, component.pmr_id_list[0]);
	CuAssertIntEquals (test, 1, component.num_pmr_ids);

	cfm.test.base.free_component_device (&cfm.test.base, &component);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_device_null (CuTest *test)
{
	struct cfm_component_device component;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	status = cfm.test.base.get_component_device (NULL, 3, &component);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.get_component_device (&cfm.test.base, 3, NULL);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_device_component_read_fail (CuTest *test)
{
	struct cfm_component_device component;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x08));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_component_device (&cfm.test.base, 3, &component);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_device_get_num_pmr_digest_fail (CuTest *test)
{
	struct cfm_component_device component;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x10));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_component_device (&cfm.test.base, 3, &component);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_device_pmr_digest_read_fail (CuTest *test)
{
	struct cfm_component_device component;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		26);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x10));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_component_device (&cfm.test.base, 3, &component);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_device_component_not_found (CuTest *test)
{
	struct cfm_component_device component;
	struct cfm_flash_testing cfm;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device2_entry, 2, CFM_TESTING.component_device2_hash,
		CFM_TESTING.component_device2_offset, CFM_TESTING.component_device2_len,
		CFM_TESTING.component_device2_len, 0);

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

	status = cfm.test.base.get_component_device (&cfm.test.base, 5, &component);
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

	status = cfm.test.base.get_component_device (&cfm.test.base, 3, &component);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_device_invalid_transcript_hash_type (CuTest *test)
{
	struct cfm_component_device component;
	struct cfm_flash_testing cfm;
	int status;
	struct manifest_toc_entry component_entry;
	struct cfm_component_device_element bad_data;
	struct cfm_component_device_element *bad_data_ptr = &bad_data;

	TEST_START;

	component_entry.type_id = CFM_COMPONENT_DEVICE;
	component_entry.parent = 0xff;
	component_entry.format = 0;
	component_entry.hash_id = CFM_TESTING.component_device1_entry;
	component_entry.offset = CFM_TESTING.component_device1_offset;
	component_entry.length = CFM_TESTING.component_device1_len;

	bad_data_ptr->attestation_protocol = 0;
	bad_data_ptr->cert_slot = 1;
	bad_data_ptr->transcript_hash_type = 6;
	bad_data_ptr->measurement_hash_type = HASH_TYPE_SHA256;
	bad_data_ptr->reserved = 0;
	bad_data_ptr->reserved2 = 0;
	bad_data_ptr->component_id = 3;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, true, 0);

	manifest_flash_v2_testing_read_element_mocked_hash_bad_entry (test, &cfm.manifest,
		&CFM_TESTING.manifest, component_entry.hash_id, 0, component_entry.hash_id,
		component_entry.offset, component_entry.length, component_entry.length, 0, &component_entry,
		(uint8_t*) bad_data_ptr);

	status = cfm.test.base.get_component_device (&cfm.test.base, 3, &component);
	CuAssertIntEquals (test, CFM_INVALID_TRANSCRIPT_HASH_TYPE, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_device_invalid_measurement_hash_type (CuTest *test)
{
	struct cfm_component_device component;
	struct cfm_flash_testing cfm;
	int status;
	struct manifest_toc_entry component_entry;
	struct cfm_component_device_element bad_data;
	struct cfm_component_device_element *bad_data_ptr = &bad_data;

	TEST_START;

	component_entry.type_id = CFM_COMPONENT_DEVICE;
	component_entry.parent = 0xff;
	component_entry.format = 0;
	component_entry.hash_id = CFM_TESTING.component_device1_entry;
	component_entry.offset = CFM_TESTING.component_device1_offset;
	component_entry.length = CFM_TESTING.component_device1_len;

	bad_data_ptr->attestation_protocol = 0;
	bad_data_ptr->cert_slot = 1;
	bad_data_ptr->transcript_hash_type = HASH_TYPE_SHA384;
	bad_data_ptr->measurement_hash_type = 5;
	bad_data_ptr->reserved = 0;
	bad_data_ptr->reserved2 = 0;
	bad_data_ptr->component_id = 3;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, true, 0);

	manifest_flash_v2_testing_read_element_mocked_hash_bad_entry (test, &cfm.manifest,
		&CFM_TESTING.manifest, component_entry.hash_id, 0, component_entry.hash_id,
		component_entry.offset, component_entry.length, component_entry.length, 0, &component_entry,
		(uint8_t*) bad_data_ptr);

	status = cfm.test.base.get_component_device (&cfm.test.base, 3, &component);
	CuAssertIntEquals (test, CFM_INVALID_MEASUREMENT_HASH_TYPE, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_device_malformed_component_device (CuTest *test)
{
	struct cfm_component_device component;
	struct cfm_flash_testing cfm;
	int status;
	struct manifest_toc_entry bad_entry;
	uint8_t bad_data[3];

	TEST_START;

	bad_entry.type_id = CFM_COMPONENT_DEVICE;
	bad_entry.parent = 0xff;
	bad_entry.format = 0;
	bad_entry.hash_id = CFM_TESTING.component_device1_hash;
	bad_entry.offset = CFM_TESTING.component_device1_offset;
	bad_entry.length = sizeof (bad_data);

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, true, 0);

	manifest_flash_v2_testing_read_element_mocked_hash_bad_entry (test, &cfm.manifest,
		&CFM_TESTING.manifest, CFM_TESTING.component_device1_entry, 0,
		CFM_TESTING.component_device1_hash, CFM_TESTING.component_device1_offset, bad_entry.length,
		bad_entry.length, 0, &bad_entry, NULL);

	status = cfm.test.base.get_component_device (&cfm.test.base, 3, &component);
	CuAssertIntEquals (test, CFM_MALFORMED_COMPONENT_DEVICE_ENTRY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_component_device_malformed_pmr_digest (CuTest *test)
{
	struct cfm_component_device component;
	struct cfm_flash_testing cfm;
	int status;
	struct manifest_toc_entry bad_entry;
	uint8_t bad_data[3];

	TEST_START;

	bad_entry.type_id = CFM_PMR_DIGEST;
	bad_entry.parent = CFM_COMPONENT_DEVICE;
	bad_entry.format = 0;
	bad_entry.hash_id = 5;
	bad_entry.offset = 0x6e4;
	bad_entry.length = sizeof (bad_data);

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, true, 0);

	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_TESTING.manifest, 2, 26);

	manifest_flash_v2_testing_read_element_mocked_hash_bad_entry (test, &cfm.manifest,
		&CFM_TESTING.manifest, bad_entry.hash_id, 2, bad_entry.hash_id, bad_entry.offset,
		bad_entry.length, bad_entry.length, 0, &bad_entry, NULL);

	status = cfm.test.base.get_component_device (&cfm.test.base, 3, &component);
	CuAssertIntEquals (test, CFM_MALFORMED_PMR_DIGEST_ENTRY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_free_component_device_null (CuTest *test)
{
	struct cfm_flash_testing cfm;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	cfm.test.base.free_component_device (&cfm.test.base, NULL);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_measurement_first (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	size_t bytes_read = 0;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	// Read Component element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		7);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		9);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		26);

	// Read Measurement element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 7, 2, 7,
		0x74c, 0x48, sizeof (struct cfm_measurement_element), bytes_read);
	bytes_read += sizeof (struct cfm_measurement_element);

	// Read Allowable Digest 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 7, 7, 7,
		0x74c, 0x48, sizeof (struct cfm_allowable_digest_element), bytes_read);
	bytes_read += sizeof (struct cfm_allowable_digest_element);

	// Read Allowable Digest 1 digests
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 7, 7, 7,
		0x74c, 0x48, 2 * SHA256_HASH_LENGTH, bytes_read);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CFM_MEASUREMENT_TYPE_DIGEST, container.measurement_type);
	CuAssertIntEquals (test, 1, container.measurement.digest.pmr_id);
	CuAssertIntEquals (test, 2, container.measurement.digest.measurement_id);
	CuAssertIntEquals (test, 1,	container.measurement.digest.allowable_digests_count);
	CuAssertIntEquals (test, 0,
		container.measurement.digest.allowable_digests[0].version_set);
	CuAssertIntEquals (test, HASH_TYPE_SHA256,
		container.measurement.digest.allowable_digests[0].digests.hash_type);
	CuAssertIntEquals (test, 2,
		container.measurement.digest.allowable_digests[0].digests.digest_count);

	status = testing_validate_array (MEASUREMENT_PMR_1_MEASUREMENT_2_DEVICE_1,
		container.measurement.digest.allowable_digests[0].digests.digests,
		sizeof (MEASUREMENT_PMR_1_MEASUREMENT_2_DEVICE_1));
	status |= testing_validate_array (MEASUREMENT_PMR_1_MEASUREMENT_2_DEVICE_1_2,
		container.measurement.digest.allowable_digests[0].digests.digests + \
		sizeof (MEASUREMENT_PMR_1_MEASUREMENT_2_DEVICE_1),
		sizeof (MEASUREMENT_PMR_1_MEASUREMENT_2_DEVICE_1_2));
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_measurement_container (&cfm.test.base, &container);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_measurement_nonzero_version_set (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	size_t bytes_read = 0;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_NONZERO_VERSION_SET_TESTING, 0,
		false, 0);

	// Read Component element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_NONZERO_VERSION_SET_TESTING.manifest,
		CFM_NONZERO_VERSION_SET_TESTING.component_device1_entry, 0,
		CFM_NONZERO_VERSION_SET_TESTING.component_device1_hash,
		CFM_NONZERO_VERSION_SET_TESTING.component_device1_offset,
		CFM_NONZERO_VERSION_SET_TESTING.component_device1_len,
		CFM_NONZERO_VERSION_SET_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_NONZERO_VERSION_SET_TESTING.manifest, 2, 7);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_NONZERO_VERSION_SET_TESTING.manifest, 2, 9);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_NONZERO_VERSION_SET_TESTING.manifest, 2, 26);

	// Read Measurement element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_NONZERO_VERSION_SET_TESTING.manifest, 7, 2, 7, 0x74c, 0x48,
		sizeof (struct cfm_measurement_element), bytes_read);
	bytes_read += sizeof (struct cfm_measurement_element);

	// Read Allowable Digest 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_NONZERO_VERSION_SET_TESTING.manifest, 7, 7, 7, 0x74c, 0x48,
		sizeof (struct cfm_allowable_digest_element), bytes_read);
	bytes_read += sizeof (struct cfm_allowable_digest_element);

	// Read Allowable Digest 1 digests
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_NONZERO_VERSION_SET_TESTING.manifest, 7, 7, 7, 0x74c, 0x48, 2 * SHA256_HASH_LENGTH,
		bytes_read);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CFM_MEASUREMENT_TYPE_DIGEST, container.measurement_type);
	CuAssertIntEquals (test, 1, container.measurement.digest.pmr_id);
	CuAssertIntEquals (test, 2, container.measurement.digest.measurement_id);
	CuAssertIntEquals (test, 1,
		container.measurement.digest.allowable_digests_count);
	CuAssertIntEquals (test, 4,
		container.measurement.digest.allowable_digests[0].version_set);
	CuAssertIntEquals (test, HASH_TYPE_SHA256,
		container.measurement.digest.allowable_digests[0].digests.hash_type);
	CuAssertIntEquals (test, 2,
		container.measurement.digest.allowable_digests[0].digests.digest_count);

	status = testing_validate_array (MEASUREMENT_PMR_1_MEASUREMENT_2_DEVICE_1,
		container.measurement.digest.allowable_digests[0].digests.digests,
		sizeof (MEASUREMENT_PMR_1_MEASUREMENT_2_DEVICE_1));
	status |= testing_validate_array (MEASUREMENT_PMR_1_MEASUREMENT_2_DEVICE_1_2,
		container.measurement.digest.allowable_digests[0].digests.digests + \
		sizeof (MEASUREMENT_PMR_1_MEASUREMENT_2_DEVICE_1),
		sizeof (MEASUREMENT_PMR_1_MEASUREMENT_2_DEVICE_1_2));
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_measurement_container (&cfm.test.base, &container);

	cfm_flash_testing_validate_and_release (test, &cfm);
}


static void cfm_flash_test_get_next_measurement_or_measurement_data_second_measurement (
	CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	size_t bytes_read = 0;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	// Read Component element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		7);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		9);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		26);

	// Read Measurement element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 7, 2, 7,
		0x74c, 0x48, sizeof (struct cfm_measurement_element), bytes_read);
	bytes_read += sizeof (struct cfm_measurement_element);

	// Read Allowable Digest 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 7, 7, 7,
		0x74c, 0x48, sizeof (struct cfm_allowable_digest_element), bytes_read);
	bytes_read += sizeof (struct cfm_allowable_digest_element);

	// Read Allowable Digest 1 digests
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 7, 7, 7,
		0x74c, 0x48, 2 * SHA256_HASH_LENGTH, bytes_read);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 8,
		26);

	bytes_read = 0;

	// Read Measurement element 2
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 8, 8, 8,
		0x794, 0x28, sizeof (struct cfm_measurement_element), bytes_read);
	bytes_read += sizeof (struct cfm_measurement_element);

	// Read Measurement element 2, Allowable Digest 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 8, 8, 8,
		0x794, 0x28, sizeof (struct cfm_allowable_digest_element), bytes_read);
	bytes_read += sizeof (struct cfm_allowable_digest_element);

	// Read Measurement element 2, Allowable Digest 1 digests
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 8, 8, 8,
		0x794, 0x28, SHA256_HASH_LENGTH, bytes_read);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		false);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CFM_MEASUREMENT_TYPE_DIGEST, container.measurement_type);
	CuAssertIntEquals (test, 2, container.measurement.digest.pmr_id);
	CuAssertIntEquals (test, 2, container.measurement.digest.measurement_id);
	CuAssertIntEquals (test, 1,
		container.measurement.digest.allowable_digests_count);
	CuAssertIntEquals (test, 0,
		container.measurement.digest.allowable_digests[0].version_set);
	CuAssertIntEquals (test, HASH_TYPE_SHA256,
		container.measurement.digest.allowable_digests[0].digests.hash_type);
	CuAssertIntEquals (test, 1,
		container.measurement.digest.allowable_digests[0].digests.digest_count);

	status = testing_validate_array (MEASUREMENT_PMR_2_MEASUREMENT_2_DEVICE_1,
		container.measurement.digest.allowable_digests[0].digests.digests,
		sizeof (MEASUREMENT_PMR_2_MEASUREMENT_2_DEVICE_1));
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_measurement_container (&cfm.test.base, &container);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_measurement_after_measurement_data (
	CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	uint32_t bytes_read = 0;
	size_t offset = 0;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_MEASUREMENT_DATA_FIRST_TESTING, 0,
		false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_entry, 0,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_hash,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_offset,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 13);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 7);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 26);

	// Read Measurement Data element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 7, 2, 7, 0x74c, 0x4, 0x4, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 10);

	// Read Allowable Data element 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 1 bitmask
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24, 6, offset); // Bitmask of length 6
	offset += 8; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 1, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 1, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24, 5, offset);
	offset += 8; // Advance offset by data length and padding length

	// Read Allowable Data element 1, Data entry 2 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 1, Data entry 2 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24, 5, offset);

	offset = 0;

	// Read Allowable Data element 2
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 9, 9, 9, 0x774, 0x18,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 2 bitmask
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 9, 9, 9, 0x774, 0x18, 5, offset); // Bitmask of length 5
	offset += 8; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 2, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 9, 9, 9, 0x774, 0x18,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 2, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 9, 9, 9, 0x774, 0x18, 5, offset);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 10, 26);

	// Read Measurement Data element 2
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 10, 10, 10, 0x78c, 0x4, 0x4, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 11, 13);

	offset = 0;

	// Read Allowable Data element 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 11, 11, 11, 0x790, 0x10,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 1 bitmask
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 11, 11, 11, 0x790, 0x10, 2, offset); // Bitmask of length 2
	offset += 4; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 1, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 11, 11, 11, 0x790, 0x10,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 1, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 11, 11, 11, 0x790, 0x10, 2, offset);

	offset = 0;

	// Read Allowable Data element 2
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 12, 12, 12, 0x7a0, 0xc,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 2, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 12, 12, 12, 0x7a0, 0xc,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 2, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 12, 12, 12, 0x7a0, 0xc, 2, offset);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 13, 26);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 13, 26);

	// Read Measurement element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 13, 13, 13, 0x7ac, 0x48,
		sizeof (struct cfm_measurement_element), bytes_read);
	bytes_read += sizeof (struct cfm_measurement_element);

	// Read Allowable Digest 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 13, 13, 13, 0x7ac, 0x48,
		sizeof (struct cfm_allowable_digest_element), bytes_read);
	bytes_read += sizeof (struct cfm_allowable_digest_element);

	// Read Allowable Digest 1 digests
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 13, 13, 13, 0x7ac, 0x48,
		2 * SHA256_HASH_LENGTH, bytes_read);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		false);
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		false);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CFM_MEASUREMENT_TYPE_DIGEST, container.measurement_type);
	CuAssertIntEquals (test, 1, container.measurement.digest.pmr_id);
	CuAssertIntEquals (test, 2, container.measurement.digest.measurement_id);
	CuAssertIntEquals (test, 1,
		container.measurement.digest.allowable_digests_count);
	CuAssertIntEquals (test, 0,
		container.measurement.digest.allowable_digests[0].version_set);
	CuAssertIntEquals (test, HASH_TYPE_SHA256,
		container.measurement.digest.allowable_digests[0].digests.hash_type);
	CuAssertIntEquals (test, 2,
		container.measurement.digest.allowable_digests[0].digests.digest_count);

	status = testing_validate_array (MEASUREMENT_PMR_1_MEASUREMENT_2_DEVICE_1,
		container.measurement.digest.allowable_digests[0].digests.digests,
		sizeof (MEASUREMENT_PMR_1_MEASUREMENT_2_DEVICE_1));
	status |= testing_validate_array (MEASUREMENT_PMR_1_MEASUREMENT_2_DEVICE_1_2,
		container.measurement.digest.allowable_digests[0].digests.digests + \
		sizeof (MEASUREMENT_PMR_1_MEASUREMENT_2_DEVICE_1),
		sizeof (MEASUREMENT_PMR_1_MEASUREMENT_2_DEVICE_1_2));
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_measurement_container (&cfm.test.base, &container);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_second_measurement_after_measurement_data (
	CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	uint32_t bytes_read = 0;
	size_t offset = 0;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_MEASUREMENT_DATA_FIRST_TESTING, 0,
		false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_entry, 0,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_hash,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_offset,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 13);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 7);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 26);

	// Read Measurement Data element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 7, 2, 7, 0x74c, 0x4, 0x4, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 10);

	// Read Allowable Data element 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 1 bitmask
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24, 6, offset); // Bitmask of length 6
	offset += 8; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 1, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 1, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24, 5, offset);
	offset += 8; // Advance offset by data length and padding length

	// Read Allowable Data element 1, Data entry 2 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 1, Data entry 2 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24, 5, offset);

	offset = 0;

	// Read Allowable Data element 2
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 9, 9, 9, 0x774, 0x18,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 2 bitmask
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 9, 9, 9, 0x774, 0x18, 5, offset); // Bitmask of length 5
	offset += 8; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 2, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 9, 9, 9, 0x774, 0x18,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 2, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 9, 9, 9, 0x774, 0x18, 5, offset);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 10, 26);

	// Read Measurement Data element 2
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 10, 10, 10, 0x78c, 0x4, 0x4, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 11, 13);

	offset = 0;

	// Read Allowable Data element 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 11, 11, 11, 0x790, 0x10,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 1 bitmask
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 11, 11, 11, 0x790, 0x10, 2, offset); // Bitmask of length 2
	offset += 4; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 1, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 11, 11, 11, 0x790, 0x10,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 1, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 11, 11, 11, 0x790, 0x10, 2, offset);

	offset = 0;

	// Read Allowable Data element 2
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 12, 12, 12, 0x7a0, 0xc,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 2, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 12, 12, 12, 0x7a0, 0xc,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 2, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 12, 12, 12, 0x7a0, 0xc, 2, offset);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 13, 26);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 13, 26);

	// Read Measurement element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 13, 13, 13, 0x7ac, 0x48,
		sizeof (struct cfm_measurement_element), bytes_read);
	bytes_read += sizeof (struct cfm_measurement_element);

	// Read Allowable Digest 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 13, 13, 13, 0x7ac, 0x48,
		sizeof (struct cfm_allowable_digest_element), bytes_read);
	bytes_read += sizeof (struct cfm_allowable_digest_element);

	// Read Allowable Digest 1 digests
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 13, 13, 13, 0x7ac, 0x48,
		2 * SHA256_HASH_LENGTH, bytes_read);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 14, 26);

	bytes_read = 0;

	// Read Measurement element 2
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 14, 14, 14, 0x7f4, 0x28,
		sizeof (struct cfm_measurement_element), bytes_read);
	bytes_read += sizeof (struct cfm_measurement_element);

	// Read Measurement element 2, Allowable Digest 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 14, 14, 14, 0x7f4, 0x28,
		sizeof (struct cfm_allowable_digest_element), bytes_read);
	bytes_read += sizeof (struct cfm_allowable_digest_element);

	// Read Measurement element 2, Allowable Digest 1 digests
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 14, 14, 14, 0x7f4, 0x28, SHA256_HASH_LENGTH,
		bytes_read);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		false);
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		false);
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		false);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CFM_MEASUREMENT_TYPE_DIGEST, container.measurement_type);
	CuAssertIntEquals (test, 2, container.measurement.digest.pmr_id);
	CuAssertIntEquals (test, 2, container.measurement.digest.measurement_id);
	CuAssertIntEquals (test, 1,
		container.measurement.digest.allowable_digests_count);
	CuAssertIntEquals (test, 0,
		container.measurement.digest.allowable_digests[0].version_set);
	CuAssertIntEquals (test, HASH_TYPE_SHA256,
		container.measurement.digest.allowable_digests[0].digests.hash_type);
	CuAssertIntEquals (test, 1,
		container.measurement.digest.allowable_digests[0].digests.digest_count);

	status = testing_validate_array (MEASUREMENT_PMR_2_MEASUREMENT_2_DEVICE_1,
		container.measurement.digest.allowable_digests[0].digests.digests,
		sizeof (MEASUREMENT_PMR_2_MEASUREMENT_2_DEVICE_1));
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_measurement_container (&cfm.test.base, &container);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_no_more_measurement_after_measurement_data (
	CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	uint32_t bytes_read = 0;
	size_t offset = 0;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_MEASUREMENT_DATA_FIRST_TESTING, 0,
		false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_entry, 0,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_hash,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_offset,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 13);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 7);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 26);

	// Read Measurement Data element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 7, 2, 7, 0x74c, 0x4, 0x4, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 10);

	// Read Allowable Data element 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 1 bitmask
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24, 6, offset); // Bitmask of length 6
	offset += 8; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 1, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 1, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24, 5, offset);
	offset += 8; // Advance offset by data length and padding length

	// Read Allowable Data element 1, Data entry 2 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 1, Data entry 2 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24, 5, offset);

	offset = 0;

	// Read Allowable Data element 2
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 9, 9, 9, 0x774, 0x18,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 2 bitmask
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 9, 9, 9, 0x774, 0x18, 5, offset); // Bitmask of length 5
	offset += 8; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 2, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 9, 9, 9, 0x774, 0x18,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 2, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 9, 9, 9, 0x774, 0x18, 5, offset);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 10, 26);

	// Read Measurement Data element 2
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 10, 10, 10, 0x78c, 0x4, 0x4, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 11, 13);

	offset = 0;

	// Read Allowable Data element 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 11, 11, 11, 0x790, 0x10,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 1 bitmask
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 11, 11, 11, 0x790, 0x10, 2, offset); // Bitmask of length 2
	offset += 4; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 1, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 11, 11, 11, 0x790, 0x10,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 1, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 11, 11, 11, 0x790, 0x10, 2, offset);

	offset = 0;

	// Read Allowable Data element 2
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 12, 12, 12, 0x7a0, 0xc,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 2, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 12, 12, 12, 0x7a0, 0xc,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 2, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 12, 12, 12, 0x7a0, 0xc, 2, offset);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 13, 26);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 13, 26);

	// Read Measurement element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 13, 13, 13, 0x7ac, 0x48,
		sizeof (struct cfm_measurement_element), bytes_read);
	bytes_read += sizeof (struct cfm_measurement_element);

	// Read Allowable Digest 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 13, 13, 13, 0x7ac, 0x48,
		sizeof (struct cfm_allowable_digest_element), bytes_read);
	bytes_read += sizeof (struct cfm_allowable_digest_element);

	// Read Allowable Digest 1 digests
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 13, 13, 13, 0x7ac, 0x48,
		2 * SHA256_HASH_LENGTH, bytes_read);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 14, 26);

	bytes_read = 0;

	// Read Measurement element 2
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 14, 14, 14, 0x7f4, 0x28,
		sizeof (struct cfm_measurement_element), bytes_read);
	bytes_read += sizeof (struct cfm_measurement_element);

	// Read Measurement element 2, Allowable Digest 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 14, 14, 14, 0x7f4, 0x28,
		sizeof (struct cfm_allowable_digest_element), bytes_read);
	bytes_read += sizeof (struct cfm_allowable_digest_element);

	// Read Measurement element 2, Allowable Digest 1 digests
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 14, 14, 14, 0x7f4, 0x28, SHA256_HASH_LENGTH,
		bytes_read);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 15, 26);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		false);
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		false);
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		false);
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		false);
	CuAssertIntEquals (test, CFM_ENTRY_NOT_FOUND, status);

	cfm.test.base.free_measurement_container (&cfm.test.base, &container);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_measurement_data_first (
	CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	struct cfm_allowable_data *allowable_data_ptr;
	size_t offset = 0;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_MEASUREMENT_DATA_FIRST_TESTING, 0,
		false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_entry, 0,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_hash,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_offset,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 13);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 7);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 26);

	// Read Measurement Data element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 7, 2, 7, 0x74c, 0x4, 0x4, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 10);

	// Read Allowable Data element 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 1 bitmask
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24, 6, offset); // Bitmask of length 6
	offset += 8; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 1, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 1, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24, 5, offset);
	offset += 8; // Advance offset by data length and padding length

	// Read Allowable Data element 1, Data entry 2 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 1, Data entry 2 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24, 5, offset);

	offset = 0;

	// Read Allowable Data element 2
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 9, 9, 9, 0x774, 0x18,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 2 bitmask
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 9, 9, 9, 0x774, 0x18, 5, offset); // Bitmask of length 5
	offset += 8; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 2, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 9, 9, 9, 0x774, 0x18,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 2, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 9, 9, 9, 0x774, 0x18, 5, offset);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CFM_MEASUREMENT_TYPE_DATA, container.measurement_type);
	CuAssertIntEquals (test, 1, container.measurement.data.pmr_id);
	CuAssertIntEquals (test, 2, container.measurement.data.measurement_id);
	CuAssertIntEquals (test, 2, container.measurement.data.data_checks_count);

	// Validate Allowable Data element 1
	allowable_data_ptr = container.measurement.data.data_checks;

	CuAssertIntEquals (test, CFM_CHECK_EQUAL, allowable_data_ptr->check);
	CuAssertIntEquals (test, true, allowable_data_ptr->big_endian);
	CuAssertIntEquals (test, 6, allowable_data_ptr->bitmask_length);
	CuAssertIntEquals (test, 2, allowable_data_ptr->data_count);
	CuAssertIntEquals (test, 0, allowable_data_ptr->allowable_data[0].version_set);
	CuAssertIntEquals (test, 5, allowable_data_ptr->allowable_data[0].data_len);
	CuAssertIntEquals (test, 0, allowable_data_ptr->allowable_data[1].version_set);
	CuAssertIntEquals (test, 5, allowable_data_ptr->allowable_data[1].data_len);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_2_DEVICE_1_BITMASK,
		allowable_data_ptr->bitmask, allowable_data_ptr->bitmask_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_2_DEVICE_1,
		allowable_data_ptr->allowable_data[0].data, allowable_data_ptr->allowable_data[0].data_len);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_2_DEVICE_1_2,
		allowable_data_ptr->allowable_data[1].data, allowable_data_ptr->allowable_data[1].data_len);
	CuAssertIntEquals (test, 0, status);

	// Validate Allowable Data element 2
	allowable_data_ptr = &container.measurement.data.data_checks[1];

	CuAssertIntEquals (test, CFM_CHECK_GREATER_THAN, allowable_data_ptr->check);
	CuAssertIntEquals (test, false, allowable_data_ptr->big_endian);
	CuAssertIntEquals (test, 5, allowable_data_ptr->bitmask_length);
	CuAssertIntEquals (test, 1, allowable_data_ptr->data_count);
	CuAssertIntEquals (test, 0, allowable_data_ptr->allowable_data[0].version_set);
	CuAssertIntEquals (test, 5, allowable_data_ptr->allowable_data[0].data_len);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_2_DEVICE_1_BITMASK_CHECK_2,
		allowable_data_ptr->bitmask, allowable_data_ptr->bitmask_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_2_DEVICE_1_CHECK_2,
		allowable_data_ptr->allowable_data[0].data,
		allowable_data_ptr->allowable_data[0].data_len);
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_measurement_container (&cfm.test.base, &container);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_measurement_data_nonzero_version_set (
	CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	struct cfm_allowable_data *allowable_data_ptr;
	size_t bytes_read = 0;
	size_t offset = 0;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_NONZERO_VERSION_SET_TESTING, 0,
		false, 0);

	// Read Component element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_NONZERO_VERSION_SET_TESTING.manifest,
		CFM_NONZERO_VERSION_SET_TESTING.component_device1_entry, 0,
		CFM_NONZERO_VERSION_SET_TESTING.component_device1_hash,
		CFM_NONZERO_VERSION_SET_TESTING.component_device1_offset,
		CFM_NONZERO_VERSION_SET_TESTING.component_device1_len,
		CFM_NONZERO_VERSION_SET_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_NONZERO_VERSION_SET_TESTING.manifest, 2, 7);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_NONZERO_VERSION_SET_TESTING.manifest, 2, 9);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_NONZERO_VERSION_SET_TESTING.manifest, 2, 26);

	// Read Measurement element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_NONZERO_VERSION_SET_TESTING.manifest, 7, 2, 7, 0x74c, 0x48,
		sizeof (struct cfm_measurement_element), bytes_read);
	bytes_read += sizeof (struct cfm_measurement_element);

	// Read Allowable Digest 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_NONZERO_VERSION_SET_TESTING.manifest, 7, 7, 7, 0x74c, 0x48,
		sizeof (struct cfm_allowable_digest_element), bytes_read);
	bytes_read += sizeof (struct cfm_allowable_digest_element);

	// Read Allowable Digest 1 digests
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_NONZERO_VERSION_SET_TESTING.manifest, 7, 7, 7, 0x74c, 0x48, 2 * SHA256_HASH_LENGTH,
		bytes_read);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_NONZERO_VERSION_SET_TESTING.manifest, 8, 26);

	bytes_read = 0;

	// Read Measurement element 2
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_NONZERO_VERSION_SET_TESTING.manifest, 8, 8, 8, 0x794, 0x28,
		sizeof (struct cfm_measurement_element), bytes_read);
	bytes_read += sizeof (struct cfm_measurement_element);

	// Read Measurement element 2, Allowable Digest 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_NONZERO_VERSION_SET_TESTING.manifest, 8, 8, 8, 0x794, 0x28,
		sizeof (struct cfm_allowable_digest_element), bytes_read);
	bytes_read += sizeof (struct cfm_allowable_digest_element);

	// Read Measurement element 2, Allowable Digest 1 digests
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_NONZERO_VERSION_SET_TESTING.manifest, 8, 8, 8, 0x794, 0x28, SHA256_HASH_LENGTH,
		bytes_read);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_NONZERO_VERSION_SET_TESTING.manifest, 9, 26);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_NONZERO_VERSION_SET_TESTING.manifest, 9, 26);

	// Read Measurement Data element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_NONZERO_VERSION_SET_TESTING.manifest, 9, 9, 9, 0x7bc, 0x4, 0x4, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_NONZERO_VERSION_SET_TESTING.manifest, 10, 12);

	// Read Allowable Data element 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_NONZERO_VERSION_SET_TESTING.manifest, 10, 10, 10, 0x7c0, 0x24,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 1 bitmask
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_NONZERO_VERSION_SET_TESTING.manifest, 10, 10, 10, 0x7c0, 0x24, 6, offset); // Bitmask of length 6
	offset += 8; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 1, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_NONZERO_VERSION_SET_TESTING.manifest, 10, 10, 10, 0x7c0, 0x24,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 1, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_NONZERO_VERSION_SET_TESTING.manifest, 10, 10, 10, 0x7c0, 0x24, 5, offset);
	offset += 8; // Advance offset by data length and padding length

	// Read Allowable Data element 1, Data entry 2 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_NONZERO_VERSION_SET_TESTING.manifest, 10, 10, 10, 0x7c0, 0x24,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 1, Data entry 2 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_NONZERO_VERSION_SET_TESTING.manifest, 10, 10, 10, 0x7c0, 0x24, 5, offset);

	offset = 0;

	// Read Allowable Data element 2
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_NONZERO_VERSION_SET_TESTING.manifest, 11, 11, 11, 0x7e4, 0x18,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 2 bitmask
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_NONZERO_VERSION_SET_TESTING.manifest, 11, 11, 11, 0x7e4, 0x18, 5, offset);
	offset += 8; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 2, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_NONZERO_VERSION_SET_TESTING.manifest, 11, 11, 11, 0x7e4, 0x18,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 2, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_NONZERO_VERSION_SET_TESTING.manifest, 11, 11, 11, 0x7e4, 0x18, 5, offset);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		false);
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		false);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CFM_MEASUREMENT_TYPE_DATA, container.measurement_type);
	CuAssertIntEquals (test, 1, container.measurement.data.pmr_id);
	CuAssertIntEquals (test, 2, container.measurement.data.measurement_id);
	CuAssertIntEquals (test, 2, container.measurement.data.data_checks_count);

	// Validate Allowable Data element 1
	allowable_data_ptr = container.measurement.data.data_checks;

	CuAssertIntEquals (test, CFM_CHECK_EQUAL, allowable_data_ptr->check);
	CuAssertIntEquals (test, true, allowable_data_ptr->big_endian);
	CuAssertIntEquals (test, 6, allowable_data_ptr->bitmask_length);
	CuAssertIntEquals (test, 2, allowable_data_ptr->data_count);
	CuAssertIntEquals (test, 2, allowable_data_ptr->allowable_data[0].version_set);
	CuAssertIntEquals (test, 5, allowable_data_ptr->allowable_data[0].data_len);
	CuAssertIntEquals (test, 2, allowable_data_ptr->allowable_data[1].version_set);
	CuAssertIntEquals (test, 5, allowable_data_ptr->allowable_data[1].data_len);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_2_DEVICE_1_BITMASK,
		allowable_data_ptr->bitmask, allowable_data_ptr->bitmask_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_2_DEVICE_1,
		allowable_data_ptr->allowable_data[0].data, allowable_data_ptr->allowable_data[0].data_len);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_2_DEVICE_1_2,
		allowable_data_ptr->allowable_data[1].data, allowable_data_ptr->allowable_data[1].data_len);
	CuAssertIntEquals (test, 0, status);

	// Validate Allowable Data element 2
	allowable_data_ptr = &container.measurement.data.data_checks[1];

	CuAssertIntEquals (test, CFM_CHECK_GREATER_THAN, allowable_data_ptr->check);
	CuAssertIntEquals (test, false, allowable_data_ptr->big_endian);
	CuAssertIntEquals (test, 5, allowable_data_ptr->bitmask_length);
	CuAssertIntEquals (test, 1, allowable_data_ptr->data_count);
	CuAssertIntEquals (test, 2, allowable_data_ptr->allowable_data[0].version_set);
	CuAssertIntEquals (test, 5, allowable_data_ptr->allowable_data[0].data_len);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_2_DEVICE_1_BITMASK_CHECK_2,
		allowable_data_ptr->bitmask, allowable_data_ptr->bitmask_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_2_DEVICE_1_CHECK_2,
		allowable_data_ptr->allowable_data[0].data,
		allowable_data_ptr->allowable_data[0].data_len);
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_measurement_container (&cfm.test.base, &container);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_second_measurement_data (
	CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	struct cfm_allowable_data *allowable_data_ptr;
	size_t offset = 0;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_MEASUREMENT_DATA_FIRST_TESTING, 0,
		false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_entry, 0,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_hash,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_offset,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 13);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 7);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 26);

	// Read Measurement Data element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 7, 2, 7, 0x74c, 0x4, 0x4, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 10);

	// Read Allowable Data element 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 1 bitmask
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24, 6, offset); // Bitmask of length 6
	offset += 8; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 1, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 1, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24, 5, offset);
	offset += 8; // Advance offset by data length and padding length

	// Read Allowable Data element 1, Data entry 2 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 1, Data entry 2 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24, 5, offset);

	offset = 0;

	// Read Allowable Data element 2
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 9, 9, 9, 0x774, 0x18,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 2 bitmask
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 9, 9, 9, 0x774, 0x18, 5, offset); // Bitmask of length 5
	offset += 8; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 2, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 9, 9, 9, 0x774, 0x18,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 2, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 9, 9, 9, 0x774, 0x18, 5, offset);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 10, 26);

	// Read Measurement Data element 2
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 10, 10, 10, 0x78c, 0x4, 0x4, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 11, 13);

	offset = 0;

	// Read Allowable Data element 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 11, 11, 11, 0x790, 0x10,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 1 bitmask
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 11, 11, 11, 0x790, 0x10, 2, offset); // Bitmask of length 2
	offset += 4; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 1, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 11, 11, 11, 0x790, 0x10,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 1, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 11, 11, 11, 0x790, 0x10, 2, offset);

	offset = 0;

	// Read Allowable Data element 2
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 12, 12, 12, 0x7a0, 0xc,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 2, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 12, 12, 12, 0x7a0, 0xc,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 2, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 12, 12, 12, 0x7a0, 0xc, 2, offset);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		false);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CFM_MEASUREMENT_TYPE_DATA, container.measurement_type);
	CuAssertIntEquals (test, 1, container.measurement.data.pmr_id);
	CuAssertIntEquals (test, 4, container.measurement.data.measurement_id);
	CuAssertIntEquals (test, 2, container.measurement.data.data_checks_count);

	allowable_data_ptr = container.measurement.data.data_checks;

	CuAssertIntEquals (test, CFM_CHECK_NOT_EQUAL, allowable_data_ptr->check);
	CuAssertIntEquals (test, false, allowable_data_ptr->big_endian);
	CuAssertIntEquals (test, 2, allowable_data_ptr->bitmask_length);
	CuAssertIntEquals (test, 1, allowable_data_ptr->data_count);
	CuAssertIntEquals (test, 0, allowable_data_ptr->allowable_data[0].version_set);
	CuAssertIntEquals (test, 2, allowable_data_ptr->allowable_data[0].data_len);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_4_DEVICE_1_BITMASK,
		allowable_data_ptr->bitmask, allowable_data_ptr->bitmask_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_4_DEVICE_1,
		allowable_data_ptr->allowable_data[0].data,
		allowable_data_ptr->allowable_data[0].data_len);
	CuAssertIntEquals (test, 0, status);

	allowable_data_ptr = &container.measurement.data.data_checks[1];

	CuAssertIntEquals (test, CFM_CHECK_NOT_EQUAL, allowable_data_ptr->check);
	CuAssertIntEquals (test, true, allowable_data_ptr->big_endian);
	CuAssertIntEquals (test, 0, allowable_data_ptr->bitmask_length);
	CuAssertIntEquals (test, 1, allowable_data_ptr->data_count);
	CuAssertIntEquals (test, 0, allowable_data_ptr->allowable_data[0].version_set);
	CuAssertIntEquals (test, 2, allowable_data_ptr->allowable_data[0].data_len);
	CuAssertPtrEquals (test, NULL, (void*) allowable_data_ptr->bitmask);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_4_DEVICE_1_2,
		allowable_data_ptr->allowable_data[0].data, allowable_data_ptr->allowable_data[0].data_len);
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_measurement_container (&cfm.test.base, &container);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_measurement_data_after_measurement (
	CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	struct cfm_allowable_data *allowable_data_ptr;
	size_t bytes_read = 0;
	size_t offset = 0;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	// Read Component element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		7);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		9);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		26);

	// Read Measurement element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 7, 2, 7,
		0x74c, 0x48, sizeof (struct cfm_measurement_element), bytes_read);
	bytes_read += sizeof (struct cfm_measurement_element);

	// Read Allowable Digest 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 7, 7, 7,
		0x74c, 0x48, sizeof (struct cfm_allowable_digest_element), bytes_read);
	bytes_read += sizeof (struct cfm_allowable_digest_element);

	// Read Allowable Digest 1 digests
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 7, 7, 7,
		0x74c, 0x48, 2 * SHA256_HASH_LENGTH, bytes_read);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 8,
		26);

	bytes_read = 0;

	// Read Measurement element 2
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 8, 8, 8,
		0x794, 0x28, sizeof (struct cfm_measurement_element), bytes_read);
	bytes_read += sizeof (struct cfm_measurement_element);

	// Read Measurement element 2, Allowable Digest 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 8, 8, 8,
		0x794, 0x28, sizeof (struct cfm_allowable_digest_element), bytes_read);
	bytes_read += sizeof (struct cfm_allowable_digest_element);

	// Read Measurement element 2, Allowable Digest 1 digests
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 8, 8, 8,
		0x794, 0x28, SHA256_HASH_LENGTH, bytes_read);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 9,
		26);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 9,
		26);

	// Read Measurement Data element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 9, 9, 9,
		0x7bc, 0x4, 0x4, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 10,
		12);

	// Read Allowable Data element 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 10, 10, 10,
		0x7c0, 0x24, sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 1 bitmask
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 10, 10, 10,
		0x7c0, 0x24, 6, offset); // Bitmask of length 6
	offset += 8; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 1, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 10, 10, 10,
		0x7c0, 0x24, sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 1, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 10, 10, 10,
		0x7c0, 0x24, 5, offset);
	offset += 8; // Advance offset by data length and padding length

	// Read Allowable Data element 1, Data entry 2 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 10, 10, 10,
		0x7c0, 0x24, sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 1, Data entry 2 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 10, 10, 10,
		0x7c0, 0x24, 5, offset);

	offset = 0;

	// Read Allowable Data element 2
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 11, 11, 11,
		0x7e4, 0x18, sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 2 bitmask
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 11, 11, 11,
		0x7e4, 0x18, 5, offset); // Bitmask of length 5
	offset += 8; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 2, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 11, 11, 11,
		0x7e4, 0x18, sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 2, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 11, 11, 11,
		0x7e4, 0x18, 5, offset);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		false);
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		false);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CFM_MEASUREMENT_TYPE_DATA, container.measurement_type);
	CuAssertIntEquals (test, 1, container.measurement.data.pmr_id);
	CuAssertIntEquals (test, 2, container.measurement.data.measurement_id);
	CuAssertIntEquals (test, 2, container.measurement.data.data_checks_count);

	// Validate Allowable Data element 1
	allowable_data_ptr = container.measurement.data.data_checks;

	CuAssertIntEquals (test, CFM_CHECK_EQUAL, allowable_data_ptr->check);
	CuAssertIntEquals (test, true, allowable_data_ptr->big_endian);
	CuAssertIntEquals (test, 6, allowable_data_ptr->bitmask_length);
	CuAssertIntEquals (test, 2, allowable_data_ptr->data_count);
	CuAssertIntEquals (test, 0, allowable_data_ptr->allowable_data[0].version_set);
	CuAssertIntEquals (test, 5, allowable_data_ptr->allowable_data[0].data_len);
	CuAssertIntEquals (test, 0, allowable_data_ptr->allowable_data[1].version_set);
	CuAssertIntEquals (test, 5, allowable_data_ptr->allowable_data[1].data_len);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_2_DEVICE_1_BITMASK,
		allowable_data_ptr->bitmask, allowable_data_ptr->bitmask_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_2_DEVICE_1,
		allowable_data_ptr->allowable_data[0].data, allowable_data_ptr->allowable_data[0].data_len);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_2_DEVICE_1_2,
		allowable_data_ptr->allowable_data[1].data, allowable_data_ptr->allowable_data[1].data_len);
	CuAssertIntEquals (test, 0, status);

	// Validate Allowable Data element 2
	allowable_data_ptr = &container.measurement.data.data_checks[1];

	CuAssertIntEquals (test, CFM_CHECK_GREATER_THAN, allowable_data_ptr->check);
	CuAssertIntEquals (test, false, allowable_data_ptr->big_endian);
	CuAssertIntEquals (test, 5, allowable_data_ptr->bitmask_length);
	CuAssertIntEquals (test, 1, allowable_data_ptr->data_count);
	CuAssertIntEquals (test, 0, allowable_data_ptr->allowable_data[0].version_set);
	CuAssertIntEquals (test, 5, allowable_data_ptr->allowable_data[0].data_len);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_2_DEVICE_1_BITMASK_CHECK_2,
		allowable_data_ptr->bitmask, allowable_data_ptr->bitmask_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_2_DEVICE_1_CHECK_2,
		allowable_data_ptr->allowable_data[0].data,
		allowable_data_ptr->allowable_data[0].data_len);
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_measurement_container (&cfm.test.base, &container);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_second_measurement_data_after_measurement (
	CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	struct cfm_allowable_data *allowable_data_ptr;
	size_t bytes_read = 0;
	size_t offset = 0;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	// Read Component element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		7);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		9);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		26);

	// Read Measurement element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 7, 2, 7,
		0x74c, 0x48, sizeof (struct cfm_measurement_element), bytes_read);
	bytes_read += sizeof (struct cfm_measurement_element);

	// Read Allowable Digest 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 7, 7, 7,
		0x74c, 0x48, sizeof (struct cfm_allowable_digest_element), bytes_read);
	bytes_read += sizeof (struct cfm_allowable_digest_element);

	// Read Allowable Digest 1 digests
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 7, 7, 7,
		0x74c, 0x48, 2 * SHA256_HASH_LENGTH, bytes_read);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 8,
		26);

	bytes_read = 0;

	// Read Measurement element 2
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 8, 8, 8,
		0x794, 0x28, sizeof (struct cfm_measurement_element), bytes_read);
	bytes_read += sizeof (struct cfm_measurement_element);

	// Read Measurement element 2, Allowable Digest 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 8, 8, 8,
		0x794, 0x28, sizeof (struct cfm_allowable_digest_element), bytes_read);
	bytes_read += sizeof (struct cfm_allowable_digest_element);

	// Read Measurement element 2, Allowable Digest 1 digests
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 8, 8, 8,
		0x794, 0x28, SHA256_HASH_LENGTH, bytes_read);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 9,
		26);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 9,
		26);

	// Read Measurement Data element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 9, 9, 9,
		0x7bc, 0x4, 0x4, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 10,
		12);

	// Read Allowable Data element 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 10, 10, 10,
		0x7c0, 0x24, sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 1 bitmask
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 10, 10, 10,
		0x7c0, 0x24, 6, offset); // Bitmask of length 6
	offset += 8; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 1, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 10, 10, 10,
		0x7c0, 0x24, sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 1, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 10, 10, 10,
		0x7c0, 0x24, 5, offset);
	offset += 8; // Advance offset by data length and padding length

	// Read Allowable Data element 1, Data entry 2 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 10, 10, 10,
		0x7c0, 0x24, sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 1, Data entry 2 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 10, 10, 10,
		0x7c0, 0x24, 5, offset);

	offset = 0;

	// Read Allowable Data element 2
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 11, 11, 11,
		0x7e4, 0x18, sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 2 bitmask
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 11, 11, 11,
		0x7e4, 0x18, 5, offset); // Bitmask of length 5
	offset += 8; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 2, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 11, 11, 11,
		0x7e4, 0x18, sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 2, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 11, 11, 11,
		0x7e4, 0x18, 5, offset);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 12,
		26);

	// Read Measurement Data element 2
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 12, 12, 12,
		0x7fc, 0x4, 0x4, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 13,
		15);

	offset = 0;

	// Read Allowable Data element 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 13, 13, 13,
		0x800, 0x10, sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 1 bitmask
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 13, 13, 13,
		0x800, 0x10, 2, offset); // Bitmask of length 2
	offset += 4; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 1, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 13, 13, 13,
		0x800, 0x10, sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 1, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 13, 13, 13,
		0x800, 0x10, 2, offset);

	offset = 0;

	// Read Allowable Data element 2
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 14, 14, 14,
		0x810, 0xc, sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 2, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 14, 14, 14,
		0x810, 0xc, sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 2, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 14, 14, 14,
		0x810, 0xc, 2, offset);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		false);
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		false);
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		false);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CFM_MEASUREMENT_TYPE_DATA, container.measurement_type);
	CuAssertIntEquals (test, 1, container.measurement.data.pmr_id);
	CuAssertIntEquals (test, 4, container.measurement.data.measurement_id);
	CuAssertIntEquals (test, 2, container.measurement.data.data_checks_count);

	allowable_data_ptr = container.measurement.data.data_checks;

	CuAssertIntEquals (test, CFM_CHECK_NOT_EQUAL, allowable_data_ptr->check);
	CuAssertIntEquals (test, false, allowable_data_ptr->big_endian);
	CuAssertIntEquals (test, 2, allowable_data_ptr->bitmask_length);
	CuAssertIntEquals (test, 1, allowable_data_ptr->data_count);
	CuAssertIntEquals (test, 0, allowable_data_ptr->allowable_data[0].version_set);
	CuAssertIntEquals (test, 2, allowable_data_ptr->allowable_data[0].data_len);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_4_DEVICE_1_BITMASK,
		allowable_data_ptr->bitmask, allowable_data_ptr->bitmask_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_4_DEVICE_1,
		allowable_data_ptr->allowable_data[0].data,
		allowable_data_ptr->allowable_data[0].data_len);
	CuAssertIntEquals (test, 0, status);

	allowable_data_ptr = &container.measurement.data.data_checks[1];

	CuAssertIntEquals (test, CFM_CHECK_NOT_EQUAL, allowable_data_ptr->check);
	CuAssertIntEquals (test, true, allowable_data_ptr->big_endian);
	CuAssertIntEquals (test, 0, allowable_data_ptr->bitmask_length);
	CuAssertIntEquals (test, 1, allowable_data_ptr->data_count);
	CuAssertIntEquals (test, 0, allowable_data_ptr->allowable_data[0].version_set);
	CuAssertIntEquals (test, 2, allowable_data_ptr->allowable_data[0].data_len);
	CuAssertPtrEquals (test, NULL, (void*) allowable_data_ptr->bitmask);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_4_DEVICE_1_2,
		allowable_data_ptr->allowable_data[0].data, allowable_data_ptr->allowable_data[0].data_len);
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_measurement_container (&cfm.test.base, &container);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_no_more_measurement_data_after_measurement (
	CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	size_t bytes_read = 0;
	size_t offset = 0;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	// Read Component element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		7);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		9);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		26);

	// Read Measurement element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 7, 2, 7,
		0x74c, 0x48, sizeof (struct cfm_measurement_element), bytes_read);
	bytes_read += sizeof (struct cfm_measurement_element);

	// Read Allowable Digest 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 7, 7, 7,
		0x74c, 0x48, sizeof (struct cfm_allowable_digest_element), bytes_read);
	bytes_read += sizeof (struct cfm_allowable_digest_element);

	// Read Allowable Digest 1 digests
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 7, 7, 7,
		0x74c, 0x48, 2 * SHA256_HASH_LENGTH, bytes_read);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 8,
		26);

	bytes_read = 0;

	// Read Measurement element 2
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 8, 8, 8,
		0x794, 0x28, sizeof (struct cfm_measurement_element), bytes_read);
	bytes_read += sizeof (struct cfm_measurement_element);

	// Read Measurement element 2, Allowable Digest 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 8, 8, 8,
		0x794, 0x28, sizeof (struct cfm_allowable_digest_element), bytes_read);
	bytes_read += sizeof (struct cfm_allowable_digest_element);

	// Read Measurement element 2, Allowable Digest 1 digests
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 8, 8, 8,
		0x794, 0x28, SHA256_HASH_LENGTH, bytes_read);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 9,
		26);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 9,
		26);

	// Read Measurement Data element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 9, 9, 9,
		0x7bc, 0x4, 0x4, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 10,
		12);

	// Read Allowable Data element 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 10, 10, 10,
		0x7c0, 0x24, sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 1 bitmask
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 10, 10, 10,
		0x7c0, 0x24, 6, offset); // Bitmask of length 6
	offset += 8; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 1, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 10, 10, 10,
		0x7c0, 0x24, sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 1, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 10, 10, 10,
		0x7c0, 0x24, 5, offset);
	offset += 8; // Advance offset by data length and padding length

	// Read Allowable Data element 1, Data entry 2 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 10, 10, 10,
		0x7c0, 0x24, sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 1, Data entry 2 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 10, 10, 10,
		0x7c0, 0x24, 5, offset);

	offset = 0;

	// Read Allowable Data element 2
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 11, 11, 11,
		0x7e4, 0x18, sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 2 bitmask
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 11, 11, 11,
		0x7e4, 0x18, 5, offset); // Bitmask of length 5
	offset += 8; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 2, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 11, 11, 11,
		0x7e4, 0x18, sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 2, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 11, 11, 11,
		0x7e4, 0x18, 5, offset);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 12,
		26);

	// Read Measurement Data element 2
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 12, 12, 12,
		0x7fc, 0x4, 0x4, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 13,
		15);

	offset = 0;

	// Read Allowable Data element 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 13, 13, 13,
		0x800, 0x10, sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 1 bitmask
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 13, 13, 13,
		0x800, 0x10, 2, offset); // Bitmask of length 2
	offset += 4; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 1, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 13, 13, 13,
		0x800, 0x10, sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 1, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 13, 13, 13,
		0x800, 0x10, 2, offset);

	offset = 0;

	// Read Allowable Data element 2
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 14, 14, 14,
		0x810, 0xc, sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 2, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 14, 14, 14,
		0x810, 0xc, sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 2, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 14, 14, 14,
		0x810, 0xc, 2, offset);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 15,
		26);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		false);
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		false);
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		false);
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		false);
	CuAssertIntEquals (test, CFM_ENTRY_NOT_FOUND, status);

	cfm.test.base.free_measurement_container (&cfm.test.base, &container);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_measurement_data_single_allowable_data (
	CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	struct cfm_allowable_data *allowable_data_ptr;
	size_t offset = 0;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_MEASUREMENT_DATA_FIRST_TESTING, 0,
		false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_entry, 0,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_hash,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_offset,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 13);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 7);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 26);

	// Read Measurement Data element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 7, 2, 7, 0x74c, 0x4, 0x4, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 10);

	// Read Allowable Data element 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 1 bitmask
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24, 6, offset); // Bitmask of length 6
	offset += 8; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 1, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 1, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24, 5, offset);
	offset += 8; // Advance offset by data length and padding length

	// Read Allowable Data element 1, Data entry 2 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 1, Data entry 2 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24, 5, offset);

	offset = 0;

	// Read Allowable Data element 2
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 9, 9, 9, 0x774, 0x18,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 2 bitmask
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 9, 9, 9, 0x774, 0x18, 5, offset); // Bitmask of length 5
	offset += 8; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 2, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 9, 9, 9, 0x774, 0x18,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 2, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 9, 9, 9, 0x774, 0x18, 5, offset);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 10, 26);

	// Read Measurement Data element 2
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 10, 10, 10, 0x78c, 0x4, 0x4, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 11, 13);

	offset = 0;

	// Read Allowable Data element 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 11, 11, 11, 0x790, 0x10,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 1 bitmask
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 11, 11, 11, 0x790, 0x10, 2, offset); // Bitmask of length 2
	offset += 4; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 1, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 11, 11, 11, 0x790, 0x10,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 1, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 11, 11, 11, 0x790, 0x10, 2, offset);

	offset = 0;

	// Read Allowable Data element 2
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 12, 12, 12, 0x7a0, 0xc,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 2, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 12, 12, 12, 0x7a0, 0xc,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 2, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 12, 12, 12, 0x7a0, 0xc, 2, offset);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		false);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CFM_MEASUREMENT_TYPE_DATA, container.measurement_type);
	CuAssertIntEquals (test, 1, container.measurement.data.pmr_id);
	CuAssertIntEquals (test, 4, container.measurement.data.measurement_id);
	CuAssertIntEquals (test, 2, container.measurement.data.data_checks_count);

	allowable_data_ptr = container.measurement.data.data_checks;

	CuAssertIntEquals (test, CFM_CHECK_NOT_EQUAL, allowable_data_ptr->check);
	CuAssertIntEquals (test, false, allowable_data_ptr->big_endian);
	CuAssertIntEquals (test, 2, allowable_data_ptr->bitmask_length);
	CuAssertIntEquals (test, 1, allowable_data_ptr->data_count);
	CuAssertIntEquals (test, 0, allowable_data_ptr->allowable_data[0].version_set);
	CuAssertIntEquals (test, 2, allowable_data_ptr->allowable_data[0].data_len);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_4_DEVICE_1_BITMASK,
		allowable_data_ptr->bitmask, allowable_data_ptr->bitmask_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_4_DEVICE_1,
		allowable_data_ptr->allowable_data[0].data,
		allowable_data_ptr->allowable_data[0].data_len);
	CuAssertIntEquals (test, 0, status);

	allowable_data_ptr = &container.measurement.data.data_checks[1];

	CuAssertIntEquals (test, CFM_CHECK_NOT_EQUAL, allowable_data_ptr->check);
	CuAssertIntEquals (test, true, allowable_data_ptr->big_endian);
	CuAssertIntEquals (test, 0, allowable_data_ptr->bitmask_length);
	CuAssertIntEquals (test, 1, allowable_data_ptr->data_count);
	CuAssertIntEquals (test, 0, allowable_data_ptr->allowable_data[0].version_set);
	CuAssertIntEquals (test, 2, allowable_data_ptr->allowable_data[0].data_len);
	CuAssertPtrEquals (test, NULL, (void*) allowable_data_ptr->bitmask);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_4_DEVICE_1_2,
		allowable_data_ptr->allowable_data[0].data, allowable_data_ptr->allowable_data[0].data_len);
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_measurement_container (&cfm.test.base, &container);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_measurement_data_no_bitmask (
	CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	struct cfm_allowable_data *allowable_data_ptr;
	size_t offset = 0;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_MEASUREMENT_DATA_FIRST_TESTING, 0,
		false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_entry, 0,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_hash,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_offset,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 13);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 7);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 26);

	// Read Measurement Data element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 7, 2, 7, 0x74c, 0x4, 0x4, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 10);

	// Read Allowable Data element 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 1 bitmask
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24, 6, offset); // Bitmask of length 6
	offset += 8; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 1, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 1, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24, 5, offset);
	offset += 8; // Advance offset by data length and padding length

	// Read Allowable Data element 1, Data entry 2 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 1, Data entry 2 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24, 5, offset);

	offset = 0;

	// Read Allowable Data element 2
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 9, 9, 9, 0x774, 0x18,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 2 bitmask
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 9, 9, 9, 0x774, 0x18, 5, offset); // Bitmask of length 5
	offset += 8; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 2, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 9, 9, 9, 0x774, 0x18,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 2, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 9, 9, 9, 0x774, 0x18, 5, offset);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 10, 26);

	// Read Measurement Data element 2
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 10, 10, 10, 0x78c, 0x4, 0x4, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 11, 13);

	offset = 0;

	// Read Allowable Data element 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 11, 11, 11, 0x790, 0x10,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 1 bitmask
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 11, 11, 11, 0x790, 0x10, 2, offset); // Bitmask of length 2
	offset += 4; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 1, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 11, 11, 11, 0x790, 0x10,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 1, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 11, 11, 11, 0x790, 0x10, 2, offset);

	offset = 0;

	// Read Allowable Data element 2
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 12, 12, 12, 0x7a0, 0xc,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 2, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 12, 12, 12, 0x7a0, 0xc,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 2, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 12, 12, 12, 0x7a0, 0xc, 2, offset);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		false);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CFM_MEASUREMENT_TYPE_DATA, container.measurement_type);
	CuAssertIntEquals (test, 1, container.measurement.data.pmr_id);
	CuAssertIntEquals (test, 4, container.measurement.data.measurement_id);
	CuAssertIntEquals (test, 2, container.measurement.data.data_checks_count);

	allowable_data_ptr = container.measurement.data.data_checks;

	CuAssertIntEquals (test, CFM_CHECK_NOT_EQUAL, allowable_data_ptr->check);
	CuAssertIntEquals (test, false, allowable_data_ptr->big_endian);
	CuAssertIntEquals (test, 2, allowable_data_ptr->bitmask_length);
	CuAssertIntEquals (test, 1, allowable_data_ptr->data_count);
	CuAssertIntEquals (test, 0, allowable_data_ptr->allowable_data[0].version_set);
	CuAssertIntEquals (test, 2, allowable_data_ptr->allowable_data[0].data_len);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_4_DEVICE_1_BITMASK,
		allowable_data_ptr->bitmask, allowable_data_ptr->bitmask_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_4_DEVICE_1,
		allowable_data_ptr->allowable_data[0].data,
		allowable_data_ptr->allowable_data[0].data_len);
	CuAssertIntEquals (test, 0, status);

	allowable_data_ptr = &container.measurement.data.data_checks[1];

	CuAssertIntEquals (test, CFM_CHECK_NOT_EQUAL, allowable_data_ptr->check);
	CuAssertIntEquals (test, true, allowable_data_ptr->big_endian);
	CuAssertIntEquals (test, 0, allowable_data_ptr->bitmask_length);
	CuAssertIntEquals (test, 1, allowable_data_ptr->data_count);
	CuAssertIntEquals (test, 0, allowable_data_ptr->allowable_data[0].version_set);
	CuAssertIntEquals (test, 2, allowable_data_ptr->allowable_data[0].data_len);
	CuAssertPtrEquals (test, NULL, (void*) allowable_data_ptr->bitmask);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_4_DEVICE_1_2,
		allowable_data_ptr->allowable_data[0].data, allowable_data_ptr->allowable_data[0].data_len);
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_measurement_container (&cfm.test.base, &container);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_single_check (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	struct cfm_allowable_data *allowable_data_ptr;
	size_t offset = 0;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_MEASUREMENT_DATA_FIRST_TESTING, 0,
		false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_entry, 0,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_hash,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_offset,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device2_entry, 2,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device2_hash,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device2_offset,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device2_len,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device2_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 27, 32);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 27, 30);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 27, 38);

	// Read Measurement Data element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 30, 27, 30, 0x93a, 0x4, 0x4, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 31, 32);

	// Read Allowable Data element 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 31, 31, 31, 0x93e, 0x10,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 1 bitmask
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 31, 31, 31, 0x93e, 0x10, 3, offset); // Bitmask of length 3
	offset += 4; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 1, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 31, 31, 31, 0x93e, 0x10,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 1, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 31, 31, 31, 0x93e, 0x10, 3, offset);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 4, &container,
		true);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CFM_MEASUREMENT_TYPE_DATA, container.measurement_type);
	CuAssertIntEquals (test, 1, container.measurement.data.pmr_id);
	CuAssertIntEquals (test, 3, container.measurement.data.measurement_id);
	CuAssertIntEquals (test, 1, container.measurement.data.data_checks_count);

	allowable_data_ptr = container.measurement.data.data_checks;

	CuAssertIntEquals (test, CFM_CHECK_GREATER_THAN, allowable_data_ptr->check);
	CuAssertIntEquals (test, false, allowable_data_ptr->big_endian);
	CuAssertIntEquals (test, 3, allowable_data_ptr->bitmask_length);
	CuAssertIntEquals (test, 1, allowable_data_ptr->data_count);
	CuAssertIntEquals (test, 0, allowable_data_ptr->allowable_data[0].version_set);
	CuAssertIntEquals (test, 3, allowable_data_ptr->allowable_data[0].data_len);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_3_DEVICE_2_BITMASK,
		allowable_data_ptr->bitmask, allowable_data_ptr->bitmask_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (MEASUREMENT_DATA_PMR_1_MEASUREMENT_3_DEVICE_2,
		allowable_data_ptr->allowable_data[0].data, allowable_data_ptr->allowable_data[0].data_len);
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_measurement_container (&cfm.test.base, &container);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_second_component (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	uint32_t bytes_read = 0;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device2_entry, 2, CFM_TESTING.component_device2_hash,
		CFM_TESTING.component_device2_offset, CFM_TESTING.component_device2_len,
		CFM_TESTING.component_device2_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,	27,
		30);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,	27,
		31);

	// Get child elements of Component 2
	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,	27,
		38);

	// Read Measurement element 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 30, 27, 30,
		0x93a, 0x38, sizeof (struct cfm_measurement_element), bytes_read);
	bytes_read += sizeof (struct cfm_measurement_element);

	// Read Measurement element 1, Allowable Digest 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 30, 30, 30,
		0x93a, 0x38, sizeof (struct cfm_allowable_digest_element), bytes_read);
	bytes_read += sizeof (struct cfm_allowable_digest_element);

	// Read Measurement element 1, Allowable Digest 1 digests
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 30, 30, 30,
		0x93a, 0x38, SHA384_HASH_LENGTH, bytes_read);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 4, &container,
		true);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CFM_MEASUREMENT_TYPE_DIGEST, container.measurement_type);
	CuAssertIntEquals (test, 1, container.measurement.digest.pmr_id);
	CuAssertIntEquals (test, 5, container.measurement.digest.measurement_id);
	CuAssertIntEquals (test, 1,
		container.measurement.digest.allowable_digests_count);
	CuAssertIntEquals (test, 0,
		container.measurement.digest.allowable_digests[0].version_set);
	CuAssertIntEquals (test, HASH_TYPE_SHA384,
		container.measurement.digest.allowable_digests[0].digests.hash_type);
	CuAssertIntEquals (test, 1,
		container.measurement.digest.allowable_digests[0].digests.digest_count);

	status = testing_validate_array (MEASUREMENT_PMR_1_MEASUREMENT_5_DEVICE_2,
		container.measurement.digest.allowable_digests[0].digests.digests,
		sizeof (MEASUREMENT_PMR_1_MEASUREMENT_5_DEVICE_2));
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_measurement_container (&cfm.test.base, &container);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_no_measurement_data (
	CuTest *test)
{
	uint8_t digest0[] = {
		0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
		0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
		0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
		0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC
	};
	uint8_t digest1[] = {
		0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,
		0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,
		0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,
		0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE
	};
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	uint32_t bytes_read = 0;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_ONLY_MEASUREMENT_TESTING, 0, false,
		0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_TESTING.manifest,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_entry, 0,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_hash,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_offset,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_len,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_TESTING.manifest, 2, 2);

	manifest_flash_v2_testing_iterate_manifest_toc_no_verify (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_TESTING.manifest, 2, 2);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_TESTING.manifest, 2, 2);

	// Read Measurement element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_TESTING.manifest, 2, 2, 2, 0xb8, 0x88,
		sizeof (struct cfm_measurement_element), bytes_read);
	bytes_read += sizeof (struct cfm_measurement_element);

	// Read Allowable Digest 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_TESTING.manifest, 2, 2, 2, 0xb8, 0x88,
		sizeof (struct cfm_allowable_digest_element), bytes_read);
	bytes_read += sizeof (struct cfm_allowable_digest_element);

	// Read Allowable Digest 1 digests
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_TESTING.manifest, 2, 2, 2, 0xb8, 0x88, 2 * SHA512_HASH_LENGTH,
		bytes_read);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CFM_MEASUREMENT_TYPE_DIGEST, container.measurement_type);
	CuAssertIntEquals (test, 1, container.measurement.digest.pmr_id);
	CuAssertIntEquals (test, 2, container.measurement.digest.measurement_id);
	CuAssertIntEquals (test, 1,
		container.measurement.digest.allowable_digests_count);
	CuAssertIntEquals (test, 0,
		container.measurement.digest.allowable_digests[0].version_set);
	CuAssertIntEquals (test, HASH_TYPE_SHA512,
		container.measurement.digest.allowable_digests[0].digests.hash_type);
	CuAssertIntEquals (test, 2,
		container.measurement.digest.allowable_digests[0].digests.digest_count);

	status = testing_validate_array (digest0,
		container.measurement.digest.allowable_digests[0].digests.digests,
		sizeof (digest0));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (digest1,
		container.measurement.digest.allowable_digests[0].digests.digests +
			sizeof (digest0),
		sizeof (digest1));
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_measurement_container (&cfm.test.base, &container);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_no_measurement (CuTest *test)
{
	uint8_t bitmask0[] = {
		0x00,0xFF,0x00,0xFF,0xFF
	};
	uint8_t bitmask1[] = {
		0x00,0x00,0xFF,0x00,0x00
	};
	uint8_t data0[] = {
		0x54,0x65,0x73,0x74,0x31
	};
	uint8_t data1[] = {
		0x54,0x65,0x73,0x74,0x32
	};
	uint8_t data2[] = {
		0x00,0x00,0x22,0x00,0x00
	};
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	struct cfm_allowable_data *allowable_data_ptr;
	size_t offset = 0;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_ONLY_MEASUREMENT_DATA_TESTING, 0,
		false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_DATA_TESTING.manifest,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_entry, 0,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_hash,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_offset,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_len,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc_no_verify (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_DATA_TESTING.manifest, 2, 4);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_DATA_TESTING.manifest, 2, 2);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_DATA_TESTING.manifest, 2, 4);

	// Read Measurement Data element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_DATA_TESTING.manifest, 2, 2, 2, 0x108, 0x4, 0x4, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_DATA_TESTING.manifest, 3, 4);

	// Read Allowable Data element 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_DATA_TESTING.manifest, 3, 3, 3, 0x10c, 0x24,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 1 bitmask
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_DATA_TESTING.manifest, 3, 3, 3, 0x10c, 0x24, 5, offset); // Bitmask of length 5
	offset += 8; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 1, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_DATA_TESTING.manifest, 3, 3, 3, 0x10c, 0x24,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 1, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_DATA_TESTING.manifest, 3, 3, 3, 0x10c, 0x24, 5, offset);
	offset += 8; // Advance offset by data length and padding length

	// Read Allowable Data element 1, Data entry 2 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_DATA_TESTING.manifest, 3, 3, 3, 0x10c, 0x24,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 1, Data entry 2 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_DATA_TESTING.manifest, 3, 3, 3, 0x10c, 0x24, 5, offset);

	offset = 0;

	// Read Allowable Data element 2
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_DATA_TESTING.manifest, 4, 4, 4, 0x130, 0x18,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 2 bitmask
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_DATA_TESTING.manifest, 4, 4, 4, 0x130, 0x18, 5, offset); // Bitmask of length 5
	offset += 8; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 2, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_DATA_TESTING.manifest, 4, 4, 4, 0x130, 0x18,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 2, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_DATA_TESTING.manifest, 4, 4, 4, 0x130, 0x18, 5, offset);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CFM_MEASUREMENT_TYPE_DATA, container.measurement_type);
	CuAssertIntEquals (test, 1, container.measurement.data.pmr_id);
	CuAssertIntEquals (test, 2, container.measurement.data.measurement_id);
	CuAssertIntEquals (test, 2, container.measurement.data.data_checks_count);

	// Validate Allowable Data element 1
	allowable_data_ptr = container.measurement.data.data_checks;

	CuAssertIntEquals (test, CFM_CHECK_EQUAL, allowable_data_ptr->check);
	CuAssertIntEquals (test, true, allowable_data_ptr->big_endian);
	CuAssertIntEquals (test, 5, allowable_data_ptr->bitmask_length);
	CuAssertIntEquals (test, 2, allowable_data_ptr->data_count);
	CuAssertIntEquals (test, 0, allowable_data_ptr->allowable_data[0].version_set);
	CuAssertIntEquals (test, 5, allowable_data_ptr->allowable_data[0].data_len);
	CuAssertIntEquals (test, 0, allowable_data_ptr->allowable_data[1].version_set);
	CuAssertIntEquals (test, 5, allowable_data_ptr->allowable_data[1].data_len);

	status = testing_validate_array (bitmask0, allowable_data_ptr->bitmask,
		allowable_data_ptr->bitmask_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data0, allowable_data_ptr->allowable_data[0].data,
		allowable_data_ptr->allowable_data[0].data_len);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data1, allowable_data_ptr->allowable_data[1].data,
		allowable_data_ptr->allowable_data[1].data_len);
	CuAssertIntEquals (test, 0, status);

	// Validate Allowable Data element 2
	allowable_data_ptr = &container.measurement.data.data_checks[1];

	CuAssertIntEquals (test, CFM_CHECK_GREATER_THAN, allowable_data_ptr->check);
	CuAssertIntEquals (test, false, allowable_data_ptr->big_endian);
	CuAssertIntEquals (test, 5, allowable_data_ptr->bitmask_length);
	CuAssertIntEquals (test, 1, allowable_data_ptr->data_count);
	CuAssertIntEquals (test, 0, allowable_data_ptr->allowable_data[0].version_set);
	CuAssertIntEquals (test, 5, allowable_data_ptr->allowable_data[0].data_len);

	status = testing_validate_array (bitmask1, allowable_data_ptr->bitmask,
		allowable_data_ptr->bitmask_length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data2,	allowable_data_ptr->allowable_data[0].data,
		allowable_data_ptr->allowable_data[0].data_len);
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_measurement_container (&cfm.test.base, &container);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_first_free_after_failure (
	CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x08));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm.test.base.free_measurement_container (&cfm.test.base, &container);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_null (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = cfm.test.base.get_next_measurement_or_measurement_data (NULL, 3, &container, true);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, NULL, true);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_verify_never_run (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	int status;

	TEST_START;

	cfm_flash_testing_init (test, &cfm, 0x10000);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_component_read_fail (
	CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x08));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_component_not_found (
	CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device2_entry, 2, CFM_TESTING.component_device2_hash,
		CFM_TESTING.component_device2_offset, CFM_TESTING.component_device2_len,
		CFM_TESTING.component_device2_len, 0);

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

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 5, &container,
		true);
	CuAssertIntEquals (test, MANIFEST_ELEMENT_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_get_first_measurement_entry_id_fail (
	CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

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

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_get_first_measurement_data_entry_id_fail (
	CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 7);

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

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_no_measurement_or_measurement_data (
	CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_ONLY_PMR_DIGEST_TESTING, 0, false,
		0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_ONLY_PMR_DIGEST_TESTING.manifest, CFM_ONLY_PMR_DIGEST_TESTING.component_device1_entry,
		0, CFM_ONLY_PMR_DIGEST_TESTING.component_device1_hash,
		CFM_ONLY_PMR_DIGEST_TESTING.component_device1_offset,
		CFM_ONLY_PMR_DIGEST_TESTING.component_device1_len,
		CFM_ONLY_PMR_DIGEST_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc_no_verify (test, &cfm.manifest,
		&CFM_ONLY_PMR_DIGEST_TESTING.manifest, 2, 2);

	manifest_flash_v2_testing_iterate_manifest_toc_no_verify (test, &cfm.manifest,
		&CFM_ONLY_PMR_DIGEST_TESTING.manifest, 2, 2);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, MANIFEST_CHILD_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_get_num_measurements_fail (
	CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	// Read Component element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		7);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		9);

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

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_measurement_read_fail (
	CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	// Read Component element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		7);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		9);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x10));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);
	CuAssertPtrEquals (test, NULL, container.measurement.digest.allowable_digests);
	CuAssertIntEquals (test, 0, container.measurement.digest.allowable_digests_count);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_allowable_digests_read_fail (
	CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	// Read Component element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		7);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		9);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 7, 2, 7,
		0x74c, 0x48, sizeof (struct cfm_measurement_element), 0);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x38));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);
	CuAssertPtrEquals (test, NULL, container.measurement.digest.allowable_digests);
	CuAssertIntEquals (test, 0, container.measurement.digest.allowable_digests_count);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_get_num_measurement_data_fail (
	CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_MEASUREMENT_DATA_FIRST_TESTING, 0,
		false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_entry, 0,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_hash,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_offset,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 13);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 7);

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

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_measurement_data_read_fail (
	CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_MEASUREMENT_DATA_FIRST_TESTING, 0,
		false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_entry, 0,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_hash,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_offset,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 13);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 7);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 26);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x10));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_get_num_allowable_data_fail (
	CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_MEASUREMENT_DATA_FIRST_TESTING, 0,
		false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_entry, 0,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_hash,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_offset,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 13);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 7);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 26);

	// Read Measurement Data element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 7, 2, 7, 0x74c, 0x4, 0x4, 0);

	status = flash_mock_expect_verify_flash (&cfm.manifest.flash, cfm.manifest.addr +
		MANIFEST_V2_TOC_ENTRY_OFFSET, CFM_TESTING.manifest.raw + MANIFEST_V2_TOC_ENTRY_OFFSET,
		MANIFEST_V2_TOC_ENTRY_SIZE * 8);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY,
		MOCK_ARG (cfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET +
			8 * MANIFEST_V2_TOC_ENTRY_SIZE), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_allowable_data_read_fail (
	CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_MEASUREMENT_DATA_FIRST_TESTING, 0,
		false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_entry, 0,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_hash,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_offset,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 13);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 7);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 26);

	// Read Measurement Data element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 7, 2, 7, 0x74c, 0x4, 0x4, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 10);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x40));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);
	CuAssertPtrEquals (test, NULL, container.measurement.data.data_checks);
	CuAssertIntEquals (test, 0, container.measurement.data.data_checks_count);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_bitmask_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	size_t offset = 0;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_MEASUREMENT_DATA_FIRST_TESTING, 0,
		false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_entry, 0,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_hash,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_offset,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 13);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 7);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 26);

	// Read Measurement Data element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 7, 2, 7, 0x74c, 0x4, 0x4, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 10);

	// Read Allowable Data element 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x40));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);
	CuAssertPtrEquals (test, NULL, container.measurement.data.data_checks);
	CuAssertIntEquals (test, 0, container.measurement.data.data_checks_count);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_allowable_data_buffer_read_fail (
	CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	size_t offset = 0;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_MEASUREMENT_DATA_FIRST_TESTING, 0,
		false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_entry, 0,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_hash,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_offset,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 13);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 7);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 26);

	// Read Measurement Data element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 7, 2, 7, 0x74c, 0x4, 0x4, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 10);

	// Read Allowable Data element 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 1 bitmask
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24, 6, offset); // Bitmask of length 6
	offset += 8; // Advance offset by bitmask length and padding length

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x40));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);
	CuAssertPtrEquals (test, NULL, container.measurement.data.data_checks);
	CuAssertIntEquals (test, 0, container.measurement.data.data_checks_count);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_digests_list_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	size_t bytes_read = 0;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	// Read first Component element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	// Reach first Measurement element
	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		7);

	// Reach first Measurement Data element
	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		9);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		26);

	// Read Measurement element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 7, 2, 7,
		0x74c, 0x48, sizeof (struct cfm_measurement_element), bytes_read);
	bytes_read += sizeof (struct cfm_measurement_element);

	// Read Allowable Digest 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 7, 7, 7,
		0x74c, 0x48, sizeof (struct cfm_allowable_digest_element), bytes_read);
	bytes_read += sizeof (struct cfm_allowable_digest_element);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG_ANY, MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_malformed_component (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	struct manifest_toc_entry bad_entry;
	uint8_t bad_data[3];
	int status;

	TEST_START;

	bad_entry.type_id = CFM_COMPONENT_DEVICE;
	bad_entry.parent = 0xff;
	bad_entry.format = 0;
	bad_entry.hash_id = CFM_TESTING.component_device1_hash;
	bad_entry.offset = CFM_TESTING.component_device1_offset;
	bad_entry.length = sizeof (bad_data);

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, true, 0);

	manifest_flash_v2_testing_read_element_mocked_hash_bad_entry (test, &cfm.manifest,
		&CFM_TESTING.manifest, bad_entry.hash_id, 0, bad_entry.hash_id, bad_entry.offset,
		bad_entry.length, bad_entry.length, 0, &bad_entry, NULL);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, CFM_MALFORMED_COMPONENT_DEVICE_ENTRY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_malformed_measurement (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	struct manifest_toc_entry bad_entry;
	uint8_t bad_data[3];
	int status;

	bad_entry.type_id = CFM_MEASUREMENT;
	bad_entry.parent = CFM_COMPONENT_DEVICE;
	bad_entry.format = 0;
	bad_entry.hash_id = 7;
	bad_entry.offset = 0x74c;
	bad_entry.length = sizeof (bad_data);

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, true, 0);

	// Read first Component element
	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	// Reach first Measurement element
	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_TESTING.manifest, 2, 7);

	// Reach first Measurement Data element
	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_TESTING.manifest, 2, 9);

	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_TESTING.manifest, 2, 26);

	// Read Measurement element
	manifest_flash_v2_testing_read_element_mocked_hash_bad_entry (test, &cfm.manifest,
		&CFM_TESTING.manifest, bad_entry.hash_id, 2, bad_entry.hash_id, bad_entry.offset,
		bad_entry.length, bad_entry.length, 0, &bad_entry, NULL);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, CFM_MALFORMED_MEASUREMENT_ENTRY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_malformed_allowable_digest (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	struct manifest_toc_entry bad_entry;
	uint8_t bad_data[3];
	size_t bytes_read = 0;
	int status;

	bad_entry.type_id = CFM_MEASUREMENT;
	bad_entry.parent = CFM_COMPONENT_DEVICE;
	bad_entry.format = 0;
	bad_entry.hash_id = 7;
	bad_entry.offset = 0x74c;
	bad_entry.length = sizeof (bad_data);

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, true, 0);

	// Read first Component element
	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	// Reach first Measurement element
	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_TESTING.manifest, 2, 7);

	// Reach first Measurement Data element
	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_TESTING.manifest, 2, 9);

	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_TESTING.manifest, 2, 26);

	// Read Measurement element
	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest, &CFM_TESTING.manifest,
		7, 2, 7, 0x74c, 0x48, sizeof (struct cfm_measurement_element), bytes_read);
	bytes_read += sizeof (struct cfm_measurement_element);

	// Read Allowable Digest 1
	manifest_flash_v2_testing_read_element_mocked_hash_bad_entry (test, &cfm.manifest,
		&CFM_TESTING.manifest, bad_entry.hash_id, 7, bad_entry.hash_id, bad_entry.offset,
		bad_entry.length, bad_entry.length, bytes_read, &bad_entry, NULL);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, CFM_MALFORMED_MEASUREMENT_ENTRY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_incomplete_digests_read (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	struct manifest_toc_entry bad_entry;
	uint8_t bad_data[3];
	size_t bytes_read = 0;
	int status;

	bad_entry.type_id = CFM_MEASUREMENT;
	bad_entry.parent = CFM_COMPONENT_DEVICE;
	bad_entry.format = 0;
	bad_entry.hash_id = 7;
	bad_entry.offset = 0x74c;
	bad_entry.length = sizeof (bad_data);

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, true, 0);

	// Read first Component element
	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	// Reach first Measurement element
	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_TESTING.manifest, 2, 7);

	// Reach first Measurement Data element
	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_TESTING.manifest, 2, 9);

	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_TESTING.manifest, 2, 26);

	// Read Measurement element
	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest, &CFM_TESTING.manifest,
		7, 2, 7, 0x74c, 0x48, sizeof (struct cfm_measurement_element), bytes_read);
	bytes_read += sizeof (struct cfm_measurement_element);

	// Read Allowable Digest 1
	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest, &CFM_TESTING.manifest,
		7, 7, 7, 0x74c, 0x48, sizeof (struct cfm_allowable_digest_element), bytes_read);
	bytes_read += sizeof (struct cfm_allowable_digest_element);

	// Read Allowable Digest 1 digests
	manifest_flash_v2_testing_read_element_mocked_hash_bad_entry (test, &cfm.manifest,
		&CFM_TESTING.manifest, bad_entry.hash_id, 7, bad_entry.hash_id, bad_entry.offset,
		bad_entry.length, bad_entry.length, bytes_read, &bad_entry, NULL);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, CFM_MALFORMED_MEASUREMENT_ENTRY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_malformed_measurement_data (
	CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	int status;
	struct manifest_toc_entry bad_entry;
	uint8_t bad_data[3];

	bad_entry.type_id = CFM_MEASUREMENT_DATA;
	bad_entry.parent = CFM_COMPONENT_DEVICE;
	bad_entry.format = 0;
	bad_entry.hash_id = 7;
	bad_entry.offset = 0x74c;
	bad_entry.length = sizeof (bad_data);

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_MEASUREMENT_DATA_FIRST_TESTING, 0,
		true, 0);

	// Read first Component element
	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_entry, 0,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_hash,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_offset,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len, 0);

	// Reach first Measurement element
	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 13);

	// Reach first Measurement Data element
	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 7);

	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 26);

	// Read Measurement Data element
	manifest_flash_v2_testing_read_element_mocked_hash_bad_entry (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, bad_entry.hash_id, 2, bad_entry.hash_id,
		bad_entry.offset, bad_entry.length, bad_entry.length, 0, &bad_entry, NULL);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, CFM_MALFORMED_MEASUREMENT_DATA_ENTRY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_malformed_allowable_data (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	int status;
	struct manifest_toc_entry bad_entry;
	uint8_t bad_data[3];

	bad_entry.type_id = CFM_ALLOWABLE_DATA;
	bad_entry.parent = CFM_MEASUREMENT_DATA;
	bad_entry.format = 0;
	bad_entry.hash_id = 8;
	bad_entry.offset = 0x750;
	bad_entry.length = sizeof (bad_data);

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_MEASUREMENT_DATA_FIRST_TESTING, 0,
		true, 0);

	// Read first Component element
	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_entry, 0,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_hash,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_offset,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len, 0);

	// Reach first Measurement element
	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 13);

	// Reach first Measurement Data element
	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 7);

	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 26);

	// Read Measurement Data element
	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 7, 2, 7, 0x74c, 0x4, 0x4, 0);

	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 10);

	// Read Allowable Data element 1
	manifest_flash_v2_testing_read_element_mocked_hash_bad_entry (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, bad_entry.hash_id, 8, bad_entry.hash_id,
		bad_entry.offset, bad_entry.length, bad_entry.length, 0, &bad_entry, NULL);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, CFM_MALFORMED_ALLOWABLE_DATA_ENTRY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_malformed_bitmask (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	int status;
	struct manifest_toc_entry bad_entry;
	uint8_t bad_data[3];
	size_t offset = 0;

	bad_entry.type_id = CFM_ALLOWABLE_DATA;
	bad_entry.parent = CFM_MEASUREMENT_DATA;
	bad_entry.format = 0;
	bad_entry.hash_id = 8;
	bad_entry.offset = 0x750;
	bad_entry.length = sizeof (bad_data);

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_MEASUREMENT_DATA_FIRST_TESTING, 0,
		true, 0);

	// Read first Component element
	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_entry, 0,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_hash,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_offset,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len, 0);

	// Reach first Measurement element
	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 13);

	// Reach first Measurement Data element
	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 7);

	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 26);

	// Read Measurement Data element
	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 7, 2, 7, 0x74c, 0x4, 0x4, 0);

	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 10);

	// Read Allowable Data element 1
	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 1 bitmask
	manifest_flash_v2_testing_read_element_mocked_hash_bad_entry (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, bad_entry.hash_id, 8, bad_entry.hash_id,
		bad_entry.offset, bad_entry.length, bad_entry.length, offset, &bad_entry, NULL);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, CFM_MALFORMED_ALLOWABLE_DATA_ENTRY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_malformed_allowable_data_entry (
	CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	int status;
	struct manifest_toc_entry bad_entry;
	uint8_t bad_data[3];
	size_t offset = 0;

	bad_entry.type_id = CFM_ALLOWABLE_DATA;
	bad_entry.parent = CFM_MEASUREMENT_DATA;
	bad_entry.format = 0;
	bad_entry.hash_id = 8;
	bad_entry.offset = 0x750;
	bad_entry.length = sizeof (bad_data);

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_MEASUREMENT_DATA_FIRST_TESTING, 0,
		true, 0);

	// Read first Component element
	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_entry, 0,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_hash,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_offset,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len, 0);

	// Reach first Measurement element
	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 13);

	// Reach first Measurement Data element
	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 7);

	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 26);

	// Read Measurement Data element
	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 7, 2, 7, 0x74c, 0x4, 0x4, 0);

	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 10);

	// Read Allowable Data element 1
	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 1 bitmask of length 6
	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24, 6, offset);
	offset += 8; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 1, Data entry 1 header
	manifest_flash_v2_testing_read_element_mocked_hash_bad_entry (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, bad_entry.hash_id, 8, bad_entry.hash_id,
		bad_entry.offset, bad_entry.length, bad_entry.length, offset, &bad_entry, NULL);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, CFM_MALFORMED_ALLOWABLE_DATA_ENTRY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_read_data_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	int status;
	size_t offset = 0;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_MEASUREMENT_DATA_FIRST_TESTING, 0,
		false, 0);

	// Read first Component element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_entry, 0,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_hash,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_offset,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len, 0);

	// Reach first Measurement element
	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 13);

	// Reach first Measurement Data element
	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 7);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 26);

	// Read Measurement Data element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 7, 2, 7, 0x74c, 0x4, 0x4, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 10);

	// Read Allowable Data element 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 1 bitmask of length 6
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24, 6, offset);
	offset += 8; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 1, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24,
		sizeof (struct cfm_allowable_data_element_entry), offset);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG_ANY, MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_measurement_or_measurement_data_malformed_allowable_data_entry_data (
	CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	int status;
	struct manifest_toc_entry bad_entry;
	uint8_t bad_data[3];
	size_t offset = 0;

	bad_entry.type_id = CFM_ALLOWABLE_DATA;
	bad_entry.parent = CFM_MEASUREMENT_DATA;
	bad_entry.format = 0;
	bad_entry.hash_id = 8;
	bad_entry.offset = 0x750;
	bad_entry.length = sizeof (bad_data);

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_MEASUREMENT_DATA_FIRST_TESTING, 0,
		true, 0);

	// Read first Component element
	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_entry, 0,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_hash,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_offset,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len, 0);

	// Reach first Measurement element
	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 13);

	// Reach first Measurement Data element
	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 7);

	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 26);

	// Read Measurement Data element
	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 7, 2, 7, 0x74c, 0x4, 0x4, 0);

	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 10);

	// Read Allowable Data element 1
	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 1 bitmask of length 6
	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24, 6, offset);
	offset += 8; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 1, Data entry 1 header
	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 1, Data entry 1 data
	manifest_flash_v2_testing_read_element_mocked_hash_bad_entry (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, bad_entry.hash_id, 8, bad_entry.hash_id,
		bad_entry.offset, bad_entry.length, bad_entry.length, offset, &bad_entry, NULL);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, CFM_MALFORMED_ALLOWABLE_DATA_ENTRY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_free_measurement_container_again_after_measurement_digest_free (
	CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	size_t bytes_read = 0;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	// Read Component element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		7);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		9);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		26);

	// Read Measurement element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 7, 2, 7,
		0x74c, 0x48, sizeof (struct cfm_measurement_element), bytes_read);
	bytes_read += sizeof (struct cfm_measurement_element);

	// Read Allowable Digest 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 7, 7, 7,
		0x74c, 0x48, sizeof (struct cfm_allowable_digest_element), bytes_read);
	bytes_read += sizeof (struct cfm_allowable_digest_element);

	// Read Allowable Digest 1 digests
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 7, 7, 7,
		0x74c, 0x48, 2 * SHA256_HASH_LENGTH, bytes_read);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_measurement_container (&cfm.test.base, &container);
	cfm.test.base.free_measurement_container (&cfm.test.base, &container);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_free_measurement_container_again_after_measurement_data_free (
	CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_measurement_container container;
	size_t offset = 0;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_MEASUREMENT_DATA_FIRST_TESTING, 0,
		false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_entry, 0,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_hash,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_offset,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len,
		CFM_MEASUREMENT_DATA_FIRST_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 13);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 7);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 2, 26);

	// Read Measurement Data element
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 7, 2, 7, 0x74c, 0x4, 0x4, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 10);

	// Read Allowable Data element 1
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 1 bitmask
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24, 6, offset); // Bitmask of length 6
	offset += 8; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 1, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 1, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24, 5, offset);
	offset += 8; // Advance offset by data length and padding length

	// Read Allowable Data element 1, Data entry 2 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 1, Data entry 2 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 8, 8, 8, 0x750, 0x24, 5, offset);

	offset = 0;

	// Read Allowable Data element 2
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 9, 9, 9, 0x774, 0x18,
		sizeof (struct cfm_allowable_data_element), offset);
	offset += sizeof (struct cfm_allowable_data_element);

	// Read Allowable Data element 2 bitmask
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 9, 9, 9, 0x774, 0x18, 5, offset); // Bitmask of length 5
	offset += 8; // Advance offset by bitmask length and padding length

	// Read Allowable Data element 2, Data entry 1 header
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 9, 9, 9, 0x774, 0x18,
		sizeof (struct cfm_allowable_data_element_entry), offset);
	offset += sizeof (struct cfm_allowable_data_element_entry);

	// Read Allowable Data element 2, Data entry 1 data
	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_MEASUREMENT_DATA_FIRST_TESTING.manifest, 9, 9, 9, 0x774, 0x18, 5, offset);

	status = cfm.test.base.get_next_measurement_or_measurement_data (&cfm.test.base, 3, &container,
		true);
	CuAssertIntEquals (test, 0, status);

	cfm.test.base.free_measurement_container (&cfm.test.base, &container);
	cfm.test.base.free_measurement_container (&cfm.test.base, &container);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_free_measurement_container_null (CuTest *test)
{
	struct cfm_measurement_container container;
	struct cfm_flash_testing cfm;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	cfm.test.base.free_measurement_container (NULL, &container);
	cfm.test.base.free_measurement_container (&cfm.test.base, NULL);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_root_ca_digest (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_root_ca_digests root_ca_digest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 2, 2, 2,
		0x658, 0x44, sizeof (struct cfm_root_ca_digests_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 2, 2, 2,
		0x658, 0x44, 0x44 - sizeof (struct cfm_root_ca_digests_element),
		sizeof (struct cfm_root_ca_digests_element));

	status = cfm.test.base.get_root_ca_digest (&cfm.test.base, 3, &root_ca_digest);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA256, root_ca_digest.digests.hash_type);
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

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device2_entry, 2, CFM_TESTING.component_device2_hash,
		CFM_TESTING.component_device2_offset, CFM_TESTING.component_device2_len,
		CFM_TESTING.component_device2_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		27, 38);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 27, 27, 27,
		0x89e, 0x34, sizeof (struct cfm_root_ca_digests_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 27, 27, 27,
		0x89e, 0x34, 0x34 - sizeof (struct cfm_root_ca_digests_element),
		sizeof (struct cfm_root_ca_digests_element));

	status = cfm.test.base.get_root_ca_digest (&cfm.test.base, 4, &root_ca_digest);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, HASH_TYPE_SHA384, root_ca_digest.digests.hash_type);
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

	status = cfm.test.base.get_root_ca_digest (NULL, 3, &root_ca_digest);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.get_root_ca_digest (&cfm.test.base, 3, NULL);
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

	status = cfm.test.base.get_root_ca_digest (&cfm.test.base, 3, &root_ca_digest);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_root_ca_digest_component_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_root_ca_digests root_ca_digest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x08));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_root_ca_digest (&cfm.test.base, 3, &root_ca_digest);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_root_ca_digest_component_not_found (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_root_ca_digests root_ca_digest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device2_entry, 2, CFM_TESTING.component_device2_hash,
		CFM_TESTING.component_device2_offset, CFM_TESTING.component_device2_len,
		CFM_TESTING.component_device2_len, 0);

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

	status = cfm.test.base.get_root_ca_digest (&cfm.test.base, 5, &root_ca_digest);
	CuAssertIntEquals (test, MANIFEST_ELEMENT_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_root_ca_digest_component_has_no_root_ca_digest (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_root_ca_digests root_ca_digest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_ONLY_MEASUREMENT_DATA_TESTING,	0,
		false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_DATA_TESTING.manifest,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_entry, 0,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_hash,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_offset,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_len,
		CFM_ONLY_MEASUREMENT_DATA_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_DATA_TESTING.manifest, 2, 4);

	status = cfm.test.base.get_root_ca_digest (&cfm.test.base, 3, &root_ca_digest);
	CuAssertIntEquals (test, CFM_ROOT_CA_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_root_ca_digest_component_get_num_root_ca_digest_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_root_ca_digests root_ca_digest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

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

	status = cfm.test.base.get_root_ca_digest (&cfm.test.base, 3, &root_ca_digest);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_root_ca_digest_root_ca_digest_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_root_ca_digests root_ca_digest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x10));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_root_ca_digest (&cfm.test.base, 3, &root_ca_digest);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_root_ca_digest_digests_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_root_ca_digests root_ca_digest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest, 2,
		26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 2, 2, 2,
		0x658, 0x44, sizeof (struct cfm_root_ca_digests_element), 0);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x10));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_root_ca_digest (&cfm.test.base, 3, &root_ca_digest);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_root_ca_digest_malformed_root_ca_digest (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_root_ca_digests root_ca_digest;
	int status;
	struct manifest_toc_entry bad_entry;
	uint8_t bad_data[3];

	TEST_START;

	bad_entry.type_id = CFM_ROOT_CA;
	bad_entry.parent = CFM_COMPONENT_DEVICE;
	bad_entry.format = 0;
	bad_entry.hash_id = 2;
	bad_entry.offset = 0x658;
	bad_entry.length = sizeof (bad_data);

	memset (bad_data, 0x66, sizeof (bad_data));

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, true, 0);

	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_TESTING.manifest, 2, 26);

	manifest_flash_v2_testing_read_element_mocked_hash_bad_entry (test, &cfm.manifest,
		&CFM_TESTING.manifest, bad_entry.hash_id, bad_entry.hash_id, bad_entry.hash_id,
		bad_entry.offset, bad_entry.length, bad_entry.length, 0, &bad_entry, NULL);

	status = cfm.test.base.get_root_ca_digest (&cfm.test.base, 3, &root_ca_digest);
	CuAssertIntEquals (test, CFM_MALFORMED_ROOT_CA_DIGESTS_ENTRY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_root_ca_digest_invalid_hash_type (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_root_ca_digests root_ca_digest;
	int status;
	struct manifest_toc_entry bad_entry;
	uint8_t bad_data[3];

	TEST_START;

	bad_entry.type_id = CFM_ROOT_CA;
	bad_entry.parent = CFM_COMPONENT_DEVICE;
	bad_entry.format = 0;
	bad_entry.hash_id = 2;
	bad_entry.offset = 0x658;
	bad_entry.length = sizeof (bad_data);

	memset (bad_data, 0x66, sizeof (bad_data));

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, true, 0);

	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_TESTING.manifest, 2, 26);

	manifest_flash_v2_testing_read_element_mocked_hash_bad_entry (test, &cfm.manifest,
		&CFM_TESTING.manifest, bad_entry.hash_id, bad_entry.hash_id, bad_entry.hash_id,
		bad_entry.offset, bad_entry.length, bad_entry.length, 0, &bad_entry, NULL);

	status = cfm.test.base.get_root_ca_digest (&cfm.test.base, 3, &root_ca_digest);
	CuAssertIntEquals (test, CFM_MALFORMED_ROOT_CA_DIGESTS_ENTRY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_free_root_ca_digest_null (CuTest *test)
{
	struct cfm_flash_testing cfm;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	cfm.test.base.free_root_ca_digest (&cfm.test.base, NULL);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_pfm_multiple_big_endian_ids (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	struct cfm_allowable_id *manifest_check_ptr;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 15, 2, 15,
		0x81c, 0xe, 0xe, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		16, 18);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 16, 16, 16,
		0x82a, 0xc, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 16, 16, 16,
		0x82a, 0xc, 0xc - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 17, 17, 17,
		0x836, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 17, 17, 17,
		0x836, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	status = cfm.test.base.get_next_pfm (&cfm.test.base, 3, &manifest, true);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, manifest.manifest_index);
	CuAssertIntEquals (test, 2, manifest.check_count);
	CuAssertStrEquals (test, CFM_ALLOWABLE_PFM_1_PLATFORM_ID_DEVICE_1, manifest.platform_id);

	CuAssertIntEquals (test, CFM_CHECK_EQUAL, manifest.check->check);
	CuAssertIntEquals (test, 2, manifest.check->id_count);
	CuAssertIntEquals (test, CFM_ALLOWABLE_PFM_1_ALLOWABLE_ID_1_DEVICE_1,
		manifest.check->allowable_id[0]);
	CuAssertIntEquals (test, CFM_ALLOWABLE_PFM_1_ALLOWABLE_ID_1_DEVICE_1_2,
		manifest.check->allowable_id[1]);

	manifest_check_ptr = &manifest.check[1];

	CuAssertIntEquals (test, CFM_CHECK_GREATER_THAN, manifest_check_ptr->check);
	CuAssertIntEquals (test, 1, manifest_check_ptr->id_count);
	CuAssertIntEquals (test, CFM_ALLOWABLE_PFM_1_ALLOWABLE_ID_2_DEVICE_1,
		manifest_check_ptr->allowable_id[0]);

	cfm.test.base.free_manifest (&cfm.test.base, &manifest);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_pfm_second_pfm_big_endian (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 15, 2, 15,
		0x81c, 0xe, 0xe, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		16, 18);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 16, 16, 16,
		0x82a, 0xc, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 16, 16, 16,
		0x82a, 0xc, 0xc - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 17, 17, 17,
		0x836, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 17, 17, 17,
		0x836, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		18, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 18, 18, 18,
		0x83e, 0xe, 0xe, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		19, 20);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 19, 19, 19,
		0x84c, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 19, 19, 19,
		0x84c, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	status = cfm.test.base.get_next_pfm (&cfm.test.base, 3, &manifest, true);
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_pfm (&cfm.test.base, 3, &manifest, false);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, manifest.manifest_index);
	CuAssertIntEquals (test, 1, manifest.check_count);
	CuAssertStrEquals (test, CFM_ALLOWABLE_PFM_2_PLATFORM_ID_DEVICE_1, manifest.platform_id);

	CuAssertIntEquals (test, CFM_CHECK_LESS_THAN_OR_EQUAL, manifest.check->check);
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

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 15, 2, 15,
		0x81c, 0xe, 0xe, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		16, 18);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 16, 16, 16,
		0x82a, 0xc, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 16, 16, 16,
		0x82a, 0xc, 0xc - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 17, 17, 17,
		0x836, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 17, 17, 17,
		0x836, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		18, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 18, 18, 18,
		0x83e, 0xe, 0xe, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		19, 20);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 19, 19, 19,
		0x84c, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 19, 19, 19,
		0x84c, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		20, 26);

	status = cfm.test.base.get_next_pfm (&cfm.test.base, 3, &manifest, true);
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_pfm (&cfm.test.base, 3, &manifest, false);
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_pfm (&cfm.test.base, 3, &manifest, false);
	CuAssertIntEquals (test, CFM_ENTRY_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_pfm_second_component_big_endian (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device2_entry, 2, CFM_TESTING.component_device2_hash,
		CFM_TESTING.component_device2_offset, CFM_TESTING.component_device2_len,
		CFM_TESTING.component_device2_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		27, 38);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 33, 27, 33,
		0x986, 0xe, 0xe, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		34, 35);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 34, 34, 34,
		0x994, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 34, 34, 34,
		0x994, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	status = cfm.test.base.get_next_pfm (&cfm.test.base, 4, &manifest, true);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, manifest.manifest_index);
	CuAssertIntEquals (test, 1, manifest.check_count);
	CuAssertStrEquals (test, CFM_ALLOWABLE_PFM_2_PLATFORM_ID_DEVICE_2, manifest.platform_id);

	CuAssertIntEquals (test, CFM_CHECK_GREATER_THAN_OR_EQUAL, manifest.check->check);
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

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device2_entry, 2, CFM_TESTING.component_device2_hash,
		CFM_TESTING.component_device2_offset, CFM_TESTING.component_device2_len,
		CFM_TESTING.component_device2_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		27, 38);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 33, 27, 33,
		0x986, 0xe, 0xe, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		34, 35);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 34, 34, 34,
		0x994, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 34, 34, 34,
		0x994, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	status = cfm.test.base.get_next_pfm (&cfm.test.base, 4, &manifest, true);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, manifest.manifest_index);
	CuAssertIntEquals (test, 1, manifest.check_count);
	CuAssertStrEquals (test, CFM_ALLOWABLE_PFM_2_PLATFORM_ID_DEVICE_2, manifest.platform_id);

	CuAssertIntEquals (test, CFM_CHECK_GREATER_THAN_OR_EQUAL, manifest.check->check);
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

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device2_entry, 2, CFM_TESTING.component_device2_hash,
		CFM_TESTING.component_device2_offset, CFM_TESTING.component_device2_len,
		CFM_TESTING.component_device2_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		27, 38);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 33, 27, 33,
		0x986, 0xe, 0xe, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		34, 35);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 34, 34, 34,
		0x994, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 34, 34, 34,
		0x994, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	status = cfm.test.base.get_next_pfm (&cfm.test.base, 4, &manifest, true);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, manifest.manifest_index);
	CuAssertIntEquals (test, 1, manifest.check_count);
	CuAssertStrEquals (test, CFM_ALLOWABLE_PFM_2_PLATFORM_ID_DEVICE_2, manifest.platform_id);

	CuAssertIntEquals (test, CFM_CHECK_GREATER_THAN_OR_EQUAL, manifest.check->check);
	CuAssertIntEquals (test, 1, manifest.check->id_count);
	CuAssertIntEquals (test, CFM_ALLOWABLE_PFM_2_ALLOWABLE_ID_DEVICE_2,
		manifest.check->allowable_id[0]);

	cfm.test.base.free_manifest (&cfm.test.base, &manifest);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_pfm_first_free_after_failure (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x08));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_pfm (&cfm.test.base, 3, &manifest, true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm.test.base.free_manifest (&cfm.test.base, &manifest);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_pfm_null (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	status = cfm.test.base.get_next_pfm (NULL, 4, &manifest, true);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.get_next_pfm (&cfm.test.base, 4, NULL, true);
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

	status = cfm.test.base.get_next_pfm (&cfm.test.base, 3, &manifest, true);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_pfm_component_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x08));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_pfm (&cfm.test.base, 3, &manifest, true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_pfm_component_not_found (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device2_entry, 2, CFM_TESTING.component_device2_hash,
		CFM_TESTING.component_device2_offset, CFM_TESTING.component_device2_len,
		CFM_TESTING.component_device2_len, 0);

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

	status = cfm.test.base.get_next_pfm (&cfm.test.base, 5, &manifest, true);
	CuAssertIntEquals (test, MANIFEST_ELEMENT_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_pfm_component_has_no_allowable_pfm (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_ONLY_MEASUREMENT_TESTING, 0, false,
		0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_TESTING.manifest,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_entry, 0,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_hash,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_offset,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_len,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_TESTING.manifest, 2, 2);

	status = cfm.test.base.get_next_pfm (&cfm.test.base, 3, &manifest, true);
	CuAssertIntEquals (test, CFM_ENTRY_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_pfm_get_num_allowable_pfm_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

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

	status = cfm.test.base.get_next_pfm (&cfm.test.base, 3, &manifest, true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_pfm_allowable_pfm_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x10));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_pfm (&cfm.test.base, 3, &manifest, true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_pfm_get_num_allowable_id_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 15, 2, 15,
		0x81c, 0xe, 0xe, 0);

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

	status = cfm.test.base.get_next_pfm (&cfm.test.base, 3, &manifest, true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_pfm_allowable_id_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 15, 2, 15,
		0x81c, 0xe, 0xe, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		16, 18);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x80));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_pfm (&cfm.test.base, 3, &manifest, true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_pfm_allowable_id_ids_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 15, 2, 15,
		0x81c, 0xe, 0xe, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		16, 18);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 16, 16, 16,
		0x82a, 0xc, sizeof (struct cfm_allowable_id_element), 0);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x80));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_pfm (&cfm.test.base, 3, &manifest, true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_pfm_malformed_allowable_id (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;
	struct manifest_toc_entry bad_entry;
	uint8_t bad_data[3];

	bad_entry.type_id = CFM_ALLOWABLE_ID;
	bad_entry.parent = CFM_ALLOWABLE_PFM;
	bad_entry.format = 0;
	bad_entry.hash_id = 16;
	bad_entry.offset = 0x82a;
	bad_entry.length = sizeof (bad_data);

	memset (bad_data, 0x66, sizeof (bad_data));

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, true, 0);

	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_TESTING.manifest, 2, 26);

	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest, &CFM_TESTING.manifest,
		15, 2, 15, 0x81c, 0xe, 0xe, 0);

	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_TESTING.manifest, 16, 18);

	manifest_flash_v2_testing_read_element_mocked_hash_bad_entry (test, &cfm.manifest,
		&CFM_TESTING.manifest, bad_entry.hash_id, bad_entry.hash_id, bad_entry.hash_id,
		bad_entry.offset, bad_entry.length, bad_entry.length, 0, &bad_entry, NULL);

	status = cfm.test.base.get_next_pfm (&cfm.test.base, 3, &manifest, true);
	CuAssertIntEquals (test, CFM_MALFORMED_ALLOWABLE_ID_ENTRY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_pfm_malformed_allowable_id_list (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	struct manifest_toc_entry bad_entry;
	uint8_t bad_data[3];
	int status;

	bad_entry.type_id = CFM_ALLOWABLE_ID;
	bad_entry.parent = CFM_ALLOWABLE_PFM;
	bad_entry.format = 0;
	bad_entry.hash_id = 16;
	bad_entry.offset = 0x82a;
	bad_entry.length = sizeof (bad_data);

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, true, 0);

	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_TESTING.manifest, 2, 26);

	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest, &CFM_TESTING.manifest,
		15, 2, 15, 0x81c, 0xe, 0xe, 0);

	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_TESTING.manifest, 16, 18);

	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest, &CFM_TESTING.manifest,
		16, 16, 16, 0x82a, 0xc, sizeof (struct cfm_allowable_id_element), 0);

	manifest_flash_v2_testing_read_element_mocked_hash_bad_entry (test, &cfm.manifest,
		&CFM_TESTING.manifest, bad_entry.hash_id, 16, bad_entry.hash_id, bad_entry.offset,
		bad_entry.length, bad_entry.length, sizeof (struct cfm_allowable_id_element), &bad_entry,
		NULL);

	status = cfm.test.base.get_next_pfm (&cfm.test.base, 3, &manifest, true);
	CuAssertIntEquals (test, CFM_MALFORMED_ALLOWABLE_ID_ENTRY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_cfm_big_endian (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 20, 2, 20,
		0x854, 0xe, 0xe, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		21, 22);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 21, 21, 21,
		0x862, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 21, 21, 21,
		0x862, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	status = cfm.test.base.get_next_cfm (&cfm.test.base, 3, &manifest, true);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, manifest.manifest_index);
	CuAssertIntEquals (test, 1, manifest.check_count);
	CuAssertStrEquals (test, CFM_ALLOWABLE_CFM_1_PLATFORM_ID_DEVICE_1, manifest.platform_id);

	CuAssertIntEquals (test, CFM_CHECK_GREATER_THAN, manifest.check->check);
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

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 20, 2, 20,
		0x854, 0xe, 0xe, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		21, 22);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 21, 21, 21,
		0x862, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 21, 21, 21,
		0x862, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		22, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 22, 22, 22,
		0x86a, 0xe, 0xe, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		23, 24);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 23, 23, 23,
		0x878, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 23, 23, 23,
		0x878, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	status = cfm.test.base.get_next_cfm (&cfm.test.base, 3, &manifest, true);
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_cfm (&cfm.test.base, 3, &manifest, false);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, manifest.manifest_index);
	CuAssertIntEquals (test, 1, manifest.check_count);
	CuAssertStrEquals (test, CFM_ALLOWABLE_CFM_2_PLATFORM_ID_DEVICE_1, manifest.platform_id);

	CuAssertIntEquals (test, CFM_CHECK_EQUAL, manifest.check->check);
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

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 20, 2, 20,
		0x854, 0xe, 0xe, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		21, 22);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 21, 21, 21,
		0x862, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 21, 21, 21,
		0x862, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		22, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 22, 22, 22,
		0x86a, 0xe, 0xe, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		23, 24);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 23, 23, 23,
		0x878, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 23, 23, 23,
		0x878, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		24, 26);

	status = cfm.test.base.get_next_cfm (&cfm.test.base, 3, &manifest, true);
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_cfm (&cfm.test.base, 3, &manifest, false);
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_cfm (&cfm.test.base, 3, &manifest, false);
	CuAssertIntEquals (test, CFM_ENTRY_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_cfm_second_component (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device2_entry, 2, CFM_TESTING.component_device2_hash,
		CFM_TESTING.component_device2_offset, CFM_TESTING.component_device2_len,
		CFM_TESTING.component_device2_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		27, 38);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 35, 27, 35,
		0x99c, 0xe, 0xe, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		36, 37);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 36, 36, 36,
		0x9aa, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 36, 36, 36,
		0x9aa, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	status = cfm.test.base.get_next_cfm (&cfm.test.base, 4, &manifest, true);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, manifest.manifest_index);
	CuAssertIntEquals (test, 1, manifest.check_count);
	CuAssertStrEquals (test, CFM_ALLOWABLE_CFM_0_PLATFORM_ID_DEVICE_2, manifest.platform_id);

	CuAssertIntEquals (test, CFM_CHECK_LESS_THAN_OR_EQUAL, manifest.check->check);
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

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device2_entry, 2, CFM_TESTING.component_device2_hash,
		CFM_TESTING.component_device2_offset, CFM_TESTING.component_device2_len,
		CFM_TESTING.component_device2_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		27, 38);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 35, 27, 35,
		0x99c, 0xe, 0xe, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		36, 37);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 36, 36, 36,
		0x9aa, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 36, 36, 36,
		0x9aa, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	status = cfm.test.base.get_next_cfm (&cfm.test.base, 4, &manifest, true);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, manifest.manifest_index);
	CuAssertIntEquals (test, 1, manifest.check_count);
	CuAssertStrEquals (test, CFM_ALLOWABLE_CFM_0_PLATFORM_ID_DEVICE_2, manifest.platform_id);

	CuAssertIntEquals (test, CFM_CHECK_LESS_THAN_OR_EQUAL, manifest.check->check);
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

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device2_entry, 2, CFM_TESTING.component_device2_hash,
		CFM_TESTING.component_device2_offset, CFM_TESTING.component_device2_len,
		CFM_TESTING.component_device2_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		27, 38);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 35, 27, 35,
		0x99c, 0xe, 0xe, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		36, 37);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 36, 36, 36,
		0x9aa, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 36, 36, 36,
		0x9aa, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	status = cfm.test.base.get_next_cfm (&cfm.test.base, 4, &manifest, true);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, manifest.manifest_index);
	CuAssertIntEquals (test, 1, manifest.check_count);
	CuAssertStrEquals (test, CFM_ALLOWABLE_CFM_0_PLATFORM_ID_DEVICE_2, manifest.platform_id);

	CuAssertIntEquals (test, CFM_CHECK_LESS_THAN_OR_EQUAL, manifest.check->check);
	CuAssertIntEquals (test, 1, manifest.check->id_count);
	CuAssertIntEquals (test, CFM_ALLOWABLE_CFM_0_ALLOWABLE_ID_DEVICE_2,
		manifest.check->allowable_id[0]);

	cfm.test.base.free_manifest (&cfm.test.base, &manifest);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_cfm_first_free_after_failure (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x08));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_cfm (&cfm.test.base, 3, &manifest, true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm.test.base.free_manifest (&cfm.test.base, &manifest);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_cfm_null (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	status = cfm.test.base.get_next_cfm (NULL, 4, &manifest, true);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.get_next_cfm (&cfm.test.base, 4, NULL, true);
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

	status = cfm.test.base.get_next_cfm (&cfm.test.base, 3, &manifest, true);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_cfm_component_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x08));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_cfm (&cfm.test.base, 3, &manifest, true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_cfm_component_not_found (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device2_entry, 2, CFM_TESTING.component_device2_hash,
		CFM_TESTING.component_device2_offset, CFM_TESTING.component_device2_len,
		CFM_TESTING.component_device2_len, 0);

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

	status = cfm.test.base.get_next_cfm (&cfm.test.base, 5, &manifest, true);
	CuAssertIntEquals (test, MANIFEST_ELEMENT_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_cfm_component_has_no_allowable_cfm (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_ONLY_MEASUREMENT_TESTING, 0, false,
		0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_TESTING.manifest,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_entry, 0,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_hash,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_offset,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_len,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_TESTING.manifest, 2, 2);

	status = cfm.test.base.get_next_cfm (&cfm.test.base, 3, &manifest, true);
	CuAssertIntEquals (test, CFM_ENTRY_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_cfm_get_num_allowable_cfm_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

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

	status = cfm.test.base.get_next_cfm (&cfm.test.base, 3, &manifest, true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_cfm_allowable_cfm_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x10));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_cfm (&cfm.test.base, 3, &manifest, true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_cfm_get_num_allowable_id_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 20, 2, 20,
		0x854, 0xe, 0xe, 0);

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

	status = cfm.test.base.get_next_cfm (&cfm.test.base, 3, &manifest, true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_cfm_allowable_id_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 20, 2, 20,
		0x854, 0xe, 0xe, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		21, 22);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0xa8));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_cfm (&cfm.test.base, 3, &manifest, true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_cfm_allowable_id_ids_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 20, 2, 20,
		0x854, 0xe, 0xe, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		21, 22);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 21, 21, 21,
		0x862, 0x8, sizeof (struct cfm_allowable_id_element), 0);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0xa8));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_next_cfm (&cfm.test.base, 3, &manifest, true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_cfm_malformed_allowable_id (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;
	struct manifest_toc_entry bad_entry;
	uint8_t bad_data[3];

	TEST_START;

	bad_entry.type_id = CFM_ALLOWABLE_ID;
	bad_entry.parent = CFM_ALLOWABLE_CFM;
	bad_entry.format = 0;
	bad_entry.hash_id = 21;
	bad_entry.offset = 0x862;
	bad_entry.length = sizeof (bad_data);

	memset (bad_data, 0x66, sizeof (bad_data));

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, true, 0);

	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_TESTING.manifest, 2, 26);

	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest, &CFM_TESTING.manifest,
		20, 2, 20, 0x854, 0xe, 0xe, 0);

	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_TESTING.manifest, 21, 22);

	manifest_flash_v2_testing_read_element_mocked_hash_bad_entry (test, &cfm.manifest,
		&CFM_TESTING.manifest, bad_entry.hash_id, bad_entry.hash_id, bad_entry.hash_id,
		bad_entry.offset, bad_entry.length, bad_entry.length, 0, &bad_entry, NULL);

	status = cfm.test.base.get_next_cfm (&cfm.test.base, 3, &manifest, true);
	CuAssertIntEquals (test, CFM_MALFORMED_ALLOWABLE_ID_ENTRY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_next_cfm_malformed_allowable_id_list (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	struct manifest_toc_entry bad_entry;
	uint8_t bad_data[3];
	int status;

	bad_entry.type_id = CFM_ALLOWABLE_ID;
	bad_entry.parent = CFM_ALLOWABLE_CFM;
	bad_entry.format = 0;
	bad_entry.hash_id = 21;
	bad_entry.offset = 0x862;
	bad_entry.length = sizeof (bad_data);

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, true, 0);

	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_TESTING.manifest, 2, 26);

	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest, &CFM_TESTING.manifest,
		20, 2, 20, 0x854, 0xe, 0xe, 0);

	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_TESTING.manifest, 21, 22);

	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest, &CFM_TESTING.manifest,
		21, 21, 21, 0x862, 0x8, sizeof (struct cfm_allowable_id_element), 0);

	manifest_flash_v2_testing_read_element_mocked_hash_bad_entry (test, &cfm.manifest,
		&CFM_TESTING.manifest, bad_entry.hash_id, 21, bad_entry.hash_id, bad_entry.offset,
		bad_entry.length, bad_entry.length, sizeof (struct cfm_allowable_id_element), &bad_entry,
		NULL);

	status = cfm.test.base.get_next_cfm (&cfm.test.base, 3, &manifest, true);
	CuAssertIntEquals (test, CFM_MALFORMED_ALLOWABLE_ID_ENTRY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_pcd (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 24, 2, 24,
		0x880, 0xe, 0xe, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		25, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 25, 25, 25,
		0x88e, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 25, 25, 25,
		0x88e, 0x8, 0x8 -sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	status = cfm.test.base.get_pcd (&cfm.test.base, 3, &manifest);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, manifest.manifest_index);
	CuAssertIntEquals (test, 1, manifest.check_count);
	CuAssertStrEquals (test, CFM_ALLOWABLE_PCD_PLATFORM_ID_DEVICE_1, manifest.platform_id);

	CuAssertIntEquals (test, CFM_CHECK_LESS_THAN_OR_EQUAL, manifest.check->check);
	CuAssertIntEquals (test, 1, manifest.check->id_count);
	CuAssertIntEquals (test, CFM_ALLOWABLE_PCD_ALLOWABLE_ID_DEVICE_1,
		manifest.check->allowable_id[0]);

	cfm.test.base.free_manifest (&cfm.test.base, &manifest);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_pcd_second_component_big_endian (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device2_entry, 2, CFM_TESTING.component_device2_hash,
		CFM_TESTING.component_device2_offset, CFM_TESTING.component_device2_len,
		CFM_TESTING.component_device2_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		27, 38);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 37, 27, 37,
		0x9b2, 0xe, 0xe, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		38, 38);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 38, 38, 38,
		0x9c0, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 38, 38, 38,
		0x9c0, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	status = cfm.test.base.get_pcd (&cfm.test.base, 4, &manifest);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, manifest.manifest_index);
	CuAssertIntEquals (test, 1, manifest.check_count);
	CuAssertStrEquals (test, CFM_ALLOWABLE_PCD_PLATFORM_ID_DEVICE_2, manifest.platform_id);

	CuAssertIntEquals (test, CFM_CHECK_LESS_THAN, manifest.check->check);
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

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device2_entry, 2, CFM_TESTING.component_device2_hash,
		CFM_TESTING.component_device2_offset, CFM_TESTING.component_device2_len,
		CFM_TESTING.component_device2_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		27, 38);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 37, 27, 37,
		0x9b2, 0xe, 0xe, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		38, 38);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 38, 38, 38,
		0x9c0, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 38, 38, 38,
		0x9c0, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	status = cfm.test.base.get_pcd (&cfm.test.base, 4, &manifest);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, manifest.manifest_index);
	CuAssertIntEquals (test, 1, manifest.check_count);
	CuAssertStrEquals (test, CFM_ALLOWABLE_PCD_PLATFORM_ID_DEVICE_2, manifest.platform_id);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, CFM_CHECK_LESS_THAN, manifest.check->check);
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

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device2_entry, 2, CFM_TESTING.component_device2_hash,
		CFM_TESTING.component_device2_offset, CFM_TESTING.component_device2_len,
		CFM_TESTING.component_device2_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		27, 38);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 37, 27, 37,
		0x9b2, 0xe, 0xe, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		38, 38);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 38, 38, 38,
		0x9c0, 0x8, sizeof (struct cfm_allowable_id_element), 0);
	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 38, 38, 38,
		0x9c0, 0x8, 0x8 - sizeof (struct cfm_allowable_id_element),
		sizeof (struct cfm_allowable_id_element));

	status = cfm.test.base.get_pcd (&cfm.test.base, 4, &manifest);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, manifest.manifest_index);
	CuAssertIntEquals (test, 1, manifest.check_count);
	CuAssertStrEquals (test, CFM_ALLOWABLE_PCD_PLATFORM_ID_DEVICE_2, manifest.platform_id);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, CFM_CHECK_LESS_THAN, manifest.check->check);
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

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	status = cfm.test.base.get_pcd (NULL, 4, &manifest);
	CuAssertIntEquals (test, CFM_INVALID_ARGUMENT, status);

	status = cfm.test.base.get_pcd (&cfm.test.base, 4, NULL);
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

	status = cfm.test.base.get_pcd (&cfm.test.base, 3, &manifest);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_pcd_component_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x08));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_pcd (&cfm.test.base, 3, &manifest);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_pcd_component_not_found (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device2_entry, 2, CFM_TESTING.component_device2_hash,
		CFM_TESTING.component_device2_offset, CFM_TESTING.component_device2_len,
		CFM_TESTING.component_device2_len, 0);

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

	status = cfm.test.base.get_pcd (&cfm.test.base, 5, &manifest);
	CuAssertIntEquals (test, MANIFEST_ELEMENT_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_pcd_component_has_no_allowable_pcd (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_ONLY_MEASUREMENT_TESTING, 0, false,
		0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_TESTING.manifest,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_entry, 0,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_hash,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_offset,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_len,
		CFM_ONLY_MEASUREMENT_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest,
		&CFM_ONLY_MEASUREMENT_TESTING.manifest, 2, 2);

	status = cfm.test.base.get_pcd (&cfm.test.base, 3, &manifest);
	CuAssertIntEquals (test, CFM_ENTRY_NOT_FOUND, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_pcd_get_num_allowable_pcd_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

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

	status = cfm.test.base.get_pcd (&cfm.test.base, 3, &manifest);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_pcd_allowable_pcd_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x10));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_pcd (&cfm.test.base, 3, &manifest);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_pcd_get_num_allowable_id_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 24, 2, 24,
		0x880, 0xe, 0xe, 0);

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

	status = cfm.test.base.get_pcd (&cfm.test.base, 3, &manifest);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_pcd_allowable_id_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 24, 2, 24,
		0x880, 0xe, 0xe, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		25, 26);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0xc8));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_pcd (&cfm.test.base, 3, &manifest);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_pcd_allowable_id_ids_read_fail (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		2, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 24, 2, 24,
		0x880, 0xe, 0xe, 0);

	manifest_flash_v2_testing_iterate_manifest_toc (test, &cfm.manifest, &CFM_TESTING.manifest,
		25, 26);

	manifest_flash_v2_testing_read_element (test, &cfm.manifest, &CFM_TESTING.manifest, 25, 25, 25,
		0x88e, 0x8, sizeof (struct cfm_allowable_id_element), 0);

	status = mock_expect (&cfm.manifest.flash.mock, cfm.manifest.flash.base.read,
		&cfm.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0xc8));
	CuAssertIntEquals (test, 0, status);

	status = cfm.test.base.get_pcd (&cfm.test.base, 3, &manifest);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_pcd_malformed_allowable_id (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	int status;
	struct manifest_toc_entry bad_entry;
	uint8_t bad_data[3];

	TEST_START;

	bad_entry.type_id = CFM_ALLOWABLE_ID;
	bad_entry.parent = CFM_ALLOWABLE_PCD;
	bad_entry.format = 0;
	bad_entry.hash_id = 25;
	bad_entry.offset = 0x88e;
	bad_entry.length = sizeof (bad_data);

	memset (bad_data, 0x66, sizeof (bad_data));

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, true, 0);

	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_TESTING.manifest, 2, 26);

	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest, &CFM_TESTING.manifest,
		24, 2, 24, 0x880, 0xe, 0xe, 0);

	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_TESTING.manifest, 25, 26);

	manifest_flash_v2_testing_read_element_mocked_hash_bad_entry (test, &cfm.manifest,
		&CFM_TESTING.manifest, bad_entry.hash_id, bad_entry.hash_id, bad_entry.hash_id,
		bad_entry.offset, bad_entry.length, bad_entry.length, 0, &bad_entry, NULL);

	status = cfm.test.base.get_pcd (&cfm.test.base, 3, &manifest);
	CuAssertIntEquals (test, CFM_MALFORMED_ALLOWABLE_ID_ENTRY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_get_pcd_malformed_allowable_id_list (CuTest *test)
{
	struct cfm_flash_testing cfm;
	struct cfm_manifest manifest;
	struct manifest_toc_entry bad_entry;
	uint8_t bad_data[3];
	int status;

	bad_entry.type_id = CFM_ALLOWABLE_ID;
	bad_entry.parent = CFM_ALLOWABLE_PCD;
	bad_entry.format = 0;
	bad_entry.hash_id = 25;
	bad_entry.offset = 0x88e;
	bad_entry.length = sizeof (bad_data);

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, true, 0);

	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest, &CFM_TESTING.manifest,
		CFM_TESTING.component_device1_entry, 0, CFM_TESTING.component_device1_hash,
		CFM_TESTING.component_device1_offset, CFM_TESTING.component_device1_len,
		CFM_TESTING.component_device1_len, 0);

	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_TESTING.manifest, 2, 26);

	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest, &CFM_TESTING.manifest,
		24, 2, 24, 0x880, 0xe, 0xe, 0);

	manifest_flash_v2_testing_iterate_manifest_toc_mocked_hash (test, &cfm.manifest,
		&CFM_TESTING.manifest, 25, 26);

	manifest_flash_v2_testing_read_element_mocked_hash (test, &cfm.manifest, &CFM_TESTING.manifest,
		25, 25, 25, 0x88e, 0x8, sizeof (struct cfm_allowable_id_element), 0);

	manifest_flash_v2_testing_read_element_mocked_hash_bad_entry (test, &cfm.manifest,
		&CFM_TESTING.manifest, bad_entry.hash_id, 25, bad_entry.hash_id, bad_entry.offset,
		bad_entry.length, bad_entry.length, sizeof (struct cfm_allowable_id_element), &bad_entry,
		NULL);

	status = cfm.test.base.get_pcd (&cfm.test.base, 3, &manifest);
	CuAssertIntEquals (test, CFM_MALFORMED_ALLOWABLE_ID_ENTRY, status);

	cfm_flash_testing_validate_and_release (test, &cfm);
}

static void cfm_flash_test_free_manifest_null (CuTest *test)
{
	struct cfm_flash_testing cfm;

	TEST_START;

	cfm_flash_testing_init_and_verify (test, &cfm, 0x10000, &CFM_TESTING, 0, false, 0);

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
TEST (cfm_flash_test_get_component_pmr_digest_invalid_hash_type);
TEST (cfm_flash_test_get_component_pmr_digest_malformed_pmr_digest);
TEST (cfm_flash_test_free_component_pmr_digest_null);
TEST (cfm_flash_test_buffer_supported_components);
TEST (cfm_flash_test_buffer_supported_components_offset_nonzero);
TEST (cfm_flash_test_buffer_supported_components_offset_too_large);
TEST (cfm_flash_test_buffer_supported_components_offset_not_word_aligned);
TEST (cfm_flash_test_buffer_supported_components_offset_in_second_component);
TEST (cfm_flash_test_buffer_supported_components_null);
TEST (cfm_flash_test_buffer_supported_components_verify_never_run);
TEST (cfm_flash_test_buffer_supported_components_component_read_fail);
TEST (cfm_flash_test_buffer_supported_components_malformed_component_device);
TEST (cfm_flash_test_get_component_device);
TEST (cfm_flash_test_get_component_device_second_component);
TEST (cfm_flash_test_get_component_device_null);
TEST (cfm_flash_test_get_component_device_component_read_fail);
TEST (cfm_flash_test_get_component_device_get_num_pmr_digest_fail);
TEST (cfm_flash_test_get_component_device_pmr_digest_read_fail);
TEST (cfm_flash_test_get_component_device_component_not_found);
TEST (cfm_flash_test_get_component_device_verify_never_run);
TEST (cfm_flash_test_get_component_device_invalid_transcript_hash_type);
TEST (cfm_flash_test_get_component_device_invalid_measurement_hash_type);
TEST (cfm_flash_test_get_component_device_malformed_component_device);
TEST (cfm_flash_test_get_component_device_malformed_pmr_digest);
TEST (cfm_flash_test_free_component_device_null);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_measurement_first);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_measurement_nonzero_version_set);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_second_measurement);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_measurement_after_measurement_data);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_second_measurement_after_measurement_data);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_no_more_measurement_after_measurement_data);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_measurement_data_first);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_measurement_data_nonzero_version_set);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_second_measurement_data);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_measurement_data_after_measurement);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_second_measurement_data_after_measurement);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_no_more_measurement_data_after_measurement);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_measurement_data_single_allowable_data);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_measurement_data_no_bitmask);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_single_check);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_second_component);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_no_measurement_data);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_no_measurement);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_first_free_after_failure);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_null);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_verify_never_run);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_component_read_fail);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_component_not_found);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_get_first_measurement_entry_id_fail);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_get_first_measurement_data_entry_id_fail);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_no_measurement_or_measurement_data);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_get_num_measurements_fail);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_measurement_read_fail);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_allowable_digests_read_fail);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_get_num_measurement_data_fail);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_measurement_data_read_fail);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_get_num_allowable_data_fail);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_allowable_data_read_fail);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_bitmask_read_fail);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_allowable_data_buffer_read_fail);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_digests_list_read_fail);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_malformed_component);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_malformed_measurement);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_malformed_allowable_digest);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_incomplete_digests_read);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_malformed_measurement_data);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_malformed_allowable_data);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_malformed_bitmask);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_malformed_allowable_data_entry);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_read_data_fail);
TEST (cfm_flash_test_get_next_measurement_or_measurement_data_malformed_allowable_data_entry_data);
TEST (cfm_flash_test_free_measurement_container_again_after_measurement_digest_free);
TEST (cfm_flash_test_free_measurement_container_again_after_measurement_data_free);
TEST (cfm_flash_test_free_measurement_container_null);
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
TEST (cfm_flash_test_get_root_ca_digest_malformed_root_ca_digest);
TEST (cfm_flash_test_get_root_ca_digest_invalid_hash_type);
TEST (cfm_flash_test_free_root_ca_digest_null);
TEST (cfm_flash_test_get_next_pfm_multiple_big_endian_ids);
TEST (cfm_flash_test_get_next_pfm_second_pfm_big_endian);
TEST (cfm_flash_test_get_next_pfm_no_more_pfm);
TEST (cfm_flash_test_get_next_pfm_second_component_big_endian);
TEST (cfm_flash_test_get_next_pfm_single_check);
TEST (cfm_flash_test_get_next_pfm_single_id);
TEST (cfm_flash_test_get_next_pfm_first_free_after_failure);
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
TEST (cfm_flash_test_get_next_pfm_malformed_allowable_id);
TEST (cfm_flash_test_get_next_pfm_malformed_allowable_id_list);
TEST (cfm_flash_test_get_next_cfm_big_endian);
TEST (cfm_flash_test_get_next_cfm_second_cfm);
TEST (cfm_flash_test_get_next_cfm_no_more_cfm);
TEST (cfm_flash_test_get_next_cfm_second_component);
TEST (cfm_flash_test_get_next_cfm_single_check);
TEST (cfm_flash_test_get_next_cfm_single_id);
TEST (cfm_flash_test_get_next_cfm_first_free_after_failure);
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
TEST (cfm_flash_test_get_next_cfm_malformed_allowable_id);
TEST (cfm_flash_test_get_next_cfm_malformed_allowable_id_list);
TEST (cfm_flash_test_get_pcd);
TEST (cfm_flash_test_get_pcd_second_component_big_endian);
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
TEST (cfm_flash_test_get_pcd_malformed_allowable_id);
TEST (cfm_flash_test_get_pcd_malformed_allowable_id_list);
TEST (cfm_flash_test_free_manifest_null);

TEST_SUITE_END;
