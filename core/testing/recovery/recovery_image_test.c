// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "platform.h"
#include "testing.h"
#include "recovery/recovery_image.h"
#include "recovery/recovery_image_section_header.h"
#include "recovery/recovery_image_header.h"
#include "cmd_interface/cmd_interface_system.h"
#include "cmd_interface/cerberus_protocol.h"
#include "flash/flash_common.h"
#include "testing/mock/crypto/signature_verification_mock.h"
#include "testing/mock/flash/flash_mock.h"
#include "testing/mock/flash/flash_master_mock.h"
#include "testing/mock/manifest/pfm_mock.h"
#include "testing/mock/manifest/pfm_manager_mock.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/common/image_header_testing.h"
#include "testing/recovery/recovery_image_testing.h"
#include "testing/recovery/recovery_image_header_testing.h"
#include "testing/recovery/recovery_image_section_header_testing.h"


TEST_SUITE_LABEL ("recovery_image");


/**
 * Dummy recovery image with one recovery section for testing.
 */
const uint8_t RECOVERY_IMAGE_DATA[] = {
	0x40,0x00,0x00,0x00,0x29,0x7c,0x14,0x8a,0x56,0x65,0x72,0x73,0x69,0x6f,0x6e,0x20,
	0x54,0x65,0x73,0x74,0x31,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x90,0x04,0x00,0x00,0x00,0x01,0x00,0x00,
	0x0f,0x50,0x6c,0x61,0x74,0x66,0x6f,0x72,0x6d,0x20,0x54,0x65,0x73,0x74,0x31,0x00,
	0x10,0x00,0x00,0x00,0x31,0x2f,0x17,0x4b,0x00,0x04,0x00,0x00,0x40,0x03,0x00,0x00,
	0x98,0xdd,0xd6,0xcb,0x9f,0x38,0xea,0x4f,0x40,0xe2,0x16,0x5a,0x33,0x1e,0xff,0x37,
	0x00,0x94,0x0e,0x89,0xe5,0xae,0x07,0x5c,0xcf,0x39,0x2f,0x55,0x22,0x70,0x8a,0x86,
	0x25,0x61,0x50,0x06,0xfc,0xa8,0xc3,0xf6,0x9a,0x2a,0xee,0x82,0xd0,0x8a,0x73,0x93,
	0x56,0x38,0xc3,0x2c,0x89,0x40,0x23,0x37,0x83,0xf8,0x73,0x27,0x77,0x10,0x2d,0x04,
	0x19,0xfc,0x9e,0xf3,0x98,0x07,0x27,0x3a,0xab,0x14,0x48,0x46,0x61,0x66,0x54,0xdf,
	0x59,0xc6,0x54,0xa0,0x62,0x00,0xbf,0xe4,0x45,0xd9,0x36,0x61,0xd2,0xe4,0xe7,0x69,
	0x4c,0x25,0x87,0x6a,0x38,0x34,0xf6,0xdd,0x2f,0xdf,0x90,0xb5,0xa4,0x6d,0xb7,0xef,
	0x04,0xff,0x86,0xfd,0x28,0xb5,0xef,0xc1,0xb7,0xfd,0x80,0x82,0x78,0x7d,0x7f,0x3f,
	0x27,0x9d,0x50,0xc4,0xf7,0x52,0x29,0xc3,0x64,0x51,0xf6,0x8b,0xc3,0x1c,0xe9,0x17,
	0x61,0xe0,0x30,0x16,0x8b,0x15,0x60,0x6d,0xe6,0x83,0x8e,0x53,0xa8,0xec,0xae,0xd6,
	0xc6,0x1c,0x6d,0xb5,0xee,0x9b,0x92,0x37,0x17,0x13,0x3a,0x92,0x45,0x08,0xb5,0x52,
	0xc5,0x19,0xaf,0xfa,0x47,0x89,0x0e,0xf1,0x21,0x4b,0x42,0x55,0x96,0xe5,0x2d,0xac,
	0xd1,0x4d,0x63,0xb6,0xcc,0xe1,0xab,0xb8,0x42,0xc8,0x41,0x13,0x7d,0x31,0xd4,0xcd,
	0x7b,0xc2,0x20,0xd6,0x06,0xf5,0x6f,0x77,0x17,0x46,0xaf,0x98,0x71,0x02,0x2d,0xd1,
	0xcf,0x02,0xbc,0x8e,0x41,0xb1,0xde,0x25,0x87,0x76,0xa1,0x62,0x15,0x3c,0xb5,0xbf,
	0x18,0x96,0xb9,0x9f,0x2c,0xfc,0x84,0x72,0x08,0x8d,0x0e,0x2b,0x7f,0x42,0x27,0x6e,
	0xe8,0xa8,0x11,0x70,0xd7,0x4f,0x9b,0x68,0x41,0x8b,0xd8,0x4f,0xf3,0xbe,0x5a,0xbe,
	0x0a,0xd9,0x07,0xbf,0x9a,0x51,0x89,0xa7,0xbe,0xca,0xd7,0xc0,0x36,0x6f,0x05,0x39,
	0x8a,0x00,0xc2,0x5c,0x59,0xa2,0x4f,0x49,0xe9,0x23,0xd2,0xf8,0x52,0x58,0x72,0x57,
	0xc4,0xcc,0xb2,0xd1,0x87,0x6a,0x94,0x15,0xa9,0xe7,0xf6,0xba,0x0e,0xf7,0xe5,0xe3,
	0x40,0x44,0x9e,0x28,0x1d,0x01,0xb1,0x92,0xac,0xeb,0x47,0x20,0xff,0x74,0xd0,0x6d,
	0x63,0x6c,0x15,0x29,0x95,0x7c,0x21,0xb9,0x8c,0x22,0x2f,0xa0,0x1e,0x43,0x2f,0xc4,
	0xe9,0xe1,0xc9,0xc5,0x26,0xce,0x2a,0x88,0x16,0x4a,0x19,0x8b,0x10,0xf1,0xb9,0x5b,
	0x28,0x94,0x62,0xba,0x84,0x1a,0x06,0x89,0x7e,0xec,0xae,0x63,0xd0,0x07,0xd2,0x0c,
	0xf0,0x72,0xd9,0x02,0x7b,0xb9,0xf9,0xc5,0x26,0x85,0x63,0x6b,0xfa,0x11,0xc4,0x77,
	0x29,0x0b,0x4b,0xd0,0xba,0xa3,0xe0,0xd9,0xa0,0xb5,0x82,0xd0,0xa5,0x7e,0x33,0xab,
	0xe5,0x86,0xf6,0xdb,0x0f,0xe1,0x9f,0x96,0xf3,0xd2,0xfb,0x13,0x18,0xc3,0xd5,0x58,
	0xe8,0x23,0x10,0x1c,0x6c,0xfa,0x41,0x40,0xd0,0xb6,0xe5,0xf0,0x14,0x52,0xfd,0xc8,
	0xf3,0x47,0xe8,0xb1,0x62,0x33,0x1f,0x3f,0xb5,0xd4,0x45,0xa8,0x73,0x16,0xc3,0xad,
	0x1c,0x0b,0xf8,0xc7,0x6f,0x02,0x29,0x45,0x49,0xdf,0xf4,0x21,0xd4,0xd8,0xc9,0xba,
	0xd0,0xa7,0xff,0xf0,0x32,0x08,0xaf,0x49,0xa1,0x9c,0x35,0x70,0x42,0x55,0x6e,0x85,
	0x32,0x3c,0x85,0x52,0x20,0xf7,0x37,0xaa,0x8b,0xb9,0xdc,0x02,0x0a,0x5c,0x98,0x17,
	0x9b,0x09,0xd8,0x0a,0xef,0xf4,0xce,0x25,0x06,0x74,0x26,0x53,0xbf,0x3b,0x3e,0xfc,
	0x03,0xf2,0x5e,0xbf,0xb1,0x74,0x67,0x6b,0x5b,0xc4,0x9f,0x44,0xb1,0xec,0x9b,0xa0,
	0x61,0xae,0x72,0xb7,0x0c,0x53,0x36,0x4c,0x73,0xe6,0xbb,0x34,0x50,0x82,0x85,0x23,
	0xdd,0x6e,0x50,0x72,0xa5,0xc3,0xb2,0xea,0xcf,0x9e,0x4e,0x42,0x57,0xf9,0x5d,0xe8,
	0x7b,0x02,0xe9,0xbb,0x36,0xd9,0xce,0x6f,0x1e,0x5d,0xc4,0x48,0xb0,0x55,0x87,0x58,
	0x07,0xd2,0xa5,0x3a,0xba,0xba,0x34,0x57,0x4b,0x3d,0x2d,0xf5,0x6a,0x87,0x1c,0x82,
	0x18,0x19,0x94,0x0d,0xe6,0x8a,0x64,0x3f,0xb4,0x7f,0x3c,0xe8,0xcd,0x74,0x4a,0x63,
	0x3d,0x8c,0x16,0x82,0x8c,0x9e,0x09,0xf2,0xd5,0xdd,0x9c,0xe5,0xfa,0x92,0xb0,0x66,
	0x4a,0x0f,0x76,0xf0,0xce,0x3f,0x49,0x84,0x76,0xe3,0x55,0xa9,0x1d,0xca,0x7d,0xfe,
	0x43,0x1d,0xac,0x1d,0xbe,0xd0,0x1b,0xc5,0x7c,0xaf,0x49,0xed,0xa6,0x21,0x6b,0xd7,
	0x3f,0x10,0x29,0x7a,0xb5,0x5f,0x81,0x3d,0xa6,0xca,0x12,0x1e,0x61,0x22,0x97,0x21,
	0xd9,0x78,0x93,0xf3,0xde,0xfc,0x26,0xc0,0xbf,0x90,0xe0,0x16,0x82,0xc9,0xf9,0x31,
	0x9b,0x9c,0x84,0x59,0xf8,0x99,0x21,0x8e,0xa6,0xe4,0xb9,0x24,0x87,0xa9,0xd5,0x68,
	0x0a,0xba,0xeb,0xa7,0x2c,0x61,0x45,0xde,0xd5,0x62,0x1c,0x84,0x66,0xd6,0x1c,0x8b,
	0x72,0xa9,0xe1,0x29,0xe6,0x4e,0x84,0xee,0xe2,0xa8,0x06,0xb3,0x46,0x8b,0xb7,0xb7,
	0x69,0x83,0x77,0x42,0x3e,0x32,0xdb,0xdf,0x4f,0xf4,0xad,0x60,0x6a,0x66,0x92,0xc2,
	0x57,0x10,0x7a,0x78,0x34,0x28,0xe9,0xa7,0x9e,0x96,0xeb,0xf1,0x1e,0x64,0xcf,0x2d,
	0x67,0x18,0x4a,0x56,0x2a,0x60,0x6e,0x24,0xd9,0x1b,0x5b,0xda,0x6b,0xd7,0x82,0xa3,
	0x79,0x43,0xc9,0x4e,0x88,0x18,0x78,0x78,0x65,0xc6,0x47,0xc5,0x63,0xa4,0xde,0xed,
	0x1e,0xbd,0xb4,0xab,0xf0,0x10,0x55,0xbd,0x0a,0x50,0x2b,0x6a,0xce,0x53,0x85,0x16,
	0xbc,0x72,0x23,0x55,0x96,0x01,0x44,0x3a,0xf4,0xea,0x1b,0x02,0x16,0x1a,0x9c,0x57,
	0xa7,0xb6,0x95,0x3f,0x8e,0xee,0xad,0xbd,0xe2,0x50,0x1d,0xe2,0x85,0xc8,0xdd,0x8e,
	0x0c,0x44,0x07,0x2a,0x08,0x1b,0x6e,0x2c,0x12,0x6d,0xa4,0x35,0x4a,0x44,0x4e,0x31,
	0x6f,0x16,0x90,0xc2,0xa8,0xd5,0x87,0x07,0x6b,0x83,0x42,0x85,0x34,0x8c,0xfa,0x0a,
	0xc1,0x05,0x1d,0x52,0xb9,0xa6,0xee,0x9c,0x5b,0x09,0x26,0x52,0xc1,0xa9,0xd2,0x72,
	0xb1,0x0b,0x6a,0x9a,0xdd,0xbc,0xba,0x3e,0xe5,0x79,0x86,0x49,0x03,0xf4,0x77,0x73,
	0x95,0x69,0x94,0x14,0x42,0x41,0x14,0xe8,0x92,0x67,0xac,0xe2,0x84,0x68,0xf8,0x9b,
	0x24,0x04,0xe5,0x17,0xd0,0xd6,0x72,0x9e,0x06,0x6e,0xe0,0x0d,0xe9,0xb4,0x2a,0x25,
	0xf6,0x8e,0xc3,0xb1,0x19,0x2e,0x4e,0xf3,0xc5,0x71,0xc4,0xda,0x07,0xc8,0x37,0x0a,
	0xa0,0x80,0x80,0x9e,0x7a,0x89,0x4f,0x97,0x6b,0xae,0xf5,0x06,0x6f,0x4c,0xdb,0x93,
	0xff,0xba,0xb2,0x32,0x2d,0xb8,0x5f,0x84,0xe0,0x86,0x44,0x42,0xe0,0x83,0x33,0x00,
	0x1f,0xc0,0xff,0x7a,0x2a,0xac,0xa0,0x23,0x3e,0x88,0xd6,0x62,0xac,0x06,0xf8,0x72,
	0x46,0x76,0x5c,0x9a,0x1c,0x09,0x19,0x06,0xdd,0x0f,0xec,0x50,0x9a,0x8a,0x03,0x00,
	0x03,0x78,0x70,0x7d,0xd4,0x22,0x46,0xa9,0xe1,0x20,0x48,0x4e,0x46,0x87,0xd6,0x5e,
	0x8d,0x92,0xa3,0xa1,0xad,0xb7,0x40,0x14,0x7d,0x9b,0xb2,0x55,0xf2,0x96,0xde,0xff,
	0x4a,0x14,0x3f,0xf0,0xd8,0xd2,0x33,0x18,0xe5,0xb0,0xd7,0x8a,0x80,0xae,0x10,0xb4
};

/**
 * Dummy recovery image with two recovery sections for testing.
 */
const uint8_t RECOVERY_IMAGE_DATA2[] = {
	0x40,0x00,0x00,0x00,0x29,0x7c,0x14,0x8a,0x56,0x65,0x72,0x73,0x69,0x6f,0x6e,0x20,
	0x54,0x65,0x73,0x74,0x31,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x90,0x04,0x00,0x00,0x00,0x01,0x00,0x00,
	0x0f,0x50,0x6c,0x61,0x74,0x66,0x6f,0x72,0x6d,0x20,0x54,0x65,0x73,0x74,0x31,0x00,
	0x10,0x00,0x00,0x00,0x31,0x2f,0x17,0x4b,0x00,0x04,0x00,0x00,0x3c,0x01,0x00,0x00,
	0xe8,0xd9,0x0d,0x92,0xe9,0xf5,0xd9,0xa8,0x46,0x21,0x9f,0xe4,0x4a,0x75,0x18,0xe5,
	0x0b,0x74,0x2d,0xd4,0x4c,0x92,0x4f,0xfa,0xa8,0x55,0x7e,0xa0,0x2f,0xfa,0xf8,0x97,
	0x5f,0x6d,0x79,0x4c,0xa1,0xe8,0x50,0x90,0x07,0x18,0xfe,0x73,0x69,0x2e,0xd3,0xe1,
	0x81,0x33,0x61,0xb5,0xc9,0xe2,0xb7,0x7d,0xf4,0xd3,0x5f,0xf3,0xec,0xab,0x74,0x50,
	0xac,0xe5,0xce,0x3c,0x84,0x04,0xfa,0x01,0xd0,0x05,0xa4,0x62,0xde,0x0a,0xf4,0xce,
	0xc0,0x74,0x1e,0x9e,0x5b,0xc0,0xa3,0xb7,0x4c,0xec,0x43,0x29,0xa0,0xdb,0x9e,0x35,
	0x38,0xbe,0xc2,0xcb,0xca,0x45,0x19,0x7e,0x91,0xdb,0x28,0x2a,0x26,0x6f,0x2b,0x17,
	0x60,0xae,0x92,0x02,0xac,0xbf,0x2b,0x9a,0x9c,0xd7,0xe5,0xd4,0x29,0x78,0x26,0x0f,
	0x5c,0x6c,0xd6,0x71,0xd8,0x54,0xb1,0x3e,0x12,0x29,0x4e,0x39,0x3a,0x13,0x46,0x19,
	0x1d,0x82,0x14,0xfc,0x95,0x23,0xb3,0x6a,0x1d,0x45,0xd7,0xe8,0x49,0xba,0xf5,0xc3,
	0x10,0x6b,0x4f,0xa1,0x79,0x64,0x3d,0xed,0x1f,0x50,0xc1,0xac,0x6c,0x49,0x31,0x5b,
	0x60,0x6e,0x1e,0x21,0xad,0x4f,0xf0,0x93,0x3e,0xad,0x7e,0xf6,0x79,0xde,0x7b,0x9e,
	0xb6,0xe0,0x43,0x2b,0xb1,0xaf,0x9f,0xde,0x14,0x87,0x2c,0x13,0xa7,0x6a,0xc2,0x56,
	0x1e,0x91,0xfe,0x5f,0x56,0x61,0xbb,0xc5,0xe8,0x84,0x3e,0x12,0x6a,0x80,0xcf,0xf8,
	0x36,0x11,0xe7,0x12,0xc9,0x8b,0x3c,0xb9,0xb4,0x27,0xcc,0x8f,0xc8,0x5c,0x6e,0x89,
	0x47,0xd7,0xf4,0xa3,0xb3,0x31,0xad,0x51,0x9e,0xed,0xcf,0xce,0xd5,0x21,0x73,0xaa,
	0x7d,0x7b,0x71,0x18,0xa4,0xc3,0x0d,0x57,0xa7,0xe3,0x60,0xd5,0x21,0x47,0x9f,0x6d,
	0x02,0x22,0xd1,0x3e,0x08,0xac,0xb7,0x8a,0xf1,0x99,0x4a,0xb0,0x0f,0xef,0xd6,0xe7,
	0x29,0xeb,0x26,0x58,0x8e,0x84,0x98,0x9f,0x9c,0x4c,0x88,0x40,0x64,0x3e,0x9b,0xbd,
	0x91,0x28,0xde,0xa4,0x27,0x77,0x4a,0xfa,0x01,0xb1,0xcd,0xa5,0x10,0x00,0x00,0x00,
	0x31,0x2f,0x17,0x4b,0x00,0x08,0x00,0x00,0xf4,0x01,0x00,0x00,0xb3,0x4d,0xbe,0x14,
	0x92,0xf3,0x6b,0xa4,0xbd,0xb6,0x65,0x6f,0xae,0xf6,0xaf,0xb7,0xcf,0x48,0xfb,0xc8,
	0x6e,0x30,0xdc,0xcb,0x8c,0x77,0x9d,0xfa,0xab,0x01,0x6d,0xfe,0xf1,0x9c,0xd5,0x26,
	0x69,0x52,0xff,0xb4,0x42,0xc6,0x2a,0xcc,0x23,0xbe,0xb5,0xe0,0xb3,0x23,0xdc,0x43,
	0xa3,0x90,0x95,0x4c,0x42,0xc8,0xca,0xbd,0x15,0x58,0x47,0x9d,0xcc,0xc4,0xb1,0x55,
	0xed,0x8d,0xf5,0x73,0xc6,0x27,0xf4,0x09,0xd2,0xf9,0xcb,0x49,0x74,0x1d,0xbc,0xaf,
	0x74,0x83,0x44,0x5c,0x9d,0x04,0x6d,0x24,0x22,0xd6,0x93,0xb7,0x57,0x6f,0x4c,0xb2,
	0x08,0xbc,0xda,0x04,0x6b,0x8f,0xcd,0xd3,0xcd,0x1b,0x87,0x03,0x97,0xe4,0x0d,0xa4,
	0x18,0x60,0x07,0x66,0xee,0x80,0xa7,0xa0,0x8b,0xad,0x75,0x8b,0x38,0x8f,0x5a,0x6a,
	0xca,0xea,0x9e,0x1c,0x88,0x1c,0x88,0xdc,0x97,0xf8,0x09,0x6e,0x57,0xf9,0x5b,0x71,
	0x0d,0x04,0xd7,0xed,0x69,0x0b,0x1a,0xef,0xd1,0x3e,0xce,0xc2,0xa4,0xef,0xad,0x05,
	0x7e,0xbf,0x72,0x06,0x63,0xcb,0x9e,0xb4,0x4c,0x41,0xe0,0x23,0xdd,0x15,0x0a,0x38,
	0x0b,0x56,0xfa,0x03,0xcf,0xf4,0xfa,0x1e,0x7e,0x8c,0x1d,0x95,0x05,0x0b,0xa9,0xeb,
	0x16,0x07,0x92,0x43,0xe8,0xab,0x1b,0x18,0xe8,0x84,0xa3,0x1e,0xf5,0xae,0xbd,0x09,
	0x62,0x3d,0x8f,0xb5,0xac,0xb9,0xfb,0xc9,0xf3,0x90,0xc1,0x7d,0xd1,0x8c,0xfe,0x60,
	0x99,0x9c,0x20,0xba,0xf0,0xe1,0x13,0x75,0x4d,0x7a,0x9e,0x43,0xfe,0x8b,0xc1,0xd2,
	0x32,0x8b,0xd3,0x80,0x86,0x50,0xdb,0x7c,0xd1,0x34,0xf1,0x7e,0xee,0x35,0x81,0x2e,
	0x9b,0x73,0x71,0xd0,0xaf,0x5a,0x06,0x91,0xbf,0x52,0xaa,0xb1,0x54,0xc6,0x94,0x26,
	0x1c,0xbe,0x7f,0x37,0x19,0x35,0xd3,0x32,0xef,0xa9,0x75,0x5e,0xe1,0xd7,0xfe,0x96,
	0xe7,0x8c,0xce,0x21,0x53,0xa7,0x6a,0x6a,0x20,0x8f,0x87,0x5d,0x49,0xfe,0x89,0x70,
	0x9c,0x25,0xab,0xa0,0x4a,0xa0,0xb3,0x31,0xe6,0x71,0xb3,0xcd,0x44,0xff,0x7e,0x12,
	0x1d,0x8e,0x74,0x8a,0xd6,0x66,0x5f,0xfb,0x19,0x64,0x45,0xb8,0x61,0x76,0xd6,0x08,
	0x15,0x6f,0x86,0x70,0xe0,0x0c,0xef,0x52,0x95,0x2a,0x60,0x44,0xc1,0xb7,0x4b,0x83,
	0xc4,0xe0,0xb4,0xb8,0x5f,0x20,0x2f,0x29,0x71,0xa9,0xe5,0xe2,0x84,0x6b,0x85,0xf0,
	0x04,0x38,0x12,0xa9,0x3d,0xb6,0x06,0xd4,0x78,0xb1,0xaa,0x17,0x08,0x91,0x9b,0xe6,
	0xa7,0x7e,0xd5,0x7b,0x75,0xd2,0x4f,0xd5,0xdc,0x6d,0x3e,0x9f,0x9a,0x52,0xd7,0x0d,
	0xe4,0x8b,0x8e,0xf9,0x30,0xee,0xc5,0xb8,0x53,0x51,0xa5,0xbd,0x15,0xef,0x29,0x9e,
	0xcc,0x14,0xed,0x2e,0x46,0x5c,0x2a,0x44,0x30,0xac,0x5b,0xab,0xbc,0x76,0x54,0xea,
	0xba,0x58,0x7d,0x91,0x4c,0x70,0xd0,0x7c,0xd6,0x64,0x57,0xc0,0x80,0x6a,0x4f,0xdf,
	0xd7,0x56,0x31,0x5c,0x23,0x72,0x7f,0xd7,0x0a,0x4e,0x45,0x14,0xd1,0xe6,0x5d,0x26,
	0xc7,0x93,0x9e,0xff,0x86,0x7e,0xf6,0x54,0xb3,0x06,0xd7,0x26,0x99,0x24,0x22,0xf8,
	0xd0,0x53,0x70,0x6d,0xc8,0x6d,0xb4,0x62,0xd3,0x75,0xe0,0xa1,0x8c,0x50,0x62,0xaf,
	0x2e,0x1c,0xc2,0x8b,0x7c,0x09,0x0b,0x95,0x97,0x00,0x1f,0x34,0x59,0x15,0x97,0xa7,
	0x92,0x67,0xb0,0x2d,0x9c,0x95,0xdb,0x02,0xb6,0x01,0x26,0x5e,0x81,0x5f,0x62,0x33,
	0x40,0xca,0xe5,0x76,0x41,0x87,0x18,0x90,0x47,0x7c,0xe6,0x00,0x88,0x22,0x53,0x51,
	0x92,0x7c,0xc6,0xed,0x64,0x05,0xe6,0xef,0x83,0x17,0x73,0x5a,0x80,0xd8,0x4a,0x62,
	0xdd,0x99,0x81,0x39,0x3a,0xf9,0x11,0xf5,0xb1,0x2a,0xf1,0x54,0xb8,0x8b,0x49,0xa1,
	0x96,0xb3,0xd5,0x87,0x84,0x7d,0xa1,0x75,0x76,0xde,0x88,0xc0,0xbe,0x84,0x4e,0xbd,
	0xab,0xe6,0xc6,0xdd,0x1f,0xd5,0x50,0xd4,0xcb,0xe2,0xe2,0x1f,0xe5,0xe3,0x51,0xb4,
	0xd9,0xd4,0x33,0x04,0xd4,0x2d,0xdb,0x4f,0xcf,0x70,0xad,0x94,0xba,0xe2,0x07,0x42,
	0x5e,0xa3,0xfc,0x1d,0xe7,0x9c,0xce,0x32,0x34,0x2f,0x1a,0x41,0x37,0x1b,0x61,0x4a,
	0x13,0x5c,0x17,0x64,0xa9,0x7e,0xb8,0xd9,0x8c,0x41,0x7d,0xdf,0xcb,0xc4,0xa7,0x4c,
	0xf2,0x6a,0x66,0x36,0x90,0xcb,0xbf,0xbe,0x74,0xe3,0xb2,0x88,0x85,0xc9,0xeb,0x49,
	0xc9,0x2b,0x95,0x84,0xa7,0xcf,0x63,0xa7,0xb2,0xe4,0xd4,0x60,0xf0,0x56,0xaf,0xc4,
	0xfa,0x08,0x0a,0x37,0x43,0x59,0xeb,0x5e,0x7e,0x52,0xa2,0xaa,0x6e,0x53,0x0d,0xdf,
	0xf9,0xe4,0x3c,0x36,0x29,0xa5,0x12,0x8d,0x33,0xa7,0x86,0x2d,0x90,0xdb,0x6c,0xaf,
	0xc9,0x40,0x8e,0x28,0x50,0x4f,0x8a,0x0f,0x5c,0xff,0x77,0xe6,0x82,0xa8,0x83,0x1f,
	0x45,0x80,0x92,0x5c,0x13,0x0d,0xb3,0x26,0x42,0xfa,0xc2,0x24,0x95,0x56,0xe2,0xe0,
};

/**
 * Length of the test recovery image data.
 */
const uint32_t RECOVERY_IMAGE_DATA_LEN = sizeof (RECOVERY_IMAGE_DATA);

/**
 * The offset from the base for the recovery image signature.
 */
const uint32_t RECOVERY_IMAGE_SIGNATURE_OFFSET = (sizeof (RECOVERY_IMAGE_DATA) -
	RECOVERY_IMAGE_HEADER_SIGNATURE_LEN);


/**
 * The signature for the recovery image.
 */
const uint8_t *RECOVERY_IMAGE_SIGNATURE = RECOVERY_IMAGE_DATA + (sizeof (RECOVERY_IMAGE_DATA) -
	RECOVERY_IMAGE_HEADER_SIGNATURE_LEN);

const uint8_t *RECOVERY_IMAGE_SIGNATURE2 = RECOVERY_IMAGE_DATA2 + (sizeof (RECOVERY_IMAGE_DATA) -
	RECOVERY_IMAGE_HEADER_SIGNATURE_LEN);

/**
 * The SHA256 hash of the test recovery image data, not including the signature.
 */
const uint8_t RECOVERY_IMAGE_HASH[] = {
	0x4c,0x62,0x50,0xa8,0x39,0xb3,0xe6,0xbb,0xb8,0x24,0xef,0x1e,0x2a,0x77,0x3c,0xf2,
	0xd5,0x64,0xce,0x87,0x2e,0xec,0x0b,0xc8,0x0c,0x55,0x00,0xdc,0xd6,0xae,0xc5,0x34
};

/**
 * The SHA256 hash digest of the test recovery image data, not including the signature.
 */
const uint8_t RECOVERY_IMAGE_HASH_DIGEST[] = {
	0x8b,0xe6,0xf7,0x2d,0x68,0x38,0xf1,0xcc,0xb5,0x7b,0xc1,0xb9,0x9e,0xb3,0xe0,0x2a,
	0xb3,0xb1,0x75,0x1a,0xb3,0xdc,0x40,0xdf,0x8b,0x80,0x1e,0xfc,0x6b,0x06,0xd2,0xc5
};

const uint8_t RECOVERY_IMAGE_HASH2[] = {
	0x87,0x44,0xfb,0x32,0x67,0x81,0xd7,0x26,0xc5,0xef,0x29,0x45,0xad,0xe4,0xdc,0xa2,
	0x26,0x0c,0x6c,0x1f,0x1f,0x81,0x24,0x1a,0x13,0xde,0x9e,0x69,0x2a,0x88,0x47,0xee,
};

/**
 * The section image lengths excluding the section header length.
 */
#define RECOVERY_IMAGE_DATA_SECTION_1_LEN \
	(0x350 - RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN)

#define RECOVERY_IMAGE_DATA2_SECTION_1_LEN		0x13c

#define RECOVERY_IMAGE_DATA2_SECTION_2_LEN		0x1f4

#define RECOVERY_IMAGE_DATA2_SECTION_1_OFFSET	RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN

#define RECOVERY_IMAGE_DATA2_SECTION_2_OFFSET	(RECOVERY_IMAGE_DATA2_SECTION_1_OFFSET + \
	RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN + RECOVERY_IMAGE_DATA2_SECTION_1_LEN)

/**
 * Length of the test recovery image hash.
 */
const uint32_t RECOVERY_IMAGE_HASH_LEN = sizeof (RECOVERY_IMAGE_HASH);


/**
 * Helper function to set-up expectations for copying a page of data to host flash.
 *
 * @param mock_dest The destination flash mock.
 * @param mock_src The source flash mock.
 * @param dest_addr The destination address to copy data to.
 * @param src_addr The source address to copy data from.
 * @param data The data to copy to host flash.
 * @param length The size of data to copy.
 *
 * @return 0 if the mock expectation set-up was successful or an error code.
 */
static int setup_expect_copy_page_to_host_flash (struct flash_master_mock *mock_dest,
	struct flash_mock *mock_src, uint32_t dest_addr, uint32_t src_addr, const uint8_t *data,
	size_t length)
{
	int status;

	status = mock_expect (&mock_src->mock, mock_src->base.read, mock_src, 0, MOCK_ARG (src_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (length));
	status |= mock_expect_output (&mock_src->mock, 1, data, length, 2);

	status |= flash_master_mock_expect_rx_xfer (mock_dest, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (mock_dest, 0, FLASH_EXP_WRITE_ENABLE);

	status |= flash_master_mock_expect_tx_xfer (mock_dest, 0,
		FLASH_EXP_WRITE_CMD (0x02, dest_addr, 0, data, length));

	status |= flash_master_mock_expect_rx_xfer (mock_dest, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (mock_dest, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (mock_dest, 0, data, length,
			FLASH_EXP_READ_CMD (0x03, dest_addr, 0, -1, length));

	return status;
}


/**
 * Helper function to set up expectations for copying data to host flash.
 *
 * @param mock_dest The destination flash mock.
 * @param mock_src The source flash mock.
 * @param dest_addr The destination address to copy data to.
 * @param src_addr The source address to copy data from.
 * @param data The data to copy to host flash.
 * @param length The size of data to copy.
 *
 * @return 0 if the mock expectation set-up was successful or an error code.
 */
static int setup_expect_copy_to_host_flash (struct flash_master_mock *mock_dest,
	struct flash_mock *mock_src, uint32_t dest_addr, uint32_t src_addr, const uint8_t *data,
	size_t length)
{
	int status = 0;
	uint32_t page_offset = FLASH_REGION_OFFSET (dest_addr, FLASH_PAGE_SIZE);
	size_t block_len;

	while (length > 0) {
		block_len = FLASH_PAGE_SIZE - page_offset;
		block_len = (length > block_len) ? block_len : length;

		status |= setup_expect_copy_page_to_host_flash (mock_dest, mock_src, dest_addr, src_addr,
			data, block_len);

		length -= block_len;
		dest_addr += block_len;
		src_addr += block_len;
		data += block_len;
		page_offset = 0;
	}

	return status;

}

/**
 * Helper function to setup the recovery image to use mocks.
 *
 * @param test The test framework.
 * @param flash The flash mock to initialize.
 * @param pfm The PFM mock to initialize.
 * @param manager The PFM manager mock to initialize.
 * @param hash The hash engine to initialize.
 * @param verification The signature verification mock to initialize.
 */
static void setup_recovery_image_mock_test (CuTest *test, struct flash_mock *flash,
	struct pfm_mock *pfm, struct pfm_manager_mock *manager, HASH_TESTING_ENGINE *hash,
	struct signature_verification_mock *verification)
{
	int status;

	status = pfm_mock_init (pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_init (manager);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (flash);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper function to release recovery image instance.
 *
 * @param test The test framework.
 * @param flash The flash mock to release.
 * @param pfm The PFM mock to release.
 * @param manager The PFM manager mock to release.
 * @param hash The hash engine to release.
 * @param verification The signature verification mock to release.
 * @param recovery_image The recovery image instance to release.
 */
static void complete_recovery_image_test (CuTest *test, struct flash_mock *flash,
	struct pfm_mock *pfm, struct pfm_manager_mock *manager, HASH_TESTING_ENGINE *hash,
	struct signature_verification_mock *verification, struct recovery_image *recovery_image)
{
	int status;

	status = flash_mock_validate_and_release (flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_release (recovery_image);

	status = pfm_mock_validate_and_release (pfm);
	CuAssertIntEquals (test, 0, status);

	status = pfm_manager_mock_validate_and_release (manager);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (hash);
}


/*******************
 * Test cases
 *******************/

static void recovery_image_test_init (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image recovery_image;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, recovery_image.verify);
	CuAssertPtrNotNull (test, recovery_image.get_hash);
	CuAssertPtrNotNull (test, recovery_image.get_version);
	CuAssertPtrNotNull (test, recovery_image.apply_to_flash);

	flash_mock_release (&flash);

	recovery_image_release (&recovery_image);
}

static void recovery_image_test_init_null (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image recovery_image;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_init (NULL, &flash.base, 0x10000);
	CuAssertIntEquals (test, RECOVERY_IMAGE_INVALID_ARGUMENT, status);

	status = recovery_image_init (&recovery_image, NULL, 0x10000);
	CuAssertIntEquals (test, RECOVERY_IMAGE_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void recovery_image_test_release_null (CuTest *test)
{
	TEST_START;

	recovery_image_release (NULL);
}

static void recovery_image_test_release_no_init (CuTest *test)
{
	struct recovery_image img;

	TEST_START;

	memset (&img, 0, sizeof (img));

	recovery_image_release (&img);
}

static void recovery_image_test_verify (CuTest *test)
{
	struct flash_mock flash;
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct recovery_image recovery_image;
	struct pfm_manager_mock manager;
	struct pfm_mock pfm;
	int status;

	TEST_START;

	setup_recovery_image_mock_test (test, &flash, &pfm, &manager, &hash, &verification);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA,
		RECOVERY_IMAGE_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_SIGNATURE_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		RECOVERY_IMAGE_SIGNATURE_OFFSET, RECOVERY_IMAGE_HEADER_SIGNATURE_LEN, 2);

	status |= flash_mock_expect_verify_flash (&flash, 0x10000, RECOVERY_IMAGE_DATA,
		RECOVERY_IMAGE_DATA_LEN - RECOVERY_IMAGE_HEADER_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (RECOVERY_IMAGE_HASH, RECOVERY_IMAGE_HASH_LEN),
		MOCK_ARG (RECOVERY_IMAGE_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RECOVERY_IMAGE_SIGNATURE,
		RECOVERY_IMAGE_HEADER_SIGNATURE_LEN), MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));

	status |= mock_expect (&manager.mock, manager.base.get_active_pfm, &manager, (intptr_t) &pfm);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_platform_id, &pfm, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&pfm.mock, 0, &RECOVERY_IMAGE_HEADER_PLATFORM_ID, sizeof (void*),
		-1);

	status |= mock_expect (&pfm.mock, pfm.base.base.free_platform_id, &pfm, 0,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_PLATFORM_ID));

	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager, 0, MOCK_ARG (&pfm));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN,
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image.verify (&recovery_image, &hash.base, &verification.base, NULL, 0,
		&manager.base);
	CuAssertIntEquals (test, 0, status);

	complete_recovery_image_test (test, &flash, &pfm, &manager, &hash, &verification,
		&recovery_image);
}

static void recovery_image_test_verify_with_multiple_recovery_sections (CuTest *test)
{
	struct flash_mock flash;
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct recovery_image recovery_image;
	struct pfm_manager_mock manager;
	struct pfm_mock pfm;
	int status;

	TEST_START;

	setup_recovery_image_mock_test (test, &flash, &pfm, &manager, &hash, &verification);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA,
		RECOVERY_IMAGE_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_SIGNATURE_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA2 +
		RECOVERY_IMAGE_SIGNATURE_OFFSET, RECOVERY_IMAGE_HEADER_SIGNATURE_LEN, 2);

	status |= flash_mock_expect_verify_flash (&flash, 0x10000, RECOVERY_IMAGE_DATA2,
		RECOVERY_IMAGE_DATA_LEN - RECOVERY_IMAGE_HEADER_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (RECOVERY_IMAGE_HASH2, RECOVERY_IMAGE_HASH_LEN),
		MOCK_ARG (RECOVERY_IMAGE_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RECOVERY_IMAGE_SIGNATURE2,
		RECOVERY_IMAGE_HEADER_SIGNATURE_LEN), MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));

	status |= mock_expect (&manager.mock, manager.base.get_active_pfm, &manager, (intptr_t) &pfm);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_platform_id, &pfm, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&pfm.mock, 0, &RECOVERY_IMAGE_HEADER_PLATFORM_ID, sizeof (void*),
		-1);

	status |= mock_expect (&pfm.mock, pfm.base.base.free_platform_id, &pfm, 0,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_PLATFORM_ID));

	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager, 0, MOCK_ARG (&pfm));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA2 +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, IMAGE_HEADER_BASE_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA2 +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN,
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN +
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN + RECOVERY_IMAGE_DATA2_SECTION_1_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA2 +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN +
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN + RECOVERY_IMAGE_DATA2_SECTION_1_LEN,
		IMAGE_HEADER_BASE_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN +
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN + RECOVERY_IMAGE_DATA2_SECTION_1_LEN +
		IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA2 +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN +
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN + RECOVERY_IMAGE_DATA2_SECTION_1_LEN +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image.verify (&recovery_image, &hash.base, &verification.base, NULL, 0,
		&manager.base);
	CuAssertIntEquals (test, 0, status);

	complete_recovery_image_test (test, &flash, &pfm, &manager, &hash, &verification,
		&recovery_image);
}

static void recovery_image_test_verify_second_recovery_section_header_too_long (CuTest *test)
{
	struct flash_mock flash;
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct recovery_image recovery_image;
	struct pfm_manager_mock manager;
	uint8_t bad_image[RECOVERY_IMAGE_DATA_LEN];
	struct pfm_mock pfm;
	int status;

	TEST_START;

	memcpy (bad_image, RECOVERY_IMAGE_DATA2, RECOVERY_IMAGE_DATA_LEN);
	*((uint16_t*) &bad_image[RECOVERY_IMAGE_DATA2_SECTION_2_OFFSET]) += 1;

	setup_recovery_image_mock_test (test, &flash, &pfm, &manager, &hash, &verification);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image,
		RECOVERY_IMAGE_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_SIGNATURE_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		RECOVERY_IMAGE_SIGNATURE_OFFSET, RECOVERY_IMAGE_HEADER_SIGNATURE_LEN, 2);

	status |= flash_mock_expect_verify_flash (&flash, 0x10000, bad_image,
		RECOVERY_IMAGE_DATA_LEN - RECOVERY_IMAGE_HEADER_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY);

	status |= mock_expect (&manager.mock, manager.base.get_active_pfm, &manager, (intptr_t) &pfm);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_platform_id, &pfm, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&pfm.mock, 0, &RECOVERY_IMAGE_HEADER_PLATFORM_ID, sizeof (void*),
		-1);

	status |= mock_expect (&pfm.mock, pfm.base.base.free_platform_id, &pfm, 0,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_PLATFORM_ID));

	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager, 0, MOCK_ARG (&pfm));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, IMAGE_HEADER_BASE_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN,
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN +
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN + RECOVERY_IMAGE_DATA2_SECTION_1_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN +
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN + RECOVERY_IMAGE_DATA2_SECTION_1_LEN,
		IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image.verify (&recovery_image, &hash.base, &verification.base, NULL, 0,
		&manager.base);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MALFORMED, status);

	complete_recovery_image_test (test, &flash, &pfm, &manager, &hash, &verification,
		&recovery_image);
}

static void recovery_image_test_verify_image_length_too_long (CuTest *test)
{
	struct flash_mock flash;
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct recovery_image recovery_image;
	uint8_t bad_image[RECOVERY_IMAGE_DATA_LEN];
	struct pfm_manager_mock manager;
	struct pfm_mock pfm;
	int status;

	TEST_START;

	memcpy (bad_image, RECOVERY_IMAGE_DATA, RECOVERY_IMAGE_DATA_LEN);
	*((uint32_t*) &bad_image[IMAGE_HEADER_BASE_LEN + CERBERUS_PROTOCOL_FW_VERSION_LEN]) += 1;

	setup_recovery_image_mock_test (test, &flash, &pfm, &manager, &hash, &verification);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image, RECOVERY_IMAGE_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image + IMAGE_HEADER_BASE_LEN,
		RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_SIGNATURE_OFFSET + 1), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		RECOVERY_IMAGE_SIGNATURE_OFFSET, RECOVERY_IMAGE_HEADER_SIGNATURE_LEN, 2);

	status |= flash_mock_expect_verify_flash (&flash, 0x10000, bad_image,
		sizeof (bad_image) + 1 - RECOVERY_IMAGE_HEADER_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY);

	status |= mock_expect (&manager.mock, manager.base.get_active_pfm, &manager, (intptr_t) &pfm);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_platform_id, &pfm, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&pfm.mock, 0, &RECOVERY_IMAGE_HEADER_PLATFORM_ID, sizeof (void*),
		-1);

	status |= mock_expect (&pfm.mock, pfm.base.base.free_platform_id, &pfm, 0,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_PLATFORM_ID));

	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager, 0, MOCK_ARG (&pfm));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN,
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG_ANY, MOCK_ARG_NOT_NULL,
		MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image.verify (&recovery_image, &hash.base, &verification.base, NULL, 0,
		&manager.base);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MALFORMED, status);

	complete_recovery_image_test (test, &flash, &pfm, &manager, &hash, &verification,
		&recovery_image);
}

static void recovery_image_test_verify_image_length_too_short (CuTest *test)
{
	struct flash_mock flash;
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct recovery_image recovery_image;
	uint8_t bad_image[RECOVERY_IMAGE_DATA_LEN];
	struct pfm_manager_mock manager;
	struct pfm_mock pfm;
	int status;

	TEST_START;

	memcpy (bad_image, RECOVERY_IMAGE_DATA, RECOVERY_IMAGE_DATA_LEN);
	*((uint32_t*) &bad_image[IMAGE_HEADER_BASE_LEN + CERBERUS_PROTOCOL_FW_VERSION_LEN]) -= 1;

	setup_recovery_image_mock_test (test, &flash, &pfm, &manager, &hash, &verification);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image, RECOVERY_IMAGE_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image + IMAGE_HEADER_BASE_LEN,
		RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_SIGNATURE_OFFSET - 1), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		RECOVERY_IMAGE_SIGNATURE_OFFSET, RECOVERY_IMAGE_HEADER_SIGNATURE_LEN, 2);

	status |= flash_mock_expect_verify_flash (&flash, 0x10000, bad_image,
		sizeof (bad_image) - 1 - RECOVERY_IMAGE_HEADER_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY);

	status |= mock_expect (&manager.mock, manager.base.get_active_pfm, &manager, (intptr_t) &pfm);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_platform_id, &pfm, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&pfm.mock, 0, &RECOVERY_IMAGE_HEADER_PLATFORM_ID, sizeof (void*),
		-1);

	status |= mock_expect (&pfm.mock, pfm.base.base.free_platform_id, &pfm, 0,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_PLATFORM_ID));

	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager, 0, MOCK_ARG (&pfm));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (
		IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN,
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image.verify (&recovery_image, &hash.base, &verification.base, NULL, 0,
		&manager.base);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MALFORMED, status);

	complete_recovery_image_test (test, &flash, &pfm, &manager, &hash, &verification,
		&recovery_image);
}

static void recovery_image_test_verify_section_image_length_too_long (CuTest *test)
{
	struct flash_mock flash;
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct recovery_image recovery_image;
	uint8_t bad_image[RECOVERY_IMAGE_DATA_LEN];
	struct pfm_manager_mock manager;
	struct pfm_mock pfm;
	int status;

	TEST_START;

	memcpy (bad_image, RECOVERY_IMAGE_DATA, RECOVERY_IMAGE_DATA_LEN);
	*((uint32_t*) &bad_image[RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN +	4])
		+= 1;

	setup_recovery_image_mock_test (test, &flash, &pfm, &manager, &hash, &verification);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image, RECOVERY_IMAGE_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image + IMAGE_HEADER_BASE_LEN,
		RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_SIGNATURE_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		RECOVERY_IMAGE_SIGNATURE_OFFSET, RECOVERY_IMAGE_HEADER_SIGNATURE_LEN, 2);

	status |= flash_mock_expect_verify_flash (&flash, 0x10000, bad_image,
		sizeof (bad_image) - RECOVERY_IMAGE_HEADER_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY);

	status |= mock_expect (&manager.mock, manager.base.get_active_pfm, &manager, (intptr_t) &pfm);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_platform_id, &pfm, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&pfm.mock, 0, &RECOVERY_IMAGE_HEADER_PLATFORM_ID, sizeof (void*),
		-1);

	status |= mock_expect (&pfm.mock, pfm.base.base.free_platform_id, &pfm, 0,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_PLATFORM_ID));

	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager, 0, MOCK_ARG (&pfm));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN,
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image.verify (&recovery_image, &hash.base, &verification.base, NULL, 0,
		&manager.base);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MALFORMED, status);

	complete_recovery_image_test (test, &flash, &pfm, &manager, &hash, &verification,
		&recovery_image);
}

static void recovery_image_test_verify_section_image_length_too_short (CuTest *test)
{
	struct flash_mock flash;
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct recovery_image recovery_image;
	uint8_t bad_image[RECOVERY_IMAGE_DATA_LEN];
	struct pfm_manager_mock manager;
	struct pfm_mock pfm;
	int status;

	TEST_START;

	memcpy (bad_image, RECOVERY_IMAGE_DATA, RECOVERY_IMAGE_DATA_LEN);
	*((uint32_t*) &bad_image[RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN + 4])
		-= 1;

	setup_recovery_image_mock_test (test, &flash, &pfm, &manager, &hash, &verification);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image, RECOVERY_IMAGE_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image + IMAGE_HEADER_BASE_LEN,
		RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_SIGNATURE_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		RECOVERY_IMAGE_SIGNATURE_OFFSET, RECOVERY_IMAGE_HEADER_SIGNATURE_LEN, 2);

	status |= flash_mock_expect_verify_flash (&flash, 0x10000, bad_image,
		sizeof (bad_image) - RECOVERY_IMAGE_HEADER_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY);

	status |= mock_expect (&manager.mock, manager.base.get_active_pfm, &manager, (intptr_t) &pfm);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_platform_id, &pfm, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&pfm.mock, 0, &RECOVERY_IMAGE_HEADER_PLATFORM_ID, sizeof (void*),
		-1);

	status |= mock_expect (&pfm.mock, pfm.base.base.free_platform_id, &pfm, 0,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_PLATFORM_ID));

	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager, 0, MOCK_ARG (&pfm));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN,
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG_ANY, MOCK_ARG_NOT_NULL,
		MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image.verify (&recovery_image, &hash.base, &verification.base, NULL, 0,
		&manager.base);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MALFORMED, status);

	complete_recovery_image_test (test, &flash, &pfm, &manager, &hash, &verification,
		&recovery_image);
}

static void recovery_image_test_verify_bad_signature (CuTest *test)
{
	struct flash_mock flash;
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct recovery_image recovery_image;
	uint8_t bad_image[RECOVERY_IMAGE_DATA_LEN];
	struct pfm_manager_mock manager;
	int status;

	TEST_START;

	memcpy (bad_image, RECOVERY_IMAGE_DATA, RECOVERY_IMAGE_DATA_LEN);
	bad_image[RECOVERY_IMAGE_SIGNATURE_OFFSET] ^= 0x55;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image, RECOVERY_IMAGE_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image + IMAGE_HEADER_BASE_LEN,
		RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_SIGNATURE_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		RECOVERY_IMAGE_SIGNATURE_OFFSET, RECOVERY_IMAGE_HEADER_SIGNATURE_LEN, 2);

	status |= flash_mock_expect_verify_flash (&flash, 0x10000, bad_image,
		sizeof (bad_image) - RECOVERY_IMAGE_HEADER_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG_PTR_CONTAINS (RECOVERY_IMAGE_HASH, RECOVERY_IMAGE_HASH_LEN),
		MOCK_ARG (RECOVERY_IMAGE_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RECOVERY_IMAGE_SIGNATURE,
		RECOVERY_IMAGE_HEADER_SIGNATURE_LEN), MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	status = recovery_image.verify (&recovery_image, &hash.base, &verification.base, NULL, 0,
		&manager.base);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	signature_verification_mock_release (&verification);

	recovery_image_release (&recovery_image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_test_verify_bad_signature_ecc_with_hash_out (CuTest *test)
{
	struct flash_mock flash;
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct recovery_image recovery_image;
	uint8_t bad_image[RECOVERY_IMAGE_DATA_LEN];
	uint8_t hash_out[SHA256_HASH_LENGTH];
	struct pfm_manager_mock manager;
	int status;

	TEST_START;

	memcpy (bad_image, RECOVERY_IMAGE_DATA, RECOVERY_IMAGE_DATA_LEN);
	bad_image[RECOVERY_IMAGE_SIGNATURE_OFFSET] ^= 0x55;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image, RECOVERY_IMAGE_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image + IMAGE_HEADER_BASE_LEN,
		RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_SIGNATURE_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		RECOVERY_IMAGE_SIGNATURE_OFFSET, RECOVERY_IMAGE_HEADER_SIGNATURE_LEN, 2);

	status |= flash_mock_expect_verify_flash (&flash, 0x10000, bad_image,
		sizeof (bad_image) - RECOVERY_IMAGE_HEADER_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		ECC_ENGINE_BAD_SIGNATURE,
		MOCK_ARG_PTR_CONTAINS (RECOVERY_IMAGE_HASH, RECOVERY_IMAGE_HASH_LEN),
		MOCK_ARG (RECOVERY_IMAGE_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RECOVERY_IMAGE_SIGNATURE,
		RECOVERY_IMAGE_HEADER_SIGNATURE_LEN), MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	memset (hash_out, 0, sizeof (hash_out));

	status = recovery_image.verify (&recovery_image, &hash.base, &verification.base, hash_out,
		sizeof (hash_out), &manager.base);
	CuAssertIntEquals (test, ECC_ENGINE_BAD_SIGNATURE, status);

	status = testing_validate_array (RECOVERY_IMAGE_HASH, hash_out, RECOVERY_IMAGE_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	signature_verification_mock_release (&verification);

	recovery_image_release (&recovery_image);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_test_verify_bad_signature_with_hash_out (CuTest *test)
{
	struct flash_mock flash;
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct recovery_image recovery_image;
	uint8_t bad_image[RECOVERY_IMAGE_DATA_LEN];
	uint8_t hash_out[SHA256_HASH_LENGTH];
	struct pfm_manager_mock manager;
	int status;

	TEST_START;

	memcpy (bad_image, RECOVERY_IMAGE_DATA, RECOVERY_IMAGE_DATA_LEN);
	bad_image[RECOVERY_IMAGE_SIGNATURE_OFFSET] ^= 0x55;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image, RECOVERY_IMAGE_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image + IMAGE_HEADER_BASE_LEN,
		RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_SIGNATURE_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		RECOVERY_IMAGE_SIGNATURE_OFFSET, RECOVERY_IMAGE_HEADER_SIGNATURE_LEN, 2);

	status |= flash_mock_expect_verify_flash (&flash, 0x10000, bad_image,
		sizeof (bad_image) - RECOVERY_IMAGE_HEADER_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG_PTR_CONTAINS (RECOVERY_IMAGE_HASH, RECOVERY_IMAGE_HASH_LEN),
		MOCK_ARG (RECOVERY_IMAGE_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RECOVERY_IMAGE_SIGNATURE,
		RECOVERY_IMAGE_HEADER_SIGNATURE_LEN), MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	memset (hash_out, 0, sizeof (hash_out));

	status = recovery_image.verify (&recovery_image, &hash.base, &verification.base, hash_out,
		sizeof (hash_out), &manager.base);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = testing_validate_array (RECOVERY_IMAGE_HASH, hash_out, RECOVERY_IMAGE_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	signature_verification_mock_release (&verification);

	recovery_image_release (&recovery_image);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_test_verify_bad_hash (CuTest *test)
{
	struct flash_mock flash;
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct recovery_image recovery_image;
	uint8_t bad_hash[RECOVERY_IMAGE_HASH_LEN];
	struct pfm_manager_mock manager;
	int status;

	TEST_START;

	memcpy (bad_hash, RECOVERY_IMAGE_HASH, RECOVERY_IMAGE_HASH_LEN);
	bad_hash[0] ^= 0x55;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA,
		RECOVERY_IMAGE_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_SIGNATURE_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		RECOVERY_IMAGE_SIGNATURE_OFFSET, RECOVERY_IMAGE_HEADER_SIGNATURE_LEN, 2);

	status |= flash_mock_expect_verify_flash (&flash, 0x10000, RECOVERY_IMAGE_DATA,
		RECOVERY_IMAGE_DATA_LEN - RECOVERY_IMAGE_HEADER_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG_PTR_CONTAINS (RECOVERY_IMAGE_HASH, RECOVERY_IMAGE_HASH_LEN),
		MOCK_ARG (RECOVERY_IMAGE_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RECOVERY_IMAGE_SIGNATURE,
		RECOVERY_IMAGE_HEADER_SIGNATURE_LEN), MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	status = recovery_image.verify (&recovery_image, &hash.base, &verification.base, NULL, 0,
		&manager.base);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	signature_verification_mock_release (&verification);

	recovery_image_release (&recovery_image);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_test_verify_null (CuTest *test)
{
	struct flash_mock flash;
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct recovery_image recovery_image;
	struct pfm_manager_mock manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image.verify (NULL, &hash.base, &verification.base, NULL, 0, &manager.base);
	CuAssertIntEquals (test, RECOVERY_IMAGE_INVALID_ARGUMENT, status);

	status = recovery_image.verify (&recovery_image, NULL, &verification.base, NULL, 0,
		&manager.base);
	CuAssertIntEquals (test, RECOVERY_IMAGE_INVALID_ARGUMENT, status);

	status = recovery_image.verify (&recovery_image, &hash.base, NULL, NULL, 0, &manager.base);
	CuAssertIntEquals (test, RECOVERY_IMAGE_INVALID_ARGUMENT, status);

	status = recovery_image.verify (&recovery_image, &hash.base, &verification.base, NULL, 0, NULL);
	CuAssertIntEquals (test, RECOVERY_IMAGE_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_release (&recovery_image);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_test_verify_with_hash_out (CuTest *test)
{
	struct flash_mock flash;
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct recovery_image recovery_image;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	struct pfm_manager_mock manager;
	struct pfm_mock pfm;
	int status;

	TEST_START;

	setup_recovery_image_mock_test (test, &flash, &pfm, &manager, &hash, &verification);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA,
		RECOVERY_IMAGE_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_SIGNATURE_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		RECOVERY_IMAGE_SIGNATURE_OFFSET, RECOVERY_IMAGE_HEADER_SIGNATURE_LEN, 2);

	status |= flash_mock_expect_verify_flash (&flash, 0x10000, RECOVERY_IMAGE_DATA,
		RECOVERY_IMAGE_DATA_LEN - RECOVERY_IMAGE_HEADER_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (RECOVERY_IMAGE_HASH, RECOVERY_IMAGE_HASH_LEN),
		MOCK_ARG (RECOVERY_IMAGE_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RECOVERY_IMAGE_SIGNATURE,
		RECOVERY_IMAGE_HEADER_SIGNATURE_LEN), MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));

	status |= mock_expect (&manager.mock, manager.base.get_active_pfm, &manager, (intptr_t) &pfm);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_platform_id, &pfm, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&pfm.mock, 0, &RECOVERY_IMAGE_HEADER_PLATFORM_ID, sizeof (void*),
		-1);

	status |= mock_expect (&pfm.mock, pfm.base.base.free_platform_id, &pfm, 0,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_PLATFORM_ID));

	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager, 0, MOCK_ARG (&pfm));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN,
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image.verify (&recovery_image, &hash.base, &verification.base, hash_out,
		sizeof (hash_out), &manager.base);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (RECOVERY_IMAGE_HASH, hash_out, RECOVERY_IMAGE_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_recovery_image_test (test, &flash, &pfm, &manager, &hash, &verification,
		&recovery_image);
}

static void recovery_image_test_verify_small_hash_buffer (CuTest *test)
{
	struct flash_mock flash;
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct recovery_image recovery_image;
	uint8_t hash_out[SHA256_HASH_LENGTH - 1];
	struct pfm_manager_mock manager;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image.verify (&recovery_image, &hash.base, &verification.base, hash_out,
		sizeof (hash_out), &manager.base);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HASH_BUFFER_TOO_SMALL, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	recovery_image_release (&recovery_image);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_test_verify_signature_read_error (CuTest *test)
{
	struct flash_mock flash;
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct recovery_image recovery_image;
	struct pfm_manager_mock manager;
	struct pfm_mock pfm;
	int status;

	TEST_START;

	setup_recovery_image_mock_test (test, &flash, &pfm, &manager, &hash, &verification);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA,
		RECOVERY_IMAGE_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_SIGNATURE_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	status = recovery_image.verify (&recovery_image, &hash.base, &verification.base, NULL, 0,
		&manager.base);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	complete_recovery_image_test (test, &flash, &pfm, &manager, &hash, &verification,
		&recovery_image);

}

static void recovery_image_test_verify_no_active_pfm (CuTest *test)
{
	struct flash_mock flash;
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct recovery_image recovery_image;
	struct pfm_manager_mock manager;
	struct pfm_mock pfm;
	int status;

	TEST_START;

	setup_recovery_image_mock_test (test, &flash, &pfm, &manager, &hash, &verification);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA,
		RECOVERY_IMAGE_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_SIGNATURE_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		RECOVERY_IMAGE_SIGNATURE_OFFSET, RECOVERY_IMAGE_HEADER_SIGNATURE_LEN, 2);

	status |= flash_mock_expect_verify_flash (&flash, 0x10000, RECOVERY_IMAGE_DATA,
		RECOVERY_IMAGE_DATA_LEN - RECOVERY_IMAGE_HEADER_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (RECOVERY_IMAGE_HASH, RECOVERY_IMAGE_HASH_LEN),
		MOCK_ARG (RECOVERY_IMAGE_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RECOVERY_IMAGE_SIGNATURE,
		RECOVERY_IMAGE_HEADER_SIGNATURE_LEN), MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));

	status |= mock_expect (&manager.mock, manager.base.get_active_pfm, &manager, (uintptr_t) NULL);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN,
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image.verify (&recovery_image, &hash.base, &verification.base, NULL, 0,
		&manager.base);
	CuAssertIntEquals (test, 0, status);

	complete_recovery_image_test (test, &flash, &pfm, &manager, &hash, &verification,
		&recovery_image);
}

static void recovery_image_test_verify_platform_id_mismatch (CuTest *test)
{
	struct flash_mock flash;
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct recovery_image recovery_image;
	struct pfm_manager_mock manager;
	struct pfm_mock pfm;
	char *platform_id = "Platform Test2";
	int status;

	TEST_START;

	setup_recovery_image_mock_test (test, &flash, &pfm, &manager, &hash, &verification);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA,
		RECOVERY_IMAGE_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_SIGNATURE_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		RECOVERY_IMAGE_SIGNATURE_OFFSET, RECOVERY_IMAGE_HEADER_SIGNATURE_LEN, 2);

	status |= flash_mock_expect_verify_flash (&flash, 0x10000, RECOVERY_IMAGE_DATA,
		RECOVERY_IMAGE_DATA_LEN - RECOVERY_IMAGE_HEADER_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (RECOVERY_IMAGE_HASH, RECOVERY_IMAGE_HASH_LEN),
		MOCK_ARG (RECOVERY_IMAGE_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RECOVERY_IMAGE_SIGNATURE,
		RECOVERY_IMAGE_HEADER_SIGNATURE_LEN), MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));

	status |= mock_expect (&manager.mock, manager.base.get_active_pfm, &manager, (intptr_t) &pfm);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_platform_id, &pfm, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&pfm.mock, 0, &platform_id, sizeof (void*), -1);

	status |= mock_expect (&pfm.mock, pfm.base.base.free_platform_id, &pfm, 0,
		MOCK_ARG (platform_id));

	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager, 0, MOCK_ARG (&pfm));

	CuAssertIntEquals (test, 0, status);

	status = recovery_image.verify (&recovery_image, &hash.base, &verification.base, NULL, 0,
		&manager.base);
	CuAssertIntEquals (test, RECOVERY_IMAGE_INCOMPATIBLE, status);

	complete_recovery_image_test (test, &flash, &pfm, &manager, &hash, &verification,
		&recovery_image);
}

static void recovery_image_test_verify_platform_id_error (CuTest *test)
{
	struct flash_mock flash;
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct recovery_image recovery_image;
	struct pfm_manager_mock manager;
	struct pfm_mock pfm;
	int status;

	TEST_START;

	setup_recovery_image_mock_test (test, &flash, &pfm, &manager, &hash, &verification);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA,
		RECOVERY_IMAGE_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_SIGNATURE_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		RECOVERY_IMAGE_SIGNATURE_OFFSET, RECOVERY_IMAGE_HEADER_SIGNATURE_LEN, 2);

	status |= flash_mock_expect_verify_flash (&flash, 0x10000, RECOVERY_IMAGE_DATA,
		RECOVERY_IMAGE_DATA_LEN - RECOVERY_IMAGE_HEADER_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (RECOVERY_IMAGE_HASH, RECOVERY_IMAGE_HASH_LEN),
		MOCK_ARG (RECOVERY_IMAGE_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RECOVERY_IMAGE_SIGNATURE,
		RECOVERY_IMAGE_HEADER_SIGNATURE_LEN), MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));

	status |= mock_expect (&manager.mock, manager.base.get_active_pfm, &manager, (intptr_t) &pfm);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_platform_id, &pfm,
		MANIFEST_GET_PLATFORM_ID_FAILED, MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);

	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager, 0, MOCK_ARG (&pfm));

	CuAssertIntEquals (test, 0, status);

	status = recovery_image.verify (&recovery_image, &hash.base, &verification.base, NULL, 0,
		&manager.base);
	CuAssertIntEquals (test, MANIFEST_GET_PLATFORM_ID_FAILED, status);

	complete_recovery_image_test (test, &flash, &pfm, &manager, &hash, &verification,
		&recovery_image);
}

static void recovery_image_test_verify_recovery_section_header_length_too_short (CuTest *test)
{
	struct flash_mock flash;
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct recovery_image recovery_image;
	uint8_t bad_image[RECOVERY_IMAGE_DATA_LEN];
	struct pfm_manager_mock manager;
	struct pfm_mock pfm;
	int status;

	TEST_START;

	memcpy (bad_image, RECOVERY_IMAGE_DATA, RECOVERY_IMAGE_DATA_LEN);
	*((uint16_t*) &bad_image[RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN]) -= 1;

	setup_recovery_image_mock_test (test, &flash, &pfm, &manager, &hash, &verification);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image, RECOVERY_IMAGE_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image + IMAGE_HEADER_BASE_LEN,
		RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_SIGNATURE_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		RECOVERY_IMAGE_SIGNATURE_OFFSET, RECOVERY_IMAGE_HEADER_SIGNATURE_LEN, 2);

	status |= flash_mock_expect_verify_flash (&flash, 0x10000, bad_image,
		sizeof (bad_image) - RECOVERY_IMAGE_HEADER_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY);

	status |= mock_expect (&manager.mock, manager.base.get_active_pfm, &manager, (intptr_t) &pfm);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_platform_id, &pfm, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&pfm.mock, 0, &RECOVERY_IMAGE_HEADER_PLATFORM_ID, sizeof (void*),
		-1);

	status |= mock_expect (&pfm.mock, pfm.base.base.free_platform_id, &pfm, 0,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_PLATFORM_ID));

	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager, 0, MOCK_ARG (&pfm));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (
		IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN,
		2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image.verify (&recovery_image, &hash.base, &verification.base, NULL, 0,
		&manager.base);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MALFORMED, status);

	complete_recovery_image_test (test, &flash, &pfm, &manager, &hash, &verification,
		&recovery_image);
}

static void recovery_image_test_verify_recovery_section_header_length_too_long (CuTest *test)
{
	struct flash_mock flash;
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct recovery_image recovery_image;
	uint8_t bad_image[RECOVERY_IMAGE_DATA_LEN];
	struct pfm_manager_mock manager;
	struct pfm_mock pfm;
	int status;

	TEST_START;

	memcpy (bad_image, RECOVERY_IMAGE_DATA, RECOVERY_IMAGE_DATA_LEN);
	*((uint16_t*) &bad_image[RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN]) += 1;

	setup_recovery_image_mock_test (test, &flash, &pfm, &manager, &hash, &verification);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image, RECOVERY_IMAGE_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image + IMAGE_HEADER_BASE_LEN,
		RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_SIGNATURE_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		RECOVERY_IMAGE_SIGNATURE_OFFSET, RECOVERY_IMAGE_HEADER_SIGNATURE_LEN, 2);

	status |= flash_mock_expect_verify_flash (&flash, 0x10000, bad_image,
		sizeof (bad_image) - RECOVERY_IMAGE_HEADER_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY);

	status |= mock_expect (&manager.mock, manager.base.get_active_pfm, &manager, (intptr_t) &pfm);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_platform_id, &pfm, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&pfm.mock, 0, &RECOVERY_IMAGE_HEADER_PLATFORM_ID, sizeof (void*),
		-1);

	status |= mock_expect (&pfm.mock, pfm.base.base.free_platform_id, &pfm, 0,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_PLATFORM_ID));

	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager, 0, MOCK_ARG (&pfm));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN,
		2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image.verify (&recovery_image, &hash.base, &verification.base, NULL, 0,
		&manager.base);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MALFORMED, status);

	complete_recovery_image_test (test, &flash, &pfm, &manager, &hash, &verification,
		&recovery_image);
}

static void recovery_image_test_verify_no_recovery_section_image (CuTest *test)
{
	struct flash_mock flash;
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct recovery_image recovery_image;
	struct pfm_manager_mock manager;
	uint8_t bad_image[RECOVERY_IMAGE_DATA_LEN - (RECOVERY_IMAGE_DATA_SECTION_1_LEN +
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN)];
	struct pfm_mock pfm;
	int status;

	TEST_START;

	memcpy (bad_image, RECOVERY_IMAGE_DATA, RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN);
	memcpy (bad_image + RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, RECOVERY_IMAGE_SIGNATURE,
		RECOVERY_IMAGE_HEADER_SIGNATURE_LEN);
	*((uint32_t*) &bad_image[IMAGE_HEADER_BASE_LEN + CERBERUS_PROTOCOL_FW_VERSION_LEN]) =
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + RECOVERY_IMAGE_HEADER_SIGNATURE_LEN;

	setup_recovery_image_mock_test (test, &flash, &pfm, &manager, &hash, &verification);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image, RECOVERY_IMAGE_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image + IMAGE_HEADER_BASE_LEN,
		RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, RECOVERY_IMAGE_HEADER_SIGNATURE_LEN, 2);

	status |= flash_mock_expect_verify_flash (&flash, 0x10000, bad_image,
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY);

	status |= mock_expect (&manager.mock, manager.base.get_active_pfm, &manager, (intptr_t) &pfm);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_platform_id, &pfm, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&pfm.mock, 0, &RECOVERY_IMAGE_HEADER_PLATFORM_ID, sizeof (void*),
		-1);

	status |= mock_expect (&pfm.mock, pfm.base.base.free_platform_id, &pfm, 0,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_PLATFORM_ID));

	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager, 0, MOCK_ARG (&pfm));

	CuAssertIntEquals (test, 0, status);

	status = recovery_image.verify (&recovery_image, &hash.base, &verification.base, NULL, 0,
		&manager.base);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MALFORMED, status);

	complete_recovery_image_test (test, &flash, &pfm, &manager, &hash, &verification,
		&recovery_image);
}

static void recovery_image_test_verify_read_error (CuTest *test)
{
	struct flash_mock flash;
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct recovery_image recovery_image;
	struct pfm_manager_mock manager;
	struct pfm_mock pfm;
	int status;

	TEST_START;

	setup_recovery_image_mock_test (test, &flash, &pfm, &manager, &hash, &verification);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA,
		RECOVERY_IMAGE_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_SIGNATURE_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		RECOVERY_IMAGE_SIGNATURE_OFFSET, RECOVERY_IMAGE_HEADER_SIGNATURE_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));

	CuAssertIntEquals (test, 0, status);

	status = recovery_image.verify (&recovery_image, &hash.base, &verification.base, NULL, 0,
		&manager.base);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	complete_recovery_image_test (test, &flash, &pfm, &manager, &hash, &verification,
		&recovery_image);
}

static void recovery_image_test_verify_read_error_with_hash_out (CuTest *test)
{
	struct flash_mock flash;
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct recovery_image recovery_image;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	uint8_t empty[sizeof (hash_out)] = {0};
	struct pfm_manager_mock manager;
	struct pfm_mock pfm;
	int status;

	TEST_START;

	setup_recovery_image_mock_test (test, &flash, &pfm, &manager, &hash, &verification);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA,
		RECOVERY_IMAGE_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));

	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_SIGNATURE_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		RECOVERY_IMAGE_SIGNATURE_OFFSET, RECOVERY_IMAGE_HEADER_SIGNATURE_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));

	CuAssertIntEquals (test, 0, status);

	memcpy (hash_out, empty, sizeof (hash_out));

	status = recovery_image.verify (&recovery_image, &hash.base, &verification.base, hash_out,
		sizeof (hash_out), &manager.base);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = testing_validate_array (empty, hash_out, sizeof (empty));
	CuAssertIntEquals (test, 0, status);

	complete_recovery_image_test (test, &flash, &pfm, &manager, &hash, &verification,
		&recovery_image);
}

static void recovery_image_test_verify_bad_magic_number (CuTest *test)
{
	struct flash_mock flash;
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct recovery_image recovery_image;
	struct pfm_manager_mock manager;
	struct pfm_mock pfm;
	uint8_t bad_image[IMAGE_HEADER_BASE_LEN];
	int status;

	TEST_START;

	memcpy (bad_image, RECOVERY_IMAGE_DATA, IMAGE_HEADER_BASE_LEN);
	bad_image[IMAGE_HEADER_BASE_LEN - 1] ^= 0x55;

	setup_recovery_image_mock_test (test, &flash, &pfm, &manager, &hash, &verification);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image, sizeof (bad_image), 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image.verify (&recovery_image, &hash.base, &verification.base, NULL, 0,
		&manager.base);
	CuAssertIntEquals (test, IMAGE_HEADER_BAD_MARKER, status);

	complete_recovery_image_test (test, &flash, &pfm, &manager, &hash, &verification,
		&recovery_image);
}

static void recovery_image_test_verify_section_address_overlap (CuTest *test)
{
	struct flash_mock flash;
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct recovery_image recovery_image;
	struct pfm_manager_mock manager;
	uint8_t bad_image[RECOVERY_IMAGE_DATA_LEN];
	struct pfm_mock pfm;
	uint32_t bad_addr;
	int status;

	TEST_START;

	memcpy (bad_image, RECOVERY_IMAGE_DATA2, RECOVERY_IMAGE_DATA_LEN);
	bad_addr =
		*((uint32_t*) &bad_image[RECOVERY_IMAGE_DATA2_SECTION_1_OFFSET + IMAGE_HEADER_BASE_LEN]) +
			RECOVERY_IMAGE_DATA2_SECTION_1_LEN - 1;
	*((uint32_t*) &bad_image[RECOVERY_IMAGE_DATA2_SECTION_2_OFFSET + IMAGE_HEADER_BASE_LEN]) =
		bad_addr;

	setup_recovery_image_mock_test (test, &flash, &pfm, &manager, &hash, &verification);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image,
		RECOVERY_IMAGE_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_SIGNATURE_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		RECOVERY_IMAGE_SIGNATURE_OFFSET, RECOVERY_IMAGE_HEADER_SIGNATURE_LEN, 2);

	status |= flash_mock_expect_verify_flash (&flash, 0x10000, bad_image,
		RECOVERY_IMAGE_DATA_LEN - RECOVERY_IMAGE_HEADER_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY, MOCK_ARG_ANY);

	status |= mock_expect (&manager.mock, manager.base.get_active_pfm, &manager, (intptr_t) &pfm);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_platform_id, &pfm, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&pfm.mock, 0, &RECOVERY_IMAGE_HEADER_PLATFORM_ID, sizeof (void*),
		-1);

	status |= mock_expect (&pfm.mock, pfm.base.base.free_platform_id, &pfm, 0,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_PLATFORM_ID));

	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager, 0, MOCK_ARG (&pfm));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, IMAGE_HEADER_BASE_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN,
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN +
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN + RECOVERY_IMAGE_DATA2_SECTION_1_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN +
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN + RECOVERY_IMAGE_DATA2_SECTION_1_LEN,
		IMAGE_HEADER_BASE_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN +
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN + RECOVERY_IMAGE_DATA2_SECTION_1_LEN +
		IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN +
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN + RECOVERY_IMAGE_DATA2_SECTION_1_LEN +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image.verify (&recovery_image, &hash.base, &verification.base, NULL, 0,
		&manager.base);
	CuAssertIntEquals (test, RECOVERY_IMAGE_INVALID_SECTION_ADDRESS, status);

	complete_recovery_image_test (test, &flash, &pfm, &manager, &hash, &verification,
		&recovery_image);
}

static void recovery_image_test_verify_bad_recovery_image_header (CuTest *test)
{
	struct flash_mock flash;
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct recovery_image recovery_image;
	struct pfm_manager_mock manager;
	struct pfm_mock pfm;
	uint8_t bad_header[RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN];
	int status;

	TEST_START;

	memcpy (bad_header, RECOVERY_IMAGE_HEADER_FORMAT_0, RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN);
	bad_header[IMAGE_HEADER_BASE_LEN] = '\0';

	setup_recovery_image_mock_test (test, &flash, &pfm, &manager, &hash, &verification);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (bad_header) - IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header +
		IMAGE_HEADER_BASE_LEN, sizeof (bad_header) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image.verify (&recovery_image, &hash.base, &verification.base, NULL, 0,
		&manager.base);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HEADER_BAD_VERSION_ID, status);

	complete_recovery_image_test (test, &flash, &pfm, &manager, &hash, &verification,
		&recovery_image);
}

static void recovery_image_test_get_hash (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	struct recovery_image recovery_image;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA,
		RECOVERY_IMAGE_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= flash_mock_expect_verify_flash (&flash, 0x10000, RECOVERY_IMAGE_DATA,
		RECOVERY_IMAGE_DATA_LEN - RECOVERY_IMAGE_HEADER_SIGNATURE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image.get_hash (&recovery_image, &hash.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (RECOVERY_IMAGE_HASH, hash_out, RECOVERY_IMAGE_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_release (&recovery_image);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_test_get_hash_after_verify (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	struct signature_verification_mock verification;
	struct recovery_image recovery_image;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	struct pfm_manager_mock manager;
	struct pfm_mock pfm;
	int status;

	TEST_START;

	setup_recovery_image_mock_test (test, &flash, &pfm, &manager, &hash, &verification);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA,
		RECOVERY_IMAGE_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_SIGNATURE_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		RECOVERY_IMAGE_SIGNATURE_OFFSET, RECOVERY_IMAGE_HEADER_SIGNATURE_LEN, 2);

	status |= flash_mock_expect_verify_flash (&flash, 0x10000, RECOVERY_IMAGE_DATA,
		RECOVERY_IMAGE_DATA_LEN - RECOVERY_IMAGE_HEADER_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (RECOVERY_IMAGE_HASH, RECOVERY_IMAGE_HASH_LEN),
		MOCK_ARG (RECOVERY_IMAGE_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RECOVERY_IMAGE_SIGNATURE,
		RECOVERY_IMAGE_HEADER_SIGNATURE_LEN), MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));

	status |= mock_expect (&manager.mock, manager.base.get_active_pfm, &manager, (intptr_t) &pfm);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_platform_id, &pfm, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&pfm.mock, 0, &RECOVERY_IMAGE_HEADER_PLATFORM_ID, sizeof (void*),
		-1);

	status |= mock_expect (&pfm.mock, pfm.base.base.free_platform_id, &pfm, 0,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_PLATFORM_ID));

	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager, 0, MOCK_ARG (&pfm));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN,
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image.verify (&recovery_image, &hash.base, &verification.base, NULL, 0,
		&manager.base);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image.get_hash (&recovery_image, &hash.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (RECOVERY_IMAGE_HASH, hash_out, RECOVERY_IMAGE_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_recovery_image_test (test, &flash, &pfm, &manager, &hash, &verification,
		&recovery_image);
}

static void recovery_image_test_get_hash_after_verify_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	struct signature_verification_mock verification;
	struct recovery_image recovery_image;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	struct pfm_manager_mock manager;
	struct pfm_mock pfm;
	int status;

	TEST_START;

	setup_recovery_image_mock_test (test, &flash, &pfm, &manager, &hash, &verification);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	/* Validate hash cache. */
	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA,
		RECOVERY_IMAGE_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_SIGNATURE_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		RECOVERY_IMAGE_SIGNATURE_OFFSET, RECOVERY_IMAGE_HEADER_SIGNATURE_LEN, 2);

	status |= flash_mock_expect_verify_flash (&flash, 0x10000, RECOVERY_IMAGE_DATA,
		RECOVERY_IMAGE_DATA_LEN - RECOVERY_IMAGE_HEADER_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (RECOVERY_IMAGE_HASH, RECOVERY_IMAGE_HASH_LEN),
		MOCK_ARG (RECOVERY_IMAGE_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RECOVERY_IMAGE_SIGNATURE,
		RECOVERY_IMAGE_HEADER_SIGNATURE_LEN), MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));

	status |= mock_expect (&manager.mock, manager.base.get_active_pfm, &manager, (intptr_t) &pfm);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_platform_id, &pfm, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&pfm.mock, 0, &RECOVERY_IMAGE_HEADER_PLATFORM_ID, sizeof (void*),
		-1);

	status |= mock_expect (&pfm.mock, pfm.base.base.free_platform_id, &pfm, 0,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_PLATFORM_ID));

	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager, 0, MOCK_ARG (&pfm));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN,
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image.verify (&recovery_image, &hash.base, &verification.base, NULL, 0,
		&manager.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.mock);
	CuAssertIntEquals (test, 0, status);

	/* Invalidate hash cache. */
	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA,
		RECOVERY_IMAGE_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_SIGNATURE_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		RECOVERY_IMAGE_SIGNATURE_OFFSET, RECOVERY_IMAGE_HEADER_SIGNATURE_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));

	CuAssertIntEquals (test, 0, status);

	status = recovery_image.verify (&recovery_image, &hash.base, &verification.base, NULL, 0,
		&manager.base);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA,
		RECOVERY_IMAGE_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= flash_mock_expect_verify_flash (&flash, 0x10000, RECOVERY_IMAGE_DATA,
		RECOVERY_IMAGE_DATA_LEN - RECOVERY_IMAGE_HEADER_SIGNATURE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image.get_hash (&recovery_image, &hash.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (RECOVERY_IMAGE_HASH, hash_out, RECOVERY_IMAGE_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_recovery_image_test (test, &flash, &pfm, &manager, &hash, &verification,
		&recovery_image);
}

static void recovery_image_test_get_hash_after_verify_bad_signature (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	struct signature_verification_mock verification;
	struct recovery_image recovery_image;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	struct pfm_manager_mock manager;
	struct pfm_mock pfm;
	uint8_t bad_image[RECOVERY_IMAGE_DATA_LEN];
	int status;

	TEST_START;

	memcpy (bad_image, RECOVERY_IMAGE_DATA, RECOVERY_IMAGE_DATA_LEN);
	bad_image[RECOVERY_IMAGE_SIGNATURE_OFFSET] ^= 0x55;

	setup_recovery_image_mock_test (test, &flash, &pfm, &manager, &hash, &verification);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image, RECOVERY_IMAGE_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image + IMAGE_HEADER_BASE_LEN,
		RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_SIGNATURE_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		RECOVERY_IMAGE_SIGNATURE_OFFSET, RECOVERY_IMAGE_HEADER_SIGNATURE_LEN, 2);

	status |= flash_mock_expect_verify_flash (&flash, 0x10000, bad_image,
		sizeof (bad_image) - RECOVERY_IMAGE_HEADER_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG_PTR_CONTAINS (RECOVERY_IMAGE_HASH, RECOVERY_IMAGE_HASH_LEN),
		MOCK_ARG (RECOVERY_IMAGE_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RECOVERY_IMAGE_SIGNATURE,
		RECOVERY_IMAGE_HEADER_SIGNATURE_LEN), MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	status = recovery_image.verify (&recovery_image, &hash.base, &verification.base, NULL, 0,
		&manager.base);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = recovery_image.get_hash (&recovery_image, &hash.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (RECOVERY_IMAGE_HASH, hash_out, RECOVERY_IMAGE_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

    status = flash_mock_validate_and_release (&flash);
    CuAssertIntEquals (test, 0, status);

    signature_verification_mock_release (&verification);

    recovery_image_release (&recovery_image);

    status = pfm_mock_validate_and_release (&pfm);
    CuAssertIntEquals (test, 0, status);

    status = pfm_manager_mock_validate_and_release (&manager);
    CuAssertIntEquals (test, 0, status);

    HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_test_get_hash_after_verify_sig_read_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	struct signature_verification_mock verification;
	struct recovery_image recovery_image;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	struct pfm_manager_mock manager;
	struct pfm_mock pfm;
	int status;

	TEST_START;

	setup_recovery_image_mock_test (test, &flash, &pfm, &manager, &hash, &verification);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	/* Validate hash cache. */
	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA,
		RECOVERY_IMAGE_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_SIGNATURE_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		RECOVERY_IMAGE_SIGNATURE_OFFSET, RECOVERY_IMAGE_HEADER_SIGNATURE_LEN, 2);

	status |= flash_mock_expect_verify_flash (&flash, 0x10000, RECOVERY_IMAGE_DATA,
		RECOVERY_IMAGE_DATA_LEN - RECOVERY_IMAGE_HEADER_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (RECOVERY_IMAGE_HASH, RECOVERY_IMAGE_HASH_LEN),
		MOCK_ARG (RECOVERY_IMAGE_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RECOVERY_IMAGE_SIGNATURE,
		RECOVERY_IMAGE_HEADER_SIGNATURE_LEN), MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));

	status |= mock_expect (&manager.mock, manager.base.get_active_pfm, &manager, (intptr_t) &pfm);

	status |= mock_expect (&pfm.mock, pfm.base.base.get_platform_id, &pfm, 0,
		MOCK_ARG_PTR_PTR (NULL), MOCK_ARG_ANY);
	status |= mock_expect_output (&pfm.mock, 0, &RECOVERY_IMAGE_HEADER_PLATFORM_ID, sizeof (void*),
		-1);

	status |= mock_expect (&pfm.mock, pfm.base.base.free_platform_id, &pfm, 0,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_PLATFORM_ID));

	status |= mock_expect (&manager.mock, manager.base.free_pfm, &manager, 0, MOCK_ARG (&pfm));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN,
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image.verify (&recovery_image, &hash.base, &verification.base, NULL, 0,
		&manager.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.mock);
	CuAssertIntEquals (test, 0, status);

	/* Invalidate hash cache. */
	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA,
		RECOVERY_IMAGE_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_SIGNATURE_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_SIGNATURE_LEN));
	CuAssertIntEquals (test, 0, status);

	status = recovery_image.verify (&recovery_image, &hash.base, &verification.base, NULL, 0,
		&manager.base);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&verification.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA,
		RECOVERY_IMAGE_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= flash_mock_expect_verify_flash (&flash, 0x10000, RECOVERY_IMAGE_DATA,
		RECOVERY_IMAGE_DATA_LEN - RECOVERY_IMAGE_HEADER_SIGNATURE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image.get_hash (&recovery_image, &hash.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (RECOVERY_IMAGE_HASH, hash_out, RECOVERY_IMAGE_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_recovery_image_test (test, &flash, &pfm, &manager, &hash, &verification,
		&recovery_image);
}

static void recovery_image_test_get_hash_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	struct recovery_image recovery_image;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image.get_hash (NULL, &hash.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, RECOVERY_IMAGE_INVALID_ARGUMENT, status);

	status = recovery_image.get_hash (&recovery_image, NULL, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, RECOVERY_IMAGE_INVALID_ARGUMENT, status);

	status = recovery_image.get_hash (&recovery_image, &hash.base, NULL, sizeof (hash_out));
	CuAssertIntEquals (test, RECOVERY_IMAGE_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_release (&recovery_image);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_test_get_hash_small_hash_buffer (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	struct recovery_image recovery_image;
	uint8_t hash_out[SHA256_HASH_LENGTH - 1];
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image.get_hash (&recovery_image, &hash.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, RECOVERY_IMAGE_HASH_BUFFER_TOO_SMALL, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_release (&recovery_image);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_test_get_hash_read_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	struct recovery_image recovery_image;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA,
		RECOVERY_IMAGE_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	CuAssertIntEquals (test, 0, status);

	status = recovery_image.get_hash (&recovery_image, &hash.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_release (&recovery_image);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_test_get_hash_bad_magic_number (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	struct recovery_image recovery_image;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	uint8_t bad_image[IMAGE_HEADER_BASE_LEN];
	int status;

	TEST_START;

	memcpy (bad_image, RECOVERY_IMAGE_DATA, IMAGE_HEADER_BASE_LEN);
	bad_image[IMAGE_HEADER_BASE_LEN - 1] ^= 0x55;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image, sizeof (bad_image), 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image.get_hash (&recovery_image, &hash.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, IMAGE_HEADER_BAD_MARKER, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_release (&recovery_image);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void recovery_image_test_get_version_null (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image recovery_image;
	char version_id[CERBERUS_PROTOCOL_FW_VERSION_LEN];
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image.get_version (NULL, version_id, CERBERUS_PROTOCOL_FW_VERSION_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_INVALID_ARGUMENT, status);

	status = recovery_image.get_version (&recovery_image, NULL, CERBERUS_PROTOCOL_FW_VERSION_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_release (&recovery_image);
}

static void recovery_image_test_get_version (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image recovery_image;
	char version_id[CERBERUS_PROTOCOL_FW_VERSION_LEN];
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA,
		RECOVERY_IMAGE_DATA_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image.get_version (&recovery_image, version_id,
		CERBERUS_PROTOCOL_FW_VERSION_LEN);
	CuAssertIntEquals (test, 0, status);
	CuAssertStrEquals (test, RECOVERY_IMAGE_HEADER_VERSION_ID, version_id);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_release (&recovery_image);
}

static void recovery_image_test_get_version_small_buffer (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image recovery_image;
	char version_id[CERBERUS_PROTOCOL_FW_VERSION_LEN];
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image.get_version (&recovery_image, version_id,
		CERBERUS_PROTOCOL_FW_VERSION_LEN - 1);
	CuAssertIntEquals (test,  RECOVERY_IMAGE_ID_BUFFER_TOO_SMALL, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_release (&recovery_image);
}

static void recovery_image_test_get_version_id_null (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image recovery_image;
	char version_id[CERBERUS_PROTOCOL_FW_VERSION_LEN];
	uint8_t bad_header[RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN];
	int status;

	TEST_START;

	memcpy (bad_header, RECOVERY_IMAGE_HEADER_FORMAT_0, RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN);
	bad_header[IMAGE_HEADER_BASE_LEN] = '\0';

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (bad_header) - IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header +
		IMAGE_HEADER_BASE_LEN, sizeof (bad_header) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image.get_version (&recovery_image, version_id,
		CERBERUS_PROTOCOL_FW_VERSION_LEN);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HEADER_BAD_VERSION_ID, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_release (&recovery_image);
}

static void recovery_image_test_apply_to_flash (CuTest *test)
{
	struct flash_mock flash;
	struct flash_master_mock host_flash_mock;
	struct spi_flash_state host_flash_state;
	struct spi_flash host_flash;
	struct recovery_image recovery_image;
	uint32_t src_addr;
	uint32_t dest_addr;
	uint32_t data_size;
	const uint8_t *data;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&host_flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&host_flash, &host_flash_state, &host_flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&host_flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA,
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (
		IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN,
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN, 2);

	src_addr = 0x10000 + RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN +
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN;
	dest_addr = *((uint32_t*) &RECOVERY_IMAGE_DATA[RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN +
		IMAGE_HEADER_BASE_LEN]);
	data = RECOVERY_IMAGE_DATA + RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN +
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN;
	data_size = *((uint32_t*) &RECOVERY_IMAGE_DATA[RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN +
		IMAGE_HEADER_BASE_LEN + 4]);
	status |= setup_expect_copy_to_host_flash (&host_flash_mock, &flash, dest_addr, src_addr, data,
		data_size);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image.apply_to_flash (&recovery_image, &host_flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&host_flash_mock);
	CuAssertIntEquals (test, 0, status);

	recovery_image_release (&recovery_image);
	spi_flash_release (&host_flash);
}

static void recovery_image_test_apply_to_flash_with_multiple_recovery_sections (CuTest *test)
{
	struct flash_mock flash;
	struct flash_master_mock host_flash_mock;
	struct spi_flash_state host_flash_state;
	struct spi_flash host_flash;
	struct recovery_image recovery_image;
	uint32_t src_addr;
	uint32_t dest_addr;
	uint32_t data_size;
	const uint8_t *data;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&host_flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&host_flash, &host_flash_state, &host_flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&host_flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA2,
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA2 +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (
		IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA2 +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA2 +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN,
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN, 2);

	src_addr = 0x10000 + RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN +
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN;
	dest_addr = *((uint32_t*) &RECOVERY_IMAGE_DATA2[RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN +
		IMAGE_HEADER_BASE_LEN]);
	data = RECOVERY_IMAGE_DATA2 + RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN +
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN;
	data_size = RECOVERY_IMAGE_DATA2_SECTION_1_LEN;
	status |= setup_expect_copy_to_host_flash (&host_flash_mock, &flash, dest_addr, src_addr, data,
		data_size);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 +
		RECOVERY_IMAGE_DATA2_SECTION_2_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA2 +
		RECOVERY_IMAGE_DATA2_SECTION_2_OFFSET,
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_DATA2_SECTION_2_OFFSET + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA2 +
		 RECOVERY_IMAGE_DATA2_SECTION_2_OFFSET +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN, 2);

	src_addr = 0x10000 + RECOVERY_IMAGE_DATA2_SECTION_2_OFFSET +
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN;
	dest_addr = *((uint32_t*) &RECOVERY_IMAGE_DATA2[RECOVERY_IMAGE_DATA2_SECTION_2_OFFSET +
		IMAGE_HEADER_BASE_LEN]);
	data = RECOVERY_IMAGE_DATA2 + RECOVERY_IMAGE_DATA2_SECTION_2_OFFSET +
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN;
	data_size = RECOVERY_IMAGE_DATA2_SECTION_2_LEN;
	status |= setup_expect_copy_to_host_flash (&host_flash_mock, &flash, dest_addr, src_addr, data,
		data_size);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image.apply_to_flash (&recovery_image, &host_flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&host_flash_mock);
	CuAssertIntEquals (test, 0, status);

	recovery_image_release (&recovery_image);
	spi_flash_release (&host_flash);
}

static void recovery_image_test_apply_to_flash_section_image_length_too_short (CuTest *test)
{
	struct flash_mock flash;
	struct flash_master_mock host_flash_mock;
	struct spi_flash_state host_flash_state;
	struct spi_flash host_flash;
	struct recovery_image recovery_image;
	uint8_t bad_image[RECOVERY_IMAGE_DATA_LEN];
	uint32_t src_addr;
	uint32_t dest_addr;
	uint32_t data_size;
	uint8_t *data;
	int status;

	TEST_START;

	memcpy (bad_image, RECOVERY_IMAGE_DATA, RECOVERY_IMAGE_DATA_LEN);
	*((uint32_t*) &bad_image[RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN + 4])
		-= 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&host_flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&host_flash, &host_flash_state, &host_flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&host_flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image,
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (
		IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN,
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN, 2);

	src_addr = 0x10000 + RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN +
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN;
	dest_addr = *((uint32_t*) &bad_image[RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN +
		IMAGE_HEADER_BASE_LEN]);
	data = bad_image + RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN +
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN;
	data_size = *((uint32_t*) &bad_image[RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN +
		IMAGE_HEADER_BASE_LEN + 4]);
	status |= setup_expect_copy_to_host_flash (&host_flash_mock, &flash, dest_addr, src_addr, data,
		data_size);

	src_addr += data_size;
	data += data_size;
	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (src_addr),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, data, IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image.apply_to_flash (&recovery_image, &host_flash);
	CuAssertIntEquals (test, IMAGE_HEADER_BAD_MARKER, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&host_flash_mock);
	CuAssertIntEquals (test, 0, status);

	recovery_image_release (&recovery_image);
	spi_flash_release (&host_flash);
}

static void recovery_image_test_apply_to_flash_section_image_length_too_long (CuTest *test)
{
	struct flash_mock flash;
	struct flash_master_mock host_flash_mock;
	struct spi_flash_state host_flash_state;
	struct spi_flash host_flash;
	struct recovery_image recovery_image;
	uint8_t bad_image[RECOVERY_IMAGE_DATA_LEN];
	uint32_t src_addr;
	uint32_t dest_addr;
	uint32_t data_size;
	uint8_t *data;
	int status;

	TEST_START;

	memcpy (bad_image, RECOVERY_IMAGE_DATA, RECOVERY_IMAGE_DATA_LEN);
	*((uint32_t*) &bad_image[RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN + 4])
		+= 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&host_flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&host_flash, &host_flash_state, &host_flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&host_flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image,
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (
		IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN,
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN, 2);

	src_addr = 0x10000 + RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN +
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN;
	dest_addr = *((uint32_t*) &bad_image[RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN +
		IMAGE_HEADER_BASE_LEN]);
	data = bad_image + RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN +
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN;
	data_size = *((uint32_t*) &bad_image[RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN +
		IMAGE_HEADER_BASE_LEN + 4]);
	status |= setup_expect_copy_to_host_flash (&host_flash_mock, &flash, dest_addr, src_addr, data,
		data_size);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image.apply_to_flash (&recovery_image, &host_flash);
	CuAssertIntEquals (test, RECOVERY_IMAGE_MALFORMED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&host_flash_mock);
	CuAssertIntEquals (test, 0, status);

	recovery_image_release (&recovery_image);
	spi_flash_release (&host_flash);
}

static void recovery_image_test_apply_to_flash_bad_image_header (CuTest *test)
{
	struct flash_mock flash;
	struct flash_master_mock host_flash_mock;
	struct spi_flash_state host_flash_state;
	struct spi_flash host_flash;
	struct recovery_image recovery_image;
	uint8_t bad_header[RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN];
	int status;

	TEST_START;

	memcpy (bad_header, RECOVERY_IMAGE_HEADER_FORMAT_0, RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN);
	bad_header[0] -= 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&host_flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&host_flash, &host_flash_state, &host_flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&host_flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (bad_header) - IMAGE_HEADER_BASE_LEN - 1));
	status |= mock_expect_output (&flash.mock, 1, bad_header +
		IMAGE_HEADER_BASE_LEN, sizeof (bad_header) - IMAGE_HEADER_BASE_LEN - 1, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image.apply_to_flash (&recovery_image, &host_flash);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HEADER_BAD_FORMAT_LENGTH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&host_flash_mock);
	CuAssertIntEquals (test, 0, status);

	recovery_image_release (&recovery_image);
	spi_flash_release (&host_flash);
}

static void recovery_image_test_apply_to_flash_bad_section_header (CuTest *test)
{
	struct flash_mock flash;
	struct flash_master_mock host_flash_mock;
	struct spi_flash_state host_flash_state;
	struct spi_flash host_flash;
	struct recovery_image recovery_image;
	uint8_t bad_image[RECOVERY_IMAGE_DATA_LEN];
	int status;

	TEST_START;

	memcpy (bad_image, RECOVERY_IMAGE_DATA, RECOVERY_IMAGE_DATA_LEN);
	*((uint16_t*) &bad_image[RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN]) -= 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&host_flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&host_flash, &host_flash_state, &host_flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&host_flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image,
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (
		IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_image +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN,
		2);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image.apply_to_flash (&recovery_image, &host_flash);
	CuAssertIntEquals (test, RECOVERY_IMAGE_SECTION_HEADER_BAD_FORMAT_LENGTH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&host_flash_mock);
	CuAssertIntEquals (test, 0, status);

	recovery_image_release (&recovery_image);
	spi_flash_release (&host_flash);
}

static void recovery_image_test_apply_to_flash_read_data_error (CuTest *test)
{
	struct flash_mock flash;
	struct flash_master_mock host_flash_mock;
	struct spi_flash_state host_flash_state;
	struct spi_flash host_flash;
	struct recovery_image recovery_image;
	uint32_t src_addr;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&host_flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&host_flash, &host_flash_state, &host_flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&host_flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA,
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (
		IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_DATA +
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + IMAGE_HEADER_BASE_LEN,
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN, 2);

	src_addr = 0x10000 + RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN +
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN;
	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (src_addr), MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_PAGE_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = recovery_image.apply_to_flash (&recovery_image, &host_flash);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&host_flash_mock);
	CuAssertIntEquals (test, 0, status);

	recovery_image_release (&recovery_image);
	spi_flash_release (&host_flash);
}

static void recovery_image_test_apply_to_flash_null (CuTest *test)
{
	struct flash_mock flash;
	struct flash_master_mock host_flash_mock;
	struct spi_flash_state host_flash_state;
	struct spi_flash host_flash;
	struct recovery_image recovery_image;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&host_flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&host_flash, &host_flash_state, &host_flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&host_flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_init (&recovery_image, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image.apply_to_flash (NULL, &host_flash);
	CuAssertIntEquals (test, RECOVERY_IMAGE_INVALID_ARGUMENT, status);

	status = recovery_image.apply_to_flash (&recovery_image, NULL);
	CuAssertIntEquals (test, RECOVERY_IMAGE_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&host_flash_mock);
	CuAssertIntEquals (test, 0, status);

	recovery_image_release (&recovery_image);
	spi_flash_release (&host_flash);
}


TEST_SUITE_START (recovery_image);

TEST (recovery_image_test_init);
TEST (recovery_image_test_init_null);
TEST (recovery_image_test_release_null);
TEST (recovery_image_test_release_no_init);
TEST (recovery_image_test_verify);
TEST (recovery_image_test_verify_with_multiple_recovery_sections);
TEST (recovery_image_test_verify_second_recovery_section_header_too_long);
TEST (recovery_image_test_verify_image_length_too_long);
TEST (recovery_image_test_verify_image_length_too_short);
TEST (recovery_image_test_verify_section_image_length_too_long);
TEST (recovery_image_test_verify_section_image_length_too_short);
TEST (recovery_image_test_verify_bad_signature);
TEST (recovery_image_test_verify_bad_signature_ecc_with_hash_out);
TEST (recovery_image_test_verify_bad_signature_with_hash_out);
TEST (recovery_image_test_verify_bad_hash);
TEST (recovery_image_test_verify_null);
TEST (recovery_image_test_verify_with_hash_out);
TEST (recovery_image_test_verify_small_hash_buffer);
TEST (recovery_image_test_verify_signature_read_error);
TEST (recovery_image_test_verify_no_active_pfm);
TEST (recovery_image_test_verify_platform_id_mismatch);
TEST (recovery_image_test_verify_platform_id_error);
TEST (recovery_image_test_verify_recovery_section_header_length_too_short);
TEST (recovery_image_test_verify_recovery_section_header_length_too_long);
TEST (recovery_image_test_verify_no_recovery_section_image);
TEST (recovery_image_test_verify_read_error);
TEST (recovery_image_test_verify_read_error_with_hash_out);
TEST (recovery_image_test_verify_bad_magic_number);
TEST (recovery_image_test_verify_section_address_overlap);
TEST (recovery_image_test_verify_bad_recovery_image_header);
TEST (recovery_image_test_get_hash);
TEST (recovery_image_test_get_hash_after_verify);
TEST (recovery_image_test_get_hash_after_verify_error);
TEST (recovery_image_test_get_hash_after_verify_bad_signature);
TEST (recovery_image_test_get_hash_after_verify_sig_read_error);
TEST (recovery_image_test_get_hash_null);
TEST (recovery_image_test_get_hash_small_hash_buffer);
TEST (recovery_image_test_get_hash_read_error);
TEST (recovery_image_test_get_hash_bad_magic_number);
TEST (recovery_image_test_get_version_null);
TEST (recovery_image_test_get_version);
TEST (recovery_image_test_get_version_small_buffer);
TEST (recovery_image_test_get_version_id_null);
TEST (recovery_image_test_apply_to_flash);
TEST (recovery_image_test_apply_to_flash_with_multiple_recovery_sections);
TEST (recovery_image_test_apply_to_flash_section_image_length_too_short);
TEST (recovery_image_test_apply_to_flash_section_image_length_too_long);
TEST (recovery_image_test_apply_to_flash_bad_image_header);
TEST (recovery_image_test_apply_to_flash_bad_section_header);
TEST (recovery_image_test_apply_to_flash_read_data_error);
TEST (recovery_image_test_apply_to_flash_null);

TEST_SUITE_END;
