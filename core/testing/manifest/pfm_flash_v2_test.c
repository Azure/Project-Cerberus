// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "manifest/pfm/pfm_flash.h"
#include "manifest/pfm/pfm_format.h"
#include "testing/mock/crypto/signature_verification_mock.h"
#include "testing/mock/flash/flash_mock.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/crypto/rsa_testing.h"
#include "testing/crypto/ecc_testing.h"
#include "testing/manifest/manifest_flash_v2_testing.h"
#include "testing/manifest/pfm_v2_testing.h"


TEST_SUITE_LABEL ("pfm_flash_v2");


/**
 * The platform identifier in the PFM data.
 */
static const char PFM_V2_PLATFORM_ID[] = "PFM Test1";

#define	PFM_V2_PLATFORM_ID_PAD		3

/**
 * Alternative platform identifier in the PFM data.
 */
static const char PFM_V2_PLATFORM_ID2[] = "PFM Test2";

#define	PFM_V2_PLATFORM_ID2_PAD		3

/**
 * The firmware identifier in the PFM data.
 */
static const char PFM_V2_FIRMWARE_ID[] = "Firmware";

#define	PFM_V2_FIRMWARE_ID_PAD		0

/**
 * Second firmware identifier in PFMs with at least two firmware images.
 */
static const char PFM_V2_FIRMWARE_ID2[] = "Firmware2";

#define	PFM_V2_FIRMWARE_ID2_PAD		3

/**
 * Thrid firmware identifier in PFMs with at least three firmware images.
 */
static const char PFM_V2_FIRMWARE_ID3[] = "FW3";

#define	PFM_V2_FIRMWARE_ID3_PAD		1

/**
 * The firmware version string in the PFM data.
 */
static const char PFM_V2_FW_VERSION[] = "Testing";

#define	PFM_V2_FW_VERSION_PAD		1

/**
 * The firmware version string v2 in the PFM data.
 */
static const char PFM_V2_FW_VERSION_V2[] = "TestingV2";

#define	PFM_V2_FW_VERSION_V2_PAD	2

/**
 * The firmware version string v3 in the PFM data.
 */
static const char PFM_V2_FW_VERSION_V3[] = "TestingV3";

#define	PFM_V2_FW_VERSION_V3_PAD	2

/**
 * Second firmware version string in PFMs with multiple firmware images.
 */
static const char PFM_V2_FW_VERSION2[] = "Testing2";

#define	PFM_V2_FW_VERSION2_PAD		0

/**
 * Second firmware version string v2 in PFMs with multiple firmware images.
 */
static const char PFM_V2_FW_VERSION2_V2[] = "Testing2V2";

#define	PFM_V2_FW_VERSION2_V2_PAD	2

/**
 * Second firmware version string v3 in PFMs with multiple firmware images.
 */
static const char PFM_V2_FW_VERSION2_V3[] = "Testing2V3";

#define	PFM_V2_FW_VERSION2_V3_PAD	2

/**
 * Thrid firmware version string in PFMs with multiple firmware images.
 */
static const char PFM_V2_FW_VERSION3[] = "Test3";

#define	PFM_V2_FW_VERSION3_PAD		3

/**
 * Thrid firmware version string v2 in PFMs with multiple firmware images.
 */
static const char PFM_V2_FW_VERSION3_V2[] = "Test3V2";

#define	PFM_V2_FW_VERSION3_V2_PAD	1

/**
 * Thrid firmware version string v3 in PFMs with multiple firmware images.
 */
static const char PFM_V2_FW_VERSION3_V3[] = "Test3V3";

#define	PFM_V2_FW_VERSION3_V3_PAD	1

/**
 * Maximum length firmware version string.
 */
static const char PFM_V2_FW_VERSION_MAX[] = "0123456789abcdef0123456789abcdef0123456789abcdef012345"
	"6789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123"
	"456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01"
	"23456789abcde";

#define	PFM_V2_FW_VERSION_MAX_PAD	1

/**
 * Maximum length firmware version string than can be stored without additional padding.
 */
static const char PFM_V2_FW_VERSION_MAX_NO_PADDING[] = "0123456789abcdef0123456789abcdef0123456789a"
	"bcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012345678"
	"9abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456"
	"789abcdef0123456789ab";

#define	PFM_V2_FW_VERSION_MAX_NO_PADDING_PAD	0

/**
 * Maximum length firmware version string (for 3 R/W regions) allowing all R/W regions to be
 * retrieved in a single read.
 */
static const char PFM_V2_FW_VERSION_MAX_NO_READ_RW[] ="0123456789abcdef0123456789abcdef0123456789ab"
	"cdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab";

#define	PFM_V2_FW_VERSION_MAX_NO_READ_RW_PAD	0

/**
 * Maximum length firmware version string (1 R/W region, 1 image region, SHA256) allowing all image
 * information to be retrieved in a single read.
 */
static const char PFM_V2_FW_VERSION_MAX_NO_READ_IMG[] ="0123456789abcdef0123456789abcdef0123456789a"
	"bcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012345678"
	"9abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567";

#define	PFM_V2_FW_VERSION_MAX_NO_READ_IMG_PAD	0

/**
 * R/W region for the first firmware component.
 */
static const struct pfm_v2_testing_data_rw PFM_V2_RW1[] = {
	{
		.start_addr = 0x2000000,
		.end_addr = 0x3ffffff,
		.flags = 0
	}
};

/**
 * R/W region for the first firmware component with one R/W regions.
 */
static const struct pfm_v2_testing_data_rw PFM_V2_RW1_ONE[] = {
	{
		.start_addr = 0x00040000,
		.end_addr = 0x0007ffff,
		.flags = 0
	}
};

/**
 * R/W region for the first firmware component with two R/W regions.
 */
static const struct pfm_v2_testing_data_rw PFM_V2_RW1_TWO[] = {
	{
		.start_addr = 0x000c0000,
		.end_addr = 0x000fffff,
		.flags = 1
	},
	{
		.start_addr = 0x00400000,
		.end_addr = 0x007fffff,
		.flags = 0
	}
};

/**
 * R/W region for the first firmware component with three R/W regions.
 */
static const struct pfm_v2_testing_data_rw PFM_V2_RW1_THREE[] = {
	{
		.start_addr = 0x00c00000,
		.end_addr = 0x00ffffff,
		.flags = 2
	},
	{
		.start_addr = 0x04000000,
		.end_addr = 0x07ffffff,
		.flags = 1
	},
	{
		.start_addr = 0x0c000000,
		.end_addr = 0x0fffffff,
		.flags = 0
	}
};

/**
 * R/W region for the second firmware component.
 */
static const struct pfm_v2_testing_data_rw PFM_V2_RW2[] = {
	{
		.start_addr = 0x6000000,
		.end_addr = 0x7ffffff,
		.flags = 1
	}
};

/**
 * R/W region for the second firmware component with one R/W regions.
 */
static const struct pfm_v2_testing_data_rw PFM_V2_RW2_ONE[] = {
	{
		.start_addr = 0x10040000,
		.end_addr = 0x1007ffff,
		.flags = 0
	}
};

/**
 * R/W region for the second firmware component with two R/W regions.
 */
static const struct pfm_v2_testing_data_rw PFM_V2_RW2_TWO[] = {
	{
		.start_addr = 0x100c0000,
		.end_addr = 0x100fffff,
		.flags = 1
	},
	{
		.start_addr = 0x10400000,
		.end_addr = 0x107fffff,
		.flags = 0
	}
};

/**
 * R/W region for the second firmware component with three R/W regions.
 */
static const struct pfm_v2_testing_data_rw PFM_V2_RW2_THREE[] = {
	{
		.start_addr = 0x10c00000,
		.end_addr = 0x10ffffff,
		.flags = 2
	},
	{
		.start_addr = 0x14000000,
		.end_addr = 0x17ffffff,
		.flags = 1
	},
	{
		.start_addr = 0x1c000000,
		.end_addr = 0x1fffffff,
		.flags = 0
	}
};

/**
 * R/W region for the third firmware component.
 */
static const struct pfm_v2_testing_data_rw PFM_V2_RW3[] = {
	{
		.start_addr = 0x8000000,
		.end_addr = 0x9ffffff,
		.flags = 0
	}
};

/**
 * R/W region for the third firmware component with one R/W regions.
 */
static const struct pfm_v2_testing_data_rw PFM_V2_RW3_ONE[] = {
	{
		.start_addr = 0x20040000,
		.end_addr = 0x2007ffff,
		.flags = 0
	}
};

/**
 * R/W region for the third firmware component with two R/W regions.
 */
static const struct pfm_v2_testing_data_rw PFM_V2_RW3_TWO[] = {
	{
		.start_addr = 0x200c0000,
		.end_addr = 0x200fffff,
		.flags = 1
	},
	{
		.start_addr = 0x20400000,
		.end_addr = 0x207fffff,
		.flags = 0
	}
};

/**
 * R/W region for the third firmware component with three R/W regions.
 */
static const struct pfm_v2_testing_data_rw PFM_V2_RW3_THREE[] = {
	{
		.start_addr = 0x20c00000,
		.end_addr = 0x20ffffff,
		.flags = 2
	},
	{
		.start_addr = 0x24000000,
		.end_addr = 0x27ffffff,
		.flags = 1
	},
	{
		.start_addr = 0x2c000000,
		.end_addr = 0x2fffffff,
		.flags = 0
	}
};

/**
 * Image region for the first firmware component.
 */
static const struct pfm_v2_testing_data_region PFM_V2_IMG1_REGION[] = {
	{
		.start_addr = 0x0000000,
		.end_addr = 0x1ffffff,
	}
};

/**
 * Image region for the first firmware component broken into multiple regions.
 */
static const struct pfm_v2_testing_data_region PFM_V2_IMG1_MULTI_REGION[] = {
	{
		.start_addr = 0x0000000,
		.end_addr = 0x004ffff,
	},
	{
		.start_addr = 0x0060000,
		.end_addr = 0x00bffff,
	},
	{
		.start_addr = 0x1000000,
		.end_addr = 0x108ffff,
	},
	{
		.start_addr = 0x1100000,
		.end_addr = 0x1ffffff,
	}
};

/**
 * Image region for the first image for the first firmware component with one image.
 */
static const struct pfm_v2_testing_data_region PFM_V2_IMG1_11_REGION[] = {
	{
		.start_addr = 0x00000000,
		.end_addr = 0x0003ffff,
	}
};

/**
 * Image region for the first image for the first firmware component with two images.
 */
static const struct pfm_v2_testing_data_region PFM_V2_IMG1_21_REGION[] = {
	{
		.start_addr = 0x00080000,
		.end_addr = 0x000bffff,
	}
};

/**
 * Image region for the second image for the first firmware component with two images.
 */
static const struct pfm_v2_testing_data_region PFM_V2_IMG1_22_REGION[] = {
	{
		.start_addr = 0x00100000,
		.end_addr = 0x003fffff,
	}
};

/**
 * Image region for the first image for the first firmware component with three images.
 */
static const struct pfm_v2_testing_data_region PFM_V2_IMG1_31_REGION[] = {
	{
		.start_addr = 0x00800000,
		.end_addr = 0x00bfffff,
	}
};

/**
 * Image region for the second image for the first firmware component with three images.
 */
static const struct pfm_v2_testing_data_region PFM_V2_IMG1_32_REGION[] = {
	{
		.start_addr = 0x01000000,
		.end_addr = 0x03ffffff,
	}
};

/**
 * Image region for the thrid image for the first firmware component with three images.
 */
static const struct pfm_v2_testing_data_region PFM_V2_IMG1_33_REGION[] = {
	{
		.start_addr = 0x08000000,
		.end_addr = 0x0bffffff,
	}
};

/**
 * Image region for the second firmware component.
 */
static const struct pfm_v2_testing_data_region PFM_V2_IMG2_REGION[] = {
	{
		.start_addr = 0x4000000,
		.end_addr = 0x5ffffff,
	}
};

/**
 * Image region for the first image for the second firmware component with one image.
 */
static const struct pfm_v2_testing_data_region PFM_V2_IMG2_11_REGION[] = {
	{
		.start_addr = 0x10000000,
		.end_addr = 0x1003ffff,
	}
};

/**
 * Image region for the first image for the second firmware component with two images.
 */
static const struct pfm_v2_testing_data_region PFM_V2_IMG2_21_REGION[] = {
	{
		.start_addr = 0x10080000,
		.end_addr = 0x100bffff,
	}
};

/**
 * Image region for the second image for the second firmware component with two images.
 */
static const struct pfm_v2_testing_data_region PFM_V2_IMG2_22_REGION[] = {
	{
		.start_addr = 0x10100000,
		.end_addr = 0x103fffff,
	}
};

/**
 * Image region for the first image for the second firmware component with three images.
 */
static const struct pfm_v2_testing_data_region PFM_V2_IMG2_31_REGION[] = {
	{
		.start_addr = 0x10800000,
		.end_addr = 0x10bfffff,
	}
};

/**
 * Image region for the second image for the second firmware component with three images.
 */
static const struct pfm_v2_testing_data_region PFM_V2_IMG2_32_REGION[] = {
	{
		.start_addr = 0x11000000,
		.end_addr = 0x13ffffff,
	}
};

/**
 * Image region for the thrid image for the second firmware component with three images.
 */
static const struct pfm_v2_testing_data_region PFM_V2_IMG2_33_REGION[] = {
	{
		.start_addr = 0x18000000,
		.end_addr = 0x1bffffff,
	}
};

/**
 * Image region for the third firmware component.
 */
static const struct pfm_v2_testing_data_region PFM_V2_IMG3_REGION[] = {
	{
		.start_addr = 0xa000000,
		.end_addr = 0xbffffff,
	}
};

/**
 * Image region for the first image for the third firmware component with one image.
 */
static const struct pfm_v2_testing_data_region PFM_V2_IMG3_11_REGION[] = {
	{
		.start_addr = 0x20000000,
		.end_addr = 0x2003ffff,
	}
};

/**
 * Image region for the first image for the third firmware component with two images.
 */
static const struct pfm_v2_testing_data_region PFM_V2_IMG3_21_REGION[] = {
	{
		.start_addr = 0x20080000,
		.end_addr = 0x200bffff,
	}
};

/**
 * Image region for the second image for the third firmware component with two images.
 */
static const struct pfm_v2_testing_data_region PFM_V2_IMG3_22_REGION[] = {
	{
		.start_addr = 0x20100000,
		.end_addr = 0x203fffff,
	}
};

/**
 * Image region for the first image for the third firmware component with three images.
 */
static const struct pfm_v2_testing_data_region PFM_V2_IMG3_31_REGION[] = {
	{
		.start_addr = 0x20800000,
		.end_addr = 0x20bfffff,
	}
};

/**
 * Image region for the second image for the third firmware component with three images.
 */
static const struct pfm_v2_testing_data_region PFM_V2_IMG3_32_REGION[] = {
	{
		.start_addr = 0x21000000,
		.end_addr = 0x23ffffff,
	}
};

/**
 * Image region for the thrid image for the third firmware component with three images.
 */
static const struct pfm_v2_testing_data_region PFM_V2_IMG3_33_REGION[] = {
	{
		.start_addr = 0x28000000,
		.end_addr = 0x2bffffff,
	}
};

/**
 * Test PFM in v2 format.  Contains one FW element and an RSA signature.
 *
 * NUM_FW=1 ./generate_pfm.sh 1 ../../core/testing/keys/rsapriv.pem
 */
static const uint8_t PFM_V2_DATA[] = {
	0x38,0x02,0x6d,0x70,0x01,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x04,0x04,0x00,0x00,
	0x10,0xff,0x00,0x00,0xd0,0x00,0x04,0x00,0x11,0xff,0x01,0x03,0xd4,0x00,0x0c,0x00,
	0x12,0x11,0x01,0x01,0xe0,0x00,0x48,0x00,0x00,0xff,0x01,0x02,0x28,0x01,0x10,0x00,
	0xa8,0xd9,0xe5,0x71,0xa3,0xf6,0xf7,0x9d,0xa5,0xff,0xf4,0xbd,0xa2,0x79,0x26,0xa1,
	0x87,0x00,0x31,0x36,0x9e,0xc1,0x37,0xd6,0x58,0x73,0x05,0xc8,0xef,0xec,0x80,0xd2,
	0xef,0x95,0x25,0xdc,0x60,0xa1,0xce,0x08,0x7f,0x89,0x91,0xe5,0xe1,0xac,0x3b,0x60,
	0x17,0x89,0x3e,0x9d,0x2d,0x08,0xaf,0x26,0x54,0x49,0xed,0x8d,0x0c,0x7c,0xb0,0x03,
	0xd3,0xb6,0xeb,0x9b,0xe0,0x85,0xcd,0xd3,0xd6,0x05,0x81,0xc8,0x0b,0x38,0x6d,0x9a,
	0xf8,0x5b,0xae,0x5f,0xed,0x50,0x36,0x38,0x55,0x0c,0xf8,0xe8,0xdb,0xd8,0x82,0x46,
	0x13,0x48,0x15,0xa0,0xd1,0xfb,0x58,0x01,0xae,0x7a,0xa2,0x15,0xb4,0xf1,0x98,0x57,
	0xda,0x88,0x4d,0x95,0x99,0x18,0x27,0x0f,0x98,0x11,0xfe,0xe5,0xd4,0x0e,0x5b,0x6c,
	0x5a,0x25,0x77,0x68,0xbf,0xbe,0x39,0x19,0x9c,0x38,0x00,0x8e,0x9d,0x15,0x76,0x03,
	0xa6,0xe6,0x49,0x89,0x86,0x37,0x25,0xee,0x62,0x2e,0x13,0x53,0xa9,0xc4,0x98,0x80,
	0xff,0x01,0x00,0x00,0x01,0x08,0x00,0x00,0x46,0x69,0x72,0x6d,0x77,0x61,0x72,0x65,
	0x01,0x01,0x07,0x00,0x45,0x23,0x01,0x00,0x54,0x65,0x73,0x74,0x69,0x6e,0x67,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0xff,0xff,0xff,0x03,0x00,0x01,0x01,0x00,
	0xae,0xf7,0x3c,0x33,0xcc,0x07,0x91,0x5e,0x52,0xdc,0x8a,0x77,0x1f,0x41,0xc2,0xdc,
	0x5b,0x8c,0x1b,0x46,0xab,0xcd,0xa3,0xf0,0x61,0x7f,0x45,0xe0,0x07,0x99,0x65,0x03,
	0x00,0x00,0x00,0x00,0xff,0xff,0xff,0x01,0x09,0x00,0x00,0x00,0x50,0x46,0x4d,0x20,
	0x54,0x65,0x73,0x74,0x31,0x00,0x00,0x00,0x88,0x18,0x9f,0x7a,0x30,0x0c,0xd1,0xce,
	0x87,0x95,0x2e,0x05,0xb5,0xa0,0x43,0x86,0xc1,0xdc,0x20,0x42,0x1d,0x6b,0xe0,0x6f,
	0xce,0x2d,0x7b,0x4a,0x21,0x14,0x07,0xf8,0x3a,0x95,0x59,0x61,0xaa,0x14,0x9e,0xbf,
	0x36,0x9d,0x4c,0xb0,0x2b,0xb1,0xb0,0xfd,0x3e,0x5a,0xbd,0x05,0x31,0x76,0x8a,0xd6,
	0x8c,0x22,0x28,0xe2,0xd8,0xb6,0x60,0x9d,0x90,0xc3,0x24,0x55,0xad,0x5f,0xd7,0x18,
	0x37,0xe9,0x9d,0xbc,0xa6,0x20,0x8d,0xde,0x04,0x86,0x14,0x01,0x12,0x10,0x86,0x98,
	0x15,0xad,0x62,0x02,0xd9,0xd2,0x88,0xb8,0xb8,0x0b,0x04,0xb7,0x7e,0x65,0x92,0xf6,
	0x26,0x5a,0x73,0x9c,0x23,0xc4,0xbe,0xa2,0x2b,0x2c,0x80,0x93,0x73,0xce,0x65,0xe3,
	0xdf,0x01,0x01,0x01,0x16,0x3e,0x56,0xb4,0x93,0x18,0x5c,0xfa,0xd9,0xa6,0xea,0xf0,
	0xcd,0x92,0xb6,0xb0,0x21,0x3b,0x85,0xff,0xde,0x48,0xf9,0xe7,0xeb,0x2f,0xf0,0xfd,
	0x51,0xa3,0xe3,0xfd,0x88,0x1b,0x5f,0x9f,0x75,0x52,0xfe,0xea,0x96,0x9b,0xc2,0x75,
	0xca,0x5c,0xd0,0x30,0x7e,0x8f,0xaa,0xfd,0xa8,0xce,0x55,0x46,0x1b,0xea,0x8f,0xc9,
	0x4a,0x94,0xc7,0xea,0x07,0xf0,0xe8,0xc0,0xb7,0x15,0xf7,0x87,0x96,0x6f,0x7b,0x61,
	0xfc,0xa1,0xdf,0xca,0x3a,0x78,0x44,0xaa,0xf5,0xe0,0xcd,0x1d,0xec,0x66,0xa3,0x6a,
	0x77,0x4f,0x06,0x72,0x59,0x31,0x15,0x32,0x79,0x74,0x00,0x85,0xbd,0x62,0x9a,0xc8,
	0x83,0xc3,0x96,0xdc,0x08,0xfa,0x40,0x4b,0x32,0x78,0x55,0x8b,0x53,0xbf,0x97,0x79,
	0x4d,0x4a,0x2a,0x27,0x5f,0x63,0x5e,0x25
};

/**
 * PFM_V2_DATA hash for testing.
 *
 * head -c -256 pfm.img | openssl dgst -sha256
 */
static const uint8_t PFM_V2_HASH[] = {
	0x75,0xc2,0x3f,0x51,0xcf,0x40,0x36,0xeb,0xa0,0x41,0x51,0x11,0x04,0x74,0xfb,0x9c,
	0xd7,0x50,0xd2,0xb6,0xb9,0xff,0x08,0xce,0xcb,0xd4,0xfa,0xf7,0x4a,0xf7,0x4e,0x67
};

/**
 * Firmware image for the test v2 PFM.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG[] = {
	{
		.img_offset = 0x00fc,
		.hash = PFM_V2_DATA + 0x0100,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG1_REGION
	}
};

/**
 * Firmware version components of the test v2 PFM.
 */
static const struct pfm_v2_testing_data_fw_ver PFM_V2_FW_VER[] = {
	{
		.fw_version = PFM_V2_DATA + 0x00e0,
		.fw_version_len = 0x0048,
		.version_str = PFM_V2_FW_VERSION,
		.version_str_len = sizeof (PFM_V2_FW_VERSION) - 1,
		.version_str_pad = PFM_V2_FW_VERSION_PAD,
		.fw_version_offset = 0x00e0,
		.fw_version_entry = 2,
		.fw_version_hash = 1,
		.version_addr = 0x012345,
		.rw_count = 1,
		.rw = PFM_V2_RW1,
		.img_count = 1,
		.img = PFM_V2_FW_IMG
	}
};

/**
 * Firmware components of the test v2 PFM.
 */
static const struct pfm_v2_testing_data_fw PFM_V2_FW[] = {
	{
		.fw = PFM_V2_DATA + 0x00d4,
		.fw_len = 0x000c,
		.fw_id_str = PFM_V2_FIRMWARE_ID,
		.fw_id_str_len = sizeof (PFM_V2_FIRMWARE_ID) - 1,
		.fw_id_str_pad = PFM_V2_FIRMWARE_ID_PAD,
		.fw_offset = 0x00d4,
		.fw_entry = 1,
		.fw_hash = 3,
		.version_count = 1,
		.version = PFM_V2_FW_VER
	}
};

/**
 * Components of the test v2 PFM.
 */
const struct pfm_v2_testing_data PFM_V2 = {
	.manifest = {
		.raw = PFM_V2_DATA,
		.length = sizeof (PFM_V2_DATA),
		.hash = PFM_V2_HASH,
		.hash_len = sizeof (PFM_V2_HASH),
		.id = 1,
		.signature = PFM_V2_DATA + (sizeof (PFM_V2_DATA) - 256),
		.sig_len = 256,
		.sig_offset = (sizeof (PFM_V2_DATA) - 256),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = PFM_V2_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x00c4,
		.toc_hash = PFM_V2_DATA + 0x00b0,
		.toc_hash_len = 32,
		.toc_hash_offset = 0x00b0,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 4,
		.toc_hashes = 4,
		.plat_id = PFM_V2_DATA + 0x128,
		.plat_id_len = 0x0010,
		.plat_id_str = PFM_V2_PLATFORM_ID,
		.plat_id_str_len = sizeof (PFM_V2_PLATFORM_ID) - 1,
		.plat_id_str_pad = PFM_V2_PLATFORM_ID_PAD,
		.plat_id_offset = 0x0128,
		.plat_id_entry = 3,
		.plat_id_hash = 2
	},
	.flash_dev = PFM_V2_DATA + 0x00d0,
	.flash_dev_len = 4,
	.flash_dev_offset = 0x00d0,
	.flash_dev_entry = 0,
	.flash_dev_hash = 0,
	.blank_byte = 0xff,
	.fw_count = 1,
	.fw = PFM_V2_FW
};

/**
 * Test PFM in v2 format.  Contains one FW element and an RSA signature.  The platform ID element
 * is first in the manifest.
 *
 * PLATFORM_FIRST=1 NUM_FW=1 ./generate_pfm.sh 2 ../../core/testing/keys/rsapriv.pem
 */
static const uint8_t PFM_V2_PLAT_FIRST_DATA[] = {
	0x38,0x02,0x6d,0x70,0x02,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x04,0x04,0x00,0x00,
	0x00,0xff,0x01,0x02,0xd0,0x00,0x10,0x00,0x10,0xff,0x00,0x00,0xe0,0x00,0x04,0x00,
	0x11,0xff,0x01,0x03,0xe4,0x00,0x0c,0x00,0x12,0x11,0x01,0x01,0xf0,0x00,0x48,0x00,
	0xa8,0xd9,0xe5,0x71,0xa3,0xf6,0xf7,0x9d,0xa5,0xff,0xf4,0xbd,0xa2,0x79,0x26,0xa1,
	0x87,0x00,0x31,0x36,0x9e,0xc1,0x37,0xd6,0x58,0x73,0x05,0xc8,0xef,0xec,0x80,0xd2,
	0xf7,0xb9,0xe3,0xda,0x95,0x41,0x6c,0x9d,0x75,0x12,0xaf,0x8b,0xa0,0xb3,0x64,0xd3,
	0xf7,0x38,0x37,0x51,0xb1,0x1f,0x2f,0x4c,0x93,0x1f,0x38,0xa9,0x55,0xe4,0xc5,0x49,
	0xd3,0xb6,0xeb,0x9b,0xe0,0x85,0xcd,0xd3,0xd6,0x05,0x81,0xc8,0x0b,0x38,0x6d,0x9a,
	0xf8,0x5b,0xae,0x5f,0xed,0x50,0x36,0x38,0x55,0x0c,0xf8,0xe8,0xdb,0xd8,0x82,0x46,
	0x13,0x48,0x15,0xa0,0xd1,0xfb,0x58,0x01,0xae,0x7a,0xa2,0x15,0xb4,0xf1,0x98,0x57,
	0xda,0x88,0x4d,0x95,0x99,0x18,0x27,0x0f,0x98,0x11,0xfe,0xe5,0xd4,0x0e,0x5b,0x6c,
	0xd5,0x00,0x85,0x3c,0xaa,0xbe,0x43,0xb3,0xe2,0xe3,0x8d,0x5a,0xe4,0xbc,0x5f,0x34,
	0x2b,0xe9,0xec,0x3c,0xf2,0x8f,0xe5,0x0b,0x96,0x59,0x9e,0x90,0x71,0x6d,0x84,0xc8,
	0x09,0x00,0x00,0x00,0x50,0x46,0x4d,0x20,0x54,0x65,0x73,0x74,0x31,0x00,0x00,0x00,
	0xff,0x01,0x00,0x00,0x01,0x08,0x00,0x00,0x46,0x69,0x72,0x6d,0x77,0x61,0x72,0x65,
	0x01,0x01,0x07,0x00,0x45,0x23,0x01,0x00,0x54,0x65,0x73,0x74,0x69,0x6e,0x67,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0xff,0xff,0xff,0x03,0x00,0x01,0x01,0x00,
	0x18,0x13,0x76,0xb1,0x42,0x6c,0x5e,0xd9,0x1e,0x07,0x42,0xa1,0x70,0x75,0x29,0x4d,
	0x9b,0x9f,0x3b,0x5f,0x32,0x7b,0x5e,0x0d,0x9c,0x20,0x50,0x24,0x63,0x74,0xf8,0x48,
	0x00,0x00,0x00,0x00,0xff,0xff,0xff,0x01,0xad,0x71,0x4c,0x8a,0xa4,0xaa,0x93,0x6c,
	0xc5,0x0b,0xca,0xe1,0xde,0xb7,0xe0,0x4a,0x9b,0xb9,0x14,0xde,0x31,0x2c,0x7c,0xfa,
	0x6e,0x6f,0x46,0xa1,0x25,0xb4,0xfa,0x90,0x42,0x38,0xf4,0xaa,0x93,0xbc,0x6f,0x82,
	0x0d,0x24,0x71,0x73,0x93,0xe1,0x2b,0xd8,0xd0,0xcc,0x28,0x89,0x31,0x41,0x6a,0xe0,
	0x8d,0xc4,0xb4,0x8a,0xc5,0x70,0xe5,0x48,0x3a,0x56,0xf3,0x3a,0x36,0x5a,0x8c,0x88,
	0x6c,0x5f,0xc6,0x49,0x43,0x68,0x23,0xcc,0x49,0xeb,0x59,0x2e,0xa5,0x92,0x17,0x35,
	0x3c,0x79,0xcd,0xaf,0x9d,0x0c,0x42,0x82,0x42,0xab,0x49,0x8d,0x1f,0x0c,0xef,0x00,
	0xd5,0xa8,0x61,0x55,0x60,0xc7,0xfd,0x6d,0xce,0xb1,0x92,0x7e,0xd2,0x9b,0xb6,0x52,
	0x72,0x84,0x97,0x4f,0xe7,0x71,0xab,0x3e,0x3e,0x97,0x3a,0xa7,0x25,0xf2,0x6c,0xc7,
	0x72,0x6b,0x20,0x96,0x45,0x92,0x58,0x1d,0x9a,0x9f,0x46,0x42,0xc9,0x1c,0xe6,0xa9,
	0x7c,0xcd,0x92,0x53,0x62,0xf2,0x2c,0x82,0x73,0xa9,0x7c,0x9f,0x23,0x53,0x16,0xa7,
	0xc9,0x6b,0x5e,0x45,0x97,0x65,0x52,0x85,0x17,0x13,0x55,0x64,0x75,0x8e,0x65,0x42,
	0x2d,0x79,0x37,0xd1,0x37,0xa4,0x06,0x24,0x5a,0x09,0x1b,0xe3,0x12,0x93,0x4b,0x18,
	0x15,0x11,0x19,0x3b,0x62,0xf8,0xdc,0x2d,0x98,0x1e,0xf6,0x87,0x05,0x18,0x99,0x8a,
	0x60,0xd4,0x97,0xe5,0x1b,0xf7,0x5b,0x1c,0xb2,0xbb,0xd3,0x4d,0xd4,0x4c,0xce,0x14,
	0x8d,0x52,0xfb,0x76,0x6b,0x01,0xc6,0x78,0x0a,0xb0,0xc4,0x4f,0x5e,0x63,0x34,0x42,
	0xaa,0x7a,0x29,0xc5,0x04,0x32,0xb4,0xe8
};

/**
 * PFM_V2_PLAT_FIRST_DATA hash for testing.
 *
 * head -c -256 pfm.img | openssl dgst -sha256
 */
static const uint8_t PFM_V2_PLAT_FIRST_HASH[] = {
	0x3f,0x2c,0xc8,0xee,0x5e,0xf5,0x54,0x64,0x02,0x50,0xe1,0x8a,0xe9,0xfb,0x15,0x3b,
	0x64,0x11,0x63,0x13,0xfd,0x1c,0xeb,0x70,0x78,0xe1,0x51,0x80,0xde,0xf9,0x62,0x80
};

/**
 * Firmware image for the test v2 PFM with platform ID first.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_PLAT_FIRST[] = {
	{
		.img_offset = 0x0010c,
		.hash = PFM_V2_PLAT_FIRST_DATA + 0x0110,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG1_REGION
	}
};

/**
 * Firmware version components of the test v2 PFM with platform ID first.
 */
static const struct pfm_v2_testing_data_fw_ver PFM_V2_FW_VER_PLAT_FIRST[] = {
	{
		.fw_version = PFM_V2_PLAT_FIRST_DATA + 0x00f0,
		.fw_version_len = 0x0048,
		.version_str = PFM_V2_FW_VERSION,
		.version_str_len = sizeof (PFM_V2_FW_VERSION) - 1,
		.version_str_pad = PFM_V2_FW_VERSION_PAD,
		.fw_version_offset = 0x00f0,
		.fw_version_entry = 3,
		.fw_version_hash = 1,
		.version_addr = 0x012345,
		.rw_count = 1,
		.rw = PFM_V2_RW1,
		.img_count = 1,
		.img = PFM_V2_FW_IMG_PLAT_FIRST
	}
};

/**
 * Firmware components of the test v2 PFM with platform ID first.
 */
static const struct pfm_v2_testing_data_fw PFM_V2_FW_PLAT_FIRST[] = {
	{
		.fw = PFM_V2_PLAT_FIRST_DATA + 0x00e4,
		.fw_len = 0x000c,
		.fw_id_str = PFM_V2_FIRMWARE_ID,
		.fw_id_str_len = sizeof (PFM_V2_FIRMWARE_ID) - 1,
		.fw_id_str_pad = PFM_V2_FIRMWARE_ID_PAD,
		.fw_offset = 0x00e4,
		.fw_entry = 2,
		.fw_hash = 3,
		.version_count = 1,
		.version = PFM_V2_FW_VER_PLAT_FIRST
	}
};

/**
 * Components of the test v2 PFM with platform ID first.
 */
const struct pfm_v2_testing_data PFM_V2_PLAT_FIRST = {
	.manifest = {
		.raw = PFM_V2_PLAT_FIRST_DATA,
		.length = sizeof (PFM_V2_PLAT_FIRST_DATA),
		.hash = PFM_V2_PLAT_FIRST_HASH,
		.hash_len = sizeof (PFM_V2_PLAT_FIRST_HASH),
		.id = 2,
		.signature = PFM_V2_PLAT_FIRST_DATA + (sizeof (PFM_V2_PLAT_FIRST_DATA) - 256),
		.sig_len = 256,
		.sig_offset = (sizeof (PFM_V2_PLAT_FIRST_DATA) - 256),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = PFM_V2_PLAT_FIRST_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x00c4,
		.toc_hash = PFM_V2_PLAT_FIRST_DATA + 0x00b0,
		.toc_hash_len = 32,
		.toc_hash_offset = 0x00b0,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 4,
		.toc_hashes = 4,
		.plat_id = PFM_V2_PLAT_FIRST_DATA + 0x00d0,
		.plat_id_len = 0x0010,
		.plat_id_str = PFM_V2_PLATFORM_ID,
		.plat_id_str_len = sizeof (PFM_V2_PLATFORM_ID) - 1,
		.plat_id_str_pad = PFM_V2_PLATFORM_ID_PAD,
		.plat_id_offset = 0x00d0,
		.plat_id_entry = 0,
		.plat_id_hash = 2
	},
	.flash_dev = PFM_V2_PLAT_FIRST_DATA + 0x00e0,
	.flash_dev_len = 4,
	.flash_dev_offset = 0x00e0,
	.flash_dev_entry = 1,
	.flash_dev_hash = 0,
	.blank_byte = 0xff,
	.fw_count = 1,
	.fw = PFM_V2_FW_PLAT_FIRST
};

/**
 * Test PFM in v2 format.  Contains two FW elements and an ECC signature.  The platform ID is in
 * between the two FW elements.
 *
 * PLATFORM="PFM Test2" NUM_FW=2 ./generate_pfm.sh 3 ../../core/testing/keys/eccpriv.pem
 */
static const uint8_t PFM_V2_TWO_FW_DATA[] = {
	0x39,0x02,0x6d,0x70,0x03,0x00,0x00,0x00,0x49,0x00,0x40,0x00,0x06,0x06,0x00,0x00,
	0x10,0xff,0x00,0x00,0x20,0x01,0x04,0x00,0x11,0xff,0x01,0x04,0x24,0x01,0x0c,0x00,
	0x12,0x11,0x01,0x01,0x30,0x01,0x48,0x00,0x00,0xff,0x01,0x03,0x78,0x01,0x10,0x00,
	0x11,0xff,0x01,0x05,0x88,0x01,0x10,0x00,0x12,0x11,0x01,0x02,0x98,0x01,0x58,0x00,
	0x9c,0x36,0x29,0xb0,0xe1,0xf5,0x54,0xa3,0x41,0xcf,0x0b,0xf0,0x7f,0xb0,0xcb,0x57,
	0x36,0xa7,0x3b,0xce,0x8c,0x4c,0xb4,0x52,0xea,0x0a,0x31,0xd9,0x9f,0xc5,0x02,0x83,
	0xb4,0x13,0x19,0xf9,0x22,0x07,0x69,0xb0,0xf2,0xa5,0x7c,0xd3,0xdf,0x60,0x18,0xd9,
	0xdb,0xc8,0x5d,0x4f,0x3a,0xbe,0xaa,0x00,0x55,0x5e,0x7d,0x20,0x7c,0xaa,0x3a,0xa7,
	0x0a,0x93,0x36,0xe2,0x30,0xd7,0x54,0x39,0xb4,0x58,0x02,0x7f,0x04,0xd9,0xd8,0x8e,
	0x27,0x3e,0x42,0xc1,0x8c,0xef,0xee,0x16,0x66,0xb8,0xaf,0xbb,0x32,0x62,0x85,0x04,
	0x67,0x98,0x4a,0xa9,0x89,0x7c,0xed,0x76,0xe5,0x8a,0x8e,0x7f,0xec,0xa4,0x38,0xdc,
	0x7a,0x8f,0x2c,0x8b,0x33,0x0b,0x87,0x09,0x53,0xbb,0xd2,0x88,0x5f,0xee,0x0d,0xe8,
	0x13,0x48,0x15,0xa0,0xd1,0xfb,0x58,0x01,0xae,0x7a,0xa2,0x15,0xb4,0xf1,0x98,0x57,
	0xda,0x88,0x4d,0x95,0x99,0x18,0x27,0x0f,0x98,0x11,0xfe,0xe5,0xd4,0x0e,0x5b,0x6c,
	0xbf,0xa8,0xbe,0x1e,0x12,0xa0,0x18,0xd5,0x25,0xec,0xf8,0xc1,0x97,0x00,0xdb,0xd7,
	0xe8,0xaa,0x94,0x96,0x24,0xe9,0xde,0x93,0x00,0x0b,0x66,0x8b,0x5c,0x2e,0x96,0x37,
	0x66,0x4f,0x41,0xa3,0x61,0xea,0x68,0x8d,0x2d,0x13,0x08,0x0f,0xbf,0xc4,0x21,0xf8,
	0x95,0xbd,0xf2,0xc6,0x61,0xb3,0xb9,0x51,0x7f,0xc1,0xa4,0xe1,0x1d,0x37,0x06,0xb6,
	0xff,0x02,0x00,0x00,0x01,0x08,0x00,0x00,0x46,0x69,0x72,0x6d,0x77,0x61,0x72,0x65,
	0x01,0x01,0x07,0x00,0x45,0x23,0x01,0x00,0x54,0x65,0x73,0x74,0x69,0x6e,0x67,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0xff,0xff,0xff,0x03,0x00,0x01,0x01,0x00,
	0xcb,0x24,0xe1,0x8d,0xfc,0x71,0xbc,0x91,0xdb,0xde,0x07,0x5d,0x82,0xeb,0xe4,0xeb,
	0x58,0x55,0xf2,0xb8,0x39,0x39,0xb7,0x24,0x23,0x8c,0x39,0xb5,0x19,0xaa,0x41,0x6d,
	0x00,0x00,0x00,0x00,0xff,0xff,0xff,0x01,0x09,0x00,0x00,0x00,0x50,0x46,0x4d,0x20,
	0x54,0x65,0x73,0x74,0x32,0x00,0x00,0x00,0x01,0x09,0x00,0x00,0x46,0x69,0x72,0x6d,
	0x77,0x61,0x72,0x65,0x32,0x00,0x00,0x00,0x01,0x01,0x08,0x00,0x45,0x23,0x11,0x00,
	0x54,0x65,0x73,0x74,0x69,0x6e,0x67,0x32,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x06,
	0xff,0xff,0xff,0x07,0x01,0x01,0x01,0x00,0x3e,0x05,0x18,0x91,0xb8,0x49,0x33,0x40,
	0x8b,0x14,0xfe,0x1d,0x04,0xad,0xb5,0x3b,0xbc,0x3b,0x50,0xff,0x45,0x2f,0xc3,0x22,
	0xb4,0x28,0x0b,0xaf,0xef,0x27,0x65,0x69,0x93,0xd0,0xc4,0x32,0xad,0x9c,0xbc,0xd8,
	0xa2,0xaf,0xf7,0xa3,0x7c,0x97,0x73,0x5a,0x00,0x00,0x00,0x04,0xff,0xff,0xff,0x05,
	0x30,0x45,0x02,0x20,0x5f,0xf0,0x56,0x61,0x57,0x0f,0x73,0x62,0x67,0xd0,0xae,0x95,
	0xbf,0x4c,0x19,0xc3,0xed,0x83,0xc2,0xa6,0xdd,0xdd,0xfa,0x11,0xf4,0x8f,0x5c,0x08,
	0xad,0xb6,0x9b,0xe7,0x02,0x21,0x00,0xd5,0xcb,0xc8,0xed,0x8a,0xf8,0xf3,0xd8,0x88,
	0xf7,0x11,0xeb,0x1f,0x36,0x15,0x85,0xb0,0x76,0xb5,0x5c,0x12,0xe5,0xa4,0x46,0xa1,
	0x5a,0x2f,0x0d,0x41,0x91,0x5d,0x76,0x00,0x00
};

/**
 * PFM_V2_TWO_FW_DATA hash for testing.
 *
 * head -c -73 pfm.img | openssl dgst -sha256
 */
static const uint8_t PFM_V2_TWO_FW_HASH[] = {
	0x55,0xe6,0xf0,0xd1,0x92,0x51,0xa5,0x7b,0xf1,0xc6,0x4f,0xf4,0xca,0xa4,0x11,0x68,
	0x89,0x0a,0x7c,0xa1,0x88,0xed,0xb0,0x00,0xf2,0x9d,0x8e,0xa1,0x97,0x30,0xaf,0xd4
};


/**
 * First firmware image for the test v2 PFM with two firmware elements.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_TWO_FW_1[] = {
	{
		.img_offset = 0x014c,
		.hash = PFM_V2_TWO_FW_DATA + 0x0150,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG1_REGION
	}
};

/**
 * First firmware version components of the test v2 PFM with two firmware elements.
 */
static const struct pfm_v2_testing_data_fw_ver PFM_V2_FW_VER_TWO_FW_1[] = {
	{
		.fw_version = PFM_V2_TWO_FW_DATA + 0x0130,
		.fw_version_len = 0x0048,
		.version_str = PFM_V2_FW_VERSION,
		.version_str_len = sizeof (PFM_V2_FW_VERSION) - 1,
		.version_str_pad = PFM_V2_FW_VERSION_PAD,
		.fw_version_offset = 0x0130,
		.fw_version_entry = 2,
		.fw_version_hash = 1,
		.version_addr = 0x012345,
		.rw_count = 1,
		.rw = PFM_V2_RW1,
		.img_count = 1,
		.img = PFM_V2_FW_IMG_TWO_FW_1
	}
};

/**
 * Second firmware image for the test v2 PFM with two firmware elements.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_TWO_FW_2[] = {
	{
		.img_offset = 0x01b4,
		.hash = PFM_V2_TWO_FW_DATA + 0x01b8,
		.hash_len = 48,
		.hash_type = HASH_TYPE_SHA384,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG2_REGION
	}
};

/**
 * Second firmware version components of the test v2 PFM with two firmware elements.
 */
static const struct pfm_v2_testing_data_fw_ver PFM_V2_FW_VER_TWO_FW_2[] = {
	{
		.fw_version = PFM_V2_TWO_FW_DATA + 0x0198,
		.fw_version_len = 0x0058,
		.version_str = PFM_V2_FW_VERSION2,
		.version_str_len = sizeof (PFM_V2_FW_VERSION2) - 1,
		.version_str_pad = PFM_V2_FW_VERSION2_PAD,
		.fw_version_offset = 0x0198,
		.fw_version_entry = 5,
		.fw_version_hash = 2,
		.version_addr = 0x112345,
		.rw_count = 1,
		.rw = PFM_V2_RW2,
		.img_count = 1,
		.img = PFM_V2_FW_IMG_TWO_FW_2
	}
};

/**
 * Firmware components of the test v2 PFM with two firmware elements.
 */
static const struct pfm_v2_testing_data_fw PFM_V2_FW_TWO_FW[] = {
	{
		.fw = PFM_V2_TWO_FW_DATA + 0x0124,
		.fw_len = 0x000c,
		.fw_id_str = PFM_V2_FIRMWARE_ID,
		.fw_id_str_len = sizeof (PFM_V2_FIRMWARE_ID) - 1,
		.fw_id_str_pad = PFM_V2_FIRMWARE_ID_PAD,
		.fw_offset = 0x0124,
		.fw_entry = 1,
		.fw_hash = 4,
		.version_count = 1,
		.version = PFM_V2_FW_VER_TWO_FW_1
	},
	{
		.fw = PFM_V2_TWO_FW_DATA + 0x0188,
		.fw_len = 0x0010,
		.fw_id_str = PFM_V2_FIRMWARE_ID2,
		.fw_id_str_len = sizeof (PFM_V2_FIRMWARE_ID2) - 1,
		.fw_id_str_pad = PFM_V2_FIRMWARE_ID2_PAD,
		.fw_offset = 0x0188,
		.fw_entry = 4,
		.fw_hash = 5,
		.version_count = 1,
		.version = PFM_V2_FW_VER_TWO_FW_2
	}
};

/**
 * Components of the test v2 PFM with two firmware elements.
 */
const struct pfm_v2_testing_data PFM_V2_TWO_FW = {
	.manifest = {
		.raw = PFM_V2_TWO_FW_DATA,
		.length = sizeof (PFM_V2_TWO_FW_DATA),
		.hash = PFM_V2_TWO_FW_HASH,
		.hash_len = sizeof (PFM_V2_TWO_FW_HASH),
		.id = 3,
		.signature = PFM_V2_TWO_FW_DATA + (sizeof (PFM_V2_TWO_FW_DATA) - 73),
		.sig_len = 73,
		.sig_offset = (sizeof (PFM_V2_TWO_FW_DATA) - 73),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = PFM_V2_TWO_FW_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x0114,
		.toc_hash = PFM_V2_TWO_FW_DATA + 0x0100,
		.toc_hash_len = 32,
		.toc_hash_offset = 0x0100,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 6,
		.toc_hashes = 6,
		.plat_id = PFM_V2_TWO_FW_DATA + 0x0178,
		.plat_id_len = 0x0010,
		.plat_id_str = PFM_V2_PLATFORM_ID2,
		.plat_id_str_len = sizeof (PFM_V2_PLATFORM_ID2) - 1,
		.plat_id_str_pad = PFM_V2_PLATFORM_ID2_PAD,
		.plat_id_offset = 0x0178,
		.plat_id_entry = 3,
		.plat_id_hash = 3
	},
	.flash_dev = PFM_V2_TWO_FW_DATA + 0x0120,
	.flash_dev_len = 4,
	.flash_dev_offset = 0x0120,
	.flash_dev_entry = 0,
	.flash_dev_hash = 0,
	.blank_byte = 0xff,
	.fw_count = 2,
	.fw = PFM_V2_FW_TWO_FW
};

/**
 * Test PFM in v2 format.  Contains one FW element and an ECC384 signature.  Hashes are SHA384.
 *
 * NUM_FW=1 HASH_TYPE=1 ./generate_pfm.sh 4 ../../core/testing/keys/ecc384priv.pem
 */
static const uint8_t PFM_V2_SHA384_DATA[] = {
	0xf1,0x01,0x6d,0x70,0x04,0x00,0x00,0x00,0x69,0x00,0x49,0x00,0x04,0x04,0x01,0x00,
	0x10,0xff,0x00,0x00,0x20,0x01,0x04,0x00,0x11,0xff,0x01,0x03,0x24,0x01,0x0c,0x00,
	0x12,0x11,0x01,0x01,0x30,0x01,0x48,0x00,0x00,0xff,0x01,0x02,0x78,0x01,0x10,0x00,
	0xd8,0x76,0xb3,0xd1,0x71,0x32,0x40,0x28,0x2e,0xb7,0xd4,0x75,0x24,0xe4,0x75,0x98,
	0x96,0x99,0xee,0x7e,0xa7,0x08,0xd9,0x44,0x60,0xac,0x9d,0xd0,0xae,0xc9,0x8d,0x7d,
	0x9e,0xe5,0xb3,0xab,0xae,0x83,0xb3,0xac,0x6d,0x7e,0x71,0xa2,0xc1,0x8a,0xf2,0xf7,
	0x17,0x6a,0xaf,0xd1,0x64,0xd0,0xa3,0xd9,0xfb,0xf4,0x8d,0x2b,0xd0,0x62,0x22,0x0e,
	0x41,0x66,0x55,0x64,0x60,0x78,0x08,0x20,0xab,0x5b,0x7e,0x4e,0x92,0x1b,0x8b,0xff,
	0x54,0x4a,0xf4,0x18,0xb0,0x69,0x78,0xcd,0x7d,0x17,0x03,0x5b,0xb8,0xa0,0xab,0xac,
	0x61,0x86,0xa8,0x3f,0x39,0xd1,0x5d,0x3a,0xd6,0x34,0xba,0x2d,0xe7,0xb1,0x33,0x78,
	0x53,0x41,0xde,0xf6,0x1e,0xdf,0x98,0xed,0x5e,0x08,0xa9,0xdd,0x64,0x06,0x83,0xa2,
	0x87,0xcb,0x1e,0x17,0x1c,0x11,0x38,0x62,0x64,0xc8,0x47,0xed,0x8c,0x25,0x22,0x86,
	0x08,0xe9,0xfd,0xb7,0xd2,0x2d,0xdd,0xe1,0x55,0x64,0x84,0x69,0xc0,0x31,0x37,0x00,
	0xa8,0x95,0x22,0x7c,0xa5,0xc5,0x02,0x2c,0xc0,0x4a,0xc6,0x69,0xaf,0x9d,0x0f,0xd7,
	0x51,0xdd,0x2c,0x34,0x5b,0xd7,0x5e,0x9c,0x1f,0x97,0x51,0x38,0xcb,0xbd,0xaf,0xe7,
	0xaa,0xe0,0x6b,0x74,0x46,0x47,0xe9,0xa0,0xc4,0xe5,0xb7,0x9e,0xa7,0xbe,0x88,0xad,
	0x83,0xca,0xb1,0x80,0xeb,0xd3,0xc2,0x5b,0x99,0x0a,0x09,0x27,0x0d,0x9b,0x6b,0xa6,
	0xe2,0xd6,0x60,0x3f,0x09,0x33,0xc6,0x40,0x42,0x3d,0x80,0xbe,0xb5,0x2a,0x9c,0xb5,
	0xff,0x01,0x00,0x00,0x01,0x08,0x00,0x00,0x46,0x69,0x72,0x6d,0x77,0x61,0x72,0x65,
	0x01,0x01,0x07,0x00,0x45,0x23,0x01,0x00,0x54,0x65,0x73,0x74,0x69,0x6e,0x67,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0xff,0xff,0xff,0x03,0x00,0x01,0x01,0x00,
	0x15,0x6e,0xda,0xdc,0x84,0x89,0x32,0x71,0x33,0x11,0x76,0x35,0x85,0x5c,0xce,0x44,
	0xe6,0x1f,0xfd,0x90,0x8f,0xb0,0x89,0xcc,0x9b,0x72,0x1e,0x9b,0x67,0x75,0xe0,0xf4,
	0x00,0x00,0x00,0x00,0xff,0xff,0xff,0x01,0x09,0x00,0x00,0x00,0x50,0x46,0x4d,0x20,
	0x54,0x65,0x73,0x74,0x31,0x00,0x00,0x00,0x30,0x66,0x02,0x31,0x00,0xaf,0x1f,0xd7,
	0xc9,0x3e,0x33,0x74,0x1d,0x34,0x48,0xe9,0x8c,0xd7,0xb4,0x3b,0x57,0xb8,0xb5,0x9a,
	0x83,0xe9,0xf4,0x40,0xc5,0x7f,0xc5,0xf2,0x5e,0xf0,0xb7,0x50,0xc4,0x27,0x60,0xc8,
	0xcf,0x40,0x81,0x87,0xac,0x85,0xb0,0xa5,0x42,0x63,0xcc,0x4c,0x25,0x02,0x31,0x00,
	0xa2,0x5b,0x71,0x52,0x7c,0xd4,0xe4,0x06,0x1f,0x73,0xbc,0x1b,0xfb,0x25,0x8d,0x67,
	0x8a,0x2a,0x9f,0x76,0xd7,0x8a,0xd9,0x3b,0xfb,0x25,0xbf,0xee,0x74,0xfa,0x4c,0x8b,
	0xeb,0x45,0x93,0x22,0xeb,0x29,0xf0,0x69,0x3f,0x1f,0x57,0x5f,0x0d,0xd3,0xab,0x6f,
	0x00
};

/**
 * PFM_V2_SHA384_DATA hash for testing.
 *
 * head -c -105 pfm.img | openssl dgst -sha384
 */
static const uint8_t PFM_V2_SHA384_HASH[] = {
	0x49,0x6b,0x47,0x2f,0x61,0xa4,0x29,0x80,0x48,0x7c,0x01,0xc4,0xc9,0xe0,0x69,0xde,
	0x91,0xe1,0x61,0xf7,0x13,0x77,0x1e,0xcf,0x13,0x0b,0x41,0xb4,0x50,0xed,0x6c,0x4b,
	0xe2,0x47,0xa8,0xe4,0xb5,0xa2,0xe3,0xae,0xe8,0xca,0x92,0xda,0xc6,0x44,0x29,0xd5
};

/**
 * Firmware image for the test v2 PFM with SHA384 hashes.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_SHA384[] = {
	{
		.img_offset = 0x014c,
		.hash = PFM_V2_SHA384_DATA + 0x0150,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG1_REGION
	}
};

/**
 * Firmware version components of the test v2 PFM with SHA384 hashes.
 */
static const struct pfm_v2_testing_data_fw_ver PFM_V2_FW_VER_SHA384[] = {
	{
		.fw_version = PFM_V2_SHA384_DATA + 0x0130,
		.fw_version_len = 0x0048,
		.version_str = PFM_V2_FW_VERSION,
		.version_str_len = sizeof (PFM_V2_FW_VERSION) - 1,
		.version_str_pad = PFM_V2_FW_VERSION_PAD,
		.fw_version_offset = 0x0130,
		.fw_version_entry = 2,
		.fw_version_hash = 1,
		.version_addr = 0x012345,
		.rw_count = 1,
		.rw = PFM_V2_RW1,
		.img_count = 1,
		.img = PFM_V2_FW_IMG_SHA384
	}
};

/**
 * Firmware components of the test v2 PFM with SHA384 hashes.
 */
static const struct pfm_v2_testing_data_fw PFM_V2_FW_SHA384[] = {
	{
		.fw = PFM_V2_SHA384_DATA + 0x0124,
		.fw_len = 0x000c,
		.fw_id_str = PFM_V2_FIRMWARE_ID,
		.fw_id_str_len = sizeof (PFM_V2_FIRMWARE_ID) - 1,
		.fw_id_str_pad = PFM_V2_FIRMWARE_ID_PAD,
		.fw_offset = 0x0124,
		.fw_entry = 1,
		.fw_hash = 3,
		.version_count = 1,
		.version = PFM_V2_FW_VER_SHA384
	}
};

/**
 * Components of the test v2 PFM with SHA384 hashes.
 */
const struct pfm_v2_testing_data PFM_V2_SHA384 = {
	.manifest = {
		.raw = PFM_V2_SHA384_DATA,
		.length = sizeof (PFM_V2_SHA384_DATA),
		.hash = PFM_V2_SHA384_HASH,
		.hash_len = sizeof (PFM_V2_SHA384_HASH),
		.id = 4,
		.signature = PFM_V2_SHA384_DATA + (sizeof (PFM_V2_SHA384_DATA) - 105),
		.sig_len = 105,
		.sig_offset = (sizeof (PFM_V2_SHA384_DATA) - 105),
		.sig_hash_type = HASH_TYPE_SHA384,
		.toc = PFM_V2_SHA384_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x0114,
		.toc_hash = PFM_V2_SHA384_DATA + 0x00f0,
		.toc_hash_len = 48,
		.toc_hash_offset = 0x00f0,
		.toc_hash_type = HASH_TYPE_SHA384,
		.toc_entries = 4,
		.toc_hashes = 4,
		.plat_id = PFM_V2_SHA384_DATA + 0x178,
		.plat_id_len = 0x0010,
		.plat_id_str = PFM_V2_PLATFORM_ID,
		.plat_id_str_len = sizeof (PFM_V2_PLATFORM_ID) - 1,
		.plat_id_str_pad = PFM_V2_PLATFORM_ID_PAD,
		.plat_id_offset = 0x0178,
		.plat_id_entry = 3,
		.plat_id_hash = 2
	},
	.flash_dev = PFM_V2_SHA384_DATA + 0x0120,
	.flash_dev_len = 4,
	.flash_dev_offset = 0x0120,
	.flash_dev_entry = 0,
	.flash_dev_hash = 0,
	.blank_byte = 0xff,
	.fw_count = 1,
	.fw = PFM_V2_FW_SHA384
};

/**
 * Test PFM in v2 format.  Contains two FW elements and an RSA4k signature.  The platform ID is in
 * between the two FW elements.  Hashes are SHA512.
 *
 * PLATFORM="PFM Test2" NUM_FW=2 HASH_TYPE=2 ./generate_pfm.sh 5 ../../core/testing/keys/rsa4kpriv.pem
 */
static const uint8_t PFM_V2_SHA512_DATA[] = {
	0xd0,0x04,0x6d,0x70,0x05,0x00,0x00,0x00,0x00,0x02,0x12,0x00,0x06,0x06,0x02,0x00,
	0x10,0xff,0x00,0x00,0x00,0x02,0x04,0x00,0x11,0xff,0x01,0x04,0x04,0x02,0x0c,0x00,
	0x12,0x11,0x01,0x01,0x10,0x02,0x48,0x00,0x00,0xff,0x01,0x03,0x58,0x02,0x10,0x00,
	0x11,0xff,0x01,0x05,0x68,0x02,0x10,0x00,0x12,0x11,0x01,0x02,0x78,0x02,0x58,0x00,
	0xdd,0x38,0xc8,0xd5,0x03,0xe1,0xe8,0x12,0x84,0x8f,0x88,0xe0,0x45,0x4e,0x2c,0x76,
	0x8b,0xb9,0x65,0x47,0x11,0x7c,0x33,0x59,0xc4,0x0c,0x1d,0x15,0xef,0xda,0x2d,0x50,
	0x16,0x8a,0x13,0x9b,0xff,0x97,0x62,0x19,0xd0,0xc3,0x59,0x76,0xa3,0xd4,0x6a,0x22,
	0x1a,0x23,0xba,0x7a,0x41,0x9a,0x88,0x3a,0xd8,0x84,0xd8,0x9b,0xc9,0x01,0xeb,0xc5,
	0xfd,0x28,0xc9,0x19,0xdd,0xc7,0x74,0x48,0x95,0x9d,0x3b,0x5a,0x5f,0x46,0x21,0xef,
	0x2a,0xf1,0x0d,0x56,0xb3,0xf9,0xb1,0x75,0x3a,0x27,0xf0,0xad,0x49,0x5d,0xeb,0xc6,
	0xe5,0x19,0x85,0x12,0xda,0x56,0x2c,0x68,0xbd,0x98,0x78,0x06,0x2d,0x49,0xd8,0x3e,
	0xea,0xa2,0x49,0xa2,0xc5,0xfb,0x01,0xfa,0x52,0xe7,0xa8,0xd9,0x63,0xf3,0x52,0x67,
	0x83,0xe6,0xb1,0xdc,0x8f,0x94,0xec,0x0e,0x0b,0x49,0xa2,0x3a,0xd3,0x4c,0x73,0x02,
	0x66,0xda,0xa5,0x1e,0x6b,0xe9,0x51,0xdc,0x2c,0xbe,0xae,0x78,0xdd,0xed,0x80,0xa4,
	0xc8,0x3c,0xae,0xfc,0x46,0x99,0xf7,0xe6,0x0a,0x20,0x29,0xda,0x03,0x49,0x39,0xa0,
	0xd7,0x2a,0xe6,0x42,0x87,0x8c,0xd5,0xb5,0x46,0x81,0xea,0xbf,0x3e,0xb4,0x18,0xf8,
	0x36,0xb5,0x31,0xdc,0xb8,0x0e,0xf3,0xfe,0x86,0x1f,0x40,0x42,0xa8,0xfa,0x2f,0xfb,
	0x7d,0x3c,0x15,0x6c,0xac,0x7d,0x56,0x55,0x23,0x58,0x3d,0x65,0x21,0x4f,0x61,0xca,
	0x3e,0xa8,0x36,0x96,0xa4,0x88,0xbe,0xbb,0x95,0x13,0x37,0xb7,0x11,0xb1,0xe6,0x2e,
	0x23,0x63,0x69,0xe3,0x02,0x43,0xd4,0xfa,0xd7,0x4c,0xaa,0xe3,0x24,0x5a,0xda,0x21,
	0x1a,0x2f,0x0c,0x17,0x5f,0x00,0xfc,0x88,0x26,0xdc,0xa7,0xc8,0x32,0x9e,0x14,0xf5,
	0xcc,0x3d,0xb2,0xb8,0x95,0xbd,0xbc,0xf2,0xca,0x27,0x92,0xc9,0x60,0xab,0x17,0x15,
	0xb9,0x80,0xb9,0x49,0x04,0x6d,0xb3,0x78,0xc1,0xc1,0xdb,0x76,0x29,0xf4,0xaa,0xd9,
	0x2d,0x52,0xef,0xdb,0x4a,0xd6,0x86,0xc1,0xee,0x41,0xcf,0x09,0x05,0x8d,0x29,0xac,
	0x28,0x42,0xe2,0x97,0x2d,0x1c,0xe5,0x2a,0x5a,0x93,0x00,0xd1,0xac,0x12,0x3c,0x90,
	0x60,0x57,0x95,0xa1,0x59,0x57,0x0a,0x1d,0x7c,0xf1,0x3b,0x19,0xf0,0x6c,0xb1,0x17,
	0xce,0x02,0xcd,0x07,0xf7,0xb4,0x40,0xcb,0x2c,0x6b,0x54,0x2a,0x46,0x02,0x78,0x80,
	0x97,0xca,0x9b,0xe1,0x59,0x99,0xef,0xdc,0x49,0xd4,0x3e,0xd6,0x2f,0xf3,0x29,0x7f,
	0x18,0x45,0x86,0xd4,0xab,0x3d,0x19,0x4e,0xe8,0x1f,0x65,0x41,0x6c,0xe2,0x66,0xca,
	0xea,0x42,0xe2,0x2a,0xb5,0xbf,0x9b,0x9d,0xc5,0x76,0xc6,0xbf,0xaf,0x13,0xc2,0x60,
	0x7d,0x73,0xaf,0xb5,0x9b,0xab,0xfa,0xa8,0x57,0xfe,0xee,0xb9,0xe0,0x35,0x26,0x6d,
	0x1a,0xc7,0x1f,0x19,0xdc,0x5a,0x6f,0x2e,0xba,0x7d,0xc7,0x9f,0xb0,0x64,0xba,0x1e,
	0xff,0x02,0x00,0x00,0x01,0x08,0x00,0x00,0x46,0x69,0x72,0x6d,0x77,0x61,0x72,0x65,
	0x01,0x01,0x07,0x00,0x45,0x23,0x01,0x00,0x54,0x65,0x73,0x74,0x69,0x6e,0x67,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0xff,0xff,0xff,0x03,0x00,0x01,0x01,0x00,
	0x79,0x09,0xe0,0x98,0x6e,0x0e,0x43,0x1e,0xf4,0x11,0x8b,0x8b,0xd8,0xeb,0x21,0xd1,
	0x08,0x15,0x45,0x34,0x71,0x19,0x24,0xdb,0xf4,0x38,0xfd,0xf8,0x59,0x76,0x24,0xa9,
	0x00,0x00,0x00,0x00,0xff,0xff,0xff,0x01,0x09,0x00,0x00,0x00,0x50,0x46,0x4d,0x20,
	0x54,0x65,0x73,0x74,0x32,0x00,0x00,0x00,0x01,0x09,0x00,0x00,0x46,0x69,0x72,0x6d,
	0x77,0x61,0x72,0x65,0x32,0x00,0x00,0x00,0x01,0x01,0x08,0x00,0x45,0x23,0x11,0x00,
	0x54,0x65,0x73,0x74,0x69,0x6e,0x67,0x32,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x06,
	0xff,0xff,0xff,0x07,0x01,0x01,0x01,0x00,0xb4,0xca,0x22,0x25,0x20,0xac,0xc1,0xae,
	0xcc,0x63,0x40,0x40,0xaa,0xc2,0x5f,0x4d,0x72,0x01,0x86,0x48,0x79,0xf4,0x7b,0x8b,
	0xc5,0xdf,0x2b,0xd4,0xbb,0xfd,0x75,0x95,0xa0,0x54,0x39,0x55,0x36,0x17,0xd2,0xd7,
	0xd8,0xec,0x08,0xe6,0x72,0x70,0x34,0x2b,0x00,0x00,0x00,0x04,0xff,0xff,0xff,0x05,
	0x82,0x67,0xd5,0x00,0x41,0x7f,0xf3,0x0a,0xd4,0x37,0x84,0x42,0x59,0x05,0x9b,0x4f,
	0x7e,0xcd,0x13,0x5e,0x8f,0x91,0xa0,0x57,0x42,0x02,0x8a,0x2f,0x96,0xbb,0xcf,0x01,
	0x82,0x89,0x5f,0x57,0xba,0x94,0x9a,0xcd,0x5f,0xb5,0xbf,0xa8,0xde,0x27,0x8b,0x27,
	0xae,0x95,0xb7,0xd1,0xe8,0x43,0x77,0x4d,0x55,0xde,0xd2,0xe3,0x0d,0x0c,0x51,0x40,
	0x21,0xa9,0x84,0xb7,0xdc,0xf5,0x94,0x30,0x5a,0x80,0x80,0xdb,0x63,0x64,0xca,0x42,
	0x23,0xe1,0x5b,0xd8,0x6b,0x0d,0x78,0x2f,0x97,0x7a,0x75,0x50,0x62,0x5f,0x39,0x89,
	0x59,0x60,0xcb,0x8d,0xf1,0xb7,0x26,0xfe,0x43,0xa6,0x94,0xd5,0xfd,0x2a,0x52,0x46,
	0xae,0x3d,0xb7,0x21,0xdf,0x41,0x09,0x2b,0xe1,0x05,0x0e,0x5a,0x07,0xe8,0x19,0x4b,
	0x30,0x73,0xdd,0x1b,0xa2,0x81,0xea,0x5c,0x5b,0x1d,0x86,0x8b,0x83,0x6b,0x31,0x3b,
	0xf3,0x93,0x09,0xf3,0x10,0x37,0x77,0x4e,0x70,0x2a,0x1e,0x9f,0xde,0x5e,0xb7,0xf7,
	0x6a,0x5d,0xd6,0xc3,0xe7,0xc0,0x6d,0x66,0x61,0xe2,0xa8,0x73,0xa7,0xaf,0xd2,0x7f,
	0xfb,0x64,0xef,0x3b,0xc0,0xcd,0xa9,0xbf,0xcf,0xfc,0x50,0xe8,0xe9,0x0e,0xee,0x70,
	0xe0,0xcf,0x18,0x1b,0x6d,0xfd,0x8f,0x0e,0xc7,0xff,0x0e,0xeb,0xa6,0x65,0x28,0xfd,
	0xdc,0xb0,0xfd,0xde,0x24,0x0a,0x49,0x47,0x78,0xf2,0x8b,0xd9,0xd9,0x27,0xd8,0x9c,
	0xff,0x6c,0x93,0xe2,0xfb,0x5e,0x4a,0x10,0xd3,0x5f,0x4f,0x42,0x66,0xc9,0x92,0x61,
	0xd3,0xbe,0xad,0xd0,0x92,0x7d,0xac,0x09,0xa5,0xe1,0x0b,0x2f,0x1b,0x4a,0x24,0x4a,
	0x8c,0x12,0xde,0xb2,0xc1,0xa3,0xf0,0x6a,0xf5,0x87,0x76,0x8a,0x16,0x46,0x48,0x34,
	0x1d,0x09,0x0a,0x0e,0x40,0xb6,0xe1,0xc5,0xcf,0xaf,0x5d,0x31,0xa9,0xf5,0x82,0x17,
	0xbb,0x19,0xce,0xd1,0xf1,0x76,0xab,0x86,0x12,0xfe,0x8c,0x1a,0x0a,0x3f,0xab,0xf7,
	0x94,0x88,0x0e,0x30,0x33,0x8c,0xa4,0x2a,0xec,0xe0,0xb6,0xd1,0xa8,0xb5,0x75,0x39,
	0xc8,0x69,0x3f,0xea,0x15,0x0e,0xa4,0x00,0x47,0xd8,0x34,0xdf,0xd0,0x9b,0xdb,0x81,
	0xaf,0x65,0x75,0x8b,0xff,0x3b,0x1c,0x86,0xc5,0xa8,0x81,0x5f,0x7f,0xa7,0x39,0xfa,
	0x5a,0x47,0x41,0x7e,0xa1,0x44,0xf0,0x35,0x6a,0xa2,0x50,0x54,0x51,0xe2,0xc1,0xc3,
	0x5f,0x83,0x35,0x5d,0xc2,0x26,0x75,0xbc,0x7e,0x72,0x12,0x07,0x91,0xf5,0x93,0x7c,
	0xf1,0x80,0xcf,0xd6,0x5b,0x09,0x82,0x78,0x2e,0x70,0xed,0x8d,0xc0,0x49,0xbb,0x0a,
	0x26,0x74,0x8f,0x43,0x1c,0xb8,0xfc,0x44,0xb1,0xe9,0x7c,0x6d,0x0c,0x82,0x7d,0x77,
	0xbc,0x5f,0x1f,0xc7,0x33,0x00,0x10,0x13,0x10,0x87,0x3d,0xca,0x81,0xc2,0x7d,0x2f,
	0x70,0x94,0x98,0xef,0x60,0x76,0x40,0x01,0x13,0x2e,0x6b,0x2e,0x54,0x0b,0x20,0x46,
	0x93,0x37,0x7a,0x3d,0x84,0x24,0xb9,0xe9,0x91,0xf1,0x62,0x6b,0x70,0xf6,0x34,0xd6,
	0xfd,0xcb,0x9a,0x04,0x83,0xee,0x15,0x0d,0xf4,0xb9,0x1a,0x12,0x44,0xac,0x10,0x32,
	0xa8,0xef,0x97,0x02,0x40,0xb2,0x6f,0xc6,0x04,0x94,0x34,0x57,0xc4,0x99,0xae,0xfc,
	0x20,0xf4,0x49,0xd5,0xbd,0x66,0x92,0xe4,0x63,0x90,0xc0,0xbc,0x33,0x70,0x1b,0xae
};

/**
 * PFM_V2_SHA512_DATA hash for testing.
 *
 * head -c -512 pfm.img | openssl dgst -sha512
 */
static const uint8_t PFM_V2_SHA512_HASH[] = {
	0x79,0x5c,0xb8,0x63,0xc1,0x38,0x06,0x74,0x9f,0x15,0xb0,0x65,0xcb,0x88,0x92,0x56,
	0x13,0xcb,0x31,0x03,0x30,0x6f,0x9e,0xb5,0xf2,0x23,0xa4,0x4d,0x18,0x83,0x40,0xa0,
	0xbd,0x4b,0x88,0x6b,0xdb,0x65,0x4e,0x38,0xd3,0x43,0xdc,0xe1,0x3f,0xfe,0x6f,0xd0,
	0xe7,0x0d,0xb2,0x8b,0x4e,0x6f,0x04,0xce,0x8a,0x06,0x7d,0x77,0x49,0x39,0x21,0xa0
};

/**
 * First firmware image for the test v2 PFM with two firmware elements and SHA512 hashes.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_SHA512_1[] = {
	{
		.img_offset = 0x022c,
		.hash = PFM_V2_SHA512_DATA + 0x0230,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG1_REGION
	}
};

/**
 * First firmware version component of the test v2 PFM with two firmware elements and SHA512 hashes.
 */
static const struct pfm_v2_testing_data_fw_ver PFM_V2_FW_VER_SHA512_1[] = {
	{
		.fw_version = PFM_V2_SHA512_DATA + 0x0210,
		.fw_version_len = 0x0048,
		.version_str = PFM_V2_FW_VERSION,
		.version_str_len = sizeof (PFM_V2_FW_VERSION) - 1,
		.version_str_pad = PFM_V2_FW_VERSION_PAD,
		.fw_version_offset = 0x0210,
		.fw_version_entry = 2,
		.fw_version_hash = 1,
		.version_addr = 0x012345,
		.rw_count = 1,
		.rw = PFM_V2_RW1,
		.img_count = 1,
		.img = PFM_V2_FW_IMG_SHA512_1
	}
};

/**
 * Second firmware image for the test v2 PFM with two firmware elements and SHA512 hashes.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_SHA512_2[] = {
	{
		.img_offset = 0x0294,
		.hash = PFM_V2_SHA512_DATA + 0x0298,
		.hash_len = 48,
		.hash_type = HASH_TYPE_SHA384,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG2_REGION
	}
};

/**
 * Second Firmware version component of the test v2 PFM with two firmware elements and SHA512
 * hashes.
 */
static const struct pfm_v2_testing_data_fw_ver PFM_V2_FW_VER_SHA512_2[] = {
	{
		.fw_version = PFM_V2_SHA512_DATA + 0x0278,
		.fw_version_len = 0x0058,
		.version_str = PFM_V2_FW_VERSION2,
		.version_str_len = sizeof (PFM_V2_FW_VERSION2) - 1,
		.version_str_pad = PFM_V2_FW_VERSION2_PAD,
		.fw_version_offset = 0x0278,
		.fw_version_entry = 5,
		.fw_version_hash = 2,
		.version_addr = 0x112345,
		.rw_count = 1,
		.rw = PFM_V2_RW2,
		.img_count = 1,
		.img = PFM_V2_FW_IMG_SHA512_2
	}
};

/**
 * Firmware components of the test v2 PFM with two firmware elements and SHA512 hashes.
 */
static const struct pfm_v2_testing_data_fw PFM_V2_FW_SHA512[] = {
	{
		.fw = PFM_V2_SHA512_DATA + 0x0204,
		.fw_len = 0x000c,
		.fw_id_str = PFM_V2_FIRMWARE_ID,
		.fw_id_str_len = sizeof (PFM_V2_FIRMWARE_ID) - 1,
		.fw_id_str_pad = PFM_V2_FIRMWARE_ID_PAD,
		.fw_offset = 0x0204,
		.fw_entry = 1,
		.fw_hash = 4,
		.version_count = 1,
		.version = PFM_V2_FW_VER_SHA512_1
	},
	{
		.fw = PFM_V2_SHA512_DATA + 0x0268,
		.fw_len = 0x0010,
		.fw_id_str = PFM_V2_FIRMWARE_ID2,
		.fw_id_str_len = sizeof (PFM_V2_FIRMWARE_ID2) - 1,
		.fw_id_str_pad = PFM_V2_FIRMWARE_ID2_PAD,
		.fw_offset = 0x0268,
		.fw_entry = 4,
		.fw_hash = 5,
		.version_count = 1,
		.version = PFM_V2_FW_VER_SHA512_2
	}
};

/**
 * Components of the test v2 PFM with two firmware elements and SHA512 hashes.
 */
const struct pfm_v2_testing_data PFM_V2_SHA512 = {
	.manifest = {
		.raw = PFM_V2_SHA512_DATA,
		.length = sizeof (PFM_V2_SHA512_DATA),
		.hash = PFM_V2_SHA512_HASH,
		.hash_len = sizeof (PFM_V2_SHA512_HASH),
		.id = 5,
		.signature = PFM_V2_SHA512_DATA + (sizeof (PFM_V2_SHA512_DATA) - 512),
		.sig_len = 512,
		.sig_offset = (sizeof (PFM_V2_SHA512_DATA) - 512),
		.sig_hash_type = HASH_TYPE_SHA512,
		.toc = PFM_V2_SHA512_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x01f4,
		.toc_hash = PFM_V2_SHA512_DATA + 0x01c0,
		.toc_hash_len = 64,
		.toc_hash_offset = 0x01c0,
		.toc_hash_type = HASH_TYPE_SHA512,
		.toc_entries = 6,
		.toc_hashes = 6,
		.plat_id = PFM_V2_SHA512_DATA + 0x0258,
		.plat_id_len = 0x0010,
		.plat_id_str = PFM_V2_PLATFORM_ID2,
		.plat_id_str_len = sizeof (PFM_V2_PLATFORM_ID2) - 1,
		.plat_id_str_pad = PFM_V2_PLATFORM_ID2_PAD,
		.plat_id_offset = 0x0258,
		.plat_id_entry = 3,
		.plat_id_hash = 3
	},
	.flash_dev = PFM_V2_SHA512_DATA + 0x0200,
	.flash_dev_len = 4,
	.flash_dev_offset = 0x0200,
	.flash_dev_entry = 0,
	.flash_dev_hash = 0,
	.blank_byte = 0xff,
	.fw_count = 2,
	.fw = PFM_V2_FW_SHA512
};

/**
 * Test PFM in v2 format.  Contains one FW element and an ECC521 signature using SHA512.  TOC
 * hashes are SHA256.
 *
 * NUM_FW=1 HASH_TYPE=2 TOC_HASH_TYPE=0 ./generate_pfm.sh 6 ../../core/testing/keys/ecc521priv.pem
 */
static const uint8_t PFM_V2_DIFF_HASH_TYPE_DATA[] = {
	0xc3,0x01,0x6d,0x70,0x06,0x00,0x00,0x00,0x8b,0x00,0x52,0x00,0x04,0x04,0x00,0x00,
	0x10,0xff,0x00,0x00,0xd0,0x00,0x04,0x00,0x11,0xff,0x01,0x03,0xd4,0x00,0x0c,0x00,
	0x12,0x11,0x01,0x01,0xe0,0x00,0x48,0x00,0x00,0xff,0x01,0x02,0x28,0x01,0x10,0x00,
	0xa8,0xd9,0xe5,0x71,0xa3,0xf6,0xf7,0x9d,0xa5,0xff,0xf4,0xbd,0xa2,0x79,0x26,0xa1,
	0x87,0x00,0x31,0x36,0x9e,0xc1,0x37,0xd6,0x58,0x73,0x05,0xc8,0xef,0xec,0x80,0xd2,
	0xd0,0xa8,0x36,0xc7,0x1e,0x5e,0xf8,0x20,0x01,0xa0,0x69,0x8d,0xab,0xc7,0xf4,0xde,
	0x51,0xdf,0xa3,0xeb,0x52,0xa2,0x8d,0xd2,0xcc,0x4e,0x03,0x06,0x8c,0x53,0xce,0xcb,
	0xd3,0xb6,0xeb,0x9b,0xe0,0x85,0xcd,0xd3,0xd6,0x05,0x81,0xc8,0x0b,0x38,0x6d,0x9a,
	0xf8,0x5b,0xae,0x5f,0xed,0x50,0x36,0x38,0x55,0x0c,0xf8,0xe8,0xdb,0xd8,0x82,0x46,
	0x13,0x48,0x15,0xa0,0xd1,0xfb,0x58,0x01,0xae,0x7a,0xa2,0x15,0xb4,0xf1,0x98,0x57,
	0xda,0x88,0x4d,0x95,0x99,0x18,0x27,0x0f,0x98,0x11,0xfe,0xe5,0xd4,0x0e,0x5b,0x6c,
	0xbe,0x78,0x82,0x37,0x1d,0x7e,0xcd,0x84,0xa6,0x21,0xb9,0xb6,0x15,0x10,0xa4,0xa0,
	0xbe,0xa5,0xc0,0xb5,0xb4,0x91,0x61,0x7b,0x17,0x4d,0x76,0xc9,0xdc,0xdd,0x8c,0x02,
	0xff,0x01,0x00,0x00,0x01,0x08,0x00,0x00,0x46,0x69,0x72,0x6d,0x77,0x61,0x72,0x65,
	0x01,0x01,0x07,0x00,0x45,0x23,0x01,0x00,0x54,0x65,0x73,0x74,0x69,0x6e,0x67,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0xff,0xff,0xff,0x03,0x00,0x01,0x01,0x00,
	0x46,0x25,0x27,0x8d,0x1f,0x76,0xf7,0x58,0x27,0x2a,0x34,0xba,0x03,0x6b,0xde,0x08,
	0xa0,0x58,0x64,0x4d,0x2e,0xba,0xaf,0xb1,0x1f,0xb3,0x28,0xe7,0xb4,0xb3,0x34,0x55,
	0x00,0x00,0x00,0x00,0xff,0xff,0xff,0x01,0x09,0x00,0x00,0x00,0x50,0x46,0x4d,0x20,
	0x54,0x65,0x73,0x74,0x31,0x00,0x00,0x00,0x30,0x81,0x88,0x02,0x42,0x01,0xc8,0xf0,
	0x24,0xbd,0xae,0xd4,0x80,0x68,0xf0,0xd6,0xf5,0x31,0xc4,0xd1,0xce,0x26,0x16,0xfa,
	0x80,0xd6,0x5e,0xca,0x34,0xb8,0xf9,0xb3,0x5e,0x45,0xf2,0x83,0x9c,0xde,0x26,0x61,
	0x87,0x5a,0xa1,0x12,0x96,0xd2,0xc9,0x22,0xb8,0x40,0xe7,0x3f,0x7b,0x5a,0x58,0xd6,
	0x2b,0xf3,0x94,0xa0,0xfd,0x1d,0x32,0xa7,0xde,0xff,0x49,0x54,0x05,0xb8,0x89,0x02,
	0x42,0x01,0x94,0x22,0x32,0xe8,0xb2,0x5a,0x5f,0xca,0xbd,0x8f,0xe7,0x56,0x6b,0xf4,
	0xf6,0x08,0x16,0x78,0xe6,0xd4,0xb9,0xfc,0x4c,0xae,0x09,0x1b,0x62,0x99,0x5b,0xca,
	0x9c,0x68,0xde,0x66,0x6a,0x3e,0x6b,0x7b,0x86,0x66,0x70,0xa0,0xec,0x00,0x40,0x96,
	0xb2,0xc1,0xd5,0x01,0x7e,0x84,0x94,0xb5,0x54,0xbb,0xd6,0xa0,0x91,0x99,0x85,0xf2,
	0xb4,0x9f,0xbd
};

/**
 * PFM_V2_DIFF_HASH_TYPE_DATA hash for testing.
 *
 * head -c -139 pfm.img | openssl dgst -sha512
 */
static const uint8_t PFM_V2_DIFF_HASH_TYPE_HASH[] = {
	0x6c,0xa4,0x5c,0x83,0xa5,0xea,0x94,0xa5,0x8a,0xaf,0x84,0x10,0x35,0xa4,0x4b,0xb7,
	0xab,0xc7,0x66,0xc1,0xe6,0xe0,0xd2,0xa9,0xd3,0x0c,0x26,0xff,0xb7,0x23,0xf9,0xdd,
	0x1d,0x78,0xc1,0xcd,0x54,0xbc,0x4d,0x53,0x91,0x73,0xb7,0x8d,0x17,0x27,0xf5,0xde,
	0x29,0x21,0x97,0x2c,0x42,0x2b,0x0b,0xaa,0x48,0x60,0x39,0x15,0xbd,0x5f,0xbf,0x2a
};

/**
 * Firmware image for the test v2 PFM with different hash algorithms between the signature and TOC.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_DIFF_HASH_TYPE[] = {
	{
		.img_offset = 0x00fc,
		.hash = PFM_V2_DIFF_HASH_TYPE_DATA + 0x0100,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG1_REGION
	}
};

/**
 * Firmware version components of the test v2 PFM with different hash algorithms between the
 * signature and TOC.
 */
static const struct pfm_v2_testing_data_fw_ver PFM_V2_FW_VER_DIFF_HASH_TYPE[] = {
	{
		.fw_version = PFM_V2_DIFF_HASH_TYPE_DATA + 0x00e0,
		.fw_version_len = 0x0048,
		.version_str = PFM_V2_FW_VERSION,
		.version_str_len = sizeof (PFM_V2_FW_VERSION) - 1,
		.version_str_pad = PFM_V2_FW_VERSION_PAD,
		.fw_version_offset = 0x00e0,
		.fw_version_entry = 2,
		.fw_version_hash = 1,
		.version_addr = 0x012345,
		.rw_count = 1,
		.rw = PFM_V2_RW1,
		.img_count = 1,
		.img = PFM_V2_FW_IMG_DIFF_HASH_TYPE
	}
};

/**
 * Firmware components of the test v2 PFM with different hash algorithms between the signature and
 * TOC.
 */
static const struct pfm_v2_testing_data_fw PFM_V2_FW_DIFF_HASH_TYPE[] = {
	{
		.fw = PFM_V2_DIFF_HASH_TYPE_DATA + 0x00d4,
		.fw_len = 0x000c,
		.fw_id_str = PFM_V2_FIRMWARE_ID,
		.fw_id_str_len = sizeof (PFM_V2_FIRMWARE_ID) - 1,
		.fw_id_str_pad = PFM_V2_FIRMWARE_ID_PAD,
		.fw_offset = 0x00d4,
		.fw_entry = 1,
		.fw_hash = 3,
		.version_count = 1,
		.version = PFM_V2_FW_VER_DIFF_HASH_TYPE
	}
};

/**
 * Components of the test v2 PFM with different hash algorithms between the signature and TOC.
 */
const struct pfm_v2_testing_data PFM_V2_DIFF_HASH_TYPE = {
	.manifest = {
		.raw = PFM_V2_DIFF_HASH_TYPE_DATA,
		.length = sizeof (PFM_V2_DIFF_HASH_TYPE_DATA),
		.hash = PFM_V2_DIFF_HASH_TYPE_HASH,
		.hash_len = sizeof (PFM_V2_DIFF_HASH_TYPE_HASH),
		.id = 6,
		.signature = PFM_V2_DIFF_HASH_TYPE_DATA + (sizeof (PFM_V2_DIFF_HASH_TYPE_DATA) - 139),
		.sig_len = 139,
		.sig_offset = (sizeof (PFM_V2_DIFF_HASH_TYPE_DATA) - 139),
		.sig_hash_type = HASH_TYPE_SHA512,
		.toc = PFM_V2_DIFF_HASH_TYPE_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x00c4,
		.toc_hash = PFM_V2_DIFF_HASH_TYPE_DATA + 0x00b0,
		.toc_hash_len = 32,
		.toc_hash_offset = 0x00b0,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 4,
		.toc_hashes = 4,
		.plat_id = PFM_V2_DIFF_HASH_TYPE_DATA + 0x128,
		.plat_id_len = 0x0010,
		.plat_id_str = PFM_V2_PLATFORM_ID,
		.plat_id_str_len = sizeof (PFM_V2_PLATFORM_ID) - 1,
		.plat_id_str_pad = PFM_V2_PLATFORM_ID_PAD,
		.plat_id_offset = 0x0128,
		.plat_id_entry = 3,
		.plat_id_hash = 2
	},
	.flash_dev = PFM_V2_DIFF_HASH_TYPE_DATA + 0x00d0,
	.flash_dev_len = 4,
	.flash_dev_offset = 0x00d0,
	.flash_dev_entry = 0,
	.flash_dev_hash = 0,
	.blank_byte = 0xff,
	.fw_count = 1,
	.fw = PFM_V2_FW_DIFF_HASH_TYPE
};

/**
 * Test PFM in v2 format.  Contains two FW elements and an ECC256 signature using SHA256.  TOC
 * hash is SHA512 but contains no element hashes.
 *
 * NUM_FW=2 TOC_HASH_TYPE=2 SKIP_HASHES=1 ./generate_pfm.sh 7 ../../core/testing/keys/eccpriv.pem
 */
static const uint8_t PFM_V2_NO_TOC_HASHES_DATA[] = {
	0x99,0x01,0x6d,0x70,0x07,0x00,0x00,0x00,0x49,0x00,0x40,0x00,0x06,0x00,0x02,0x00,
	0x10,0xff,0x00,0xff,0x80,0x00,0x04,0x00,0x11,0xff,0x01,0xff,0x84,0x00,0x0c,0x00,
	0x12,0x11,0x01,0xff,0x90,0x00,0x48,0x00,0x00,0xff,0x01,0xff,0xd8,0x00,0x10,0x00,
	0x11,0xff,0x01,0xff,0xe8,0x00,0x10,0x00,0x12,0x11,0x01,0xff,0xf8,0x00,0x58,0x00,
	0xb4,0x77,0xe3,0xb2,0x35,0x96,0xbf,0xfc,0x9a,0xfb,0x4d,0x92,0x4e,0x93,0x35,0xc9,
	0xed,0x42,0x5c,0x06,0x80,0x1d,0x7c,0x2e,0x50,0x2c,0x82,0x02,0x1d,0xff,0x7a,0xd3,
	0xd0,0x69,0x24,0x04,0xec,0x1d,0xda,0x85,0x69,0xab,0x3b,0x6b,0x60,0x4b,0x92,0xa3,
	0x10,0xea,0x27,0x2a,0xc6,0x7d,0xb5,0x45,0xbb,0x88,0xca,0x93,0xc6,0x25,0x71,0x6f,
	0xff,0x02,0x00,0x00,0x01,0x08,0x00,0x00,0x46,0x69,0x72,0x6d,0x77,0x61,0x72,0x65,
	0x01,0x01,0x07,0x00,0x45,0x23,0x01,0x00,0x54,0x65,0x73,0x74,0x69,0x6e,0x67,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0xff,0xff,0xff,0x03,0x00,0x01,0x01,0x00,
	0x17,0x90,0x49,0x1b,0xf9,0xb5,0x9e,0x66,0x9c,0xe2,0x27,0xc8,0x3b,0x2a,0x6e,0x1b,
	0xb9,0xdb,0x0b,0x45,0x80,0x6e,0x13,0x22,0x99,0x77,0x69,0x43,0x4a,0x3d,0x7b,0xe1,
	0x00,0x00,0x00,0x00,0xff,0xff,0xff,0x01,0x09,0x00,0x00,0x00,0x50,0x46,0x4d,0x20,
	0x54,0x65,0x73,0x74,0x31,0x00,0x00,0x00,0x01,0x09,0x00,0x00,0x46,0x69,0x72,0x6d,
	0x77,0x61,0x72,0x65,0x32,0x00,0x00,0x00,0x01,0x01,0x08,0x00,0x45,0x23,0x11,0x00,
	0x54,0x65,0x73,0x74,0x69,0x6e,0x67,0x32,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x06,
	0xff,0xff,0xff,0x07,0x01,0x01,0x01,0x00,0xbd,0xde,0xd5,0x00,0xbf,0x0e,0xc0,0x1e,
	0xbf,0x8d,0xa0,0xc8,0xa0,0xe3,0x10,0xa4,0xc7,0x19,0x3b,0xf9,0x78,0xf3,0x9a,0xa3,
	0xb8,0xdb,0xdb,0x42,0xf4,0x2a,0x0c,0x3b,0x01,0x06,0xb2,0x18,0x25,0x36,0x1b,0x5c,
	0xfe,0xa5,0x00,0xe8,0x50,0xb8,0xaa,0x0a,0x00,0x00,0x00,0x04,0xff,0xff,0xff,0x05,
	0x30,0x46,0x02,0x21,0x00,0xe7,0x14,0x67,0x2a,0xc6,0xa7,0x10,0x97,0xa2,0x12,0xdd,
	0xb5,0x34,0xad,0xf1,0x1c,0x21,0x1c,0x68,0xf3,0x3e,0xea,0xb5,0x20,0x62,0x7e,0xc6,
	0x68,0x63,0xc9,0xb5,0xa7,0x02,0x21,0x00,0xac,0xc5,0x6e,0xa3,0x58,0x8c,0x09,0x50,
	0x28,0x5d,0x2a,0x23,0x21,0xdf,0xf3,0x43,0xf1,0x02,0x2c,0xf8,0x45,0x55,0x7b,0x16,
	0x3c,0x0a,0x98,0x83,0x30,0x2d,0x84,0xdb,0x00
};

/**
 * PFM_V2_NO_TOC_HASHES_DATA hash for testing.
 *
 * head -c -73 pfm.img | openssl dgst -sha256
 */
static const uint8_t PFM_V2_NO_TOC_HASHES_HASH[] = {
	0x0f,0x7f,0xbb,0x63,0x21,0xb0,0xd2,0x18,0x79,0x3a,0x29,0xe0,0xca,0x1c,0xe1,0xfc,
	0x3e,0xe3,0x61,0xc0,0x1b,0x4e,0x73,0x1f,0xbd,0x27,0xad,0x6e,0x9c,0x4c,0xb6,0x17
};

/**
 * First firmware image for the test v2 PFM with no TOC element hashes.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_NO_TOC_HASHES_1[] = {
	{
		.img_offset = 0x00ac,
		.hash = PFM_V2_NO_TOC_HASHES_DATA + 0x00b0,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG1_REGION
	}
};

/**
 * First firmware version component of the test v2 PFM with no TOC element hashes.
 */
static const struct pfm_v2_testing_data_fw_ver PFM_V2_FW_VER_NO_TOC_HASHES_1[] = {
	{
		.fw_version = PFM_V2_NO_TOC_HASHES_DATA + 0x0090,
		.fw_version_len = 0x0048,
		.version_str = PFM_V2_FW_VERSION,
		.version_str_len = sizeof (PFM_V2_FW_VERSION) - 1,
		.version_str_pad = PFM_V2_FW_VERSION_PAD,
		.fw_version_offset = 0x0090,
		.fw_version_entry = 2,
		.fw_version_hash = -1,
		.version_addr = 0x012345,
		.rw_count = 1,
		.rw = PFM_V2_RW1,
		.img_count = 1,
		.img = PFM_V2_FW_IMG_NO_TOC_HASHES_1
	}
};

/**
 * Second firmware image for the test v2 PFM with no TOC element hashes.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_NO_TOC_HASHES_2[] = {
	{
		.img_offset = 0x0114,
		.hash = PFM_V2_NO_TOC_HASHES_DATA + 0x0118,
		.hash_len = 48,
		.hash_type = HASH_TYPE_SHA384,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG2_REGION
	}
};

/**
 * Second Firmware version component of the test v2 PFM with no TOC element hashes.
 */
static const struct pfm_v2_testing_data_fw_ver PFM_V2_FW_VER_NO_TOC_HASHES_2[] = {
	{
		.fw_version = PFM_V2_NO_TOC_HASHES_DATA + 0x00f8,
		.fw_version_len = 0x0058,
		.version_str = PFM_V2_FW_VERSION2,
		.version_str_len = sizeof (PFM_V2_FW_VERSION2) - 1,
		.version_str_pad = PFM_V2_FW_VERSION2_PAD,
		.fw_version_offset = 0x00f8,
		.fw_version_entry = 5,
		.fw_version_hash = -1,
		.version_addr = 0x112345,
		.rw_count = 1,
		.rw = PFM_V2_RW2,
		.img_count = 1,
		.img = PFM_V2_FW_IMG_NO_TOC_HASHES_2
	}
};

/**
 * Firmware components of the test v2 PFM with no TOC element hashes.
 */
static const struct pfm_v2_testing_data_fw PFM_V2_FW_NO_TOC_HASHES[] = {
	{
		.fw = PFM_V2_NO_TOC_HASHES_DATA + 0x0084,
		.fw_len = 0x000c,
		.fw_id_str = PFM_V2_FIRMWARE_ID,
		.fw_id_str_len = sizeof (PFM_V2_FIRMWARE_ID) - 1,
		.fw_id_str_pad = PFM_V2_FIRMWARE_ID_PAD,
		.fw_offset = 0x0084,
		.fw_entry = 1,
		.fw_hash = -1,
		.version_count = 1,
		.version = PFM_V2_FW_VER_NO_TOC_HASHES_1
	},
	{
		.fw = PFM_V2_NO_TOC_HASHES_DATA + 0x00e8,
		.fw_len = 0x0010,
		.fw_id_str = PFM_V2_FIRMWARE_ID2,
		.fw_id_str_len = sizeof (PFM_V2_FIRMWARE_ID2) - 1,
		.fw_id_str_pad = PFM_V2_FIRMWARE_ID2_PAD,
		.fw_offset = 0x00e8,
		.fw_entry = 4,
		.fw_hash = -1,
		.version_count = 1,
		.version = PFM_V2_FW_VER_NO_TOC_HASHES_2
	}
};

/**
 * Components of the test v2 PFM with no TOC element hashes.
 */
const struct pfm_v2_testing_data PFM_V2_NO_TOC_HASHES = {
	.manifest = {
		.raw = PFM_V2_NO_TOC_HASHES_DATA,
		.length = sizeof (PFM_V2_NO_TOC_HASHES_DATA),
		.hash = PFM_V2_NO_TOC_HASHES_HASH,
		.hash_len = sizeof (PFM_V2_NO_TOC_HASHES_HASH),
		.id = 7,
		.signature = PFM_V2_NO_TOC_HASHES_DATA + (sizeof (PFM_V2_NO_TOC_HASHES_DATA) - 73),
		.sig_len = 73,
		.sig_offset = (sizeof (PFM_V2_NO_TOC_HASHES_DATA) - 73),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = PFM_V2_NO_TOC_HASHES_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x0074,
		.toc_hash = PFM_V2_NO_TOC_HASHES_DATA + 0x0040,
		.toc_hash_len = 64,
		.toc_hash_offset = 0x0040,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 6,
		.toc_hashes = 0,
		.plat_id = PFM_V2_NO_TOC_HASHES_DATA + 0x00d8,
		.plat_id_len = 0x0010,
		.plat_id_str = PFM_V2_PLATFORM_ID,
		.plat_id_str_len = sizeof (PFM_V2_PLATFORM_ID) - 1,
		.plat_id_str_pad = PFM_V2_PLATFORM_ID_PAD,
		.plat_id_offset = 0x00d8,
		.plat_id_entry = 3,
		.plat_id_hash = -1
	},
	.flash_dev = PFM_V2_NO_TOC_HASHES_DATA + 0x0080,
	.flash_dev_len = 4,
	.flash_dev_offset = 0x0080,
	.flash_dev_entry = 0,
	.flash_dev_hash = -1,
	.blank_byte = 0xff,
	.fw_count = 1,
	.fw = PFM_V2_FW_NO_TOC_HASHES
};

/**
 * Test PFM in v2 format.  Contains two FW elements and an ECC256 signature using SHA256.  Firmware
 * elements do not have hash entries.  The hash IDs are invalid, but not 0xff.
 *
 * PLATFORM="PFM Test2" NUM_FW=2 SKIP_FW_HASH=1 ./generate_pfm.sh 8 ../../core/testing/keys/eccpriv.pem
 */
static const uint8_t PFM_V2_NO_FW_HASHES_DATA[] = {
	0xf9,0x01,0x6d,0x70,0x08,0x00,0x00,0x00,0x49,0x00,0x40,0x00,0x06,0x04,0x00,0x00,
	0x10,0xff,0x00,0x00,0xe0,0x00,0x04,0x00,0x11,0xff,0x01,0x04,0xe4,0x00,0x0c,0x00,
	0x12,0x11,0x01,0x01,0xf0,0x00,0x48,0x00,0x00,0xff,0x01,0x03,0x38,0x01,0x10,0x00,
	0x11,0xff,0x01,0x05,0x48,0x01,0x10,0x00,0x12,0x11,0x01,0x02,0x58,0x01,0x58,0x00,
	0x9c,0x36,0x29,0xb0,0xe1,0xf5,0x54,0xa3,0x41,0xcf,0x0b,0xf0,0x7f,0xb0,0xcb,0x57,
	0x36,0xa7,0x3b,0xce,0x8c,0x4c,0xb4,0x52,0xea,0x0a,0x31,0xd9,0x9f,0xc5,0x02,0x83,
	0xf7,0xc4,0xd5,0xfe,0x56,0x43,0x7c,0x22,0x09,0xd9,0xe2,0x19,0x18,0x59,0xab,0x34,
	0x0c,0xb5,0x91,0x3c,0xf2,0xec,0xba,0x15,0x64,0x9b,0xd4,0x4a,0xc6,0xc4,0x83,0x42,
	0xdd,0x1e,0x01,0x01,0x06,0x62,0x78,0x10,0x3d,0x90,0x96,0x0f,0x5b,0x49,0xe8,0xb6,
	0x06,0x66,0x5a,0x93,0xf7,0x66,0xa1,0xfe,0x17,0xdc,0x5c,0x0a,0xb6,0xae,0x1d,0xe6,
	0x67,0x98,0x4a,0xa9,0x89,0x7c,0xed,0x76,0xe5,0x8a,0x8e,0x7f,0xec,0xa4,0x38,0xdc,
	0x7a,0x8f,0x2c,0x8b,0x33,0x0b,0x87,0x09,0x53,0xbb,0xd2,0x88,0x5f,0xee,0x0d,0xe8,
	0xb9,0xe8,0xff,0x4c,0x77,0x85,0x48,0xbf,0xe0,0x9e,0xe9,0x87,0x21,0x6c,0x43,0xc2,
	0xdd,0x61,0x12,0xc8,0xdc,0xc9,0x67,0x76,0xc4,0xf6,0x33,0xd8,0x25,0x8b,0x28,0x37,
	0xff,0x02,0x00,0x00,0x01,0x08,0x00,0x00,0x46,0x69,0x72,0x6d,0x77,0x61,0x72,0x65,
	0x01,0x01,0x07,0x00,0x45,0x23,0x01,0x00,0x54,0x65,0x73,0x74,0x69,0x6e,0x67,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0xff,0xff,0xff,0x03,0x00,0x01,0x01,0x00,
	0xa5,0x44,0x49,0x2d,0xb0,0x44,0x6c,0x08,0x85,0x7c,0x48,0x9c,0xa9,0xf1,0xe4,0x45,
	0x5e,0x84,0x9e,0x31,0x5c,0xa5,0xb2,0xfa,0x67,0xe4,0x29,0xbd,0xd4,0x31,0xc0,0xc7,
	0x00,0x00,0x00,0x00,0xff,0xff,0xff,0x01,0x09,0x00,0x00,0x00,0x50,0x46,0x4d,0x20,
	0x54,0x65,0x73,0x74,0x32,0x00,0x00,0x00,0x01,0x09,0x00,0x00,0x46,0x69,0x72,0x6d,
	0x77,0x61,0x72,0x65,0x32,0x00,0x00,0x00,0x01,0x01,0x08,0x00,0x45,0x23,0x11,0x00,
	0x54,0x65,0x73,0x74,0x69,0x6e,0x67,0x32,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x06,
	0xff,0xff,0xff,0x07,0x01,0x01,0x01,0x00,0xc5,0x06,0xfe,0x42,0xfa,0x60,0xb9,0x39,
	0x99,0xf6,0xd7,0x4a,0x03,0xd1,0x8e,0x67,0xa4,0x57,0x53,0xa7,0x53,0xd6,0x4b,0x9a,
	0x38,0x0d,0xb9,0xc6,0x0a,0x30,0x0c,0x3e,0x8b,0x54,0x22,0x8c,0x50,0x66,0x19,0xd5,
	0xac,0x0c,0xa7,0x2b,0x23,0x24,0x2c,0x23,0x00,0x00,0x00,0x04,0xff,0xff,0xff,0x05,
	0x30,0x45,0x02,0x20,0x27,0x58,0x74,0x52,0x57,0x34,0x75,0xed,0xa5,0x98,0x0f,0xb1,
	0x70,0xf3,0x62,0x7f,0xb3,0xe5,0x9c,0x69,0xee,0x6d,0x51,0xc1,0x33,0xd9,0x25,0xd8,
	0xb2,0xb3,0x75,0xd2,0x02,0x21,0x00,0xbf,0xca,0x18,0xe7,0xbc,0xf2,0x94,0x51,0xaa,
	0x6c,0x34,0x1b,0x77,0x75,0xc9,0xc1,0x38,0x93,0x16,0x2b,0x51,0x10,0xcf,0xff,0x1e,
	0x1c,0x88,0x92,0xe4,0x01,0x9e,0x1b,0x00,0x00
};

/**
 * PFM_V2_NO_FW_HASHES_DATA hash for testing.
 *
 * head -c -73 pfm.img | openssl dgst -sha256
 */
static const uint8_t PFM_V2_NO_FW_HASHES_HASH[] = {
	0x54,0x24,0xd8,0xd5,0x83,0x8c,0xb1,0xee,0xdc,0xf0,0x50,0x2f,0xab,0xa2,0x48,0xbd,
	0x31,0x63,0xf2,0xc4,0xa6,0x0d,0x47,0x05,0x30,0xc4,0x4f,0xe7,0x1c,0x79,0x43,0x16
};

/**
 * First firmware image for the test v2 PFM with no firmware element hashes.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_NO_FW_HASHES_1[] = {
	{
		.img_offset = 0x010c,
		.hash = PFM_V2_NO_FW_HASHES_DATA + 0x0110,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG1_REGION
	}
};

/**
 * First firmware version component of the test v2 PFM with no firmware element hashes.
 */
static const struct pfm_v2_testing_data_fw_ver PFM_V2_FW_VER_NO_FW_HASHES_1[] = {
	{
		.fw_version = PFM_V2_NO_FW_HASHES_DATA + 0x00f0,
		.fw_version_len = 0x0048,
		.version_str = PFM_V2_FW_VERSION,
		.version_str_len = sizeof (PFM_V2_FW_VERSION) - 1,
		.version_str_pad = PFM_V2_FW_VERSION_PAD,
		.fw_version_offset = 0x00f0,
		.fw_version_entry = 2,
		.fw_version_hash = 1,
		.version_addr = 0x012345,
		.rw_count = 1,
		.rw = PFM_V2_RW1,
		.img_count = 1,
		.img = PFM_V2_FW_IMG_NO_FW_HASHES_1
	}
};

/**
 * Second firmware image for the test v2 PFM with no firmware element hashas.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_NO_FW_HASHES_2[] = {
	{
		.img_offset = 0x0174,
		.hash = PFM_V2_NO_FW_HASHES_DATA + 0x0178,
		.hash_len = 48,
		.hash_type = HASH_TYPE_SHA384,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG2_REGION
	}
};

/**
 * Second Firmware version component of the test v2 PFM with no firmware element hashes.
 */
static const struct pfm_v2_testing_data_fw_ver PFM_V2_FW_VER_NO_FW_HASHES_2[] = {
	{
		.fw_version = PFM_V2_NO_FW_HASHES_DATA + 0x0158,
		.fw_version_len = 0x0058,
		.version_str = PFM_V2_FW_VERSION2,
		.version_str_len = sizeof (PFM_V2_FW_VERSION2) - 1,
		.version_str_pad = PFM_V2_FW_VERSION2_PAD,
		.fw_version_offset = 0x0158,
		.fw_version_entry = 5,
		.fw_version_hash = 2,
		.version_addr = 0x112345,
		.rw_count = 1,
		.rw = PFM_V2_RW2,
		.img_count = 1,
		.img = PFM_V2_FW_IMG_NO_FW_HASHES_2
	}
};

/**
 * Firmware components of the test v2 PFM with no firmware element hashes.
 */
static const struct pfm_v2_testing_data_fw PFM_V2_FW_NO_FW_HASHES[] = {
	{
		.fw = PFM_V2_NO_FW_HASHES_DATA + 0x00e4,
		.fw_len = 0x000c,
		.fw_id_str = PFM_V2_FIRMWARE_ID,
		.fw_id_str_len = sizeof (PFM_V2_FIRMWARE_ID) - 1,
		.fw_id_str_pad = PFM_V2_FIRMWARE_ID_PAD,
		.fw_offset = 0x00e4,
		.fw_entry = 1,
		.fw_hash = -1,
		.version_count = 1,
		.version = PFM_V2_FW_VER_NO_FW_HASHES_1
	},
	{
		.fw = PFM_V2_NO_FW_HASHES_DATA + 0x0148,
		.fw_len = 0x0010,
		.fw_id_str = PFM_V2_FIRMWARE_ID2,
		.fw_id_str_len = sizeof (PFM_V2_FIRMWARE_ID2) - 1,
		.fw_id_str_pad = PFM_V2_FIRMWARE_ID2_PAD,
		.fw_offset = 0x0148,
		.fw_entry = 4,
		.fw_hash = -1,
		.version_count = 1,
		.version = PFM_V2_FW_VER_NO_FW_HASHES_2
	}
};

/**
 * Components of the test v2 PFM with no firmware element hashes.
 */
const struct pfm_v2_testing_data PFM_V2_NO_FW_HASHES = {
	.manifest = {
		.raw = PFM_V2_NO_FW_HASHES_DATA,
		.length = sizeof (PFM_V2_NO_FW_HASHES_DATA),
		.hash = PFM_V2_NO_FW_HASHES_HASH,
		.hash_len = sizeof (PFM_V2_NO_FW_HASHES_HASH),
		.id = 8,
		.signature = PFM_V2_NO_FW_HASHES_DATA + (sizeof (PFM_V2_NO_FW_HASHES_DATA) - 73),
		.sig_len = 73,
		.sig_offset = (sizeof (PFM_V2_NO_FW_HASHES_DATA) - 73),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = PFM_V2_NO_FW_HASHES_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x00d4,
		.toc_hash = PFM_V2_NO_FW_HASHES_DATA + 0x00c0,
		.toc_hash_len = 32,
		.toc_hash_offset = 0x00c0,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 6,
		.toc_hashes = 4,
		.plat_id = PFM_V2_NO_FW_HASHES_DATA + 0x0138,
		.plat_id_len = 0x0010,
		.plat_id_str = PFM_V2_PLATFORM_ID,
		.plat_id_str_len = sizeof (PFM_V2_PLATFORM_ID) - 1,
		.plat_id_str_pad = PFM_V2_PLATFORM_ID_PAD,
		.plat_id_offset = 0x0138,
		.plat_id_entry = 3,
		.plat_id_hash = 3
	},
	.flash_dev = PFM_V2_NO_FW_HASHES_DATA + 0x00e0,
	.flash_dev_len = 4,
	.flash_dev_offset = 0x00e0,
	.flash_dev_entry = 0,
	.flash_dev_hash = 0,
	.blank_byte = 0xff,
	.fw_count = 1,
	.fw = PFM_V2_FW_NO_FW_HASHES
};

/**
 * Test PFM in v2 format.  Contains one FW element and an RSA signature.  There is no flash device
 * element.
 *
 * NUM_FW=1 NO_FLASH_DEV=1 ./generate_pfm.sh 9 ../../core/testing/keys/rsapriv.pem
 */
static const uint8_t PFM_V2_NO_FLASH_DEV_DATA[] = {
	0x0c,0x02,0x6d,0x70,0x09,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x03,0x03,0x00,0x00,
	0x11,0xff,0x01,0x02,0xa8,0x00,0x0c,0x00,0x12,0x11,0x01,0x00,0xb4,0x00,0x48,0x00,
	0x00,0xff,0x01,0x01,0xfc,0x00,0x10,0x00,0xb5,0x68,0xfc,0x09,0x95,0x9f,0x0d,0xd3,
	0x1f,0xf8,0xe8,0x6d,0xdc,0xcf,0x9f,0x15,0xc7,0x9f,0x67,0x5e,0xac,0xe3,0x48,0xb8,
	0x4f,0xc6,0xb2,0x10,0x9d,0x4c,0x6d,0xfd,0xd3,0xb6,0xeb,0x9b,0xe0,0x85,0xcd,0xd3,
	0xd6,0x05,0x81,0xc8,0x0b,0x38,0x6d,0x9a,0xf8,0x5b,0xae,0x5f,0xed,0x50,0x36,0x38,
	0x55,0x0c,0xf8,0xe8,0xdb,0xd8,0x82,0x46,0x13,0x48,0x15,0xa0,0xd1,0xfb,0x58,0x01,
	0xae,0x7a,0xa2,0x15,0xb4,0xf1,0x98,0x57,0xda,0x88,0x4d,0x95,0x99,0x18,0x27,0x0f,
	0x98,0x11,0xfe,0xe5,0xd4,0x0e,0x5b,0x6c,0x7f,0x58,0xd1,0xe5,0x17,0x7d,0xd9,0xfd,
	0x59,0x27,0xad,0x47,0x6f,0x5e,0x87,0x83,0x92,0xb4,0x95,0x4a,0xc6,0xba,0x54,0xe1,
	0x97,0xeb,0xe4,0x00,0x54,0x22,0xbd,0xc9,0x01,0x08,0x00,0x00,0x46,0x69,0x72,0x6d,
	0x77,0x61,0x72,0x65,0x01,0x01,0x07,0x00,0x45,0x23,0x01,0x00,0x54,0x65,0x73,0x74,
	0x69,0x6e,0x67,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0xff,0xff,0xff,0x03,
	0x00,0x01,0x01,0x00,0x18,0x4e,0x5f,0x62,0x79,0x1b,0xd2,0xaf,0x65,0x55,0xdb,0x85,
	0x82,0x1a,0x03,0xc7,0x4b,0x36,0x6d,0xe5,0xf6,0xce,0x71,0xf0,0xc1,0x37,0x78,0xeb,
	0xe4,0x16,0x31,0x1f,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0x01,0x09,0x00,0x00,0x00,
	0x50,0x46,0x4d,0x20,0x54,0x65,0x73,0x74,0x31,0x00,0x00,0x00,0x3a,0x94,0xbb,0x71,
	0x13,0x74,0xd7,0xc5,0xfb,0x94,0xca,0x94,0xbb,0xcb,0xec,0xa5,0xad,0x30,0x2c,0xee,
	0x0a,0x40,0x94,0x22,0x28,0xe6,0x4d,0x77,0x53,0x3c,0xf5,0x0c,0x3d,0x48,0xc0,0x33,
	0xe1,0x2b,0x0a,0x50,0x22,0x8f,0x5e,0x26,0xed,0x43,0xd9,0x8a,0x02,0x6d,0xb0,0x6a,
	0x55,0xb4,0xeb,0xfa,0x16,0x23,0x4c,0xf1,0x7a,0x60,0xc4,0xe3,0xef,0x0d,0x67,0x48,
	0xe0,0x41,0xed,0xcc,0x06,0xee,0x0b,0xca,0xb6,0x31,0x15,0xb3,0x84,0x16,0x84,0x77,
	0x10,0xf8,0xbb,0xe7,0x06,0xae,0x62,0x92,0x70,0xa0,0x4f,0x80,0xd9,0x54,0xc3,0x1d,
	0x9a,0x3f,0x75,0xf5,0xb2,0xf6,0x2f,0x06,0xa3,0x9b,0xab,0x09,0x63,0x3b,0xb1,0x78,
	0x98,0x73,0xbd,0x5f,0xbd,0x64,0x56,0x80,0x16,0xb8,0xca,0xb9,0x1b,0xbf,0xbd,0x7d,
	0x41,0xcd,0xa4,0xa9,0xa9,0x56,0x5a,0xb2,0x26,0x02,0x3e,0x7c,0xa0,0x62,0x20,0x0b,
	0x8a,0xd0,0x94,0x59,0xf2,0xe7,0x2a,0x58,0x9b,0x22,0xc3,0x9e,0x19,0x56,0x13,0x13,
	0x2c,0x79,0xfa,0x1f,0x68,0x1c,0x6e,0x88,0x1f,0xa6,0x58,0x37,0x1b,0x0b,0xb6,0x0c,
	0xdb,0x9a,0x9d,0x4b,0x23,0xcb,0x4d,0x73,0xeb,0xc5,0xf3,0x62,0xf1,0x45,0x4a,0xd2,
	0xf9,0xa5,0x95,0xb4,0x32,0xf3,0x28,0x60,0x4d,0x47,0xb3,0x61,0x7d,0x83,0x4e,0xae,
	0xeb,0x13,0x22,0x9e,0x04,0x59,0x8d,0x45,0xd6,0x0c,0xab,0x54,0x4f,0xbb,0xca,0xfa,
	0x7e,0x82,0xd4,0xe0,0x07,0x2d,0xa8,0x97,0xa4,0x11,0x4e,0xde,0xd2,0x98,0x8e,0x47,
	0x43,0xe5,0x9e,0x05,0x5a,0xdc,0xa4,0xd0,0xf9,0x4c,0x69,0xfd
};

/**
 * PFM_V2_NO_FLASH_DEV_DATA hash for testing.
 *
 * head -c -256 pfm.img | openssl dgst -sha256
 */
static const uint8_t PFM_V2_NO_FLASH_DEV_HASH[] = {
	0x1f,0x44,0xf8,0x9e,0xfb,0xd4,0x9e,0x72,0x01,0x22,0x8f,0x4d,0x3f,0xae,0x4d,0xf0,
	0xd7,0x4b,0x07,0x67,0x9c,0x26,0xdd,0x78,0xef,0x1b,0x27,0x4a,0xc9,0x1d,0x62,0xe0
};

/**
 * Firmware image for the test v2 PFM with no flash device element.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_NO_FLASH_DEV[] = {
	{
		.img_offset = 0x00d0,
		.hash = PFM_V2_NO_FLASH_DEV_DATA + 0x00d4,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG1_REGION
	}
};

/**
 * Firmware version components of the test v2 PFM with no flash device element.
 */
static const struct pfm_v2_testing_data_fw_ver PFM_V2_FW_VER_NO_FLASH_DEV[] = {
	{
		.fw_version = PFM_V2_NO_FLASH_DEV_DATA + 0x00b4,
		.fw_version_len = 0x0048,
		.version_str = PFM_V2_FW_VERSION,
		.version_str_len = sizeof (PFM_V2_FW_VERSION) - 1,
		.version_str_pad = PFM_V2_FW_VERSION_PAD,
		.fw_version_offset = 0x00b4,
		.fw_version_entry = 1,
		.fw_version_hash = 0,
		.version_addr = 0x012345,
		.rw_count = 1,
		.rw = PFM_V2_RW1,
		.img_count = 1,
		.img = PFM_V2_FW_IMG_NO_FLASH_DEV
	}
};

/**
 * Firmware components of the test v2 PFM with no flash device element.
 */
static const struct pfm_v2_testing_data_fw PFM_V2_FW_NO_FLASH_DEV[] = {
	{
		.fw = PFM_V2_NO_FLASH_DEV_DATA + 0x00a8,
		.fw_len = 0x000c,
		.fw_id_str = PFM_V2_FIRMWARE_ID,
		.fw_id_str_len = sizeof (PFM_V2_FIRMWARE_ID) - 1,
		.fw_id_str_pad = PFM_V2_FIRMWARE_ID_PAD,
		.fw_offset = 0x00a8,
		.fw_entry = 0,
		.fw_hash = 2,
		.version_count = 1,
		.version = PFM_V2_FW_VER_NO_FLASH_DEV
	}
};

/**
 * Components of the test v2 PFM with no flash device element.
 */
const struct pfm_v2_testing_data PFM_V2_NO_FLASH_DEV = {
	.manifest = {
		.raw = PFM_V2_NO_FLASH_DEV_DATA,
		.length = sizeof (PFM_V2_NO_FLASH_DEV_DATA),
		.hash = PFM_V2_NO_FLASH_DEV_HASH,
		.hash_len = sizeof (PFM_V2_NO_FLASH_DEV_HASH),
		.id = 9,
		.signature = PFM_V2_NO_FLASH_DEV_DATA + (sizeof (PFM_V2_NO_FLASH_DEV_DATA) - 256),
		.sig_len = 256,
		.sig_offset = (sizeof (PFM_V2_NO_FLASH_DEV_DATA) - 256),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = PFM_V2_NO_FLASH_DEV_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x0094,
		.toc_hash = PFM_V2_NO_FLASH_DEV_DATA + 0x0088,
		.toc_hash_len = 32,
		.toc_hash_offset = 0x0088,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 3,
		.toc_hashes = 3,
		.plat_id = PFM_V2_NO_FLASH_DEV_DATA + 0x00fc,
		.plat_id_len = 0x0010,
		.plat_id_str = PFM_V2_PLATFORM_ID,
		.plat_id_str_len = sizeof (PFM_V2_PLATFORM_ID) - 1,
		.plat_id_str_pad = PFM_V2_PLATFORM_ID_PAD,
		.plat_id_offset = 0x00fc,
		.plat_id_entry = 2,
		.plat_id_hash = 1
	},
	.flash_dev = NULL,
	.flash_dev_len = 0,
	.flash_dev_offset = 0,
	.flash_dev_entry = -1,
	.flash_dev_hash = -1,
	.blank_byte = -1,
	.fw_count = 1,
	.fw = PFM_V2_FW_NO_FLASH_DEV
};

/**
 * Test PFM in v2 format.  This is an empty PFM with a SHA256 RSA signature.
 *
 * EMPTY_MANIFEST=1 ./generate_pfm.sh 10 ../../core/testing/keys/rsapriv.pem
 */
static const uint8_t PFM_V2_EMPTY_DATA[] = {
	0x68,0x01,0x6d,0x70,0x0a,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x01,0x01,0x00,0x00,
	0x00,0xff,0x01,0x00,0x58,0x00,0x10,0x00,0xd3,0xb6,0xeb,0x9b,0xe0,0x85,0xcd,0xd3,
	0xd6,0x05,0x81,0xc8,0x0b,0x38,0x6d,0x9a,0xf8,0x5b,0xae,0x5f,0xed,0x50,0x36,0x38,
	0x55,0x0c,0xf8,0xe8,0xdb,0xd8,0x82,0x46,0xb9,0x5b,0x0d,0x7c,0x8a,0x76,0x7f,0x0b,
	0xd3,0xf8,0x29,0x3b,0x34,0x62,0x0a,0x9e,0x52,0x19,0xc6,0x95,0x3a,0x18,0x5f,0x70,
	0xd3,0xef,0x35,0x47,0x48,0x7e,0x43,0xcd,0x09,0x00,0x00,0x00,0x50,0x46,0x4d,0x20,
	0x54,0x65,0x73,0x74,0x31,0x00,0x00,0x00,0x9e,0x46,0xfb,0x0f,0xfa,0xff,0xab,0x8a,
	0x5a,0x9b,0x58,0xf9,0x5c,0xe1,0x5b,0x24,0x2b,0xb9,0x5a,0x97,0x1f,0x25,0x8a,0xd9,
	0xd4,0xb8,0x5b,0x2d,0xf0,0x17,0x0d,0x20,0xfe,0xe1,0xf3,0x3a,0x5f,0x68,0x85,0xd8,
	0x80,0x77,0x17,0x31,0xf8,0xb9,0x7f,0x1e,0xca,0x8c,0xf8,0x95,0xdb,0xea,0x6c,0xe2,
	0x1b,0x67,0x68,0x61,0xd0,0xd4,0xd2,0x28,0xc7,0x10,0x33,0x3e,0x4a,0x95,0x9b,0x7b,
	0x98,0x2a,0x96,0x7e,0x83,0x5d,0xe0,0x48,0xa8,0x7f,0x9b,0xc8,0x9a,0xc5,0x00,0xfd,
	0xe0,0x44,0x7b,0xd9,0xc6,0xa6,0x3d,0x8b,0x73,0x67,0x10,0xe3,0x29,0xd7,0x52,0xe4,
	0xdf,0x6f,0xb5,0xca,0x92,0x70,0x79,0xdf,0x1b,0x45,0xf7,0xab,0xa1,0x8b,0x51,0xf6,
	0xcd,0xa2,0xbb,0xad,0x4b,0x03,0x4f,0x77,0x03,0xb2,0x61,0xe2,0x30,0x57,0x8f,0x72,
	0x12,0x47,0x55,0xf3,0xe1,0x17,0x63,0x2c,0x7d,0x2c,0x68,0x66,0xc8,0xd5,0xe1,0x39,
	0x18,0xc5,0x65,0x55,0x95,0x21,0x0b,0x41,0xf0,0xd2,0xaa,0x69,0x18,0x61,0x4f,0xcd,
	0xc6,0x21,0xa2,0x2f,0x39,0xa3,0xf3,0x66,0xf9,0x63,0x84,0xc9,0xd0,0x36,0x07,0x0c,
	0xec,0xa2,0xfa,0x5e,0xf0,0xac,0xbe,0x6d,0x63,0xf1,0xad,0xa9,0x88,0xb0,0xf5,0x1f,
	0xd3,0xa3,0x65,0xd1,0x49,0xac,0xf6,0xc2,0x90,0xb6,0xc9,0x8b,0xb9,0x25,0x8b,0x77,
	0x95,0x81,0xdd,0x47,0xe4,0x3b,0x28,0x7c,0x5f,0x9f,0x30,0xa1,0x9f,0xb0,0x06,0x6b,
	0xd2,0xcb,0x19,0x4e,0xcb,0x1c,0x3c,0x94,0x30,0xdb,0x27,0x0e,0x52,0xc8,0x5f,0x4c,
	0x81,0x08,0xd4,0xcb,0x11,0x52,0x31,0x92
};

/**
 * PFM_V2_EMPTY_DATA hash for testing.
 *
 * head -c -256 pfm.img | openssl dgst -sha256
 */
static const uint8_t PFM_V2_EMPTY_HASH[] = {
	0xe9,0x95,0x63,0xb7,0x15,0xa0,0x31,0x3a,0x1a,0x24,0x7a,0xb0,0x29,0xbf,0xff,0x35,
	0x58,0x36,0xf9,0x47,0x72,0x69,0x2b,0x53,0xd0,0x1a,0xfa,0xe7,0x78,0xc4,0x89,0x82
};

/**
 * Components of the test v2 empty PFM.
 */
const struct pfm_v2_testing_data PFM_V2_EMPTY = {
	.manifest = {
		.raw = PFM_V2_EMPTY_DATA,
		.length = sizeof (PFM_V2_EMPTY_DATA),
		.hash = PFM_V2_EMPTY_HASH,
		.hash_len = sizeof (PFM_V2_EMPTY_HASH),
		.id = 10,
		.signature = PFM_V2_EMPTY_DATA + (sizeof (PFM_V2_EMPTY_DATA) - 256),
		.sig_len = 256,
		.sig_offset = (sizeof (PFM_V2_EMPTY_DATA) - 256),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = PFM_V2_EMPTY_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x0044,
		.toc_hash = PFM_V2_EMPTY_DATA + 0x0038,
		.toc_hash_len = 32,
		.toc_hash_offset = 0x0038,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 1,
		.toc_hashes = 1,
		.plat_id = PFM_V2_EMPTY_DATA + 0x0058,
		.plat_id_len = 0x0010,
		.plat_id_str = PFM_V2_PLATFORM_ID,
		.plat_id_str_len = sizeof (PFM_V2_PLATFORM_ID) - 1,
		.plat_id_str_pad = PFM_V2_PLATFORM_ID_PAD,
		.plat_id_offset = 0x0058,
		.plat_id_entry = 0,
		.plat_id_hash = 0
	},
	.flash_dev = NULL,
	.flash_dev_len = 0,
	.flash_dev_offset = 0,
	.flash_dev_entry = -1,
	.flash_dev_hash = -1,
	.blank_byte = -1,
	.fw_count = 0,
	.fw = NULL
};

/**
 * Test PFM in v2 format.  There are no firmware entries with a SHA256 RSA signature.
 *
 * NUM_FW=0 ./generate_pfm.sh 11 ../../core/testing/keys/rsapriv.pem
 */
static const uint8_t PFM_V2_NO_FW_DATA[] = {
	0x94,0x01,0x6d,0x70,0x0b,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x02,0x02,0x00,0x00,
	0x10,0xff,0x00,0x00,0x80,0x00,0x04,0x00,0x00,0xff,0x01,0x01,0x84,0x00,0x10,0x00,
	0x81,0xff,0x65,0xef,0xc4,0x48,0x78,0x53,0xbd,0xb4,0x62,0x55,0x59,0xe6,0x9a,0xb4,
	0x4f,0x19,0xe0,0xf5,0xef,0xbd,0x6d,0x5b,0x2a,0xf5,0xe3,0xab,0x26,0x7c,0x8e,0x06,
	0xd3,0xb6,0xeb,0x9b,0xe0,0x85,0xcd,0xd3,0xd6,0x05,0x81,0xc8,0x0b,0x38,0x6d,0x9a,
	0xf8,0x5b,0xae,0x5f,0xed,0x50,0x36,0x38,0x55,0x0c,0xf8,0xe8,0xdb,0xd8,0x82,0x46,
	0xad,0xbc,0xb0,0xe6,0x03,0x8e,0xe9,0xa5,0xd1,0xf5,0x2b,0x18,0x57,0xb0,0x81,0x83,
	0x0e,0xdb,0xaa,0x37,0x5c,0x5c,0xab,0xff,0xbf,0x08,0x4c,0xbc,0x65,0x52,0x9c,0xd4,
	0xff,0x00,0x00,0x00,0x09,0x00,0x00,0x00,0x50,0x46,0x4d,0x20,0x54,0x65,0x73,0x74,
	0x31,0x00,0x00,0x00,0x9c,0xaf,0xde,0x57,0x21,0x64,0xb3,0xc0,0x5d,0xdd,0x37,0xc0,
	0x7f,0x2f,0xbb,0xf9,0x9d,0xee,0x6c,0x81,0x02,0x02,0x8d,0x5c,0x38,0xbc,0x3e,0xda,
	0xf9,0x95,0x45,0xc7,0xf0,0xf1,0xd4,0xa7,0x4e,0x58,0xd7,0x85,0xcc,0xf4,0x7c,0x72,
	0xd4,0x7d,0x8f,0x77,0x15,0x51,0x90,0x5c,0x3b,0xed,0x8f,0x1a,0xd5,0xe2,0x79,0x42,
	0xeb,0xf4,0xd7,0x68,0xe2,0x49,0xe5,0x01,0xf4,0x1b,0x58,0xc6,0x43,0x15,0x65,0x92,
	0xce,0x9a,0x64,0x67,0x20,0xd0,0x8a,0x30,0x2e,0x07,0x09,0xe4,0x10,0xe6,0x73,0xd7,
	0xdf,0x92,0x09,0xcd,0x48,0x78,0x9c,0xac,0x73,0xd4,0xfa,0x52,0x37,0x95,0xaa,0xca,
	0x1c,0xeb,0x16,0x0c,0x6f,0x4d,0x14,0xe1,0x66,0x27,0x1a,0x1c,0x5d,0xd2,0x4e,0x77,
	0x69,0x84,0x37,0xc2,0x08,0x96,0xe0,0xd4,0x8b,0x04,0x02,0xe9,0xea,0x70,0x87,0xaf,
	0x30,0x63,0xd5,0xb1,0xaf,0x27,0x50,0x10,0x0c,0x42,0x2c,0x37,0x4b,0xf3,0x80,0x5e,
	0xbd,0x42,0xe7,0x95,0x26,0x56,0xa0,0x9b,0xe3,0x15,0x72,0x66,0xa2,0xaa,0xd4,0xd5,
	0xf1,0xb5,0x44,0x74,0x82,0x7c,0x97,0x1f,0xf8,0xec,0x34,0xfe,0x11,0xde,0x46,0x7a,
	0x48,0x9b,0x29,0x1d,0xc9,0x8c,0xea,0x68,0x23,0x3a,0x53,0x96,0x0e,0xaa,0x78,0x06,
	0xc6,0xb0,0x58,0x0f,0x35,0x23,0x47,0xeb,0x10,0xdc,0xce,0xdc,0xb7,0x7e,0x26,0x6b,
	0x95,0xfd,0x81,0xc1,0x34,0x08,0x88,0xbd,0xca,0x6b,0x7e,0x72,0x02,0xf8,0xb4,0x32,
	0xc5,0xcc,0x0a,0x8a,0x16,0xe4,0xd4,0xb6,0x64,0xd5,0x78,0x64,0xa9,0x1a,0xbd,0x47,
	0x39,0xbd,0x63,0x38
};

/**
 * PFM_V2_NO_FW_DATA hash for testing.
 *
 * head -c -256 pfm.img | openssl dgst -sha256
 */
static const uint8_t PFM_V2_NO_FW_HASH[] = {
	0xa0,0xd0,0x92,0x97,0x67,0x94,0x24,0xd8,0x85,0x6c,0x1e,0xfb,0x0d,0x9c,0x6e,0x0f,
	0xef,0x0e,0xe4,0x53,0xeb,0xae,0xa7,0x58,0xef,0x08,0x1c,0x7e,0x07,0xc6,0x41,0x81
};

/**
 * Components of the test v2 with no firmware entries.
 */
const struct pfm_v2_testing_data PFM_V2_NO_FW = {
	.manifest = {
		.raw = PFM_V2_NO_FW_DATA,
		.length = sizeof (PFM_V2_NO_FW_DATA),
		.hash = PFM_V2_NO_FW_HASH,
		.hash_len = sizeof (PFM_V2_NO_FW_HASH),
		.id = 11,
		.signature = PFM_V2_NO_FW_DATA + (sizeof (PFM_V2_NO_FW_DATA) - 256),
		.sig_len = 256,
		.sig_offset = (sizeof (PFM_V2_NO_FW_DATA) - 256),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = PFM_V2_NO_FW_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x0074,
		.toc_hash = PFM_V2_NO_FW_DATA + 0x0060,
		.toc_hash_len = 32,
		.toc_hash_offset = 0x0060,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 2,
		.toc_hashes = 2,
		.plat_id = PFM_V2_NO_FW_DATA + 0x0084,
		.plat_id_len = 0x0010,
		.plat_id_str = PFM_V2_PLATFORM_ID,
		.plat_id_str_len = sizeof (PFM_V2_PLATFORM_ID) - 1,
		.plat_id_str_pad = PFM_V2_PLATFORM_ID_PAD,
		.plat_id_offset = 0x0084,
		.plat_id_entry = 1,
		.plat_id_hash = 1
	},
	.flash_dev = PFM_V2_NO_FW_DATA + 0x0080,
	.flash_dev_len = 4,
	.flash_dev_offset = 0x0080,
	.flash_dev_entry = 0,
	.flash_dev_hash = 0,
	.blank_byte = 0xff,
	.fw_count = 0,
	.fw = NULL
};

/**
 * Test PFM in v2 format.  Contains three FW elements and an ECC384 signature.  The platform ID is
 * in between the first two FW elements.  None of the FW elements have supported versions.
 *
 * NUM_FW=3 NUM_FW_VER=0 HASH_TYPE=1 ./generate_pfm.sh 12 ../../core/testing/keys/ecc384priv.pem
 */
static const uint8_t PFM_V2_THREE_FW_NO_VER_DATA[] = {
	0xf9,0x01,0x6d,0x70,0x0c,0x00,0x00,0x00,0x69,0x00,0x49,0x00,0x05,0x05,0x01,0x00,
	0x10,0xff,0x00,0x00,0x58,0x01,0x04,0x00,0x11,0xff,0x01,0x02,0x5c,0x01,0x0c,0x00,
	0x00,0xff,0x01,0x01,0x68,0x01,0x10,0x00,0x11,0xff,0x01,0x03,0x78,0x01,0x10,0x00,
	0x11,0xff,0x01,0x04,0x88,0x01,0x08,0x00,0xcd,0x38,0x81,0x12,0x7b,0xce,0x03,0xbb,
	0xab,0xf5,0x57,0x4d,0x7e,0x41,0xce,0xd7,0x7d,0x2c,0xbf,0xe4,0xf3,0xb4,0x10,0x70,
	0xaf,0x8e,0x02,0x78,0xf1,0x60,0x1c,0x7e,0xe7,0x05,0xbe,0x8a,0x40,0x61,0xf5,0xb3,
	0xc8,0xcf,0xa2,0xf7,0xdc,0x83,0x44,0x7f,0x61,0x86,0xa8,0x3f,0x39,0xd1,0x5d,0x3a,
	0xd6,0x34,0xba,0x2d,0xe7,0xb1,0x33,0x78,0x53,0x41,0xde,0xf6,0x1e,0xdf,0x98,0xed,
	0x5e,0x08,0xa9,0xdd,0x64,0x06,0x83,0xa2,0x87,0xcb,0x1e,0x17,0x1c,0x11,0x38,0x62,
	0x64,0xc8,0x47,0xed,0x8c,0x25,0x22,0x86,0x99,0x9a,0xde,0xec,0x20,0x56,0xf4,0xb9,
	0xc0,0x2a,0x31,0xb1,0x41,0x63,0x32,0x1c,0x02,0x2b,0x88,0xaf,0x44,0x49,0xe8,0x47,
	0x15,0x75,0xe6,0x82,0x75,0x74,0xd5,0x40,0x50,0xe8,0x6b,0x82,0xff,0x01,0x77,0x3d,
	0x74,0x49,0x9f,0x48,0x30,0xbf,0x13,0x58,0x83,0x08,0xc0,0x4c,0xb6,0xc2,0xb3,0x53,
	0x46,0xb1,0x08,0x24,0x9d,0x0a,0x76,0xc3,0xc0,0x01,0x8f,0xed,0x1d,0xfe,0xf2,0x95,
	0x3c,0x6f,0xb9,0xd9,0x5e,0xfc,0x2e,0x42,0x8c,0x52,0x37,0xdf,0x83,0x40,0xcb,0xd7,
	0xd2,0xa3,0x7d,0x6f,0x9d,0x5a,0x74,0x3c,0x6e,0x80,0x96,0x50,0x9a,0x34,0xea,0xb8,
	0xf7,0x76,0xb8,0x85,0x7a,0x66,0xc0,0x0a,0x55,0x4a,0xea,0x47,0xc4,0xbe,0xd1,0x88,
	0x2b,0x7a,0xc1,0x76,0x2e,0xd9,0xc8,0x73,0xc1,0x3e,0x36,0x3b,0xae,0x77,0xad,0xc1,
	0x71,0xd5,0x66,0x72,0xc9,0x8b,0x7a,0x45,0x3c,0xea,0x94,0x36,0x29,0x34,0xf6,0x40,
	0xf8,0xf5,0x4d,0xa8,0xed,0xf5,0x5a,0x77,0x06,0xfd,0x78,0x83,0x54,0x34,0x59,0x94,
	0xd8,0xc0,0xae,0xc3,0xc7,0x3a,0xe1,0x34,0x6e,0xce,0x8c,0xb8,0xca,0x48,0x0f,0x02,
	0x6a,0xa1,0x04,0xce,0x7a,0x31,0xb8,0x12,0xff,0x03,0x00,0x00,0x00,0x08,0x00,0x00,
	0x46,0x69,0x72,0x6d,0x77,0x61,0x72,0x65,0x09,0x00,0x00,0x00,0x50,0x46,0x4d,0x20,
	0x54,0x65,0x73,0x74,0x31,0x00,0x00,0x00,0x00,0x09,0x00,0x00,0x46,0x69,0x72,0x6d,
	0x77,0x61,0x72,0x65,0x32,0x00,0x00,0x00,0x00,0x03,0x00,0x00,0x46,0x57,0x33,0x00,
	0x30,0x66,0x02,0x31,0x00,0xca,0x0b,0xc0,0x38,0x93,0x60,0x79,0xfa,0xfd,0x6a,0x44,
	0xba,0xc9,0x4d,0x7a,0xd0,0x8f,0x73,0x35,0xed,0x70,0x85,0x6b,0xae,0xde,0x2c,0x52,
	0x1c,0x64,0x26,0x3d,0xe3,0xa2,0x0d,0x89,0x3b,0x18,0x32,0xab,0xa4,0x27,0x43,0x88,
	0x7b,0x31,0x2e,0xcc,0x1b,0x02,0x31,0x00,0x8b,0x4c,0x65,0xfa,0xb6,0xa6,0x19,0xeb,
	0x52,0x0f,0x65,0x9b,0x64,0xf8,0x06,0x7b,0x16,0x49,0x25,0x7f,0x50,0x25,0x81,0x2e,
	0x98,0x18,0x84,0xd9,0xeb,0x96,0xbd,0xaf,0x6d,0x46,0x40,0x22,0x8d,0x9f,0x27,0xcd,
	0xcf,0xc6,0x23,0xdc,0xe5,0xfa,0xfc,0xf1,0x00
};

/**
 * PFM_V2_THREE_FW_NO_VER_DATA hash for testing.
 *
 * head -c -105 pfm.img | openssl dgst -sha384
 */
static const uint8_t PFM_V2_THREE_FW_NO_VER_HASH[] = {
	0xc1,0x84,0xc1,0x18,0x15,0x7b,0x7e,0x9d,0x2b,0x1b,0x4e,0xd3,0x2d,0xf3,0xf2,0xaf,
	0xc8,0xea,0xd2,0x5a,0xde,0xac,0x71,0xf7,0x70,0xfd,0x86,0xc7,0x7a,0x08,0x5e,0xb4,
	0x36,0x82,0x9d,0x3d,0x84,0xa8,0x2e,0xeb,0x22,0x61,0xf7,0x9b,0x32,0x57,0xa7,0x50
};

/**
 * Firmware components of the test v2 PFM with three firmware elements.
 */
static const struct pfm_v2_testing_data_fw PFM_V2_FW_THREE_FW_NO_VER[] = {
	{
		.fw = PFM_V2_THREE_FW_NO_VER_DATA + 0x015c,
		.fw_len = 0x000c,
		.fw_id_str = PFM_V2_FIRMWARE_ID,
		.fw_id_str_len = sizeof (PFM_V2_FIRMWARE_ID) - 1,
		.fw_id_str_pad = PFM_V2_FIRMWARE_ID_PAD,
		.fw_offset = 0x015c,
		.fw_entry = 1,
		.fw_hash = 2,
		.version_count = 0,
		.version = NULL
	},
	{
		.fw = PFM_V2_THREE_FW_NO_VER_DATA + 0x0178,
		.fw_len = 0x0010,
		.fw_id_str = PFM_V2_FIRMWARE_ID2,
		.fw_id_str_len = sizeof (PFM_V2_FIRMWARE_ID2) - 1,
		.fw_id_str_pad = PFM_V2_FIRMWARE_ID2_PAD,
		.fw_offset = 0x0178,
		.fw_entry = 3,
		.fw_hash = 3,
		.version_count = 0,
		.version = NULL
	},
	{
		.fw = PFM_V2_THREE_FW_NO_VER_DATA + 0x0188,
		.fw_len = 0x0008,
		.fw_id_str = PFM_V2_FIRMWARE_ID3,
		.fw_id_str_len = sizeof (PFM_V2_FIRMWARE_ID3) - 1,
		.fw_id_str_pad = PFM_V2_FIRMWARE_ID3_PAD,
		.fw_offset = 0x0188,
		.fw_entry = 4,
		.fw_hash = 4,
		.version_count = 0,
		.version = NULL
	}
};

/**
 * Components of the test v2 PFM with three firmware elements.
 */
const struct pfm_v2_testing_data PFM_V2_THREE_FW_NO_VER = {
	.manifest = {
		.raw = PFM_V2_THREE_FW_NO_VER_DATA,
		.length = sizeof (PFM_V2_THREE_FW_NO_VER_DATA),
		.hash = PFM_V2_THREE_FW_NO_VER_HASH,
		.hash_len = sizeof (PFM_V2_THREE_FW_NO_VER_HASH),
		.id = 12,
		.signature = PFM_V2_THREE_FW_NO_VER_DATA + (sizeof (PFM_V2_THREE_FW_NO_VER_DATA) - 105),
		.sig_len = 105,
		.sig_offset = (sizeof (PFM_V2_THREE_FW_NO_VER_DATA) - 105),
		.sig_hash_type = HASH_TYPE_SHA384,
		.toc = PFM_V2_THREE_FW_NO_VER_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x014c,
		.toc_hash = PFM_V2_THREE_FW_NO_VER_DATA + 0x0128,
		.toc_hash_len = 48,
		.toc_hash_offset = 0x0128,
		.toc_hash_type = HASH_TYPE_SHA384,
		.toc_entries = 5,
		.toc_hashes = 5,
		.plat_id = PFM_V2_THREE_FW_NO_VER_DATA + 0x0168,
		.plat_id_len = 0x0010,
		.plat_id_str = PFM_V2_PLATFORM_ID,
		.plat_id_str_len = sizeof (PFM_V2_PLATFORM_ID) - 1,
		.plat_id_str_pad = PFM_V2_PLATFORM_ID_PAD,
		.plat_id_offset = 0x0168,
		.plat_id_entry = 2,
		.plat_id_hash = 1
	},
	.flash_dev = PFM_V2_THREE_FW_NO_VER_DATA + 0x0158,
	.flash_dev_len = 4,
	.flash_dev_offset = 0x0158,
	.flash_dev_entry = 0,
	.flash_dev_hash = 0,
	.blank_byte = 0xff,
	.fw_count = 3,
	.fw = PFM_V2_FW_THREE_FW_NO_VER
};

/**
 * Test PFM in v2 format.  Contains multiple firmware elements, versions, and regions with an
 * ECC384 signature.  The blank byte is set to 0x55.
 *
 * PLATFORM="PFM Test2" NUM_FW=3 NUM_FW_VER=3 HASH_TYPE=1 BLANK_BYTE=0x55 ./generate_pfm.sh 13 ../../core/testing/keys/ecc384priv.pem
 */
static const uint8_t PFM_V2_MULTIPLE_DATA[] = {
	0x41,0x09,0x6d,0x70,0x0d,0x00,0x00,0x00,0x69,0x00,0x49,0x00,0x0e,0x0e,0x01,0x00,
	0x10,0xff,0x00,0x00,0x50,0x03,0x04,0x00,0x11,0xff,0x01,0x05,0x54,0x03,0x0c,0x00,
	0x12,0x11,0x01,0x01,0x60,0x03,0x48,0x00,0x12,0x11,0x01,0x08,0xa8,0x03,0x94,0x00,
	0x12,0x11,0x01,0x0b,0x3c,0x04,0xec,0x00,0x00,0xff,0x01,0x04,0x28,0x05,0x10,0x00,
	0x11,0xff,0x01,0x06,0x38,0x05,0x10,0x00,0x12,0x11,0x01,0x02,0x48,0x05,0x90,0x00,
	0x12,0x11,0x01,0x09,0xd8,0x05,0xec,0x00,0x12,0x11,0x01,0x0c,0xc4,0x06,0x4c,0x00,
	0x11,0xff,0x01,0x07,0x10,0x07,0x08,0x00,0x12,0x11,0x01,0x03,0x18,0x07,0xe8,0x00,
	0x12,0x11,0x01,0x0a,0x00,0x08,0x48,0x00,0x12,0x11,0x01,0x0d,0x48,0x08,0x90,0x00,
	0x69,0xdc,0x06,0x83,0x5a,0x42,0x82,0xb7,0x85,0xc8,0x32,0xb9,0x7d,0x3e,0x06,0x1d,
	0x32,0xa8,0x40,0xe1,0x79,0x27,0x11,0xe1,0xac,0xa8,0x0b,0x32,0xa3,0x9a,0x74,0x39,
	0xb5,0xa2,0x09,0xd0,0xa1,0xb2,0xd8,0xa5,0xef,0x25,0xfc,0xa0,0x74,0xb5,0x8b,0xcf,
	0x5b,0x22,0xd0,0x52,0x3e,0x9b,0x93,0x30,0x19,0x41,0x3d,0xf8,0x29,0x3f,0xb7,0x42,
	0x18,0x37,0x17,0xf6,0x91,0xf7,0x67,0xbb,0x07,0x49,0x6b,0xfc,0x24,0x00,0x55,0xcc,
	0x5e,0x31,0x73,0x6e,0x8d,0xa1,0xf6,0xf9,0xec,0xbc,0x4a,0x65,0x75,0xc0,0x7b,0xb7,
	0x38,0xe0,0x60,0xe5,0xb8,0xcb,0xe8,0xf8,0x8f,0x76,0xb6,0x13,0xa5,0x86,0x19,0xa0,
	0xc0,0x44,0x45,0xcc,0x3d,0xb7,0xcc,0xfd,0xbc,0x2c,0xd9,0x0f,0xfa,0xde,0xb7,0xad,
	0x35,0xd4,0x8d,0x67,0xd2,0xd7,0x96,0xf3,0x01,0x07,0xf5,0xe7,0xf6,0x1c,0x15,0x0c,
	0x74,0x8a,0x98,0x16,0x9c,0xc5,0x76,0xdc,0x1f,0xca,0x6d,0x80,0x95,0xbd,0xb1,0x74,
	0x93,0x91,0x64,0x45,0x7c,0x70,0x57,0x5c,0x15,0xd3,0xd9,0xee,0x7e,0x17,0x63,0xff,
	0x0e,0x80,0xf8,0x08,0xb9,0xf7,0xd1,0xa2,0x7e,0x82,0xf9,0xca,0x88,0x0b,0x56,0x6f,
	0xb4,0xec,0xa4,0x82,0x95,0x5b,0x25,0xea,0x8f,0x2d,0xe6,0x85,0x51,0x4d,0x5a,0x20,
	0x17,0x57,0x34,0x17,0xa5,0xa3,0x87,0x6c,0x2f,0x81,0xc6,0x1f,0x4d,0x4c,0x2e,0xfe,
	0xf8,0x45,0x97,0x76,0x0d,0xe9,0x7c,0xd4,0x88,0xd7,0x9f,0x45,0xac,0xf0,0xbd,0xda,
	0xdf,0x99,0x5f,0xd5,0xd7,0x9c,0x81,0xc5,0xa9,0x7d,0x74,0x2e,0x9f,0xe9,0x19,0x64,
	0x38,0x39,0x58,0xdf,0xa3,0xc7,0x87,0x00,0x3c,0x8c,0xc7,0x89,0x55,0x47,0xfb,0xa7,
	0x8b,0x20,0x24,0x88,0x4e,0xd4,0xb1,0x75,0xda,0x39,0x7d,0x33,0xad,0xba,0xf9,0x40,
	0x63,0xd5,0xe6,0x68,0x1e,0xed,0xf5,0xc2,0xe3,0x60,0x01,0x79,0x7e,0x9a,0xf1,0x31,
	0x00,0xcb,0x41,0xa2,0x36,0x18,0x9b,0x9e,0x91,0x32,0xaf,0x7f,0x85,0xb5,0xa8,0xeb,
	0x61,0x71,0x23,0x04,0x2d,0xe9,0xdc,0xcf,0x2f,0x34,0xa2,0x7e,0xb4,0xcb,0x92,0xe9,
	0x2e,0x43,0xdf,0xa6,0x8b,0x96,0x07,0x89,0x93,0x13,0xd8,0x6d,0xed,0x00,0xa9,0xaa,
	0x7f,0xb4,0x4d,0xe0,0x22,0x35,0x61,0x54,0xa2,0xdf,0xc7,0x4c,0x9a,0x7b,0x2c,0x88,
	0x24,0xaa,0xa5,0x7e,0x54,0xf6,0x78,0x28,0x88,0x3f,0x3f,0xbe,0xdc,0xd4,0x5b,0xb0,
	0xc7,0xc4,0xca,0x3a,0x42,0x7e,0xb4,0x9d,0x94,0xe7,0x2f,0x69,0x67,0xe9,0x8e,0x79,
	0x80,0xe4,0xf1,0x52,0x56,0xb7,0x83,0xed,0xb2,0x69,0x68,0xe6,0x90,0xe1,0x10,0x01,
	0x4a,0x73,0x29,0x47,0xc0,0x4f,0xdb,0x78,0x50,0x67,0x38,0xa6,0x02,0xf1,0xfa,0xea,
	0x78,0x8c,0x9e,0xf1,0x26,0xa7,0xb3,0xe3,0xbc,0x87,0x86,0x60,0x70,0x8d,0x03,0x62,
	0x4d,0x65,0x30,0xa0,0x6f,0xcd,0xc7,0xe9,0x84,0x08,0x89,0x29,0xbf,0xa2,0x00,0xc7,
	0xb1,0x6f,0x16,0xd0,0x58,0xec,0x3f,0x7f,0x4f,0x28,0x49,0xa5,0xa3,0x1e,0xac,0x53,
	0xaf,0xd0,0xd8,0xd4,0xc5,0xc8,0xf3,0x0f,0xfb,0x23,0xcf,0xb3,0x46,0xfe,0x76,0xd3,
	0x48,0x65,0x09,0xca,0xc7,0x79,0x38,0x70,0xa5,0x83,0x45,0x3e,0x18,0x3f,0x92,0x3b,
	0x20,0x5a,0xf8,0x02,0x31,0x13,0x71,0xb3,0x7c,0x3a,0xe4,0x0b,0x22,0xaa,0x08,0xe2,
	0x2b,0xa0,0xc7,0x9e,0x5e,0xfe,0xf9,0x08,0x15,0x50,0xa2,0x61,0xfe,0x92,0xe1,0x96,
	0x11,0x54,0xc2,0x64,0x04,0x8c,0x9c,0x25,0x4a,0xd8,0xc9,0x63,0x78,0xb3,0x0b,0x35,
	0xeb,0xd4,0x9e,0x63,0xbb,0xe1,0x6e,0x20,0x9c,0xe9,0x71,0x47,0xa9,0xdf,0x68,0xee,
	0x52,0x23,0x52,0x33,0x7a,0x93,0x8e,0xed,0xbb,0x8d,0x42,0xc5,0xa3,0x92,0xad,0x7a,
	0xf5,0xf9,0x17,0xa5,0x8a,0xb7,0x10,0xab,0x06,0x76,0x85,0x52,0x8b,0x42,0xdc,0x8c,
	0xd9,0xf0,0x74,0x9c,0x76,0xaf,0xf6,0x89,0x9b,0xa4,0x9f,0xa9,0x0d,0x64,0x47,0x34,
	0x9b,0x9f,0x3a,0xad,0x07,0xbe,0x86,0x0a,0x0a,0x26,0x77,0x10,0xb8,0x12,0x31,0xe3,
	0xde,0x1e,0x06,0xc7,0x41,0x79,0x07,0x4c,0x1f,0x27,0x35,0x48,0x34,0x2a,0x38,0x34,
	0xf6,0x6d,0x6b,0x26,0x05,0xf9,0xb4,0xaf,0xf1,0xea,0xb1,0x66,0xed,0x28,0xdf,0x38,
	0x62,0xc6,0x63,0x88,0x7a,0x4e,0x26,0xe2,0xeb,0xf5,0x78,0xe2,0xd5,0xb7,0x38,0x23,
	0x3a,0x45,0x6a,0x1f,0x01,0xb2,0x79,0xc1,0x35,0x85,0x37,0x90,0x6a,0x20,0x47,0xf6,
	0xff,0x5c,0x00,0x96,0xb3,0x79,0x20,0x85,0x7c,0x85,0xa5,0x47,0x14,0xa1,0xd0,0xd2,
	0x55,0x03,0x00,0x00,0x03,0x08,0x00,0x00,0x46,0x69,0x72,0x6d,0x77,0x61,0x72,0x65,
	0x01,0x01,0x07,0x00,0x45,0x23,0x01,0x00,0x54,0x65,0x73,0x74,0x69,0x6e,0x67,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x00,0xff,0xff,0x07,0x00,0x00,0x01,0x01,0x00,
	0xb3,0xde,0x4e,0x5a,0xd6,0xa8,0x6d,0x96,0x5c,0xd9,0x4a,0xa6,0x75,0xf2,0xc2,0x75,
	0xfc,0xd5,0x4c,0x7c,0x68,0xef,0xf7,0xca,0xc1,0x20,0x0f,0x08,0x32,0x9e,0x39,0x45,
	0x00,0x00,0x00,0x00,0xff,0xff,0x03,0x00,0x02,0x02,0x09,0x00,0x45,0x23,0x01,0x01,
	0x54,0x65,0x73,0x74,0x69,0x6e,0x67,0x56,0x32,0x00,0x00,0x00,0x01,0x00,0x00,0x00,
	0x00,0x00,0x0c,0x00,0xff,0xff,0x0f,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,
	0xff,0xff,0x7f,0x00,0x01,0x01,0x01,0x00,0xe5,0x9b,0xff,0xb3,0x12,0xf9,0x3d,0x27,
	0xe5,0x03,0xfb,0x23,0xc1,0x9c,0x0c,0x3d,0xfd,0x55,0x65,0xe9,0x34,0xe8,0x47,0xf0,
	0x31,0x19,0x76,0x49,0x22,0x52,0x32,0x3c,0xb1,0x7a,0x24,0x8d,0x6f,0xf5,0x0c,0x51,
	0x63,0x39,0x08,0x7e,0xe2,0x66,0xcb,0x24,0x00,0x00,0x08,0x00,0xff,0xff,0x0b,0x00,
	0x00,0x01,0x01,0x00,0xc9,0x27,0x6c,0x4a,0x36,0xdc,0xa3,0x27,0x4a,0x75,0x03,0xef,
	0x28,0xe1,0x32,0xcc,0x60,0xbf,0x60,0x05,0xb7,0x58,0x2b,0xd3,0xdf,0xb9,0x53,0x08,
	0xeb,0xed,0xc1,0xaa,0x00,0x00,0x10,0x00,0xff,0xff,0x3f,0x00,0x03,0x03,0x09,0x00,
	0x45,0x23,0x01,0x02,0x54,0x65,0x73,0x74,0x69,0x6e,0x67,0x56,0x33,0x00,0x00,0x00,
	0x02,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0xff,0xff,0xff,0x00,0x01,0x00,0x00,0x00,
	0x00,0x00,0x00,0x04,0xff,0xff,0xff,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0c,
	0xff,0xff,0xff,0x0f,0x02,0x01,0x01,0x00,0x7b,0x7d,0x38,0x90,0xe2,0x1f,0x1a,0xcf,
	0xb2,0x34,0xaf,0xe4,0xaf,0x78,0x9d,0x6b,0x94,0xb8,0xd7,0xee,0xa8,0xd1,0xaa,0x7a,
	0xb9,0xc9,0x18,0x82,0x6d,0x41,0x70,0x59,0xf3,0xd2,0x8b,0xc3,0x5c,0xef,0x49,0xdb,
	0xee,0x4f,0xaf,0xe1,0x6a,0x52,0x25,0x6f,0x72,0x3a,0x91,0xc0,0xdf,0xec,0xea,0xc7,
	0xc5,0x1b,0x74,0x39,0x9c,0x68,0x26,0xb4,0x00,0x00,0x80,0x00,0xff,0xff,0xbf,0x00,
	0x01,0x01,0x01,0x00,0x36,0xdc,0x9e,0x38,0xb6,0xef,0xd0,0x20,0xee,0xcd,0xb0,0x79,
	0xc3,0x49,0x2d,0xed,0xc0,0xa3,0x19,0x7c,0x69,0x9f,0x54,0x91,0x94,0x13,0x15,0x5d,
	0xe9,0x48,0xc2,0x70,0xe2,0xcc,0xac,0xbc,0xd5,0x56,0x4f,0x99,0x38,0x36,0x08,0xcf,
	0xc9,0x63,0xb4,0x1b,0x00,0x00,0x00,0x01,0xff,0xff,0xff,0x03,0x00,0x01,0x01,0x00,
	0xef,0x5d,0xa8,0xdf,0x10,0xb6,0x02,0xf4,0x82,0x22,0x91,0x97,0xd2,0xd4,0xdc,0xdd,
	0x67,0x26,0xc2,0xc0,0xfc,0x25,0xe0,0x04,0x55,0xea,0x98,0x34,0x9a,0x33,0xcc,0xcc,
	0x00,0x00,0x00,0x08,0xff,0xff,0xff,0x0b,0x09,0x00,0x00,0x00,0x50,0x46,0x4d,0x20,
	0x54,0x65,0x73,0x74,0x32,0x00,0x00,0x00,0x03,0x09,0x00,0x00,0x46,0x69,0x72,0x6d,
	0x77,0x61,0x72,0x65,0x32,0x00,0x00,0x00,0x02,0x02,0x08,0x00,0x45,0x23,0x11,0x01,
	0x54,0x65,0x73,0x74,0x69,0x6e,0x67,0x32,0x01,0x00,0x00,0x00,0x00,0x00,0x0c,0x10,
	0xff,0xff,0x0f,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x10,0xff,0xff,0x7f,0x10,
	0x01,0x01,0x01,0x00,0x80,0x1b,0x57,0xd8,0x07,0x23,0x7d,0x6e,0x2c,0x38,0x22,0x51,
	0x55,0x62,0x06,0x91,0xed,0x1c,0x37,0xa2,0x7f,0x3e,0x02,0xa8,0x3a,0x5a,0xbc,0x2f,
	0x29,0xcc,0xa1,0x41,0x6c,0xe7,0x41,0x7f,0x3d,0xe2,0xc3,0xfd,0xb9,0x31,0x31,0xb9,
	0x4a,0x11,0xa2,0xe0,0x00,0x00,0x08,0x10,0xff,0xff,0x0b,0x10,0x00,0x01,0x01,0x00,
	0x9e,0x99,0x2d,0x16,0xc8,0x1e,0x12,0x7c,0x9a,0x2f,0xa0,0x54,0x02,0x6e,0xcd,0x0e,
	0xfd,0xf5,0xf4,0x9e,0x6e,0x14,0x29,0xdd,0x3a,0x7a,0x53,0x5e,0xdf,0xeb,0x02,0xf7,
	0x00,0x00,0x10,0x10,0xff,0xff,0x3f,0x10,0x03,0x03,0x0a,0x00,0x45,0x23,0x11,0x02,
	0x54,0x65,0x73,0x74,0x69,0x6e,0x67,0x32,0x56,0x32,0x00,0x00,0x02,0x00,0x00,0x00,
	0x00,0x00,0xc0,0x10,0xff,0xff,0xff,0x10,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x14,
	0xff,0xff,0xff,0x17,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x1c,0xff,0xff,0xff,0x1f,
	0x02,0x01,0x01,0x00,0x80,0x2a,0xb6,0xa3,0xaf,0x82,0x9d,0x85,0x4a,0xf4,0xf9,0x14,
	0x8b,0xc2,0x19,0x81,0x97,0x54,0xea,0x0d,0x4f,0x39,0x46,0xe9,0xcc,0xbf,0xc4,0x42,
	0x61,0xc9,0x1d,0x46,0x79,0x73,0xa0,0x73,0x0c,0xe8,0xcf,0x56,0x93,0x18,0x4f,0xae,
	0x6d,0x87,0xb2,0x5c,0x37,0x28,0xc1,0x2c,0xf5,0x45,0x2b,0x02,0x9c,0x82,0x08,0xa3,
	0x39,0x27,0x0b,0xe4,0x00,0x00,0x80,0x10,0xff,0xff,0xbf,0x10,0x01,0x01,0x01,0x00,
	0x3b,0x14,0xad,0x34,0xff,0x8f,0xc4,0x92,0xb9,0x22,0x67,0xdb,0x20,0xeb,0xa9,0x6a,
	0xa0,0x4c,0x35,0x3b,0xc8,0x40,0x43,0x7a,0x27,0x1e,0x10,0x04,0xd3,0x77,0x4b,0x81,
	0x48,0x05,0x1a,0xd3,0x89,0xc2,0x73,0x6e,0xad,0x90,0x55,0xa3,0x12,0x22,0x42,0xce,
	0x00,0x00,0x00,0x11,0xff,0xff,0xff,0x13,0x00,0x01,0x01,0x00,0x62,0x5e,0x69,0x2c,
	0xd4,0x46,0xf2,0x66,0x87,0x7e,0x4c,0x35,0x64,0x5d,0x2b,0x31,0xe0,0x05,0x65,0x67,
	0x96,0x60,0xa7,0x8f,0xb4,0x77,0xb8,0x25,0xf6,0x00,0x4c,0x65,0x00,0x00,0x00,0x18,
	0xff,0xff,0xff,0x1b,0x01,0x01,0x0a,0x00,0x45,0x23,0x11,0x00,0x54,0x65,0x73,0x74,
	0x69,0x6e,0x67,0x32,0x56,0x33,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x10,
	0xff,0xff,0x07,0x10,0x00,0x01,0x01,0x00,0x8e,0x7e,0xe2,0xb5,0x73,0xea,0x3b,0x0a,
	0xfa,0xe1,0xde,0x65,0x8a,0x47,0x0a,0x77,0x38,0xea,0xd8,0x9d,0x48,0x51,0x1b,0x5c,
	0xef,0x46,0xb8,0x6d,0x7d,0x55,0x05,0x23,0x00,0x00,0x00,0x10,0xff,0xff,0x03,0x10,
	0x03,0x03,0x00,0x00,0x46,0x57,0x33,0x00,0x03,0x03,0x05,0x00,0x45,0x23,0x21,0x02,
	0x54,0x65,0x73,0x74,0x33,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,0x00,0xc0,0x20,
	0xff,0xff,0xff,0x20,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x24,0xff,0xff,0xff,0x27,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x2c,0xff,0xff,0xff,0x2f,0x02,0x01,0x01,0x00,
	0x1a,0x38,0xc5,0x38,0x9e,0x45,0x90,0x13,0x69,0x6d,0x9a,0x4f,0x47,0xa2,0x8d,0x26,
	0xa5,0x9a,0xf0,0x46,0x60,0x2e,0xd2,0x41,0x75,0xea,0x45,0x23,0xa6,0x1d,0x64,0x3a,
	0x19,0x25,0x60,0xfa,0x5e,0x32,0x80,0x8b,0x7d,0xb6,0x76,0xe2,0xcd,0x15,0xef,0xb0,
	0x45,0xa0,0xc4,0xbb,0xea,0x6a,0x74,0x10,0x82,0xee,0x5d,0xb2,0x54,0x19,0xf2,0xa4,
	0x00,0x00,0x80,0x20,0xff,0xff,0xbf,0x20,0x01,0x01,0x01,0x00,0x92,0x4f,0xbe,0x94,
	0xae,0xa7,0xbe,0x52,0x8e,0xeb,0xa4,0x68,0x87,0x57,0x07,0x62,0xc5,0x3b,0xcb,0x1d,
	0x97,0x74,0x49,0xfc,0xcb,0x08,0xe2,0xe7,0x4b,0xd4,0xea,0xa7,0x40,0xcc,0x02,0x01,
	0x99,0xc3,0x11,0x2f,0xe8,0x97,0x72,0xbc,0xb6,0x2a,0x5b,0x11,0x00,0x00,0x00,0x21,
	0xff,0xff,0xff,0x23,0x00,0x01,0x01,0x00,0x94,0x6e,0xbf,0x60,0xe8,0xf0,0xf0,0x64,
	0xe3,0x1c,0x6f,0x12,0xb8,0xcf,0x50,0x95,0x77,0xcd,0x1c,0x74,0xb1,0xc4,0x83,0x1c,
	0x1a,0x3c,0x1c,0xcf,0x31,0x52,0x12,0x4c,0x00,0x00,0x00,0x28,0xff,0xff,0xff,0x2b,
	0x01,0x01,0x07,0x00,0x45,0x23,0x21,0x00,0x54,0x65,0x73,0x74,0x33,0x56,0x32,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x20,0xff,0xff,0x07,0x20,0x00,0x01,0x01,0x00,
	0x9e,0x7b,0xe5,0x18,0x13,0x15,0x44,0x5a,0x3f,0xae,0xa1,0xc4,0x0e,0x10,0x42,0x0c,
	0x3c,0xbc,0x66,0x7a,0x7f,0x32,0xf8,0x68,0x21,0x13,0xba,0xbf,0x21,0x91,0xce,0x44,
	0x00,0x00,0x00,0x20,0xff,0xff,0x03,0x20,0x02,0x02,0x07,0x00,0x45,0x23,0x21,0x01,
	0x54,0x65,0x73,0x74,0x33,0x56,0x33,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x0c,0x20,
	0xff,0xff,0x0f,0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x20,0xff,0xff,0x7f,0x20,
	0x01,0x01,0x01,0x00,0x50,0x4b,0x83,0xec,0xfa,0x48,0xe8,0x00,0x5e,0xdd,0xd4,0xeb,
	0x09,0x11,0x0f,0xeb,0x19,0x7e,0x0a,0x50,0x36,0x31,0xce,0x6e,0xd2,0x12,0x34,0xce,
	0xbd,0x85,0xb3,0xae,0x9a,0xc4,0x0b,0x55,0x70,0x26,0x6e,0x40,0x72,0xc1,0x6f,0x01,
	0xe2,0x98,0x24,0xa2,0x00,0x00,0x08,0x20,0xff,0xff,0x0b,0x20,0x00,0x01,0x01,0x00,
	0x43,0x04,0x72,0x79,0x2f,0x1d,0x4a,0x92,0x50,0x6e,0x72,0xd7,0xf4,0xb1,0x6a,0x9d,
	0x38,0x36,0x2d,0xf1,0x92,0x0b,0x75,0xbf,0x56,0xe8,0xe6,0x4e,0x99,0x4e,0xa4,0x31,
	0x00,0x00,0x10,0x20,0xff,0xff,0x3f,0x20,0x30,0x66,0x02,0x31,0x00,0x92,0xdb,0x6b,
	0x05,0xb7,0x79,0x99,0xa7,0x46,0xc2,0x42,0x19,0xd8,0xb4,0x3b,0x9b,0x76,0x42,0xed,
	0x78,0x3f,0x25,0xa6,0x51,0x7d,0xdd,0x12,0xe4,0xb7,0x8b,0x54,0xfc,0x3a,0x9b,0x66,
	0x64,0x25,0xb7,0x70,0xf0,0x55,0x05,0x91,0x76,0x1d,0xcc,0xa4,0x11,0x02,0x31,0x00,
	0xc6,0xc9,0x46,0x45,0xb1,0xca,0xa0,0xd5,0x83,0x44,0x52,0x2a,0xfe,0x29,0xe6,0xf4,
	0x34,0x3d,0xd3,0x93,0xf7,0x5e,0x7c,0x78,0x35,0x0f,0xb0,0xcf,0x21,0xd8,0xb1,0x71,
	0x7c,0xdd,0x27,0x23,0xaa,0xb0,0xa7,0x61,0x0b,0x6b,0xf5,0x9d,0x57,0xf0,0x95,0x9c,
	0x00
};

/**
 * PFM_V2_MULTIPLE_DATA hash for testing.
 *
 * head -c -105 pfm.img | openssl dgst -sha384
 */
static const uint8_t PFM_V2_MULTIPLE_HASH[] = {
	0xd7,0x76,0xf7,0xf9,0xe7,0xf3,0x4e,0x90,0x64,0x5b,0x3b,0xa3,0x20,0xdd,0x39,0x7b,
	0x27,0x78,0x93,0x63,0x8f,0xaf,0x44,0x8b,0x80,0x6b,0x33,0xd4,0xe8,0x7d,0xb6,0x96,
	0x7d,0x71,0x6e,0x60,0xaf,0x7f,0x6a,0xdd,0x4e,0xe9,0x3c,0x2a,0x8f,0xb7,0xcc,0xd7
};

/**
 * First firmware image of the first firmware component for the test v2 PFM with multiple firmware
 * elements.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_MULTIPLE_11[] = {
	{
		.img_offset = 0x037c,
		.hash = PFM_V2_MULTIPLE_DATA + 0x0380,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG1_11_REGION
	}
};

/**
 * Second firmware image of the first firmware copmonent for test v2 PFM with multiple firmware
 * elements.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_MULTIPLE_12[] = {
	{
		.img_offset = 0x03d4,
		.hash = PFM_V2_MULTIPLE_DATA + 0x03d8,
		.hash_len = 48,
		.hash_type = HASH_TYPE_SHA384,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG1_21_REGION
	},
	{
		.img_offset = 0x0410,
		.hash = PFM_V2_MULTIPLE_DATA + 0x0414,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 0,
		.region_count = 1,
		.region = PFM_V2_IMG1_22_REGION
	}
};

/**
 * Third firmware image of the first firmware component for the test v2 PFM with multiple firmware
 * elements.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_MULTIPLE_13[] = {
	{
		.img_offset = 0x0474,
		.hash = PFM_V2_MULTIPLE_DATA + 0x0478,
		.hash_len = 64,
		.hash_type = HASH_TYPE_SHA512,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG1_31_REGION
	},
	{
		.img_offset = 0x04c0,
		.hash = PFM_V2_MULTIPLE_DATA + 0x04c4,
		.hash_len = 48,
		.hash_type = HASH_TYPE_SHA384,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG1_32_REGION
	},
	{
		.img_offset = 0x04fc,
		.hash = PFM_V2_MULTIPLE_DATA + 0x0500,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG1_33_REGION
	}
};

/**
 * First firmware version components of the test v2 PFM with multiple firmware elements.
 */
static const struct pfm_v2_testing_data_fw_ver PFM_V2_FW_VER_MULTIPLE_1[] = {
	{
		.fw_version = PFM_V2_MULTIPLE_DATA + 0x0360,
		.fw_version_len = 0x0048,
		.version_str = PFM_V2_FW_VERSION,
		.version_str_len = sizeof (PFM_V2_FW_VERSION) - 1,
		.version_str_pad = PFM_V2_FW_VERSION_PAD,
		.fw_version_offset = 0x0360,
		.fw_version_entry = 2,
		.fw_version_hash = 1,
		.version_addr = 0x012345,
		.rw_count = 1,
		.rw = PFM_V2_RW1_ONE,
		.img_count = 1,
		.img = PFM_V2_FW_IMG_MULTIPLE_11
	},
	{
		.fw_version = PFM_V2_MULTIPLE_DATA + 0x03a8,
		.fw_version_len = 0x0094,
		.version_str = PFM_V2_FW_VERSION_V2,
		.version_str_len = sizeof (PFM_V2_FW_VERSION_V2) - 1,
		.version_str_pad = PFM_V2_FW_VERSION_V2_PAD,
		.fw_version_offset = 0x03a8,
		.fw_version_entry = 3,
		.fw_version_hash = 8,
		.version_addr = 0x1012345,
		.rw_count = 2,
		.rw = PFM_V2_RW1_TWO,
		.img_count = 2,
		.img = PFM_V2_FW_IMG_MULTIPLE_12
	},
	{
		.fw_version = PFM_V2_MULTIPLE_DATA + 0x043c,
		.fw_version_len = 0x00ec,
		.version_str = PFM_V2_FW_VERSION_V3,
		.version_str_len = sizeof (PFM_V2_FW_VERSION_V3) - 1,
		.version_str_pad = PFM_V2_FW_VERSION_V3_PAD,
		.fw_version_offset = 0x043c,
		.fw_version_entry = 4,
		.fw_version_hash = 11,
		.version_addr = 0x2012345,
		.rw_count = 3,
		.rw = PFM_V2_RW1_THREE,
		.img_count = 3,
		.img = PFM_V2_FW_IMG_MULTIPLE_13
	}
};

/**
 * First firmware image of the second firmware copmonent for test v2 PFM with multiple firmware
 * elements.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_MULTIPLE_21[] = {
	{
		.img_offset = 0x0570,
		.hash = PFM_V2_MULTIPLE_DATA + 0x0574,
		.hash_len = 48,
		.hash_type = HASH_TYPE_SHA384,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG2_21_REGION
	},
	{
		.img_offset = 0x05ac,
		.hash = PFM_V2_MULTIPLE_DATA + 0x05b0,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG2_22_REGION
	}
};

/**
 * Second firmware image of the second firmware component for the test v2 PFM with multiple firmware
 * elements.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_MULTIPLE_22[] = {
	{
		.img_offset = 0x0610,
		.hash = PFM_V2_MULTIPLE_DATA + 0x0614,
		.hash_len = 64,
		.hash_type = HASH_TYPE_SHA512,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG2_31_REGION
	},
	{
		.img_offset = 0x065c,
		.hash = PFM_V2_MULTIPLE_DATA + 0x0660,
		.hash_len = 48,
		.hash_type = HASH_TYPE_SHA384,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG2_32_REGION
	},
	{
		.img_offset = 0x0698,
		.hash = PFM_V2_MULTIPLE_DATA + 0x069c,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG2_33_REGION
	}
};

/**
 * Third firmware image of the second firmware component for the test v2 PFM with multiple firmware
 * elements.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_MULTIPLE_23[] = {
	{
		.img_offset = 0x06e4,
		.hash = PFM_V2_MULTIPLE_DATA + 0x06e8,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG2_11_REGION
	}
};

/**
 * Second firmware version components of the test v2 PFM with multiple firmware elements.
 */
static const struct pfm_v2_testing_data_fw_ver PFM_V2_FW_VER_MULTIPLE_2[] = {
	{
		.fw_version = PFM_V2_MULTIPLE_DATA + 0x0548,
		.fw_version_len = 0x0090,
		.version_str = PFM_V2_FW_VERSION2,
		.version_str_len = sizeof (PFM_V2_FW_VERSION2) - 1,
		.version_str_pad = PFM_V2_FW_VERSION2_PAD,
		.fw_version_offset = 0x0548,
		.fw_version_entry = 7,
		.fw_version_hash = 2,
		.version_addr = 0x1112345,
		.rw_count = 2,
		.rw = PFM_V2_RW2_TWO,
		.img_count = 2,
		.img = PFM_V2_FW_IMG_MULTIPLE_21
	},
	{
		.fw_version = PFM_V2_MULTIPLE_DATA + 0x05d8,
		.fw_version_len = 0x00ec,
		.version_str = PFM_V2_FW_VERSION2_V2,
		.version_str_len = sizeof (PFM_V2_FW_VERSION2_V2) - 1,
		.version_str_pad = PFM_V2_FW_VERSION2_V2_PAD,
		.fw_version_offset = 0x05d8,
		.fw_version_entry = 8,
		.fw_version_hash = 9,
		.version_addr = 0x2112345,
		.rw_count = 3,
		.rw = PFM_V2_RW2_THREE,
		.img_count = 3,
		.img = PFM_V2_FW_IMG_MULTIPLE_22
	},
	{
		.fw_version = PFM_V2_MULTIPLE_DATA + 0x06c4,
		.fw_version_len = 0x004c,
		.version_str = PFM_V2_FW_VERSION2_V3,
		.version_str_len = sizeof (PFM_V2_FW_VERSION2_V3) - 1,
		.version_str_pad = PFM_V2_FW_VERSION2_V3_PAD,
		.fw_version_offset = 0x06c4,
		.fw_version_entry = 9,
		.fw_version_hash = 12,
		.version_addr = 0x0112345,
		.rw_count = 1,
		.rw = PFM_V2_RW2_ONE,
		.img_count = 1,
		.img = PFM_V2_FW_IMG_MULTIPLE_23
	}
};

/**
 * First firmware image of the third firmware component for the test v2 PFM with multiple firmware
 * elements.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_MULTIPLE_31[] = {
	{
		.img_offset = 0x074c,
		.hash = PFM_V2_MULTIPLE_DATA + 0x0750,
		.hash_len = 64,
		.hash_type = HASH_TYPE_SHA512,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG3_31_REGION
	},
	{
		.img_offset = 0x0798,
		.hash = PFM_V2_MULTIPLE_DATA + 0x079c,
		.hash_len = 48,
		.hash_type = HASH_TYPE_SHA384,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG3_32_REGION
	},
	{
		.img_offset = 0x07d4,
		.hash = PFM_V2_MULTIPLE_DATA + 0x07d8,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG3_33_REGION
	}
};

/**
 * Second firmware image of the third firmware component for the test v2 PFM with multiple firmware
 * elements.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_MULTIPLE_32[] = {
	{
		.img_offset = 0x081c,
		.hash = PFM_V2_MULTIPLE_DATA + 0x0820,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG3_11_REGION
	}
};

/**
 * Third firmware image of the third firmware copmonent for test v2 PFM with multiple firmware
 * elements.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_MULTIPLE_33[] = {
	{
		.img_offset = 0x0870,
		.hash = PFM_V2_MULTIPLE_DATA + 0x0874,
		.hash_len = 48,
		.hash_type = HASH_TYPE_SHA384,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG3_21_REGION
	},
	{
		.img_offset = 0x08ac,
		.hash = PFM_V2_MULTIPLE_DATA + 0x08b0,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG3_22_REGION
	}
};

/**
 * Thrid firmware version components of the test v2 PFM with multiple firmware elements.
 */
static const struct pfm_v2_testing_data_fw_ver PFM_V2_FW_VER_MULTIPLE_3[] = {
	{
		.fw_version = PFM_V2_MULTIPLE_DATA + 0x0718,
		.fw_version_len = 0x00e8,
		.version_str = PFM_V2_FW_VERSION3,
		.version_str_len = sizeof (PFM_V2_FW_VERSION3) - 1,
		.version_str_pad = PFM_V2_FW_VERSION3_PAD,
		.fw_version_offset = 0x0718,
		.fw_version_entry = 11,
		.fw_version_hash = 3,
		.version_addr = 0x2212345,
		.rw_count = 3,
		.rw = PFM_V2_RW3_THREE,
		.img_count = 3,
		.img = PFM_V2_FW_IMG_MULTIPLE_31
	},
	{
		.fw_version = PFM_V2_MULTIPLE_DATA + 0x0800,
		.fw_version_len = 0x0048,
		.version_str = PFM_V2_FW_VERSION3_V2,
		.version_str_len = sizeof (PFM_V2_FW_VERSION3_V2) - 1,
		.version_str_pad = PFM_V2_FW_VERSION3_V2_PAD,
		.fw_version_offset = 0x0800,
		.fw_version_entry = 12,
		.fw_version_hash = 10,
		.version_addr = 0x0212345,
		.rw_count = 1,
		.rw = PFM_V2_RW3_ONE,
		.img_count = 1,
		.img = PFM_V2_FW_IMG_MULTIPLE_32
	},
	{
		.fw_version = PFM_V2_MULTIPLE_DATA + 0x0848,
		.fw_version_len = 0x0090,
		.version_str = PFM_V2_FW_VERSION3_V3,
		.version_str_len = sizeof (PFM_V2_FW_VERSION3_V3) - 1,
		.version_str_pad = PFM_V2_FW_VERSION3_V3_PAD,
		.fw_version_offset = 0x0848,
		.fw_version_entry = 13,
		.fw_version_hash = 13,
		.version_addr = 0x1212345,
		.rw_count = 2,
		.rw = PFM_V2_RW3_TWO,
		.img_count = 2,
		.img = PFM_V2_FW_IMG_MULTIPLE_33
	}
};

/**
 * Firmware components of the test v2 PFM with multiple firmware elements.
 */
static const struct pfm_v2_testing_data_fw PFM_V2_FW_MULTIPLE[] = {
	{
		.fw = PFM_V2_MULTIPLE_DATA + 0x0354,
		.fw_len = 0x000c,
		.fw_id_str = PFM_V2_FIRMWARE_ID,
		.fw_id_str_len = sizeof (PFM_V2_FIRMWARE_ID) - 1,
		.fw_id_str_pad = PFM_V2_FIRMWARE_ID_PAD,
		.fw_offset = 0x0354,
		.fw_entry = 1,
		.fw_hash = 5,
		.version_count = 3,
		.version = PFM_V2_FW_VER_MULTIPLE_1
	},
	{
		.fw = PFM_V2_MULTIPLE_DATA + 0x0538,
		.fw_len = 0x0010,
		.fw_id_str = PFM_V2_FIRMWARE_ID2,
		.fw_id_str_len = sizeof (PFM_V2_FIRMWARE_ID2) - 1,
		.fw_id_str_pad = PFM_V2_FIRMWARE_ID2_PAD,
		.fw_offset = 0x0538,
		.fw_entry = 6,
		.fw_hash = 6,
		.version_count = 3,
		.version = PFM_V2_FW_VER_MULTIPLE_2
	},
	{
		.fw = PFM_V2_MULTIPLE_DATA + 0x0710,
		.fw_len = 0x0008,
		.fw_id_str = PFM_V2_FIRMWARE_ID3,
		.fw_id_str_len = sizeof (PFM_V2_FIRMWARE_ID3) - 1,
		.fw_id_str_pad = PFM_V2_FIRMWARE_ID3_PAD,
		.fw_offset = 0x0710,
		.fw_entry = 10,
		.fw_hash = 7,
		.version_count = 3,
		.version = PFM_V2_FW_VER_MULTIPLE_3
	}
};

/**
 * Components of the test v2 PFM with multiple firmware elements.
 */
const struct pfm_v2_testing_data PFM_V2_MULTIPLE = {
	.manifest = {
		.raw = PFM_V2_MULTIPLE_DATA,
		.length = sizeof (PFM_V2_MULTIPLE_DATA),
		.hash = PFM_V2_MULTIPLE_HASH,
		.hash_len = sizeof (PFM_V2_MULTIPLE_HASH),
		.id = 13,
		.signature = PFM_V2_MULTIPLE_DATA + (sizeof (PFM_V2_MULTIPLE_DATA) - 105),
		.sig_len = 105,
		.sig_offset = (sizeof (PFM_V2_MULTIPLE_DATA) - 105),
		.sig_hash_type = HASH_TYPE_SHA384,
		.toc = PFM_V2_MULTIPLE_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x0344,
		.toc_hash = PFM_V2_MULTIPLE_DATA + 0x0320,
		.toc_hash_len = 48,
		.toc_hash_offset = 0x0320,
		.toc_hash_type = HASH_TYPE_SHA384,
		.toc_entries = 14,
		.toc_hashes = 14,
		.plat_id = PFM_V2_MULTIPLE_DATA + 0x0528,
		.plat_id_len = 0x0010,
		.plat_id_str = PFM_V2_PLATFORM_ID2,
		.plat_id_str_len = sizeof (PFM_V2_PLATFORM_ID2) - 1,
		.plat_id_str_pad = PFM_V2_PLATFORM_ID2_PAD,
		.plat_id_offset = 0x0528,
		.plat_id_entry = 5,
		.plat_id_hash = 4
	},
	.flash_dev = PFM_V2_MULTIPLE_DATA + 0x0350,
	.flash_dev_len = 4,
	.flash_dev_offset = 0x0350,
	.flash_dev_entry = 0,
	.flash_dev_hash = 0,
	.blank_byte = 0x55,
	.fw_count = 3,
	.fw = PFM_V2_FW_MULTIPLE
};

/**
 * Test PFM in v2 format.  Contains three firmware images with large firmware version strings:
 * max version string, max string with no padding, large string without needing R/W to be read
 * again.
 *
 * NUM_FW=3 MAX_VERSION=1 ./generate_pfm.sh 14 ../../core/testing/keys/rsapriv.pem
 */
static const uint8_t PFM_V2_MAX_VERSION_DATA[] = {
	0x28,0x07,0x6d,0x70,0x0e,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x08,0x08,0x00,0x00,
	0x10,0xff,0x00,0x00,0x70,0x01,0x04,0x00,0x11,0xff,0x01,0x05,0x74,0x01,0x0c,0x00,
	0x12,0x11,0x01,0x01,0x80,0x01,0x40,0x01,0x00,0xff,0x01,0x04,0xc0,0x02,0x10,0x00,
	0x11,0xff,0x01,0x06,0xd0,0x02,0x10,0x00,0x12,0x11,0x01,0x02,0xe0,0x02,0x84,0x01,
	0x11,0xff,0x01,0x07,0x64,0x04,0x08,0x00,0x12,0x11,0x01,0x03,0x6c,0x04,0xbc,0x01,
	0xbd,0xdc,0x2e,0x22,0xf5,0xa0,0x30,0x66,0xde,0xdb,0x6a,0xf5,0x5f,0x4d,0x76,0x95,
	0x52,0x8d,0x71,0x9c,0xea,0x2a,0x86,0x05,0xfc,0xcb,0xaf,0x5e,0x07,0xc7,0x25,0xa9,
	0xc6,0x05,0xc2,0xd7,0xdd,0x10,0x8c,0x8f,0x24,0x2e,0x2a,0x42,0xe7,0x04,0x2f,0x40,
	0x19,0xb7,0x57,0x9f,0xbb,0xbe,0x71,0x19,0x56,0x86,0x91,0xc1,0x6b,0xb6,0x4f,0xef,
	0xfd,0x92,0x8b,0xf7,0x44,0x7b,0xaf,0xc2,0xa8,0xc3,0xaa,0x6b,0x6d,0x72,0x59,0xe9,
	0x98,0x04,0xad,0xbe,0xec,0x37,0x8c,0x40,0x5b,0x04,0xff,0x4c,0x0f,0x11,0x03,0xa1,
	0x21,0xd8,0xc9,0xdc,0x88,0xc2,0x50,0x36,0x7d,0x70,0x1b,0x64,0xb8,0x2f,0x13,0xdb,
	0x45,0x36,0x7b,0x8f,0x91,0x99,0xdd,0x4b,0x63,0xbe,0xb2,0x87,0x54,0x25,0x0c,0x77,
	0xd3,0xb6,0xeb,0x9b,0xe0,0x85,0xcd,0xd3,0xd6,0x05,0x81,0xc8,0x0b,0x38,0x6d,0x9a,
	0xf8,0x5b,0xae,0x5f,0xed,0x50,0x36,0x38,0x55,0x0c,0xf8,0xe8,0xdb,0xd8,0x82,0x46,
	0x13,0x48,0x15,0xa0,0xd1,0xfb,0x58,0x01,0xae,0x7a,0xa2,0x15,0xb4,0xf1,0x98,0x57,
	0xda,0x88,0x4d,0x95,0x99,0x18,0x27,0x0f,0x98,0x11,0xfe,0xe5,0xd4,0x0e,0x5b,0x6c,
	0xbf,0xa8,0xbe,0x1e,0x12,0xa0,0x18,0xd5,0x25,0xec,0xf8,0xc1,0x97,0x00,0xdb,0xd7,
	0xe8,0xaa,0x94,0x96,0x24,0xe9,0xde,0x93,0x00,0x0b,0x66,0x8b,0x5c,0x2e,0x96,0x37,
	0x1f,0xf1,0x6e,0x54,0xb0,0x0f,0x20,0xc4,0x19,0x33,0x20,0x1f,0xf5,0x33,0x0d,0x03,
	0xd8,0x88,0x95,0x31,0x11,0xcd,0xde,0x95,0x8e,0x47,0x86,0xff,0xd4,0xa4,0xbb,0x85,
	0x7b,0xe0,0x61,0x1c,0x6a,0xb1,0x3e,0x7e,0xe4,0x70,0xa2,0x06,0x24,0x92,0x15,0x14,
	0x23,0x03,0x14,0xf1,0x07,0x8d,0x8b,0x5b,0x1e,0x2b,0x2e,0xab,0xd1,0x5c,0x76,0xc3,
	0xff,0x03,0x00,0x00,0x01,0x08,0x00,0x00,0x46,0x69,0x72,0x6d,0x77,0x61,0x72,0x65,
	0x01,0x01,0xff,0x00,0x45,0x23,0x01,0x00,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x00,
	0xff,0xff,0x07,0x00,0x00,0x01,0x01,0x00,0xb8,0x33,0xbe,0x6f,0xc0,0x4e,0x45,0x69,
	0x6b,0x37,0x48,0xb2,0x15,0xf4,0x33,0xdb,0x80,0x68,0x13,0x7c,0x6f,0x0e,0xbb,0x83,
	0xae,0x49,0xfe,0x99,0xce,0x54,0x0e,0xbc,0x00,0x00,0x00,0x00,0xff,0xff,0x03,0x00,
	0x09,0x00,0x00,0x00,0x50,0x46,0x4d,0x20,0x54,0x65,0x73,0x74,0x31,0x00,0x00,0x00,
	0x01,0x09,0x00,0x00,0x46,0x69,0x72,0x6d,0x77,0x61,0x72,0x65,0x32,0x00,0x00,0x00,
	0x02,0x02,0xfc,0x00,0x45,0x23,0x11,0x01,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x01,0x00,0x00,0x00,0x00,0x00,0x0c,0x10,0xff,0xff,0x0f,0x10,
	0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x10,0xff,0xff,0x7f,0x10,0x01,0x01,0x01,0x00,
	0xc7,0xd5,0x65,0xc0,0x38,0x62,0x0e,0xf9,0xcb,0x6d,0xb3,0x3d,0x99,0xdc,0xd7,0xee,
	0xbb,0xae,0x51,0x25,0xd4,0xdb,0x4d,0xca,0xaa,0xeb,0x29,0xe7,0x95,0xdc,0x2e,0xc9,
	0xb3,0x6a,0x4f,0x8f,0xf3,0xe8,0xe0,0x24,0x6f,0xc2,0x03,0xf6,0x28,0xf7,0x8f,0x15,
	0x00,0x00,0x08,0x10,0xff,0xff,0x0b,0x10,0x00,0x01,0x01,0x00,0x1d,0xb1,0x36,0x32,
	0x33,0x37,0x02,0xd8,0x6e,0x7b,0xbd,0x09,0x04,0xaa,0xcd,0x42,0x6a,0xfd,0xc7,0xad,
	0xd3,0x03,0xbb,0xb4,0x3d,0x56,0x8a,0x6b,0x01,0x01,0x5d,0x4f,0x00,0x00,0x10,0x10,
	0xff,0xff,0x3f,0x10,0x01,0x03,0x00,0x00,0x46,0x57,0x33,0x00,0x03,0x03,0xdc,0x00,
	0x45,0x23,0x21,0x02,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x61,0x62,
	0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x61,0x62,
	0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x61,0x62,
	0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x61,0x62,
	0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x61,0x62,
	0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x61,0x62,
	0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x61,0x62,
	0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x61,0x62,
	0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x61,0x62,
	0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x61,0x62,
	0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x61,0x62,
	0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x61,0x62,
	0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x61,0x62,
	0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x61,0x62,
	0x02,0x00,0x00,0x00,0x00,0x00,0xc0,0x20,0xff,0xff,0xff,0x20,0x01,0x00,0x00,0x00,
	0x00,0x00,0x00,0x24,0xff,0xff,0xff,0x27,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x2c,
	0xff,0xff,0xff,0x2f,0x02,0x01,0x01,0x00,0x0b,0x29,0xa0,0x6d,0x49,0x84,0x68,0xac,
	0xff,0xb4,0x5e,0xe5,0x4a,0xa1,0xed,0xff,0xb8,0xdf,0x3c,0xbf,0x3e,0xe1,0x2c,0x05,
	0xb7,0xdc,0x6a,0x7c,0x1d,0x15,0x22,0x90,0xde,0x7f,0xa5,0xce,0x8e,0x86,0x8a,0xfe,
	0x0c,0xbb,0xc2,0x89,0x7a,0x56,0xbd,0xaa,0x29,0x15,0xcf,0xf9,0x16,0x44,0x54,0xe1,
	0x05,0xdc,0xb5,0xbe,0xdb,0x7f,0x5e,0x57,0x00,0x00,0x80,0x20,0xff,0xff,0xbf,0x20,
	0x01,0x01,0x01,0x00,0xc3,0x44,0x39,0x2d,0x2a,0x38,0x99,0x28,0x6d,0x49,0xef,0x3d,
	0xeb,0x9e,0xd8,0x1e,0xb4,0x17,0x7f,0xb2,0x13,0x59,0x21,0xd6,0xba,0x6b,0xa5,0x3e,
	0x7e,0x69,0xff,0x04,0x0b,0x86,0xfd,0xed,0x8c,0xee,0xf0,0x08,0xb0,0x56,0x14,0xf5,
	0x47,0x8c,0xfa,0xd0,0x00,0x00,0x00,0x21,0xff,0xff,0xff,0x23,0x00,0x01,0x01,0x00,
	0x5c,0xfe,0x20,0xc1,0xb9,0xad,0xa8,0xc8,0xb6,0x85,0x83,0x55,0x90,0xef,0x6a,0x91,
	0x9c,0x52,0xe1,0x8c,0x53,0xd5,0x5a,0x0b,0xfd,0x86,0xe7,0x14,0x8f,0xcf,0xa8,0x38,
	0x00,0x00,0x00,0x28,0xff,0xff,0xff,0x2b,0x99,0x5d,0x45,0xd5,0xa7,0x8a,0xac,0x02,
	0x75,0xb1,0xa0,0xbd,0xb0,0x22,0x4c,0xaa,0xc0,0xde,0x00,0xc8,0x64,0x45,0xb0,0xd7,
	0xaf,0x11,0x38,0xe5,0x38,0xf7,0xf8,0x9e,0x92,0xcf,0x1d,0x20,0x6f,0xf7,0x5d,0xb2,
	0x26,0x72,0x48,0xc0,0x9c,0xf7,0xdb,0x42,0x6c,0xf5,0x01,0x27,0xf0,0x73,0xfa,0xcf,
	0x67,0x6c,0x48,0x46,0xd4,0xb9,0x4a,0x84,0x5d,0x84,0xd9,0x4d,0xaf,0x2c,0xeb,0x96,
	0xdf,0x2a,0xd2,0x16,0xbe,0xb2,0xe0,0xbb,0x27,0xda,0x70,0x38,0xfa,0x51,0x4b,0x94,
	0x28,0xba,0x7a,0xe0,0xaa,0x2b,0xc3,0x18,0x61,0xa3,0xca,0x67,0x0b,0xed,0xda,0x94,
	0x03,0x9c,0xe2,0xf0,0x1d,0x7c,0x06,0xf4,0xc8,0xd6,0xf7,0xe5,0x0e,0x49,0xca,0xd9,
	0x13,0xc6,0x95,0x9b,0xe1,0xc2,0x2f,0xf5,0x81,0x4f,0xac,0x2a,0x86,0xe4,0x40,0x68,
	0x34,0x43,0xa9,0x7a,0xf2,0xfa,0xe7,0x91,0xac,0x1b,0x92,0x6f,0xd7,0x74,0x25,0xa6,
	0x75,0x51,0x87,0x20,0xfb,0x88,0x77,0xb9,0x6a,0xc1,0x6d,0xa9,0xd7,0x6e,0x1d,0x03,
	0x7b,0xa8,0x62,0x12,0xd2,0x82,0x03,0x9b,0xe9,0xd6,0x09,0xbe,0x79,0xeb,0x99,0x6b,
	0xba,0xdc,0xe0,0xb8,0x0a,0x9b,0x53,0xc5,0x07,0x50,0x16,0x90,0x00,0xf1,0xa8,0xe2,
	0xfe,0x32,0xa3,0x6d,0x1a,0x85,0xd0,0x24,0x5e,0x17,0x08,0x91,0xa7,0xb8,0xf4,0x92,
	0x09,0x47,0xef,0x65,0x0d,0xa1,0x13,0x21,0x08,0x8b,0x6f,0x2b,0x17,0xa3,0x5d,0xb5,
	0xc9,0x17,0x66,0xaf,0xec,0xb9,0x4c,0xab,0x6b,0xf4,0x92,0xcb,0xd4,0xaa,0x24,0xac,
	0x68,0xfc,0xa5,0xcd,0x64,0x66,0xdf,0x58
};

/**
 * PFM_V2_MAX_VERSION_DATA hash for testing.
 *
 * head -c -256 pfm.img | openssl dgst -sha256
 */
static const uint8_t PFM_V2_MAX_VERSION_HASH[] = {
	0x4a,0xee,0xe3,0xe6,0xd7,0xf4,0x75,0xef,0xc1,0xa2,0xe1,0x54,0x1b,0x19,0x50,0x37,
	0x2e,0x06,0x3c,0xb0,0x26,0x29,0xe7,0xa7,0xab,0xd5,0xc1,0x9d,0x3c,0x4f,0xba,0x38
};

/**
 * First firmware image of the first firmware component for the test v2 PFM with large version
 * strings.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_MAX_VERSION_11[] = {
	{
		.img_offset = 0x0294,
		.hash = PFM_V2_MAX_VERSION_DATA + 0x0298,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG1_11_REGION
	}
};

/**
 * First firmware version components of the test v2 PFM with large version strings.
 */
static const struct pfm_v2_testing_data_fw_ver PFM_V2_FW_VER_MAX_VERSION_1[] = {
	{
		.fw_version = PFM_V2_MAX_VERSION_DATA + 0x0180,
		.fw_version_len = 0x0140,
		.version_str = PFM_V2_FW_VERSION_MAX,
		.version_str_len = sizeof (PFM_V2_FW_VERSION_MAX) - 1,
		.version_str_pad = PFM_V2_FW_VERSION_MAX_PAD,
		.fw_version_offset = 0x0180,
		.fw_version_entry = 2,
		.fw_version_hash = 1,
		.version_addr = 0x012345,
		.rw_count = 1,
		.rw = PFM_V2_RW1_ONE,
		.img_count = 1,
		.img = PFM_V2_FW_IMG_MAX_VERSION_11
	}
};

/**
 * First firmware image of the second firmware copmonent for test v2 PFM with large version strings.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_MAX_VERSION_21[] = {
	{
		.img_offset = 0x03fc,
		.hash = PFM_V2_MAX_VERSION_DATA + 0x0400,
		.hash_len = 48,
		.hash_type = HASH_TYPE_SHA384,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG2_21_REGION
	},
	{
		.img_offset = 0x0438,
		.hash = PFM_V2_MAX_VERSION_DATA + 0x043c,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG2_22_REGION
	}
};

/**
 * Second firmware version components of the test v2 PFM with large version strings.
 */
static const struct pfm_v2_testing_data_fw_ver PFM_V2_FW_VER_MAX_VERSION_2[] = {
	{
		.fw_version = PFM_V2_MAX_VERSION_DATA + 0x02e0,
		.fw_version_len = 0x0184,
		.version_str = PFM_V2_FW_VERSION_MAX_NO_PADDING,
		.version_str_len = sizeof (PFM_V2_FW_VERSION_MAX_NO_PADDING) - 1,
		.version_str_pad = PFM_V2_FW_VERSION_MAX_NO_PADDING_PAD,
		.fw_version_offset = 0x02e0,
		.fw_version_entry = 5,
		.fw_version_hash = 2,
		.version_addr = 0x1112345,
		.rw_count = 2,
		.rw = PFM_V2_RW2_TWO,
		.img_count = 2,
		.img = PFM_V2_FW_IMG_MAX_VERSION_21
	}
};

/**
 * First firmware image of the third firmware component for the test v2 PFM with large version
 * strings.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_MAX_VERSION_31[] = {
	{
		.img_offset = 0x0574,
		.hash = PFM_V2_MAX_VERSION_DATA + 0x0578,
		.hash_len = 64,
		.hash_type = HASH_TYPE_SHA512,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG3_31_REGION
	},
	{
		.img_offset = 0x05c0,
		.hash = PFM_V2_MAX_VERSION_DATA + 0x05c4,
		.hash_len = 48,
		.hash_type = HASH_TYPE_SHA384,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG3_32_REGION
	},
	{
		.img_offset = 0x05fc,
		.hash = PFM_V2_MAX_VERSION_DATA + 0x0600,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG3_33_REGION
	}
};

/**
 * Thrid firmware version components of the test v2 PFM with large version strings.
 */
static const struct pfm_v2_testing_data_fw_ver PFM_V2_FW_VER_MAX_VERSION_3[] = {
	{
		.fw_version = PFM_V2_MAX_VERSION_DATA + 0x046c,
		.fw_version_len = 0x01bc,
		.version_str = PFM_V2_FW_VERSION_MAX_NO_READ_RW,
		.version_str_len = sizeof (PFM_V2_FW_VERSION_MAX_NO_READ_RW) - 1,
		.version_str_pad = PFM_V2_FW_VERSION_MAX_NO_READ_RW_PAD,
		.fw_version_offset = 0x046c,
		.fw_version_entry = 7,
		.fw_version_hash = 3,
		.version_addr = 0x2212345,
		.rw_count = 3,
		.rw = PFM_V2_RW3_THREE,
		.img_count = 3,
		.img = PFM_V2_FW_IMG_MAX_VERSION_31
	}
};

/**
 * Firmware components of the test v2 PFM with large version strings.
 */
static const struct pfm_v2_testing_data_fw PFM_V2_FW_MAX_VERSION[] = {
	{
		.fw = PFM_V2_MAX_VERSION_DATA + 0x0174,
		.fw_len = 0x000c,
		.fw_id_str = PFM_V2_FIRMWARE_ID,
		.fw_id_str_len = sizeof (PFM_V2_FIRMWARE_ID) - 1,
		.fw_id_str_pad = PFM_V2_FIRMWARE_ID_PAD,
		.fw_offset = 0x0174,
		.fw_entry = 1,
		.fw_hash = 5,
		.version_count = 1,
		.version = PFM_V2_FW_VER_MAX_VERSION_1
	},
	{
		.fw = PFM_V2_MAX_VERSION_DATA + 0x02d0,
		.fw_len = 0x0010,
		.fw_id_str = PFM_V2_FIRMWARE_ID2,
		.fw_id_str_len = sizeof (PFM_V2_FIRMWARE_ID2) - 1,
		.fw_id_str_pad = PFM_V2_FIRMWARE_ID2_PAD,
		.fw_offset = 0x02d0,
		.fw_entry = 4,
		.fw_hash = 6,
		.version_count = 1,
		.version = PFM_V2_FW_VER_MAX_VERSION_2
	},
	{
		.fw = PFM_V2_MULTIPLE_DATA + 0x0464,
		.fw_len = 0x0008,
		.fw_id_str = PFM_V2_FIRMWARE_ID3,
		.fw_id_str_len = sizeof (PFM_V2_FIRMWARE_ID3) - 1,
		.fw_id_str_pad = PFM_V2_FIRMWARE_ID3_PAD,
		.fw_offset = 0x0464,
		.fw_entry = 6,
		.fw_hash = 7,
		.version_count = 1,
		.version = PFM_V2_FW_VER_MAX_VERSION_3
	}
};

/**
 * Components of the test v2 PFM with large version strings.
 */
const struct pfm_v2_testing_data PFM_V2_MAX_VERSION = {
	.manifest = {
		.raw = PFM_V2_MAX_VERSION_DATA,
		.length = sizeof (PFM_V2_MAX_VERSION_DATA),
		.hash = PFM_V2_MAX_VERSION_HASH,
		.hash_len = sizeof (PFM_V2_MAX_VERSION_HASH),
		.id = 14,
		.signature = PFM_V2_MAX_VERSION_DATA + (sizeof (PFM_V2_MAX_VERSION_DATA) - 256),
		.sig_len = 256,
		.sig_offset = (sizeof (PFM_V2_MAX_VERSION_DATA) - 256),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = PFM_V2_MAX_VERSION_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x0164,
		.toc_hash = PFM_V2_MAX_VERSION_DATA + 0x0150,
		.toc_hash_len = 32,
		.toc_hash_offset = 0x0150,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 8,
		.toc_hashes = 8,
		.plat_id = PFM_V2_MAX_VERSION_DATA + 0x02c0,
		.plat_id_len = 0x0010,
		.plat_id_str = PFM_V2_PLATFORM_ID,
		.plat_id_str_len = sizeof (PFM_V2_PLATFORM_ID) - 1,
		.plat_id_str_pad = PFM_V2_PLATFORM_ID_PAD,
		.plat_id_offset = 0x02c0,
		.plat_id_entry = 3,
		.plat_id_hash = 4
	},
	.flash_dev = PFM_V2_MAX_VERSION_DATA + 0x0170,
	.flash_dev_len = 4,
	.flash_dev_offset = 0x0170,
	.flash_dev_entry = 0,
	.flash_dev_hash = 0,
	.blank_byte = 0xff,
	.fw_count = 3,
	.fw = PFM_V2_FW_MAX_VERSION
};

/**
 * Test PFM in v2 format.  Contains three firmware images with edge conditions for R/W testing:
 * no R/W regions, max R/W regions supported, too many R/W regions.
 *
 * NUM_FW=3 RW_TEST=1 ./generate_pfm.sh 15 ../../core/testing/keys/rsapriv.pem
 */
static const uint8_t PFM_V2_RW_TEST_DATA[] = {
	0x24,0x06,0x6d,0x70,0x0f,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x08,0x08,0x00,0x00,
	0x10,0xff,0x00,0x00,0x70,0x01,0x04,0x00,0x11,0xff,0x01,0x05,0x74,0x01,0x0c,0x00,
	0x12,0x11,0x01,0x01,0x80,0x01,0x3c,0x00,0x00,0xff,0x01,0x04,0xbc,0x01,0x10,0x00,
	0x11,0xff,0x01,0x06,0xcc,0x01,0x10,0x00,0x12,0x11,0x01,0x02,0xdc,0x01,0x74,0x01,
	0x11,0xff,0x01,0x07,0x50,0x03,0x08,0x00,0x12,0x11,0x01,0x03,0x58,0x03,0xcc,0x01,
	0xbd,0xdc,0x2e,0x22,0xf5,0xa0,0x30,0x66,0xde,0xdb,0x6a,0xf5,0x5f,0x4d,0x76,0x95,
	0x52,0x8d,0x71,0x9c,0xea,0x2a,0x86,0x05,0xfc,0xcb,0xaf,0x5e,0x07,0xc7,0x25,0xa9,
	0xfb,0x1a,0x71,0x4d,0x2b,0xc6,0x6c,0x4d,0xb3,0x78,0x11,0x0d,0xd1,0x8b,0xf0,0x09,
	0xcd,0x99,0xeb,0xc4,0x4d,0x05,0x94,0xbc,0x74,0x05,0x4d,0x2b,0xba,0xfb,0x57,0x70,
	0x1b,0xf8,0xf6,0xe2,0x25,0xb6,0x78,0x17,0x82,0xfd,0x57,0x64,0xd0,0x68,0xe2,0x4f,
	0xc5,0x5b,0x96,0x6c,0x60,0x53,0x2b,0x7c,0xee,0xc5,0x4d,0x90,0x70,0x76,0xaa,0xce,
	0xdd,0x89,0x7f,0x72,0x6e,0xba,0x21,0x14,0x3c,0xef,0xc0,0x3f,0x1b,0x7f,0x63,0x3d,
	0xfa,0xd1,0x06,0x3f,0x71,0x61,0xe4,0xfb,0x82,0xaf,0x4f,0x7c,0xec,0x42,0xc6,0x98,
	0xd3,0xb6,0xeb,0x9b,0xe0,0x85,0xcd,0xd3,0xd6,0x05,0x81,0xc8,0x0b,0x38,0x6d,0x9a,
	0xf8,0x5b,0xae,0x5f,0xed,0x50,0x36,0x38,0x55,0x0c,0xf8,0xe8,0xdb,0xd8,0x82,0x46,
	0x13,0x48,0x15,0xa0,0xd1,0xfb,0x58,0x01,0xae,0x7a,0xa2,0x15,0xb4,0xf1,0x98,0x57,
	0xda,0x88,0x4d,0x95,0x99,0x18,0x27,0x0f,0x98,0x11,0xfe,0xe5,0xd4,0x0e,0x5b,0x6c,
	0xbf,0xa8,0xbe,0x1e,0x12,0xa0,0x18,0xd5,0x25,0xec,0xf8,0xc1,0x97,0x00,0xdb,0xd7,
	0xe8,0xaa,0x94,0x96,0x24,0xe9,0xde,0x93,0x00,0x0b,0x66,0x8b,0x5c,0x2e,0x96,0x37,
	0x1f,0xf1,0x6e,0x54,0xb0,0x0f,0x20,0xc4,0x19,0x33,0x20,0x1f,0xf5,0x33,0x0d,0x03,
	0xd8,0x88,0x95,0x31,0x11,0xcd,0xde,0x95,0x8e,0x47,0x86,0xff,0xd4,0xa4,0xbb,0x85,
	0x97,0x52,0x55,0xe8,0xd2,0x70,0xd1,0xcf,0x02,0x16,0x56,0x5d,0x2c,0xd0,0xee,0x05,
	0xf0,0xd9,0x29,0x57,0x34,0xe3,0x70,0x57,0x2b,0x78,0xb2,0xa0,0x4b,0x5a,0x72,0x68,
	0xff,0x03,0x00,0x00,0x01,0x08,0x00,0x00,0x46,0x69,0x72,0x6d,0x77,0x61,0x72,0x65,
	0x01,0x00,0x07,0x00,0x45,0x23,0x01,0x00,0x54,0x65,0x73,0x74,0x69,0x6e,0x67,0x00,
	0x00,0x01,0x01,0x00,0x22,0xf5,0x3f,0x2b,0x22,0xd4,0x69,0xdc,0x37,0x52,0xa0,0x34,
	0x0a,0x13,0x89,0xa1,0x9f,0x22,0x29,0xfa,0x7d,0xe4,0xc4,0xd3,0x39,0xf5,0x58,0x3b,
	0x3f,0x94,0x1f,0x32,0x00,0x00,0x00,0x00,0xff,0xff,0x03,0x00,0x09,0x00,0x00,0x00,
	0x50,0x46,0x4d,0x20,0x54,0x65,0x73,0x74,0x31,0x00,0x00,0x00,0x01,0x09,0x00,0x00,
	0x46,0x69,0x72,0x6d,0x77,0x61,0x72,0x65,0x32,0x00,0x00,0x00,0x02,0x15,0x08,0x00,
	0x45,0x23,0x11,0x01,0x54,0x65,0x73,0x74,0x69,0x6e,0x67,0x32,0x00,0x00,0x00,0x00,
	0x00,0x00,0x10,0x00,0xff,0xff,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x11,0x00,
	0xff,0xff,0x11,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x12,0x00,0xff,0xff,0x12,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x13,0x00,0xff,0xff,0x13,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x14,0x00,0xff,0xff,0x14,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x15,0x00,
	0xff,0xff,0x15,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x16,0x00,0xff,0xff,0x16,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x17,0x00,0xff,0xff,0x17,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x18,0x00,0xff,0xff,0x18,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x19,0x00,
	0xff,0xff,0x19,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x01,0xff,0xff,0x10,0x01,
	0x00,0x00,0x00,0x00,0x00,0x00,0x11,0x01,0xff,0xff,0x11,0x01,0x00,0x00,0x00,0x00,
	0x00,0x00,0x12,0x01,0xff,0xff,0x12,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x13,0x01,
	0xff,0xff,0x13,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x14,0x01,0xff,0xff,0x14,0x01,
	0x00,0x00,0x00,0x00,0x00,0x00,0x15,0x01,0xff,0xff,0x15,0x01,0x00,0x00,0x00,0x00,
	0x00,0x00,0x16,0x01,0xff,0xff,0x16,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x17,0x01,
	0xff,0xff,0x17,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x18,0x01,0xff,0xff,0x18,0x01,
	0x00,0x00,0x00,0x00,0x00,0x00,0x19,0x01,0xff,0xff,0x19,0x01,0x00,0x00,0x00,0x00,
	0x00,0x00,0x20,0x01,0xff,0xff,0x20,0x01,0x01,0x01,0x01,0x00,0x45,0x8c,0x7b,0x22,
	0x27,0x0e,0xca,0xfe,0x12,0x50,0xd1,0x3e,0xf7,0xda,0x53,0x8b,0x5e,0xef,0x09,0xc7,
	0xd7,0xf8,0xd2,0x1e,0x71,0xa9,0x91,0x69,0x5b,0x4e,0x3d,0xc0,0xc0,0x84,0x94,0xe2,
	0x06,0x48,0xb7,0x70,0xab,0x48,0x5f,0xa0,0x8a,0x2b,0xff,0x37,0x00,0x00,0x08,0x10,
	0xff,0xff,0x0b,0x10,0x00,0x01,0x01,0x00,0xf2,0x91,0x0e,0x36,0x43,0xfe,0x42,0x6f,
	0xa7,0xf4,0x26,0x10,0xb0,0x15,0x2d,0xb2,0x89,0xa8,0xe4,0x09,0xad,0xb4,0x18,0x94,
	0xa1,0xf6,0xb4,0x3d,0x42,0xee,0x72,0xe8,0x00,0x00,0x10,0x10,0xff,0xff,0x3f,0x10,
	0x01,0x03,0x00,0x00,0x46,0x57,0x33,0x00,0x03,0x16,0x05,0x00,0x45,0x23,0x21,0x02,
	0x54,0x65,0x73,0x74,0x33,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x20,0x00,
	0xff,0xff,0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x21,0x00,0xff,0xff,0x21,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x22,0x00,0xff,0xff,0x22,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x23,0x00,0xff,0xff,0x23,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x24,0x00,
	0xff,0xff,0x24,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x25,0x00,0xff,0xff,0x25,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x26,0x00,0xff,0xff,0x26,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x27,0x00,0xff,0xff,0x27,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x28,0x00,
	0xff,0xff,0x28,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x29,0x00,0xff,0xff,0x29,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x02,0xff,0xff,0x10,0x02,0x00,0x00,0x00,0x00,
	0x00,0x00,0x11,0x02,0xff,0xff,0x11,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x12,0x02,
	0xff,0xff,0x12,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x13,0x02,0xff,0xff,0x13,0x02,
	0x00,0x00,0x00,0x00,0x00,0x00,0x14,0x02,0xff,0xff,0x14,0x02,0x00,0x00,0x00,0x00,
	0x00,0x00,0x15,0x02,0xff,0xff,0x15,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x16,0x02,
	0xff,0xff,0x16,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x17,0x02,0xff,0xff,0x17,0x02,
	0x00,0x00,0x00,0x00,0x00,0x00,0x18,0x02,0xff,0xff,0x18,0x02,0x00,0x00,0x00,0x00,
	0x00,0x00,0x19,0x02,0xff,0xff,0x19,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x20,0x02,
	0xff,0xff,0x20,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x21,0x02,0xff,0xff,0x21,0x02,
	0x02,0x01,0x01,0x00,0x19,0x6a,0xfb,0xa1,0x84,0xb1,0x62,0x9b,0x91,0x6d,0xee,0xe8,
	0xcf,0x94,0x75,0x06,0xec,0x19,0x6e,0x1b,0x3d,0xa4,0x33,0xc7,0x41,0xc2,0x71,0x70,
	0x79,0x7a,0xef,0xb7,0x32,0x3c,0x63,0xe3,0x82,0x5b,0xaf,0x91,0x49,0x36,0x10,0x0e,
	0xff,0xcd,0xd4,0xf6,0x41,0xb9,0x16,0xaf,0x4a,0x3a,0x90,0x01,0x0d,0x11,0xd8,0xbe,
	0x77,0xf3,0xe0,0x4f,0x00,0x00,0x80,0x20,0xff,0xff,0xbf,0x20,0x01,0x01,0x01,0x00,
	0xa8,0x64,0x61,0x5a,0x3c,0x0c,0x15,0xba,0x6b,0xf4,0xe6,0x6f,0x03,0x8b,0x75,0x0f,
	0x63,0x51,0x8c,0x78,0x07,0xab,0x1f,0x83,0xd6,0x03,0x96,0x39,0x96,0x2b,0xe4,0xe4,
	0xf5,0x79,0x93,0x09,0xf6,0xf2,0xed,0xbd,0xe8,0xd0,0x8f,0x24,0xfa,0x91,0x24,0xd3,
	0x00,0x00,0x00,0x21,0xff,0xff,0xff,0x23,0x00,0x01,0x01,0x00,0x25,0x79,0xa6,0xc0,
	0x90,0xd0,0x2a,0x84,0xe1,0xe9,0x41,0x21,0xc9,0xfb,0xcc,0x4a,0xc1,0x6b,0x0f,0xe5,
	0xa5,0xc3,0x9d,0x79,0xbc,0x99,0x6f,0xb2,0x3e,0x70,0xac,0xca,0x00,0x00,0x00,0x28,
	0xff,0xff,0xff,0x2b,0x46,0x70,0xce,0x66,0x06,0x36,0xfb,0xf1,0xe6,0xa7,0xba,0x4e,
	0x7c,0x32,0x38,0xb0,0x0e,0x52,0xf8,0xc7,0xe0,0x5f,0xa5,0xb6,0x30,0x46,0x3b,0x87,
	0xe0,0xc7,0xc5,0x4d,0xeb,0xdb,0xc5,0x4b,0xfc,0x4b,0x38,0x47,0x6f,0xf6,0x5e,0x8f,
	0xb0,0x56,0x86,0xe4,0xf9,0xd8,0x05,0xb0,0x42,0xa7,0x8d,0x4e,0x7c,0xe1,0xee,0x48,
	0x78,0x33,0x2c,0x70,0xc7,0xde,0x5a,0xd0,0xa0,0x23,0x45,0xea,0x3e,0xa4,0x7e,0x89,
	0x0c,0xb8,0x6c,0xd5,0x61,0x29,0xf7,0x33,0x39,0xd0,0xbc,0xed,0xf2,0x1a,0xb1,0x9d,
	0xb9,0x32,0xdd,0x7a,0x38,0x6a,0xcf,0xe9,0xe6,0xcb,0xd8,0xfb,0x92,0x81,0xc3,0xa9,
	0x26,0xcc,0x0b,0xb7,0xf4,0xf9,0xd4,0x0d,0xd3,0x8d,0xc4,0x76,0x15,0x02,0xf7,0xd2,
	0x9e,0x6e,0x79,0xb4,0x84,0xbc,0x96,0xc4,0x98,0x30,0x8c,0xee,0x0d,0xc8,0x64,0x70,
	0xf3,0xb7,0xcf,0x3a,0x9e,0xdc,0xe7,0x06,0x7e,0x41,0xe8,0x85,0x67,0x97,0x7a,0x7e,
	0x55,0xb2,0x86,0xe1,0x37,0xbb,0x36,0x9b,0x78,0x2f,0x72,0x9f,0xb9,0xc6,0xc3,0xa9,
	0x6d,0xe0,0xfc,0x75,0xc1,0xba,0x8f,0x54,0xc9,0x26,0x7a,0x06,0xaf,0x43,0x38,0x93,
	0x53,0x54,0x37,0xcf,0x3f,0x54,0x5c,0x23,0x8b,0x8c,0xe7,0xb8,0xd7,0x77,0x01,0x10,
	0xca,0x0b,0xf7,0x7d,0x31,0x7e,0xca,0x7e,0x58,0x71,0xbf,0x55,0x1f,0xc7,0x6b,0xd2,
	0x09,0xee,0xc8,0x76,0x96,0x74,0x70,0xfc,0x5a,0x0f,0xea,0x81,0xd6,0xf6,0xa8,0x06,
	0x33,0xa2,0x6d,0x1b,0x6d,0x5e,0xd8,0xd3,0xe1,0xfc,0xaa,0xab,0x64,0x02,0x61,0xba,
	0x3e,0xed,0x79,0xb8
};

/**
 * PFM_V2_RW_TEST_DATA hash for testing.
 *
 * head -c -256 pfm.img | openssl dgst -sha256
 */
static const uint8_t PFM_V2_RW_TEST_HASH[] = {
	0x9d,0x7d,0x42,0x24,0x70,0x50,0xd5,0x51,0x34,0x87,0x65,0xe4,0xa2,0x39,0x38,0xe5,
	0xbc,0x58,0xc8,0x3c,0x16,0xe0,0x22,0x65,0xc3,0x7e,0x3d,0xa2,0xa6,0xf8,0xec,0x3f
};

/**
 * First firmware image of the first firmware component for the test v2 PFM for R/W testing.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_RW_TEST_11[] = {
	{
		.img_offset = 0x0190,
		.hash = PFM_V2_RW_TEST_DATA + 0x0194,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG1_11_REGION
	}
};

/**
 * First firmware version components of the test v2 PFM with for R/W testing.
 */
static const struct pfm_v2_testing_data_fw_ver PFM_V2_FW_VER_RW_TEST_1[] = {
	{
		.fw_version = PFM_V2_RW_TEST_DATA + 0x0180,
		.fw_version_len = 0x003c,
		.version_str = PFM_V2_FW_VERSION,
		.version_str_len = sizeof (PFM_V2_FW_VERSION) - 1,
		.version_str_pad = PFM_V2_FW_VERSION_PAD,
		.fw_version_offset = 0x0180,
		.fw_version_entry = 2,
		.fw_version_hash = 1,
		.version_addr = 0x012345,
		.rw_count = 0,
		.rw = NULL,
		.img_count = 1,
		.img = PFM_V2_FW_IMG_RW_TEST_11
	}
};

/**
 * First firmware image of the second firmware copmonent for test v2 PFM for R/W testing.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_RW_TEST_21[] = {
	{
		.img_offset = 0x02e8,
		.hash = PFM_V2_RW_TEST_DATA + 0x02ec,
		.hash_len = 48,
		.hash_type = HASH_TYPE_SHA384,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG2_21_REGION
	},
	{
		.img_offset = 0x0324,
		.hash = PFM_V2_RW_TEST_DATA + 0x0328,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG2_22_REGION
	}
};

/**
 * R/W region for the second firmware component for R/W testing.
 */
static const struct pfm_v2_testing_data_rw PFM_V2_RW_TEST_RW2[] = {
	{
		.start_addr = 0x100000,
		.end_addr = 0x10ffff,
		.flags = 0
	},
	{
		.start_addr = 0x110000,
		.end_addr = 0x11ffff,
		.flags = 0
	},
	{
		.start_addr = 0x120000,
		.end_addr = 0x12ffff,
		.flags = 0
	},
	{
		.start_addr = 0x130000,
		.end_addr = 0x13ffff,
		.flags = 0
	},
	{
		.start_addr = 0x140000,
		.end_addr = 0x14ffff,
		.flags = 0
	},
	{
		.start_addr = 0x150000,
		.end_addr = 0x15ffff,
		.flags = 0
	},
	{
		.start_addr = 0x160000,
		.end_addr = 0x16ffff,
		.flags = 0
	},
	{
		.start_addr = 0x170000,
		.end_addr = 0x17ffff,
		.flags = 0
	},
	{
		.start_addr = 0x180000,
		.end_addr = 0x18ffff,
		.flags = 0
	},
	{
		.start_addr = 0x190000,
		.end_addr = 0x19ffff,
		.flags = 0
	},
	{
		.start_addr = 0x1100000,
		.end_addr = 0x110ffff,
		.flags = 0
	},
	{
		.start_addr = 0x1110000,
		.end_addr = 0x111ffff,
		.flags = 0
	},
	{
		.start_addr = 0x1120000,
		.end_addr = 0x112ffff,
		.flags = 0
	},
	{
		.start_addr = 0x1130000,
		.end_addr = 0x113ffff,
		.flags = 0
	},
	{
		.start_addr = 0x1140000,
		.end_addr = 0x114ffff,
		.flags = 0
	},
	{
		.start_addr = 0x1150000,
		.end_addr = 0x115ffff,
		.flags = 0
	},
	{
		.start_addr = 0x1160000,
		.end_addr = 0x116ffff,
		.flags = 0
	},
	{
		.start_addr = 0x1170000,
		.end_addr = 0x117ffff,
		.flags = 0
	},
	{
		.start_addr = 0x1180000,
		.end_addr = 0x118ffff,
		.flags = 0
	},
	{
		.start_addr = 0x1190000,
		.end_addr = 0x119ffff,
		.flags = 0
	},
	{
		.start_addr = 0x1200000,
		.end_addr = 0x120ffff,
		.flags = 0
	}
};

/**
 * Second firmware version components of the test v2 PFM for R/W testing.
 */
static const struct pfm_v2_testing_data_fw_ver PFM_V2_FW_VER_RW_TEST_2[] = {
	{
		.fw_version = PFM_V2_RW_TEST_DATA + 0x01dc,
		.fw_version_len = 0x0174,
		.version_str = PFM_V2_FW_VERSION2,
		.version_str_len = sizeof (PFM_V2_FW_VERSION2) - 1,
		.version_str_pad = PFM_V2_FW_VERSION2_PAD,
		.fw_version_offset = 0x01dc,
		.fw_version_entry = 5,
		.fw_version_hash = 2,
		.version_addr = 0x1112345,
		.rw_count = 21,
		.rw = PFM_V2_RW_TEST_RW2,
		.img_count = 2,
		.img = PFM_V2_FW_IMG_RW_TEST_21
	}
};

/**
 * First firmware image of the third firmware component for the test v2 PFM for R/W testing.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_RW_TEST_31[] = {
	{
		.img_offset = 0x0470,
		.hash = PFM_V2_RW_TEST_DATA + 0x0474,
		.hash_len = 64,
		.hash_type = HASH_TYPE_SHA512,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG3_31_REGION
	},
	{
		.img_offset = 0x04bc,
		.hash = PFM_V2_RW_TEST_DATA + 0x04c0,
		.hash_len = 48,
		.hash_type = HASH_TYPE_SHA384,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG3_32_REGION
	},
	{
		.img_offset = 0x04f8,
		.hash = PFM_V2_RW_TEST_DATA + 0x04fc,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG3_33_REGION
	}
};

/**
 * R/W region for the third firmware component for R/W testing.
 */
static const struct pfm_v2_testing_data_rw PFM_V2_RW_TEST_RW3[] = {
	{
		.start_addr = 0x200000,
		.end_addr = 0x20ffff,
		.flags = 0
	},
	{
		.start_addr = 0x210000,
		.end_addr = 0x21ffff,
		.flags = 0
	},
	{
		.start_addr = 0x220000,
		.end_addr = 0x22ffff,
		.flags = 0
	},
	{
		.start_addr = 0x230000,
		.end_addr = 0x23ffff,
		.flags = 0
	},
	{
		.start_addr = 0x240000,
		.end_addr = 0x24ffff,
		.flags = 0
	},
	{
		.start_addr = 0x250000,
		.end_addr = 0x25ffff,
		.flags = 0
	},
	{
		.start_addr = 0x260000,
		.end_addr = 0x26ffff,
		.flags = 0
	},
	{
		.start_addr = 0x270000,
		.end_addr = 0x27ffff,
		.flags = 0
	},
	{
		.start_addr = 0x280000,
		.end_addr = 0x28ffff,
		.flags = 0
	},
	{
		.start_addr = 0x290000,
		.end_addr = 0x29ffff,
		.flags = 0
	},
	{
		.start_addr = 0x2100000,
		.end_addr = 0x210ffff,
		.flags = 0
	},
	{
		.start_addr = 0x2110000,
		.end_addr = 0x211ffff,
		.flags = 0
	},
	{
		.start_addr = 0x2120000,
		.end_addr = 0x212ffff,
		.flags = 0
	},
	{
		.start_addr = 0x2130000,
		.end_addr = 0x213ffff,
		.flags = 0
	},
	{
		.start_addr = 0x2140000,
		.end_addr = 0x214ffff,
		.flags = 0
	},
	{
		.start_addr = 0x2150000,
		.end_addr = 0x215ffff,
		.flags = 0
	},
	{
		.start_addr = 0x2160000,
		.end_addr = 0x216ffff,
		.flags = 0
	},
	{
		.start_addr = 0x2170000,
		.end_addr = 0x217ffff,
		.flags = 0
	},
	{
		.start_addr = 0x2180000,
		.end_addr = 0x218ffff,
		.flags = 0
	},
	{
		.start_addr = 0x2190000,
		.end_addr = 0x219ffff,
		.flags = 0
	},
	{
		.start_addr = 0x2200000,
		.end_addr = 0x220ffff,
		.flags = 0
	},
	{
		.start_addr = 0x2210000,
		.end_addr = 0x221ffff,
		.flags = 0
	}
};

/**
 * Thrid firmware version components of the test v2 PFM for R/W testing.
 */
static const struct pfm_v2_testing_data_fw_ver PFM_V2_FW_VER_RW_TEST_3[] = {
	{
		.fw_version = PFM_V2_RW_TEST_DATA + 0x0358,
		.fw_version_len = 0x01cc,
		.version_str = PFM_V2_FW_VERSION3,
		.version_str_len = sizeof (PFM_V2_FW_VERSION3) - 1,
		.version_str_pad = PFM_V2_FW_VERSION3_PAD,
		.fw_version_offset = 0x0358,
		.fw_version_entry = 7,
		.fw_version_hash = 3,
		.version_addr = 0x2212345,
		.rw_count = 22,
		.rw = PFM_V2_RW_TEST_RW3,
		.img_count = 3,
		.img = PFM_V2_FW_IMG_RW_TEST_31
	}
};

/**
 * Firmware components of the test v2 PFM for R/W testing.
 */
static const struct pfm_v2_testing_data_fw PFM_V2_FW_RW_TEST[] = {
	{
		.fw = PFM_V2_RW_TEST_DATA + 0x0174,
		.fw_len = 0x000c,
		.fw_id_str = PFM_V2_FIRMWARE_ID,
		.fw_id_str_len = sizeof (PFM_V2_FIRMWARE_ID) - 1,
		.fw_id_str_pad = PFM_V2_FIRMWARE_ID_PAD,
		.fw_offset = 0x0174,
		.fw_entry = 1,
		.fw_hash = 5,
		.version_count = 1,
		.version = PFM_V2_FW_VER_RW_TEST_1
	},
	{
		.fw = PFM_V2_RW_TEST_DATA + 0x01cc,
		.fw_len = 0x0010,
		.fw_id_str = PFM_V2_FIRMWARE_ID2,
		.fw_id_str_len = sizeof (PFM_V2_FIRMWARE_ID2) - 1,
		.fw_id_str_pad = PFM_V2_FIRMWARE_ID2_PAD,
		.fw_offset = 0x01cc,
		.fw_entry = 4,
		.fw_hash = 6,
		.version_count = 1,
		.version = PFM_V2_FW_VER_RW_TEST_2
	},
	{
		.fw = PFM_V2_MULTIPLE_DATA + 0x0350,
		.fw_len = 0x0008,
		.fw_id_str = PFM_V2_FIRMWARE_ID3,
		.fw_id_str_len = sizeof (PFM_V2_FIRMWARE_ID3) - 1,
		.fw_id_str_pad = PFM_V2_FIRMWARE_ID3_PAD,
		.fw_offset = 0x0350,
		.fw_entry = 6,
		.fw_hash = 7,
		.version_count = 1,
		.version = PFM_V2_FW_VER_RW_TEST_3
	}
};

/**
 * Components of the test v2 PFM for R/W testing.
 */
const struct pfm_v2_testing_data PFM_V2_RW_TEST = {
	.manifest = {
		.raw = PFM_V2_RW_TEST_DATA,
		.length = sizeof (PFM_V2_RW_TEST_DATA),
		.hash = PFM_V2_RW_TEST_HASH,
		.hash_len = sizeof (PFM_V2_RW_TEST_HASH),
		.id = 15,
		.signature = PFM_V2_RW_TEST_DATA + (sizeof (PFM_V2_RW_TEST_DATA) - 256),
		.sig_len = 256,
		.sig_offset = (sizeof (PFM_V2_RW_TEST_DATA) - 256),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = PFM_V2_RW_TEST_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x0164,
		.toc_hash = PFM_V2_RW_TEST_DATA + 0x0150,
		.toc_hash_len = 32,
		.toc_hash_offset = 0x0150,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 8,
		.toc_hashes = 8,
		.plat_id = PFM_V2_RW_TEST_DATA + 0x01bc,
		.plat_id_len = 0x0010,
		.plat_id_str = PFM_V2_PLATFORM_ID,
		.plat_id_str_len = sizeof (PFM_V2_PLATFORM_ID) - 1,
		.plat_id_str_pad = PFM_V2_PLATFORM_ID_PAD,
		.plat_id_offset = 0x01bc,
		.plat_id_entry = 3,
		.plat_id_hash = 4
	},
	.flash_dev = PFM_V2_RW_TEST_DATA + 0x0170,
	.flash_dev_len = 4,
	.flash_dev_offset = 0x0170,
	.flash_dev_entry = 0,
	.flash_dev_hash = 0,
	.blank_byte = 0xff,
	.fw_count = 3,
	.fw = PFM_V2_FW_RW_TEST
};

/**
 * Test PFM in v2 format.  Contains three FW elements and an ECC signature.  The platform ID is in
 * between the first two FW elements.
 *
 * PLATFORM="PFM Test2" NUM_FW=3 ./generate_pfm.sh 16 ../../core/testing/keys/eccpriv.pem
 */
static const uint8_t PFM_V2_THREE_FW_DATA[] = {
	0xf9,0x02,0x6d,0x70,0x10,0x00,0x00,0x00,0x49,0x00,0x40,0x00,0x08,0x08,0x00,0x00,
	0x10,0xff,0x00,0x00,0x70,0x01,0x04,0x00,0x11,0xff,0x01,0x05,0x74,0x01,0x0c,0x00,
	0x12,0x11,0x01,0x01,0x80,0x01,0x48,0x00,0x00,0xff,0x01,0x04,0xc8,0x01,0x10,0x00,
	0x11,0xff,0x01,0x06,0xd8,0x01,0x10,0x00,0x12,0x11,0x01,0x02,0xe8,0x01,0x58,0x00,
	0x11,0xff,0x01,0x07,0x40,0x02,0x08,0x00,0x12,0x11,0x01,0x03,0x48,0x02,0x68,0x00,
	0xbd,0xdc,0x2e,0x22,0xf5,0xa0,0x30,0x66,0xde,0xdb,0x6a,0xf5,0x5f,0x4d,0x76,0x95,
	0x52,0x8d,0x71,0x9c,0xea,0x2a,0x86,0x05,0xfc,0xcb,0xaf,0x5e,0x07,0xc7,0x25,0xa9,
	0xd1,0x9c,0x5d,0xdf,0x08,0xeb,0x03,0xd4,0x32,0xd9,0x38,0x91,0x9a,0xd1,0x9f,0xb9,
	0x9b,0x4d,0x27,0x02,0xd9,0xe0,0x7a,0x93,0x26,0xaa,0xed,0x05,0x9a,0xb0,0xf3,0x40,
	0xdc,0x63,0x1c,0x98,0x3c,0xc1,0xcc,0xeb,0xa8,0x57,0x86,0x7b,0x87,0x57,0x1f,0xc3,
	0x49,0x94,0x08,0xdb,0x65,0x3b,0xe6,0xa5,0x2c,0xbe,0x70,0xef,0x83,0x0b,0xeb,0xe1,
	0xf1,0x83,0xec,0x18,0x31,0x54,0x9c,0x7a,0xa7,0xf8,0x3f,0x3a,0x9e,0xe4,0x7a,0x9b,
	0xa1,0x8e,0xae,0x66,0x4e,0xe9,0x4e,0x42,0xd0,0x56,0xc5,0x06,0x70,0x0d,0x8a,0x69,
	0x67,0x98,0x4a,0xa9,0x89,0x7c,0xed,0x76,0xe5,0x8a,0x8e,0x7f,0xec,0xa4,0x38,0xdc,
	0x7a,0x8f,0x2c,0x8b,0x33,0x0b,0x87,0x09,0x53,0xbb,0xd2,0x88,0x5f,0xee,0x0d,0xe8,
	0x13,0x48,0x15,0xa0,0xd1,0xfb,0x58,0x01,0xae,0x7a,0xa2,0x15,0xb4,0xf1,0x98,0x57,
	0xda,0x88,0x4d,0x95,0x99,0x18,0x27,0x0f,0x98,0x11,0xfe,0xe5,0xd4,0x0e,0x5b,0x6c,
	0xbf,0xa8,0xbe,0x1e,0x12,0xa0,0x18,0xd5,0x25,0xec,0xf8,0xc1,0x97,0x00,0xdb,0xd7,
	0xe8,0xaa,0x94,0x96,0x24,0xe9,0xde,0x93,0x00,0x0b,0x66,0x8b,0x5c,0x2e,0x96,0x37,
	0x1f,0xf1,0x6e,0x54,0xb0,0x0f,0x20,0xc4,0x19,0x33,0x20,0x1f,0xf5,0x33,0x0d,0x03,
	0xd8,0x88,0x95,0x31,0x11,0xcd,0xde,0x95,0x8e,0x47,0x86,0xff,0xd4,0xa4,0xbb,0x85,
	0xcb,0xc0,0x68,0xa5,0xd7,0x8b,0x5e,0xba,0x58,0x80,0x07,0x45,0xe6,0x79,0xbe,0x84,
	0x9b,0x27,0x95,0x12,0xa8,0x9b,0xd6,0x10,0x55,0xd4,0xea,0x26,0x03,0x18,0xc5,0x7e,
	0xff,0x03,0x00,0x00,0x01,0x08,0x00,0x00,0x46,0x69,0x72,0x6d,0x77,0x61,0x72,0x65,
	0x01,0x01,0x07,0x00,0x45,0x23,0x01,0x00,0x54,0x65,0x73,0x74,0x69,0x6e,0x67,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0xff,0xff,0xff,0x03,0x00,0x01,0x01,0x00,
	0x3c,0x9a,0xf0,0x13,0xfd,0x58,0xd6,0xc7,0x95,0xd3,0x25,0x23,0x83,0x98,0x47,0x21,
	0x9b,0x18,0xbb,0x9b,0xbb,0x42,0x5a,0x09,0x8b,0x92,0x75,0x61,0x01,0x3e,0x25,0xb5,
	0x00,0x00,0x00,0x00,0xff,0xff,0xff,0x01,0x09,0x00,0x00,0x00,0x50,0x46,0x4d,0x20,
	0x54,0x65,0x73,0x74,0x32,0x00,0x00,0x00,0x01,0x09,0x00,0x00,0x46,0x69,0x72,0x6d,
	0x77,0x61,0x72,0x65,0x32,0x00,0x00,0x00,0x01,0x01,0x08,0x00,0x45,0x23,0x11,0x01,
	0x54,0x65,0x73,0x74,0x69,0x6e,0x67,0x32,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x06,
	0xff,0xff,0xff,0x07,0x01,0x01,0x01,0x00,0x44,0x6d,0xf4,0xb4,0x6e,0x62,0x06,0xd8,
	0xa7,0x10,0x4a,0x70,0xec,0xc0,0x3c,0x84,0x98,0x1f,0x71,0x52,0x50,0x3d,0xc7,0x27,
	0xd5,0xa6,0x49,0x2e,0xf9,0x5d,0xfe,0x63,0xf4,0xcf,0xfe,0xbe,0xce,0x29,0x9e,0xf0,
	0x0d,0xd8,0xf3,0xcf,0x80,0x67,0xb4,0x38,0x00,0x00,0x00,0x04,0xff,0xff,0xff,0x05,
	0x01,0x03,0x00,0x00,0x46,0x57,0x33,0x00,0x01,0x01,0x05,0x00,0x45,0x23,0x21,0x02,
	0x54,0x65,0x73,0x74,0x33,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08,
	0xff,0xff,0xff,0x09,0x02,0x01,0x00,0x00,0x5c,0xde,0xc9,0x68,0x64,0xf6,0x0b,0x36,
	0x01,0xc6,0x9a,0xdf,0xbb,0x2c,0x7f,0xf8,0x4d,0x5f,0x53,0xda,0x8c,0x4a,0xd9,0xdb,
	0x05,0x69,0xf2,0x52,0x28,0xa6,0xa4,0xf1,0x5f,0x8c,0xa4,0x74,0x65,0xaf,0x15,0xb0,
	0x95,0x1f,0x38,0x63,0xb8,0x04,0xc2,0xdb,0x65,0x08,0x72,0xc9,0x7d,0x7c,0xb4,0x55,
	0x71,0x13,0x7e,0x07,0x98,0x07,0x2e,0x97,0x00,0x00,0x00,0x0a,0xff,0xff,0xff,0x0b,
	0x30,0x46,0x02,0x21,0x00,0xc4,0xa2,0x12,0xad,0xed,0x66,0x08,0xaf,0x04,0x75,0xca,
	0xdc,0x96,0x44,0x28,0xc5,0x81,0x82,0x18,0xc9,0xd1,0x0d,0x35,0xef,0x48,0x8b,0x7e,
	0xc3,0xa1,0x29,0xcc,0xf1,0x02,0x21,0x00,0x96,0x5e,0x89,0x06,0x11,0xd9,0xab,0x7d,
	0x9c,0x9c,0xc0,0xaf,0x7d,0xfb,0x69,0x32,0x4d,0x5e,0x1c,0xd6,0xb2,0x84,0xb2,0x88,
	0x41,0x8e,0x98,0x8a,0xca,0xa3,0xaa,0x35,0x00
};

/**
 * PFM_V2_THREE_FW_DATA hash for testing.
 *
 * head -c -73 pfm.img | openssl dgst -sha256
 */
static const uint8_t PFM_V2_THREE_FW_HASH[] = {
	0x41,0xd3,0xe5,0x19,0x19,0x96,0x46,0xaa,0xe3,0x28,0x72,0xcd,0xf0,0xb3,0x83,0xc9,
	0x77,0x65,0xb1,0xfa,0xf7,0xe2,0xfb,0x9b,0x3c,0xaf,0xaa,0xb9,0x93,0xc0,0x3e,0x96
};


/**
 * First firmware image for the test v2 PFM with three firmware elements.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_THREE_FW_1[] = {
	{
		.img_offset = 0x019c,
		.hash = PFM_V2_THREE_FW_DATA + 0x01a0,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG1_REGION
	}
};

/**
 * First firmware version components of the test v2 PFM with three firmware elements.
 */
static const struct pfm_v2_testing_data_fw_ver PFM_V2_FW_VER_THREE_FW_1[] = {
	{
		.fw_version = PFM_V2_THREE_FW_DATA + 0x0180,
		.fw_version_len = 0x0048,
		.version_str = PFM_V2_FW_VERSION,
		.version_str_len = sizeof (PFM_V2_FW_VERSION) - 1,
		.version_str_pad = PFM_V2_FW_VERSION_PAD,
		.fw_version_offset = 0x0180,
		.fw_version_entry = 2,
		.fw_version_hash = 1,
		.version_addr = 0x012345,
		.rw_count = 1,
		.rw = PFM_V2_RW1,
		.img_count = 1,
		.img = PFM_V2_FW_IMG_THREE_FW_1
	}
};

/**
 * Second firmware image for the test v2 PFM with three firmware elements.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_THREE_FW_2[] = {
	{
		.img_offset = 0x0204,
		.hash = PFM_V2_THREE_FW_DATA + 0x0208,
		.hash_len = 48,
		.hash_type = HASH_TYPE_SHA384,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG2_REGION
	}
};

/**
 * Second firmware version components of the test v2 PFM with three firmware elements.
 */
static const struct pfm_v2_testing_data_fw_ver PFM_V2_FW_VER_THREE_FW_2[] = {
	{
		.fw_version = PFM_V2_THREE_FW_DATA + 0x01e8,
		.fw_version_len = 0x0058,
		.version_str = PFM_V2_FW_VERSION2,
		.version_str_len = sizeof (PFM_V2_FW_VERSION2) - 1,
		.version_str_pad = PFM_V2_FW_VERSION2_PAD,
		.fw_version_offset = 0x01e8,
		.fw_version_entry = 5,
		.fw_version_hash = 2,
		.version_addr = 0x112345,
		.rw_count = 1,
		.rw = PFM_V2_RW2,
		.img_count = 1,
		.img = PFM_V2_FW_IMG_THREE_FW_2
	}
};

/**
 * Third firmware image for the test v2 PFM with three firmware elements.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_THREE_FW_3[] = {
	{
		.img_offset = 0x0264,
		.hash = PFM_V2_THREE_FW_DATA + 0x0268,
		.hash_len = 64,
		.hash_type = HASH_TYPE_SHA512,
		.flags = 0,
		.region_count = 1,
		.region = PFM_V2_IMG3_REGION
	}
};

/**
 * Third firmware version components of the test v2 PFM with three firmware elements.
 */
static const struct pfm_v2_testing_data_fw_ver PFM_V2_FW_VER_THREE_FW_3[] = {
	{
		.fw_version = PFM_V2_THREE_FW_DATA + 0x0248,
		.fw_version_len = 0x0068,
		.version_str = PFM_V2_FW_VERSION3,
		.version_str_len = sizeof (PFM_V2_FW_VERSION3) - 1,
		.version_str_pad = PFM_V2_FW_VERSION3_PAD,
		.fw_version_offset = 0x0248,
		.fw_version_entry = 7,
		.fw_version_hash = 3,
		.version_addr = 0x212345,
		.rw_count = 1,
		.rw = PFM_V2_RW3,
		.img_count = 1,
		.img = PFM_V2_FW_IMG_THREE_FW_3
	}
};

/**
 * Firmware components of the test v2 PFM with two firmware elements.
 */
static const struct pfm_v2_testing_data_fw PFM_V2_FW_THREE_FW[] = {
	{
		.fw = PFM_V2_THREE_FW_DATA + 0x0174,
		.fw_len = 0x000c,
		.fw_id_str = PFM_V2_FIRMWARE_ID,
		.fw_id_str_len = sizeof (PFM_V2_FIRMWARE_ID) - 1,
		.fw_id_str_pad = PFM_V2_FIRMWARE_ID_PAD,
		.fw_offset = 0x0174,
		.fw_entry = 1,
		.fw_hash = 5,
		.version_count = 1,
		.version = PFM_V2_FW_VER_THREE_FW_1
	},
	{
		.fw = PFM_V2_THREE_FW_DATA + 0x01d8,
		.fw_len = 0x0010,
		.fw_id_str = PFM_V2_FIRMWARE_ID2,
		.fw_id_str_len = sizeof (PFM_V2_FIRMWARE_ID2) - 1,
		.fw_id_str_pad = PFM_V2_FIRMWARE_ID2_PAD,
		.fw_offset = 0x01d8,
		.fw_entry = 4,
		.fw_hash = 6,
		.version_count = 1,
		.version = PFM_V2_FW_VER_THREE_FW_2
	},
	{
		.fw = PFM_V2_THREE_FW_DATA + 0x0240,
		.fw_len = 0x0008,
		.fw_id_str = PFM_V2_FIRMWARE_ID3,
		.fw_id_str_len = sizeof (PFM_V2_FIRMWARE_ID3) - 1,
		.fw_id_str_pad = PFM_V2_FIRMWARE_ID3_PAD,
		.fw_offset = 0x0240,
		.fw_entry = 6,
		.fw_hash = 7,
		.version_count = 1,
		.version = PFM_V2_FW_VER_THREE_FW_3
	}
};

/**
 * Components of the test v2 PFM with two firmware elements.
 */
const struct pfm_v2_testing_data PFM_V2_THREE_FW = {
	.manifest = {
		.raw = PFM_V2_THREE_FW_DATA,
		.length = sizeof (PFM_V2_THREE_FW_DATA),
		.hash = PFM_V2_THREE_FW_HASH,
		.hash_len = sizeof (PFM_V2_THREE_FW_HASH),
		.id = 16,
		.signature = PFM_V2_THREE_FW_DATA + (sizeof (PFM_V2_THREE_FW_DATA) - 73),
		.sig_len = 73,
		.sig_offset = (sizeof (PFM_V2_THREE_FW_DATA) - 73),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = PFM_V2_THREE_FW_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x0164,
		.toc_hash = PFM_V2_THREE_FW_DATA + 0x0150,
		.toc_hash_len = 32,
		.toc_hash_offset = 0x0150,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 8,
		.toc_hashes = 8,
		.plat_id = PFM_V2_THREE_FW_DATA + 0x01c8,
		.plat_id_len = 0x0010,
		.plat_id_str = PFM_V2_PLATFORM_ID2,
		.plat_id_str_len = sizeof (PFM_V2_PLATFORM_ID2) - 1,
		.plat_id_str_pad = PFM_V2_PLATFORM_ID2_PAD,
		.plat_id_offset = 0x01c8,
		.plat_id_entry = 3,
		.plat_id_hash = 4
	},
	.flash_dev = PFM_V2_THREE_FW_DATA + 0x0170,
	.flash_dev_len = 4,
	.flash_dev_offset = 0x0170,
	.flash_dev_entry = 0,
	.flash_dev_hash = 0,
	.blank_byte = 0xff,
	.fw_count = 3,
	.fw = PFM_V2_FW_THREE_FW
};

/**
 * Test PFM in v2 format.  Contains one FW element with multiple regions defining the FW image.
 *
 * IMG_MULTI_REGION=1 NUM_FW=1 ./generate_pfm.sh 17 ../../core/testing/keys/rsapriv.pem
 */
static const uint8_t PFM_V2_MULTI_IMG_REGION_DATA[] = {
	0x50,0x02,0x6d,0x70,0x11,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x04,0x04,0x00,0x00,
	0x10,0xff,0x00,0x00,0xd0,0x00,0x04,0x00,0x11,0xff,0x01,0x03,0xd4,0x00,0x0c,0x00,
	0x12,0x11,0x01,0x01,0xe0,0x00,0x60,0x00,0x00,0xff,0x01,0x02,0x40,0x01,0x10,0x00,
	0xa8,0xd9,0xe5,0x71,0xa3,0xf6,0xf7,0x9d,0xa5,0xff,0xf4,0xbd,0xa2,0x79,0x26,0xa1,
	0x87,0x00,0x31,0x36,0x9e,0xc1,0x37,0xd6,0x58,0x73,0x05,0xc8,0xef,0xec,0x80,0xd2,
	0xa2,0x7f,0x29,0x3e,0x10,0x5e,0x20,0xda,0xec,0x90,0x70,0x47,0x85,0x7c,0x38,0x78,
	0x7b,0x23,0x8b,0x9d,0x22,0x40,0xf1,0xbf,0x16,0x2e,0x05,0x73,0x59,0xe2,0xcc,0xbd,
	0xd3,0xb6,0xeb,0x9b,0xe0,0x85,0xcd,0xd3,0xd6,0x05,0x81,0xc8,0x0b,0x38,0x6d,0x9a,
	0xf8,0x5b,0xae,0x5f,0xed,0x50,0x36,0x38,0x55,0x0c,0xf8,0xe8,0xdb,0xd8,0x82,0x46,
	0x13,0x48,0x15,0xa0,0xd1,0xfb,0x58,0x01,0xae,0x7a,0xa2,0x15,0xb4,0xf1,0x98,0x57,
	0xda,0x88,0x4d,0x95,0x99,0x18,0x27,0x0f,0x98,0x11,0xfe,0xe5,0xd4,0x0e,0x5b,0x6c,
	0xd1,0x76,0x7b,0x40,0x13,0x31,0x81,0x61,0xc8,0xb8,0x37,0x71,0x37,0xf7,0xe8,0xd3,
	0x13,0xc7,0x3d,0x96,0xec,0xd6,0xe8,0x7e,0x07,0xa2,0x4c,0xf5,0x71,0x37,0x89,0xac,
	0xff,0x01,0x00,0x00,0x01,0x08,0x00,0x00,0x46,0x69,0x72,0x6d,0x77,0x61,0x72,0x65,
	0x01,0x01,0x07,0x00,0x45,0x23,0x01,0x00,0x54,0x65,0x73,0x74,0x69,0x6e,0x67,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0xff,0xff,0xff,0x03,0x00,0x04,0x01,0x00,
	0x2c,0xc1,0xbc,0xc8,0x5e,0xed,0xc2,0xdf,0x47,0x84,0x82,0x9f,0xf8,0xc6,0x04,0x48,
	0xde,0x68,0x45,0xe6,0x03,0x9d,0x73,0x59,0x0b,0x34,0x54,0x4e,0xbf,0x73,0xbb,0x3e,
	0x00,0x00,0x00,0x00,0xff,0xff,0x04,0x00,0x00,0x00,0x06,0x00,0xff,0xff,0x0b,0x00,
	0x00,0x00,0x00,0x01,0xff,0xff,0x08,0x01,0x00,0x00,0x10,0x01,0xff,0xff,0xff,0x01,
	0x09,0x00,0x00,0x00,0x50,0x46,0x4d,0x20,0x54,0x65,0x73,0x74,0x31,0x00,0x00,0x00,
	0x89,0x9b,0x53,0xcc,0x54,0xa3,0x32,0x06,0xad,0xc1,0x41,0xbb,0x35,0x96,0x7f,0xc3,
	0x47,0xc5,0x22,0x7a,0xee,0x51,0x32,0x11,0xc0,0x21,0xa2,0x01,0x8d,0xd3,0x19,0xcb,
	0x6d,0x86,0x0e,0xdd,0xc2,0x4a,0x5b,0x75,0x95,0xe1,0x34,0x1b,0xc9,0xf8,0x98,0x81,
	0xe7,0x80,0x9d,0x8c,0x8c,0x38,0xd9,0xaf,0x8b,0xd9,0xba,0x4d,0x05,0x9c,0xe9,0x3d,
	0x7c,0xf0,0xd8,0xf5,0xdb,0x7f,0x9b,0xb0,0x80,0xb8,0xff,0xdc,0x07,0xf7,0xe0,0xb8,
	0x25,0x79,0xa9,0x69,0x0f,0x85,0xbf,0x93,0x07,0x60,0xef,0x96,0xae,0x49,0x88,0x62,
	0xbd,0x6e,0x97,0xe2,0x27,0x54,0x9c,0x15,0x62,0x1d,0x18,0x13,0xf5,0x07,0x00,0xd2,
	0xe9,0x0d,0x68,0x92,0x3f,0x74,0xea,0xd8,0xcd,0x51,0xd3,0x2a,0x25,0x94,0xa3,0xff,
	0x8e,0x1f,0xd9,0x73,0xb6,0x87,0x86,0xa1,0x9b,0x92,0x0d,0x9c,0xa5,0x28,0x15,0xf5,
	0x74,0x64,0x16,0x67,0x70,0x22,0x6d,0x04,0x34,0x97,0xb5,0xbf,0x55,0x0e,0x00,0x32,
	0x5a,0xc5,0x8a,0xe9,0x1d,0x14,0x80,0xb7,0x5d,0x6e,0x1e,0xb8,0x2a,0xec,0xd2,0xd6,
	0xa7,0xea,0x55,0xdf,0xf6,0x59,0xdb,0x6a,0x77,0x8c,0x1c,0x29,0xc0,0x34,0x90,0xf7,
	0xcc,0x3d,0xa1,0x48,0x57,0xd4,0x11,0xb4,0xc2,0x71,0x72,0x6a,0x8c,0x54,0x4d,0x59,
	0xdc,0x92,0x86,0x98,0x57,0x1f,0x08,0x44,0xbf,0x6b,0x01,0xbb,0xfe,0xa4,0x5b,0x85,
	0x12,0xea,0x93,0x1f,0xf9,0x5a,0x9e,0xe6,0x07,0x0a,0xdb,0xbb,0xd6,0x38,0x7a,0x60,
	0x59,0x6e,0x94,0x3f,0xac,0x93,0xb0,0x28,0x50,0x4f,0x7e,0xfa,0x46,0xb4,0x66,0xe6
};

/**
 * PFM_V2_MULTI_IMG_REGION_DATA hash for testing.
 *
 * head -c -256 pfm.img | openssl dgst -sha256
 */
static const uint8_t PFM_V2_MULTI_IMG_REGION_HASH[] = {
	0x25,0xc2,0xe6,0x56,0x5b,0x2a,0x64,0xbc,0x8e,0x4e,0x87,0x92,0x47,0xb8,0xa3,0x6f,
	0xbd,0xfa,0x18,0x5d,0xe9,0xd7,0x2b,0xae,0xc9,0x32,0x36,0xb5,0x2e,0x43,0x7e,0xaa
};

/**
 * Firmware image for the test v2 PFM with multiple image regions.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_MULTI_IMG_REGION[] = {
	{
		.img_offset = 0x00fc,
		.hash = PFM_V2_MULTI_IMG_REGION_DATA + 0x0100,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 1,
		.region_count = 4,
		.region = PFM_V2_IMG1_MULTI_REGION
	}
};

/**
 * Firmware version components of the test v2 PFM with multiple image regions.
 */
static const struct pfm_v2_testing_data_fw_ver PFM_V2_FW_VER_MULTI_IMG_REGION[] = {
	{
		.fw_version = PFM_V2_MULTI_IMG_REGION_DATA + 0x00e0,
		.fw_version_len = 0x0060,
		.version_str = PFM_V2_FW_VERSION,
		.version_str_len = sizeof (PFM_V2_FW_VERSION) - 1,
		.version_str_pad = PFM_V2_FW_VERSION_PAD,
		.fw_version_offset = 0x00e0,
		.fw_version_entry = 2,
		.fw_version_hash = 1,
		.version_addr = 0x012345,
		.rw_count = 1,
		.rw = PFM_V2_RW1,
		.img_count = 1,
		.img = PFM_V2_FW_IMG_MULTI_IMG_REGION
	}
};

/**
 * Firmware components of the test v2 PFM with multiple image regions.
 */
static const struct pfm_v2_testing_data_fw PFM_V2_FW_MULTI_IMG_REGION[] = {
	{
		.fw = PFM_V2_MULTI_IMG_REGION_DATA + 0x00d4,
		.fw_len = 0x000c,
		.fw_id_str = PFM_V2_FIRMWARE_ID,
		.fw_id_str_len = sizeof (PFM_V2_FIRMWARE_ID) - 1,
		.fw_id_str_pad = PFM_V2_FIRMWARE_ID_PAD,
		.fw_offset = 0x00d4,
		.fw_entry = 1,
		.fw_hash = 3,
		.version_count = 1,
		.version = PFM_V2_FW_VER_MULTI_IMG_REGION
	}
};

/**
 * Components of the test v2 PFM with multiple image regions.
 */
const struct pfm_v2_testing_data PFM_V2_MULTI_IMG_REGION = {
	.manifest = {
		.raw = PFM_V2_MULTI_IMG_REGION_DATA,
		.length = sizeof (PFM_V2_MULTI_IMG_REGION_DATA),
		.hash = PFM_V2_MULTI_IMG_REGION_HASH,
		.hash_len = sizeof (PFM_V2_MULTI_IMG_REGION_HASH),
		.id = 17,
		.signature = PFM_V2_MULTI_IMG_REGION_DATA + (sizeof (PFM_V2_MULTI_IMG_REGION_DATA) - 256),
		.sig_len = 256,
		.sig_offset = (sizeof (PFM_V2_MULTI_IMG_REGION_DATA) - 256),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = PFM_V2_MULTI_IMG_REGION_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x00c4,
		.toc_hash = PFM_V2_MULTI_IMG_REGION_DATA + 0x00b0,
		.toc_hash_len = 32,
		.toc_hash_offset = 0x00b0,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 4,
		.toc_hashes = 4,
		.plat_id = PFM_V2_MULTI_IMG_REGION_DATA + 0x0140,
		.plat_id_len = 0x0010,
		.plat_id_str = PFM_V2_PLATFORM_ID,
		.plat_id_str_len = sizeof (PFM_V2_PLATFORM_ID) - 1,
		.plat_id_str_pad = PFM_V2_PLATFORM_ID_PAD,
		.plat_id_offset = 0x0140,
		.plat_id_entry = 3,
		.plat_id_hash = 2
	},
	.flash_dev = PFM_V2_MULTI_IMG_REGION_DATA + 0x00d0,
	.flash_dev_len = 4,
	.flash_dev_offset = 0x00d0,
	.flash_dev_entry = 0,
	.flash_dev_hash = 0,
	.blank_byte = 0xff,
	.fw_count = 1,
	.fw = PFM_V2_FW_MULTI_IMG_REGION
};

/**
 * Test PFM in v2 format.  Contains specific conditions to test parsing image information:
 * 0 0 -> Max in a single read with large version string
 * 1 0 -> Multiple images with multiple regions
 * 2 0 -> Multiple images across multiple element reads
 * 0 1 -> Extra image flags set
 * 1 1 -> Image definition too large
 * 2 1 -> Maximum image definition size
 * 0 2 -> Multiple element reads with multiple images in each read
 * 1 2 -> Image defined with no regions
 * 2 2 -> Invalid hash type
 *
 * PLATFORM="PFM Test2" NUM_FW=3 NUM_FW_VER=3 IMG_TEST=1 ./generate_pfm.sh 18 ../../core/testing/keys/eccpriv.pem
 */
static const uint8_t PFM_V2_IMG_TEST_DATA[] = {
	0x05,0x0d,0x6d,0x70,0x12,0x00,0x00,0x00,0x49,0x00,0x40,0x00,0x0e,0x0e,0x00,0x00,
	0x10,0xff,0x00,0x00,0x60,0x02,0x04,0x00,0x11,0xff,0x01,0x05,0x64,0x02,0x0c,0x00,
	0x12,0x11,0x01,0x01,0x70,0x02,0x08,0x01,0x12,0x11,0x01,0x08,0x78,0x03,0x94,0x00,
	0x12,0x11,0x01,0x0b,0x0c,0x04,0xf4,0x01,0x00,0xff,0x01,0x04,0x00,0x06,0x10,0x00,
	0x11,0xff,0x01,0x06,0x10,0x06,0x10,0x00,0x12,0x11,0x01,0x02,0x20,0x06,0xb0,0x00,
	0x12,0x11,0x01,0x09,0xd0,0x06,0x3c,0x01,0x12,0x11,0x01,0x0c,0x0c,0x08,0x44,0x00,
	0x11,0xff,0x01,0x07,0x50,0x08,0x08,0x00,0x12,0x11,0x01,0x03,0x58,0x08,0xbc,0x02,
	0x12,0x11,0x01,0x0a,0x14,0x0b,0x18,0x01,0x12,0x11,0x01,0x0d,0x2c,0x0c,0x90,0x00,
	0xbd,0xdc,0x2e,0x22,0xf5,0xa0,0x30,0x66,0xde,0xdb,0x6a,0xf5,0x5f,0x4d,0x76,0x95,
	0x52,0x8d,0x71,0x9c,0xea,0x2a,0x86,0x05,0xfc,0xcb,0xaf,0x5e,0x07,0xc7,0x25,0xa9,
	0xd8,0xa1,0x12,0x07,0xc9,0x6a,0xf9,0xcb,0x94,0x5b,0x5e,0xe7,0xad,0x94,0xd0,0x05,
	0xe7,0x94,0x5b,0x03,0x87,0x76,0xe6,0x5d,0xdd,0x7d,0x65,0x4b,0xbe,0xa0,0x42,0x44,
	0x79,0x3e,0x18,0x93,0x2d,0xd0,0x98,0x7f,0x17,0x00,0x6f,0x06,0xce,0x0a,0x0a,0x42,
	0x0d,0xc0,0x40,0x61,0x6b,0x8f,0x60,0xbb,0x47,0x8e,0xe4,0x5b,0x5d,0x42,0x1f,0xd1,
	0x0c,0xcf,0xe9,0xff,0xc9,0x60,0x66,0x83,0xaf,0xb7,0xc0,0x61,0x44,0x50,0x74,0xd1,
	0x76,0xa2,0x9c,0x91,0x70,0x76,0x1c,0x7b,0xb0,0xf4,0x81,0x3a,0x30,0xba,0xda,0x42,
	0x67,0x98,0x4a,0xa9,0x89,0x7c,0xed,0x76,0xe5,0x8a,0x8e,0x7f,0xec,0xa4,0x38,0xdc,
	0x7a,0x8f,0x2c,0x8b,0x33,0x0b,0x87,0x09,0x53,0xbb,0xd2,0x88,0x5f,0xee,0x0d,0xe8,
	0x90,0x47,0x2d,0x33,0xfb,0xf1,0x52,0x62,0x96,0x79,0x2e,0x5d,0x2f,0xcb,0x97,0x2d,
	0xa7,0xaa,0xaf,0x61,0xb8,0xce,0xca,0xe3,0x44,0xaa,0x06,0x3b,0x1f,0x3e,0xb4,0xd0,
	0xdd,0x46,0x6a,0x60,0x06,0xe1,0x59,0xdd,0xe4,0x15,0x09,0x99,0x62,0x3e,0x1b,0x07,
	0xd7,0xba,0x2f,0x4d,0xbe,0x20,0x04,0x6a,0x83,0x61,0xb2,0x58,0x84,0x9a,0xee,0x98,
	0xd6,0x48,0x22,0x3c,0xa3,0x2a,0xcb,0x11,0xc4,0xc9,0x82,0x6c,0x13,0xbc,0x8c,0xfa,
	0x3c,0x6f,0xfe,0x08,0x05,0x47,0x9c,0x6a,0xbb,0xee,0x0a,0xf2,0xaa,0x02,0x22,0x7a,
	0x69,0x61,0x48,0xc1,0x2c,0xe2,0xfa,0xd8,0x43,0xb3,0x8c,0x35,0xcb,0xce,0xf0,0x2e,
	0xaa,0x0f,0x3c,0x2a,0xb8,0xe2,0xeb,0x11,0xc2,0xcd,0x23,0x96,0x13,0x53,0x7e,0x2c,
	0xce,0x06,0x02,0x82,0x22,0xd8,0xe2,0x49,0xa7,0x15,0xfe,0x1a,0xae,0x54,0x39,0xac,
	0x07,0xdb,0xab,0x87,0xa2,0xf5,0x16,0xe3,0xd4,0x10,0x02,0xc2,0x29,0x39,0x3a,0x70,
	0xbf,0x08,0xd4,0x1e,0x95,0x6a,0x05,0xf2,0x2a,0x24,0xf4,0xf7,0xb3,0x95,0xed,0xf3,
	0x85,0x9d,0x65,0xe8,0xd8,0x62,0xc3,0xc9,0x73,0x31,0x40,0x87,0x15,0x8b,0x30,0xf8,
	0xf4,0xa8,0xef,0x73,0x4a,0xa1,0xc9,0xd1,0xf9,0xe4,0x21,0xb8,0x3c,0xca,0x20,0x11,
	0x91,0xa0,0xeb,0x61,0x80,0x16,0x0c,0x56,0x9b,0x08,0xd6,0x2f,0xb6,0x9f,0xc5,0x3c,
	0x2c,0x7c,0x85,0x4a,0xbc,0xed,0x76,0x41,0xc0,0xe0,0xa7,0x9b,0xfb,0x11,0xca,0xa0,
	0x71,0xd7,0xae,0x09,0xc0,0xd6,0xa9,0x58,0x02,0x7e,0x58,0x67,0x5a,0x4b,0xe5,0xeb,
	0x27,0xc7,0x84,0xee,0x25,0xbb,0x51,0xac,0xe8,0x5f,0x68,0x43,0x57,0xb3,0x01,0xfe,
	0x71,0xde,0x20,0x33,0x9b,0x0f,0x15,0x68,0x91,0x2d,0x84,0xf0,0xf2,0x63,0xdf,0x5c,
	0xfc,0x2b,0xef,0xef,0x32,0xe3,0x12,0x6c,0xd4,0x50,0xe5,0x4c,0x42,0xcb,0x6b,0x53,
	0x3e,0x6f,0x05,0x6d,0x53,0xa0,0xd3,0xb0,0x21,0xd4,0xdd,0x2c,0x01,0xd3,0x2e,0xda,
	0xff,0x03,0x00,0x00,0x03,0x08,0x00,0x00,0x46,0x69,0x72,0x6d,0x77,0x61,0x72,0x65,
	0x01,0x01,0xc8,0x00,0x45,0x23,0x01,0x00,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
	0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x00,0xff,0xff,0x07,0x00,0x00,0x01,0x01,0x00,
	0xdf,0x7b,0x3a,0x52,0xee,0x88,0x09,0x6d,0x89,0x8e,0xa1,0x09,0xbf,0x6e,0xf4,0x8f,
	0x74,0x47,0x86,0x7c,0xfb,0x0b,0xc7,0x57,0xfb,0x80,0x35,0xb5,0xe0,0xed,0x48,0x8c,
	0x00,0x00,0x00,0x00,0xff,0xff,0x03,0x00,0x02,0x02,0x09,0x00,0x45,0x23,0x01,0x01,
	0x54,0x65,0x73,0x74,0x69,0x6e,0x67,0x56,0x32,0x00,0x00,0x00,0x01,0x00,0x00,0x00,
	0x00,0x00,0x0c,0x00,0xff,0xff,0x0f,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,
	0xff,0xff,0x7f,0x00,0x01,0x01,0x02,0x00,0x68,0x95,0x5f,0x6e,0xd5,0x6f,0x27,0x7d,
	0x69,0xbc,0x98,0xda,0xea,0x34,0xa8,0x6f,0xd9,0xad,0x13,0x5f,0xf6,0x3c,0x6b,0x60,
	0x9b,0x1e,0x03,0x98,0x03,0xfa,0x3f,0xc4,0xc7,0xe6,0x5b,0xc4,0x85,0xec,0x8d,0x42,
	0x7b,0x9c,0x8d,0x53,0xa7,0x13,0x86,0x8c,0x00,0x00,0x08,0x00,0xff,0xff,0x0b,0x00,
	0x00,0x01,0x07,0x00,0xcf,0x21,0xaf,0xfd,0x72,0x55,0x62,0x07,0x3f,0xfe,0xaf,0xe7,
	0x75,0x16,0xe6,0x70,0x39,0x10,0x6b,0x6e,0x14,0x9c,0x16,0xc5,0x08,0x07,0x48,0xd6,
	0xfe,0xc9,0xfb,0x8a,0x00,0x00,0x10,0x00,0xff,0xff,0x3f,0x00,0x07,0x03,0x09,0x00,
	0x45,0x23,0x01,0x02,0x54,0x65,0x73,0x74,0x69,0x6e,0x67,0x56,0x33,0x00,0x00,0x00,
	0x02,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0xff,0xff,0xff,0x00,0x01,0x00,0x00,0x00,
	0x00,0x00,0x00,0x04,0xff,0xff,0xff,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0c,
	0xff,0xff,0xff,0x0f,0x02,0x01,0x01,0x00,0x6b,0xd8,0x96,0x5f,0x00,0x09,0x3e,0xb0,
	0x61,0xc6,0x4a,0x8e,0x51,0x39,0x63,0xf4,0xc9,0x0c,0x20,0xc3,0x8e,0x7e,0x82,0x65,
	0x91,0x36,0x44,0x78,0x24,0x57,0x84,0xc0,0xc5,0x33,0xe7,0x9e,0xf4,0x98,0x50,0x12,
	0x75,0x40,0xf3,0x53,0xad,0x40,0x67,0x06,0x3e,0xa0,0x7b,0xff,0x92,0xc5,0xfd,0xcc,
	0xe0,0xc0,0x5f,0x0b,0xc5,0x1b,0xb8,0xf8,0x00,0x00,0x80,0x00,0xff,0xff,0xbf,0x00,
	0x01,0x01,0x01,0x00,0xd8,0x72,0xbb,0x6b,0x80,0xc4,0x89,0xed,0x0b,0x12,0xd2,0xeb,
	0xb0,0x6f,0x3f,0xf3,0x82,0xaa,0xaf,0x25,0x2c,0xd5,0xae,0x75,0xca,0xc0,0x3e,0x98,
	0xb6,0x88,0x46,0xa8,0xe3,0xe3,0xdd,0x52,0x6f,0x05,0x3a,0xc8,0xf2,0x93,0xfa,0x75,
	0x79,0x71,0x63,0xa2,0x00,0x00,0x00,0x01,0xff,0xff,0xff,0x03,0x00,0x01,0x01,0x00,
	0x9b,0x50,0xfa,0x66,0xc1,0x12,0x75,0xc3,0x85,0x7e,0x8a,0x76,0xc9,0xae,0xb4,0x73,
	0x9e,0x92,0x58,0x35,0x1e,0x33,0x84,0x9e,0x40,0x8e,0x68,0xbe,0x03,0x68,0x25,0xd5,
	0x00,0x00,0x00,0x08,0xff,0xff,0xff,0x0b,0x02,0x01,0x01,0x00,0x81,0x4d,0xbb,0xea,
	0x60,0xa4,0x9a,0x9e,0xbc,0xd5,0x1a,0x42,0xfb,0xac,0x72,0xad,0xfc,0x71,0xfa,0x30,
	0xad,0xce,0xb1,0xa8,0x4b,0xc4,0x17,0x4d,0x3d,0x71,0x5a,0xf8,0x15,0x61,0x65,0xc3,
	0x0f,0xf9,0x68,0x64,0xdf,0xff,0xf7,0x4c,0xb1,0x72,0xc4,0x55,0xfe,0x5e,0xbe,0xf7,
	0x8d,0x90,0xc3,0x7f,0x31,0x37,0x74,0x8f,0xe5,0xc5,0xd4,0xf1,0x00,0x00,0x50,0x30,
	0xff,0xff,0xbf,0x30,0x01,0x01,0x01,0x00,0x6a,0xa4,0x4b,0xfd,0xac,0xda,0xe7,0xb6,
	0xa9,0x90,0x73,0x75,0x75,0x5a,0xb3,0x0c,0x5d,0x4c,0x27,0x5f,0x0d,0xb6,0xc9,0xe9,
	0xee,0xe7,0x94,0xd6,0xdf,0xac,0xc9,0xec,0xcf,0x23,0xdb,0xac,0x31,0x26,0xe9,0x96,
	0x84,0x89,0x12,0x83,0xf8,0x35,0x43,0x53,0x00,0x00,0x00,0x31,0xff,0xff,0xff,0x36,
	0x00,0x01,0x01,0x00,0x0f,0x33,0x96,0x5b,0x10,0xc8,0xdc,0x19,0xdb,0x4c,0x8e,0xfd,
	0xb3,0xc5,0xac,0x46,0x73,0x82,0x33,0xca,0x08,0x00,0xaa,0xd5,0x6b,0x0a,0x06,0xa7,
	0x27,0x4e,0xec,0xeb,0x00,0x00,0x00,0x38,0xff,0xff,0xff,0x3d,0x02,0x02,0x01,0x00,
	0xaf,0xf2,0xbe,0x53,0x8e,0x7b,0x62,0xd0,0x5d,0xf7,0xc4,0xd0,0xa5,0x5f,0x6f,0x1d,
	0x91,0x5a,0xf3,0x86,0x96,0xdf,0x3b,0xc7,0xbb,0x8e,0x8b,0xa5,0xac,0xb9,0xd4,0xcd,
	0xea,0x86,0x5d,0x8f,0x55,0x44,0xa1,0xe3,0xef,0x67,0x7d,0x0c,0xc6,0xfa,0xc6,0xb1,
	0x2b,0x83,0x99,0x5f,0x39,0xc4,0x83,0x84,0x10,0xa5,0x7d,0x27,0xcc,0xc9,0x7c,0xda,
	0x00,0x00,0x00,0x40,0xff,0xff,0xbf,0x40,0x00,0x00,0x00,0x41,0xff,0xff,0xff,0x4a,
	0x09,0x00,0x00,0x00,0x50,0x46,0x4d,0x20,0x54,0x65,0x73,0x74,0x32,0x00,0x00,0x00,
	0x03,0x09,0x00,0x00,0x46,0x69,0x72,0x6d,0x77,0x61,0x72,0x65,0x32,0x00,0x00,0x00,
	0x02,0x02,0x08,0x00,0x45,0x23,0x11,0x01,0x54,0x65,0x73,0x74,0x69,0x6e,0x67,0x32,
	0x01,0x00,0x00,0x00,0x00,0x00,0x0c,0x10,0xff,0xff,0x0f,0x10,0x00,0x00,0x00,0x00,
	0x00,0x00,0x40,0x10,0xff,0xff,0x7f,0x10,0x01,0x04,0x01,0x00,0x3e,0xae,0xdb,0xbf,
	0x03,0x66,0x26,0xfa,0x81,0x10,0x76,0x74,0x29,0xc9,0x89,0xd6,0xd9,0x19,0xe7,0x77,
	0xba,0x69,0x25,0x44,0xd6,0xdc,0xf9,0x2c,0x68,0x74,0x1c,0xc9,0x9c,0x20,0x12,0xe7,
	0x74,0x08,0x75,0x22,0x28,0x8c,0xcd,0xbb,0x7e,0xf3,0x44,0xb5,0x00,0x00,0x08,0x10,
	0xff,0xff,0x08,0x10,0x00,0x00,0x09,0x10,0xff,0xff,0x09,0x10,0x00,0x00,0x0a,0x10,
	0xff,0xff,0x0a,0x10,0x00,0x00,0x0b,0x10,0xff,0xff,0x0b,0x10,0x00,0x02,0x01,0x00,
	0x70,0xff,0x99,0x32,0xf0,0xcd,0xd9,0x1b,0x82,0xd6,0x11,0x64,0x70,0x80,0xe3,0x45,
	0x93,0x65,0xc7,0xc2,0x64,0xa8,0x3c,0x11,0xeb,0x27,0xfd,0x99,0x51,0x4d,0xe3,0x0f,
	0x00,0x00,0x10,0x10,0xff,0xff,0x2f,0x10,0x00,0x00,0x20,0x10,0xff,0xff,0x3f,0x10,
	0x01,0x03,0x0a,0x00,0x45,0x23,0x11,0x02,0x54,0x65,0x73,0x74,0x69,0x6e,0x67,0x32,
	0x56,0x32,0x00,0x00,0x02,0x00,0x00,0x00,0x00,0x00,0xc0,0x10,0xff,0xff,0xff,0x10,
	0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x14,0xff,0xff,0xff,0x17,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x1c,0xff,0xff,0xff,0x1f,0x02,0x18,0x01,0x00,0xfb,0xd9,0x89,0x3f,
	0x78,0x17,0xbf,0xf5,0x33,0xa4,0x9e,0x99,0x70,0x00,0x37,0x7a,0xa9,0x4d,0xb0,0x29,
	0xba,0xac,0x12,0x12,0xc2,0x03,0x37,0x05,0xe1,0x25,0x42,0xbb,0x27,0x0f,0x16,0xd7,
	0x7f,0xb7,0x06,0xca,0x40,0x11,0xfc,0xc9,0xca,0x16,0xa7,0xcb,0x9c,0xcd,0x70,0x61,
	0x84,0x81,0xa4,0xfd,0xce,0x5a,0xbf,0xd1,0x99,0xb7,0xef,0xc0,0x00,0x00,0x10,0x00,
	0xff,0xff,0x10,0x00,0x00,0x00,0x11,0x00,0xff,0xff,0x11,0x00,0x00,0x00,0x12,0x00,
	0xff,0xff,0x12,0x00,0x00,0x00,0x13,0x00,0xff,0xff,0x13,0x00,0x00,0x00,0x14,0x00,
	0xff,0xff,0x14,0x00,0x00,0x00,0x15,0x00,0xff,0xff,0x15,0x00,0x00,0x00,0x16,0x00,
	0xff,0xff,0x16,0x00,0x00,0x00,0x17,0x00,0xff,0xff,0x17,0x00,0x00,0x00,0x18,0x00,
	0xff,0xff,0x18,0x00,0x00,0x00,0x19,0x00,0xff,0xff,0x19,0x00,0x00,0x00,0x10,0x01,
	0xff,0xff,0x10,0x01,0x00,0x00,0x11,0x01,0xff,0xff,0x11,0x01,0x00,0x00,0x12,0x01,
	0xff,0xff,0x12,0x01,0x00,0x00,0x13,0x01,0xff,0xff,0x13,0x01,0x00,0x00,0x14,0x01,
	0xff,0xff,0x14,0x01,0x00,0x00,0x15,0x01,0xff,0xff,0x15,0x01,0x00,0x00,0x16,0x01,
	0xff,0xff,0x16,0x01,0x00,0x00,0x17,0x01,0xff,0xff,0x17,0x01,0x00,0x00,0x18,0x01,
	0xff,0xff,0x18,0x01,0x00,0x00,0x19,0x01,0xff,0xff,0x19,0x01,0x00,0x00,0x20,0x01,
	0xff,0xff,0x20,0x01,0x00,0x00,0x21,0x01,0xff,0xff,0x21,0x01,0x00,0x00,0x22,0x01,
	0xff,0xff,0x22,0x01,0x00,0x00,0x23,0x01,0xff,0xff,0x23,0x01,0x01,0x01,0x0a,0x00,
	0x45,0x23,0x11,0x00,0x54,0x65,0x73,0x74,0x69,0x6e,0x67,0x32,0x56,0x33,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x10,0xff,0xff,0x07,0x10,0x00,0x00,0x01,0x00,
	0xe1,0xeb,0x23,0xcd,0xdd,0x11,0x68,0x93,0x5c,0xcb,0x80,0xb9,0x9c,0x2f,0x43,0xf5,
	0x52,0xda,0xa6,0xbf,0x2a,0x0f,0x2f,0x72,0x27,0x5c,0x1f,0x1c,0x60,0xc6,0x4b,0x57,
	0x03,0x03,0x00,0x00,0x46,0x57,0x33,0x00,0x04,0x03,0x05,0x00,0x45,0x23,0x21,0x02,
	0x54,0x65,0x73,0x74,0x33,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,0x00,0xc0,0x20,
	0xff,0xff,0xff,0x20,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x24,0xff,0xff,0xff,0x27,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x2c,0xff,0xff,0xff,0x2f,0x02,0x0d,0x01,0x00,
	0x67,0x05,0xcc,0xe3,0xd1,0x1f,0x44,0x53,0x01,0x2d,0xd1,0xe8,0x9e,0xcf,0x81,0x3f,
	0xe5,0xd1,0x32,0xba,0xa3,0x59,0xef,0x9b,0xbe,0xf5,0xde,0x8c,0x61,0x43,0x68,0xc5,
	0x0e,0x94,0x37,0x2d,0x1f,0xb5,0xed,0x11,0xba,0xd8,0xb7,0x46,0x5c,0xbf,0x80,0xd4,
	0x7b,0xa4,0x9f,0xe2,0x56,0x61,0x73,0x0d,0x22,0xed,0x6c,0x88,0x05,0x21,0xa3,0xd1,
	0x00,0x00,0x20,0x00,0xff,0xff,0x20,0x00,0x00,0x00,0x21,0x00,0xff,0xff,0x21,0x00,
	0x00,0x00,0x22,0x00,0xff,0xff,0x22,0x00,0x00,0x00,0x23,0x00,0xff,0xff,0x23,0x00,
	0x00,0x00,0x24,0x00,0xff,0xff,0x24,0x00,0x00,0x00,0x25,0x00,0xff,0xff,0x25,0x00,
	0x00,0x00,0x26,0x00,0xff,0xff,0x26,0x00,0x00,0x00,0x27,0x00,0xff,0xff,0x27,0x00,
	0x00,0x00,0x28,0x00,0xff,0xff,0x28,0x00,0x00,0x00,0x29,0x00,0xff,0xff,0x29,0x00,
	0x00,0x00,0x10,0x02,0xff,0xff,0x10,0x02,0x00,0x00,0x11,0x02,0xff,0xff,0x11,0x02,
	0x00,0x00,0x12,0x02,0xff,0xff,0x12,0x02,0x01,0x15,0x01,0x00,0xc9,0x53,0x56,0x3d,
	0x6a,0xf7,0x1d,0x2d,0xee,0xd4,0x1d,0xe8,0x32,0x7f,0x8d,0xdc,0x75,0xd1,0x92,0xee,
	0x15,0x1d,0x1c,0x81,0x18,0xc5,0xc2,0x7d,0xf1,0x3c,0xf2,0x49,0x4f,0x6f,0xf4,0x34,
	0x5c,0xfc,0x9b,0x0f,0x56,0xaf,0x05,0xb8,0x8a,0x8f,0x36,0x78,0x00,0x00,0x20,0x00,
	0xff,0xff,0x20,0x00,0x00,0x00,0x21,0x00,0xff,0xff,0x21,0x00,0x00,0x00,0x22,0x00,
	0xff,0xff,0x22,0x00,0x00,0x00,0x23,0x00,0xff,0xff,0x23,0x00,0x00,0x00,0x24,0x00,
	0xff,0xff,0x24,0x00,0x00,0x00,0x25,0x00,0xff,0xff,0x25,0x00,0x00,0x00,0x26,0x00,
	0xff,0xff,0x26,0x00,0x00,0x00,0x27,0x00,0xff,0xff,0x27,0x00,0x00,0x00,0x28,0x00,
	0xff,0xff,0x28,0x00,0x00,0x00,0x29,0x00,0xff,0xff,0x29,0x00,0x00,0x00,0x10,0x02,
	0xff,0xff,0x10,0x02,0x00,0x00,0x11,0x02,0xff,0xff,0x11,0x02,0x00,0x00,0x12,0x02,
	0xff,0xff,0x12,0x02,0x00,0x00,0x13,0x02,0xff,0xff,0x13,0x02,0x00,0x00,0x14,0x02,
	0xff,0xff,0x14,0x02,0x00,0x00,0x15,0x02,0xff,0xff,0x15,0x02,0x00,0x00,0x16,0x02,
	0xff,0xff,0x16,0x02,0x00,0x00,0x17,0x02,0xff,0xff,0x17,0x02,0x00,0x00,0x18,0x02,
	0xff,0xff,0x18,0x02,0x00,0x00,0x19,0x02,0xff,0xff,0x19,0x02,0x00,0x00,0x20,0x02,
	0xff,0xff,0x20,0x02,0x00,0x01,0x01,0x00,0x9e,0x3f,0x72,0xf5,0xb5,0xfc,0x19,0xd0,
	0xe0,0x70,0xbf,0x2e,0x75,0x32,0xc4,0xac,0x9a,0xd6,0x8d,0xfd,0xdb,0x23,0x77,0xce,
	0x3e,0x28,0xdb,0xcb,0x4f,0xfc,0xb4,0xd0,0x00,0x00,0x00,0x28,0xff,0xff,0xff,0x2b,
	0x00,0x16,0x01,0x00,0xc6,0x6b,0xec,0x54,0x3c,0x48,0xbc,0x10,0xd7,0x4f,0xe2,0x4d,
	0x3a,0x9b,0xe8,0x7d,0x5d,0xcc,0x79,0x1c,0x52,0x3a,0x22,0xa8,0xb1,0x65,0x92,0x71,
	0x3a,0xc8,0x00,0x93,0x00,0x00,0x20,0x00,0xff,0xff,0x20,0x00,0x00,0x00,0x21,0x00,
	0xff,0xff,0x21,0x00,0x00,0x00,0x22,0x00,0xff,0xff,0x22,0x00,0x00,0x00,0x23,0x00,
	0xff,0xff,0x23,0x00,0x00,0x00,0x24,0x00,0xff,0xff,0x24,0x00,0x00,0x00,0x25,0x00,
	0xff,0xff,0x25,0x00,0x00,0x00,0x26,0x00,0xff,0xff,0x26,0x00,0x00,0x00,0x27,0x00,
	0xff,0xff,0x27,0x00,0x00,0x00,0x28,0x00,0xff,0xff,0x28,0x00,0x00,0x00,0x29,0x00,
	0xff,0xff,0x29,0x00,0x00,0x00,0x10,0x02,0xff,0xff,0x10,0x02,0x00,0x00,0x11,0x02,
	0xff,0xff,0x11,0x02,0x00,0x00,0x12,0x02,0xff,0xff,0x12,0x02,0x00,0x00,0x13,0x02,
	0xff,0xff,0x13,0x02,0x00,0x00,0x14,0x02,0xff,0xff,0x14,0x02,0x00,0x00,0x15,0x02,
	0xff,0xff,0x15,0x02,0x00,0x00,0x16,0x02,0xff,0xff,0x16,0x02,0x00,0x00,0x17,0x02,
	0xff,0xff,0x17,0x02,0x00,0x00,0x18,0x02,0xff,0xff,0x18,0x02,0x00,0x00,0x19,0x02,
	0xff,0xff,0x19,0x02,0x00,0x00,0x20,0x02,0xff,0xff,0x20,0x02,0x00,0x00,0x21,0x02,
	0xff,0xff,0x21,0x02,0x01,0x01,0x07,0x00,0x45,0x23,0x21,0x00,0x54,0x65,0x73,0x74,
	0x33,0x56,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x20,0xff,0xff,0x07,0x20,
	0x00,0x1b,0x01,0x00,0x12,0x59,0x11,0x33,0x0e,0x69,0xc2,0x0a,0x4e,0xc9,0x1e,0x8b,
	0xbe,0xf9,0x77,0x1d,0x6c,0xfe,0xf0,0x44,0x8b,0xfe,0x0e,0x1a,0xd3,0x78,0xb8,0x08,
	0xc2,0xd5,0x71,0xf2,0x00,0x00,0x20,0x00,0xff,0xff,0x20,0x00,0x00,0x00,0x21,0x00,
	0xff,0xff,0x21,0x00,0x00,0x00,0x22,0x00,0xff,0xff,0x22,0x00,0x00,0x00,0x23,0x00,
	0xff,0xff,0x23,0x00,0x00,0x00,0x24,0x00,0xff,0xff,0x24,0x00,0x00,0x00,0x25,0x00,
	0xff,0xff,0x25,0x00,0x00,0x00,0x26,0x00,0xff,0xff,0x26,0x00,0x00,0x00,0x27,0x00,
	0xff,0xff,0x27,0x00,0x00,0x00,0x28,0x00,0xff,0xff,0x28,0x00,0x00,0x00,0x29,0x00,
	0xff,0xff,0x29,0x00,0x00,0x00,0x10,0x02,0xff,0xff,0x10,0x02,0x00,0x00,0x11,0x02,
	0xff,0xff,0x11,0x02,0x00,0x00,0x12,0x02,0xff,0xff,0x12,0x02,0x00,0x00,0x13,0x02,
	0xff,0xff,0x13,0x02,0x00,0x00,0x14,0x02,0xff,0xff,0x14,0x02,0x00,0x00,0x15,0x02,
	0xff,0xff,0x15,0x02,0x00,0x00,0x16,0x02,0xff,0xff,0x16,0x02,0x00,0x00,0x17,0x02,
	0xff,0xff,0x17,0x02,0x00,0x00,0x18,0x02,0xff,0xff,0x18,0x02,0x00,0x00,0x19,0x02,
	0xff,0xff,0x19,0x02,0x00,0x00,0x20,0x02,0xff,0xff,0x20,0x02,0x00,0x00,0x21,0x02,
	0xff,0xff,0x21,0x02,0x00,0x00,0x22,0x02,0xff,0xff,0x22,0x02,0x00,0x00,0x23,0x02,
	0xff,0xff,0x23,0x02,0x00,0x00,0x24,0x02,0xff,0xff,0x24,0x02,0x00,0x00,0x25,0x02,
	0xff,0xff,0x25,0x02,0x00,0x00,0x26,0x02,0xff,0xff,0x26,0x02,0x02,0x02,0x07,0x00,
	0x45,0x23,0x21,0x01,0x54,0x65,0x73,0x74,0x33,0x56,0x33,0x00,0x01,0x00,0x00,0x00,
	0x00,0x00,0x0c,0x20,0xff,0xff,0x0f,0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x20,
	0xff,0xff,0x7f,0x20,0x03,0x01,0x01,0x00,0x4e,0xa8,0xa0,0xc8,0x88,0x31,0xf1,0x14,
	0x6e,0xad,0x6c,0x06,0x05,0xf6,0x0f,0x8f,0x4a,0x7c,0x8b,0xb6,0x25,0x95,0xc6,0x66,
	0x0b,0x36,0x1c,0x41,0xa4,0x05,0x19,0xd2,0x94,0x28,0x10,0xae,0x78,0xa9,0xfb,0x1d,
	0xed,0xc5,0x31,0x07,0x3c,0x7f,0x1e,0x70,0x00,0x00,0x08,0x20,0xff,0xff,0x0b,0x20,
	0x00,0x01,0x01,0x00,0x94,0x21,0x78,0x8d,0x0e,0xde,0x22,0x05,0xb1,0x00,0x2a,0x16,
	0x2d,0x20,0x46,0xf7,0xc0,0x72,0x3d,0x6c,0x45,0x6c,0xa3,0xff,0x4b,0xbb,0xd6,0xaf,
	0x36,0x84,0x97,0x1b,0x00,0x00,0x10,0x20,0xff,0xff,0x3f,0x20,0x30,0x44,0x02,0x20,
	0x0e,0x72,0xaa,0xf6,0xa7,0x9b,0x73,0x72,0xa9,0x55,0xcb,0xeb,0x4c,0x06,0xb5,0x92,
	0xfe,0xab,0x5a,0x6a,0x8e,0x4b,0xe2,0x50,0xb4,0x5a,0x4c,0x6e,0x04,0xa0,0xd4,0x9d,
	0x02,0x20,0x10,0x2e,0x1b,0xf5,0x98,0x01,0xf2,0x47,0xeb,0xce,0xcc,0xc1,0x99,0x76,
	0xc0,0x14,0x84,0x85,0xa5,0x65,0x6b,0xc6,0xd8,0x63,0x7b,0x32,0x58,0xf6,0x76,0x00,
	0xbc,0x43,0x00,0x00,0x00
};

/**
 * PFM_V2_IMG_TEST_DATA hash for testing.
 *
 * head -c -73 pfm.img | openssl dgst -sha256
 */
static const uint8_t PFM_V2_IMG_TEST_HASH[] = {
	0x97,0x33,0xd0,0xd8,0xa1,0x3f,0x68,0xc7,0x56,0x2f,0x7f,0x57,0xf5,0x4a,0x1f,0x05,
	0x48,0xc3,0xe2,0x78,0xe6,0x25,0x1f,0x55,0xec,0x04,0xb9,0x55,0x56,0x7e,0xa6,0x55
};

/**
 * First firmware image of the first firmware component for the test v2 PFM for image parsing tests.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_IMG_TEST_11[] = {
	{
		.img_offset = 0x034c,
		.hash = PFM_V2_IMG_TEST_DATA + 0x0350,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG1_11_REGION
	}
};

/**
 * Second firmware image of the first firmware copmonent for test v2 PFM for image parsing tests.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_IMG_TEST_12[] = {
	{
		.img_offset = 0x03a4,
		.hash = PFM_V2_IMG_TEST_DATA + 0x03a8,
		.hash_len = 48,
		.hash_type = HASH_TYPE_SHA384,
		.flags = 2,
		.region_count = 1,
		.region = PFM_V2_IMG1_21_REGION
	},
	{
		.img_offset = 0x03e0,
		.hash = PFM_V2_IMG_TEST_DATA + 0x03e4,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 7,
		.region_count = 1,
		.region = PFM_V2_IMG1_22_REGION
	}
};

/**
 * Image region for the fourth image for the first firmware component for image parsing tests.
 */
static const struct pfm_v2_testing_data_region PFM_V2_IMG1_34_REGION_IMG_TEST[] = {
	{
		.start_addr = 0x30500000,
		.end_addr = 0x30bfffff,
	}
};

/**
 * Image region for the fifth image for the first firmware component for image parsing tests.
 */
static const struct pfm_v2_testing_data_region PFM_V2_IMG1_35_REGION_IMG_TEST[] = {
	{
		.start_addr = 0x31000000,
		.end_addr = 0x36ffffff,
	}
};

/**
 * Image region for the sixth image for the first firmware component for image parsing tests.
 */
static const struct pfm_v2_testing_data_region PFM_V2_IMG1_36_REGION_IMG_TEST[] = {
	{
		.start_addr = 0x38000000,
		.end_addr = 0x3dffffff,
	}
};

/**
 * Image region for the seventh image for the first firmware component for image parsing tests.
 */
static const struct pfm_v2_testing_data_region PFM_V2_IMG1_37_REGION_IMG_TEST[] = {
	{
		.start_addr = 0x40000000,
		.end_addr = 0x40bfffff,
	},
	{
		.start_addr = 0x41000000,
		.end_addr = 0x4affffff,
	}
};

/**
 * Third firmware image of the first firmware component for the test v2 PFM for image parsing tests.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_IMG_TEST_13[] = {
	{
		.img_offset = 0x0444,
		.hash = PFM_V2_IMG_TEST_DATA + 0x0448,
		.hash_len = 64,
		.hash_type = HASH_TYPE_SHA512,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG1_31_REGION
	},
	{
		.img_offset = 0x0490,
		.hash = PFM_V2_IMG_TEST_DATA + 0x0494,
		.hash_len = 48,
		.hash_type = HASH_TYPE_SHA384,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG1_32_REGION
	},
	{
		.img_offset = 0x04cc,
		.hash = PFM_V2_IMG_TEST_DATA + 0x04d0,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG1_33_REGION
	},
	{
		.img_offset = 0x04f8,
		.hash = PFM_V2_IMG_TEST_DATA + 0x04fc,
		.hash_len = 64,
		.hash_type = HASH_TYPE_SHA512,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG1_34_REGION_IMG_TEST
	},
	{
		.img_offset = 0x0544,
		.hash = PFM_V2_IMG_TEST_DATA + 0x0548,
		.hash_len = 48,
		.hash_type = HASH_TYPE_SHA384,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG1_35_REGION_IMG_TEST
	},
	{
		.img_offset = 0x0580,
		.hash = PFM_V2_IMG_TEST_DATA + 0x0584,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG1_36_REGION_IMG_TEST
	},
	{
		.img_offset = 0x05ac,
		.hash = PFM_V2_IMG_TEST_DATA + 0x05b0,
		.hash_len = 64,
		.hash_type = HASH_TYPE_SHA512,
		.flags = 1,
		.region_count = 2,
		.region = PFM_V2_IMG1_37_REGION_IMG_TEST
	}
};

/**
 * First firmware version components of the test v2 PFM for image parsing tests.
 */
static const struct pfm_v2_testing_data_fw_ver PFM_V2_FW_VER_IMG_TEST_1[] = {
	{
		.fw_version = PFM_V2_IMG_TEST_DATA + 0x0270,
		.fw_version_len = 0x0108,
		.version_str = PFM_V2_FW_VERSION_MAX_NO_READ_IMG,
		.version_str_len = sizeof (PFM_V2_FW_VERSION_MAX_NO_READ_IMG) - 1,
		.version_str_pad = PFM_V2_FW_VERSION_MAX_NO_READ_IMG_PAD,
		.fw_version_offset = 0x0270,
		.fw_version_entry = 2,
		.fw_version_hash = 1,
		.version_addr = 0x012345,
		.rw_count = 1,
		.rw = PFM_V2_RW1_ONE,
		.img_count = 1,
		.img = PFM_V2_FW_IMG_IMG_TEST_11
	},
	{
		.fw_version = PFM_V2_IMG_TEST_DATA + 0x0378,
		.fw_version_len = 0x0094,
		.version_str = PFM_V2_FW_VERSION_V2,
		.version_str_len = sizeof (PFM_V2_FW_VERSION_V2) - 1,
		.version_str_pad = PFM_V2_FW_VERSION_V2_PAD,
		.fw_version_offset = 0x0378,
		.fw_version_entry = 3,
		.fw_version_hash = 8,
		.version_addr = 0x1012345,
		.rw_count = 2,
		.rw = PFM_V2_RW1_TWO,
		.img_count = 2,
		.img = PFM_V2_FW_IMG_IMG_TEST_12
	},
	{
		.fw_version = PFM_V2_IMG_TEST_DATA + 0x040c,
		.fw_version_len = 0x01f4,
		.version_str = PFM_V2_FW_VERSION_V3,
		.version_str_len = sizeof (PFM_V2_FW_VERSION_V3) - 1,
		.version_str_pad = PFM_V2_FW_VERSION_V3_PAD,
		.fw_version_offset = 0x040c,
		.fw_version_entry = 4,
		.fw_version_hash = 11,
		.version_addr = 0x2012345,
		.rw_count = 3,
		.rw = PFM_V2_RW1_THREE,
		.img_count = 7,
		.img = PFM_V2_FW_IMG_IMG_TEST_13
	}
};

/**
 * Image region for the first image for the second firmware component for image parsing tests.
 */
static const struct pfm_v2_testing_data_region PFM_V2_IMG2_11_REGION_IMG_TEST[] = {
	{
		.start_addr = 0x10080000,
		.end_addr = 0x1008ffff,
	},
	{
		.start_addr = 0x10090000,
		.end_addr = 0x1009ffff,
	},
	{
		.start_addr = 0x100a0000,
		.end_addr = 0x100affff,
	},
	{
		.start_addr = 0x100b0000,
		.end_addr = 0x100bffff,
	}
};

/**
 * Image region for the second image for the second firmware component for image parsing tests.
 */
static const struct pfm_v2_testing_data_region PFM_V2_IMG2_12_REGION_IMG_TEST[] = {
	{
		.start_addr = 0x10100000,
		.end_addr = 0x102fffff,
	},
	{
		.start_addr = 0x10200000,
		.end_addr = 0x103fffff,
	}
};

/**
 * First firmware image of the second firmware copmonent for test v2 PFM for image parsing tests.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_IMG_TEST_21[] = {
	{
		.img_offset = 0x0648,
		.hash = PFM_V2_IMG_TEST_DATA + 0x064c,
		.hash_len = 48,
		.hash_type = HASH_TYPE_SHA384,
		.flags = 1,
		.region_count = 4,
		.region = PFM_V2_IMG2_11_REGION_IMG_TEST
	},
	{
		.img_offset = 0x069c,
		.hash = PFM_V2_IMG_TEST_DATA + 0x06a0,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 1,
		.region_count = 2,
		.region = PFM_V2_IMG2_12_REGION_IMG_TEST
	}
};

/**
 * Image regions for the second image for the second firmware component for image parsing tests.
 */
static const struct pfm_v2_testing_data_region PFM_V2_IMG2_22_REGION_IMG_TEST[] = {
	{
		.start_addr = 0x100000,
		.end_addr = 0x10ffff,
	},
	{
		.start_addr = 0x110000,
		.end_addr = 0x11ffff,
	},
	{
		.start_addr = 0x120000,
		.end_addr = 0x12ffff,
	},
	{
		.start_addr = 0x130000,
		.end_addr = 0x13ffff,
	},
	{
		.start_addr = 0x140000,
		.end_addr = 0x14ffff,
	},
	{
		.start_addr = 0x150000,
		.end_addr = 0x15ffff,
	},
	{
		.start_addr = 0x160000,
		.end_addr = 0x16ffff,
	},
	{
		.start_addr = 0x170000,
		.end_addr = 0x17ffff,
	},
	{
		.start_addr = 0x180000,
		.end_addr = 0x18ffff,
	},
	{
		.start_addr = 0x190000,
		.end_addr = 0x19ffff,
	},
	{
		.start_addr = 0x1100000,
		.end_addr = 0x110ffff,
	},
	{
		.start_addr = 0x1110000,
		.end_addr = 0x111ffff,
	},
	{
		.start_addr = 0x1120000,
		.end_addr = 0x112ffff,
	},
	{
		.start_addr = 0x1130000,
		.end_addr = 0x113ffff,
	},
	{
		.start_addr = 0x1140000,
		.end_addr = 0x114ffff,
	},
	{
		.start_addr = 0x1150000,
		.end_addr = 0x115ffff,
	},
	{
		.start_addr = 0x1160000,
		.end_addr = 0x116ffff,
	},
	{
		.start_addr = 0x1170000,
		.end_addr = 0x117ffff,
	},
	{
		.start_addr = 0x1180000,
		.end_addr = 0x118ffff,
	},
	{
		.start_addr = 0x1190000,
		.end_addr = 0x119ffff,
	},
	{
		.start_addr = 0x1200000,
		.end_addr = 0x120ffff,
	},
	{
		.start_addr = 0x1210000,
		.end_addr = 0x121ffff,
	},
	{
		.start_addr = 0x1220000,
		.end_addr = 0x122ffff,
	},
	{
		.start_addr = 0x1230000,
		.end_addr = 0x123ffff,
	}
};

/**
 * Second firmware image of the second firmware component for the test v2 PFM for image parsing
 * tests.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_IMG_TEST_22[] = {
	{
		.img_offset = 0x0708,
		.hash = PFM_V2_IMG_TEST_DATA + 0x070c,
		.hash_len = 64,
		.hash_type = HASH_TYPE_SHA512,
		.flags = 1,
		.region_count = 24,
		.region = PFM_V2_IMG2_22_REGION_IMG_TEST
	}
};

/**
 * Third firmware image of the second firmware component for the test v2 PFM for image parsing
 * tests.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_IMG_TEST_23[] = {
	{
		.img_offset = 0x082c,
		.hash = PFM_V2_IMG_TEST_DATA + 0x0830,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 1,
		.region_count = 0,
		.region = NULL
	}
};

/**
 * Second firmware version components of the test v2 PFM for image parsing tests.
 */
static const struct pfm_v2_testing_data_fw_ver PFM_V2_FW_VER_IMG_TEST_2[] = {
	{
		.fw_version = PFM_V2_IMG_TEST_DATA + 0x0620,
		.fw_version_len = 0x00b0,
		.version_str = PFM_V2_FW_VERSION2,
		.version_str_len = sizeof (PFM_V2_FW_VERSION2) - 1,
		.version_str_pad = PFM_V2_FW_VERSION2_PAD,
		.fw_version_offset = 0x0620,
		.fw_version_entry = 7,
		.fw_version_hash = 2,
		.version_addr = 0x1112345,
		.rw_count = 2,
		.rw = PFM_V2_RW2_TWO,
		.img_count = 2,
		.img = PFM_V2_FW_IMG_IMG_TEST_21
	},
	{
		.fw_version = PFM_V2_IMG_TEST_DATA + 0x06d0,
		.fw_version_len = 0x013c,
		.version_str = PFM_V2_FW_VERSION2_V2,
		.version_str_len = sizeof (PFM_V2_FW_VERSION2_V2) - 1,
		.version_str_pad = PFM_V2_FW_VERSION2_V2_PAD,
		.fw_version_offset = 0x06d0,
		.fw_version_entry = 8,
		.fw_version_hash = 9,
		.version_addr = 0x2112345,
		.rw_count = 3,
		.rw = PFM_V2_RW2_THREE,
		.img_count = 3,
		.img = PFM_V2_FW_IMG_IMG_TEST_22
	},
	{
		.fw_version = PFM_V2_IMG_TEST_DATA + 0x080c,
		.fw_version_len = 0x0044,
		.version_str = PFM_V2_FW_VERSION2_V3,
		.version_str_len = sizeof (PFM_V2_FW_VERSION2_V3) - 1,
		.version_str_pad = PFM_V2_FW_VERSION2_V3_PAD,
		.fw_version_offset = 0x080c,
		.fw_version_entry = 9,
		.fw_version_hash = 12,
		.version_addr = 0x0112345,
		.rw_count = 1,
		.rw = PFM_V2_RW2_ONE,
		.img_count = 1,
		.img = PFM_V2_FW_IMG_IMG_TEST_23
	}
};

/**
 * Image region for the first image for the third firmware component for image parsing tests.
 */
static const struct pfm_v2_testing_data_region PFM_V2_IMG3_11_REGION_IMG_TEST[] = {
	{
		.start_addr = 0x200000,
		.end_addr = 0x20ffff,
	},
	{
		.start_addr = 0x210000,
		.end_addr = 0x21ffff,
	},
	{
		.start_addr = 0x220000,
		.end_addr = 0x22ffff,
	},
	{
		.start_addr = 0x230000,
		.end_addr = 0x23ffff,
	},
	{
		.start_addr = 0x240000,
		.end_addr = 0x24ffff,
	},
	{
		.start_addr = 0x250000,
		.end_addr = 0x25ffff,
	},
	{
		.start_addr = 0x260000,
		.end_addr = 0x26ffff,
	},
	{
		.start_addr = 0x270000,
		.end_addr = 0x27ffff,
	},
	{
		.start_addr = 0x280000,
		.end_addr = 0x28ffff,
	},
	{
		.start_addr = 0x290000,
		.end_addr = 0x29ffff,
	},
	{
		.start_addr = 0x2100000,
		.end_addr = 0x210ffff,
	},
	{
		.start_addr = 0x2110000,
		.end_addr = 0x211ffff,
	},
	{
		.start_addr = 0x2120000,
		.end_addr = 0x212ffff,
	}
};

/**
 * Image region for the second image for the third firmware component for image parsing tests.
 */
static const struct pfm_v2_testing_data_region PFM_V2_IMG3_12_REGION_IMG_TEST[] = {
	{
		.start_addr = 0x200000,
		.end_addr = 0x20ffff,
	},
	{
		.start_addr = 0x210000,
		.end_addr = 0x21ffff,
	},
	{
		.start_addr = 0x220000,
		.end_addr = 0x22ffff,
	},
	{
		.start_addr = 0x230000,
		.end_addr = 0x23ffff,
	},
	{
		.start_addr = 0x240000,
		.end_addr = 0x24ffff,
	},
	{
		.start_addr = 0x250000,
		.end_addr = 0x25ffff,
	},
	{
		.start_addr = 0x260000,
		.end_addr = 0x26ffff,
	},
	{
		.start_addr = 0x270000,
		.end_addr = 0x27ffff,
	},
	{
		.start_addr = 0x280000,
		.end_addr = 0x28ffff,
	},
	{
		.start_addr = 0x290000,
		.end_addr = 0x29ffff,
	},
	{
		.start_addr = 0x2100000,
		.end_addr = 0x210ffff,
	},
	{
		.start_addr = 0x2110000,
		.end_addr = 0x211ffff,
	},
	{
		.start_addr = 0x2120000,
		.end_addr = 0x212ffff,
	},
	{
		.start_addr = 0x2130000,
		.end_addr = 0x213ffff,
	},
	{
		.start_addr = 0x2140000,
		.end_addr = 0x214ffff,
	},
	{
		.start_addr = 0x2150000,
		.end_addr = 0x215ffff,
	},
	{
		.start_addr = 0x2160000,
		.end_addr = 0x216ffff,
	},
	{
		.start_addr = 0x2170000,
		.end_addr = 0x217ffff,
	},
	{
		.start_addr = 0x2180000,
		.end_addr = 0x218ffff,
	},
	{
		.start_addr = 0x2190000,
		.end_addr = 0x219ffff,
	},
	{
		.start_addr = 0x2200000,
		.end_addr = 0x220ffff,
	}
};

/**
 * Image region for the fourth image for the third firmware component for image parsing tests.
 */
static const struct pfm_v2_testing_data_region PFM_V2_IMG3_14_REGION_IMG_TEST[] = {
	{
		.start_addr = 0x200000,
		.end_addr = 0x20ffff,
	},
	{
		.start_addr = 0x210000,
		.end_addr = 0x21ffff,
	},
	{
		.start_addr = 0x220000,
		.end_addr = 0x22ffff,
	},
	{
		.start_addr = 0x230000,
		.end_addr = 0x23ffff,
	},
	{
		.start_addr = 0x240000,
		.end_addr = 0x24ffff,
	},
	{
		.start_addr = 0x250000,
		.end_addr = 0x25ffff,
	},
	{
		.start_addr = 0x260000,
		.end_addr = 0x26ffff,
	},
	{
		.start_addr = 0x270000,
		.end_addr = 0x27ffff,
	},
	{
		.start_addr = 0x280000,
		.end_addr = 0x28ffff,
	},
	{
		.start_addr = 0x290000,
		.end_addr = 0x29ffff,
	},
	{
		.start_addr = 0x2100000,
		.end_addr = 0x210ffff,
	},
	{
		.start_addr = 0x2110000,
		.end_addr = 0x211ffff,
	},
	{
		.start_addr = 0x2120000,
		.end_addr = 0x212ffff,
	},
	{
		.start_addr = 0x2130000,
		.end_addr = 0x213ffff,
	},
	{
		.start_addr = 0x2140000,
		.end_addr = 0x214ffff,
	},
	{
		.start_addr = 0x2150000,
		.end_addr = 0x215ffff,
	},
	{
		.start_addr = 0x2160000,
		.end_addr = 0x216ffff,
	},
	{
		.start_addr = 0x2170000,
		.end_addr = 0x217ffff,
	},
	{
		.start_addr = 0x2180000,
		.end_addr = 0x218ffff,
	},
	{
		.start_addr = 0x2190000,
		.end_addr = 0x219ffff,
	},
	{
		.start_addr = 0x2200000,
		.end_addr = 0x220ffff,
	},
	{
		.start_addr = 0x2210000,
		.end_addr = 0x221ffff,
	}
};

/**
 * First firmware image of the third firmware component for the test v2 PFM for image parsing tests.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_IMG_TEST_31[] = {
	{
		.img_offset = 0x088c,
		.hash = PFM_V2_IMG_TEST_DATA + 0x0890,
		.hash_len = 64,
		.hash_type = HASH_TYPE_SHA512,
		.flags = 1,
		.region_count = 13,
		.region = PFM_V2_IMG3_11_REGION_IMG_TEST
	},
	{
		.img_offset = 0x0938,
		.hash = PFM_V2_IMG_TEST_DATA + 0x093c,
		.hash_len = 48,
		.hash_type = HASH_TYPE_SHA384,
		.flags = 1,
		.region_count = 21,
		.region = PFM_V2_IMG3_12_REGION_IMG_TEST
	},
	{
		.img_offset = 0x0a14,
		.hash = PFM_V2_IMG_TEST_DATA + 0x0a18,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG3_33_REGION
	},
	{
		.img_offset = 0x0a40,
		.hash = PFM_V2_IMG_TEST_DATA + 0x0a44,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 1,
		.region_count = 22,
		.region = PFM_V2_IMG3_14_REGION_IMG_TEST
	}
};

/**
 * Image region for the first image for the third firmware component for image parsing tests.
 */
static const struct pfm_v2_testing_data_region PFM_V2_IMG3_21_REGION_IMG_TEST[] = {
	{
		.start_addr = 0x200000,
		.end_addr = 0x20ffff,
	},
	{
		.start_addr = 0x210000,
		.end_addr = 0x21ffff,
	},
	{
		.start_addr = 0x220000,
		.end_addr = 0x22ffff,
	},
	{
		.start_addr = 0x230000,
		.end_addr = 0x23ffff,
	},
	{
		.start_addr = 0x240000,
		.end_addr = 0x24ffff,
	},
	{
		.start_addr = 0x250000,
		.end_addr = 0x25ffff,
	},
	{
		.start_addr = 0x260000,
		.end_addr = 0x26ffff,
	},
	{
		.start_addr = 0x270000,
		.end_addr = 0x27ffff,
	},
	{
		.start_addr = 0x280000,
		.end_addr = 0x28ffff,
	},
	{
		.start_addr = 0x290000,
		.end_addr = 0x29ffff,
	},
	{
		.start_addr = 0x2100000,
		.end_addr = 0x210ffff,
	},
	{
		.start_addr = 0x2110000,
		.end_addr = 0x211ffff,
	},
	{
		.start_addr = 0x2120000,
		.end_addr = 0x212ffff,
	},
	{
		.start_addr = 0x2130000,
		.end_addr = 0x213ffff,
	},
	{
		.start_addr = 0x2140000,
		.end_addr = 0x214ffff,
	},
	{
		.start_addr = 0x2150000,
		.end_addr = 0x215ffff,
	},
	{
		.start_addr = 0x2160000,
		.end_addr = 0x216ffff,
	},
	{
		.start_addr = 0x2170000,
		.end_addr = 0x217ffff,
	},
	{
		.start_addr = 0x2180000,
		.end_addr = 0x218ffff,
	},
	{
		.start_addr = 0x2190000,
		.end_addr = 0x219ffff,
	},
	{
		.start_addr = 0x2200000,
		.end_addr = 0x220ffff,
	},
	{
		.start_addr = 0x2210000,
		.end_addr = 0x221ffff,
	},
	{
		.start_addr = 0x2220000,
		.end_addr = 0x222ffff,
	},
	{
		.start_addr = 0x2230000,
		.end_addr = 0x223ffff,
	},
	{
		.start_addr = 0x2240000,
		.end_addr = 0x224ffff,
	},
	{
		.start_addr = 0x2250000,
		.end_addr = 0x225ffff,
	},
	{
		.start_addr = 0x2260000,
		.end_addr = 0x226ffff,
	}
};

/**
 * Second firmware image of the third firmware component for the test v2 PFM for image parsing
 * tests.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_IMG_TEST_32[] = {
	{
		.img_offset = 0x0b30,
		.hash = PFM_V2_IMG_TEST_DATA + 0x0b34,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 1,
		.region_count = 27,
		.region = PFM_V2_IMG3_21_REGION_IMG_TEST
	}
};

/**
 * Third firmware image of the third firmware copmonent for test v2 PFM for image parsing tests.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_IMG_TEST_33[] = {
	{
		.img_offset = 0x0c54,
		.hash = PFM_V2_IMG_TEST_DATA + 0x0c58,
		.hash_len = 48,
		.hash_type = (enum hash_type) 4,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG3_21_REGION
	},
	{
		.img_offset = 0x0c90,
		.hash = PFM_V2_IMG_TEST_DATA + 0x0c94,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_IMG3_22_REGION
	}
};

/**
 * Thrid firmware version components of the test v2 PFM for image parsing tests.
 */
static const struct pfm_v2_testing_data_fw_ver PFM_V2_FW_VER_IMG_TEST_3[] = {
	{
		.fw_version = PFM_V2_IMG_TEST_DATA + 0x0858,
		.fw_version_len = 0x02bc,
		.version_str = PFM_V2_FW_VERSION3,
		.version_str_len = sizeof (PFM_V2_FW_VERSION3) - 1,
		.version_str_pad = PFM_V2_FW_VERSION3_PAD,
		.fw_version_offset = 0x0858,
		.fw_version_entry = 11,
		.fw_version_hash = 3,
		.version_addr = 0x2212345,
		.rw_count = 3,
		.rw = PFM_V2_RW3_THREE,
		.img_count = 4,
		.img = PFM_V2_FW_IMG_IMG_TEST_31
	},
	{
		.fw_version = PFM_V2_IMG_TEST_DATA + 0x0b14,
		.fw_version_len = 0x0118,
		.version_str = PFM_V2_FW_VERSION3_V2,
		.version_str_len = sizeof (PFM_V2_FW_VERSION3_V2) - 1,
		.version_str_pad = PFM_V2_FW_VERSION3_V2_PAD,
		.fw_version_offset = 0x0b14,
		.fw_version_entry = 12,
		.fw_version_hash = 10,
		.version_addr = 0x0212345,
		.rw_count = 1,
		.rw = PFM_V2_RW3_ONE,
		.img_count = 1,
		.img = PFM_V2_FW_IMG_IMG_TEST_32
	},
	{
		.fw_version = PFM_V2_IMG_TEST_DATA + 0x0c2c,
		.fw_version_len = 0x0090,
		.version_str = PFM_V2_FW_VERSION3_V3,
		.version_str_len = sizeof (PFM_V2_FW_VERSION3_V3) - 1,
		.version_str_pad = PFM_V2_FW_VERSION3_V3_PAD,
		.fw_version_offset = 0x0c2c,
		.fw_version_entry = 13,
		.fw_version_hash = 13,
		.version_addr = 0x1212345,
		.rw_count = 2,
		.rw = PFM_V2_RW3_TWO,
		.img_count = 2,
		.img = PFM_V2_FW_IMG_IMG_TEST_33
	}
};

/**
 * Firmware components of the test v2 PFM for image parsing tests.
 */
static const struct pfm_v2_testing_data_fw PFM_V2_FW_IMG_TEST[] = {
	{
		.fw = PFM_V2_IMG_TEST_DATA + 0x0264,
		.fw_len = 0x000c,
		.fw_id_str = PFM_V2_FIRMWARE_ID,
		.fw_id_str_len = sizeof (PFM_V2_FIRMWARE_ID) - 1,
		.fw_id_str_pad = PFM_V2_FIRMWARE_ID_PAD,
		.fw_offset = 0x0264,
		.fw_entry = 1,
		.fw_hash = 5,
		.version_count = 3,
		.version = PFM_V2_FW_VER_IMG_TEST_1
	},
	{
		.fw = PFM_V2_IMG_TEST_DATA + 0x0610,
		.fw_len = 0x0010,
		.fw_id_str = PFM_V2_FIRMWARE_ID2,
		.fw_id_str_len = sizeof (PFM_V2_FIRMWARE_ID2) - 1,
		.fw_id_str_pad = PFM_V2_FIRMWARE_ID2_PAD,
		.fw_offset = 0x0610,
		.fw_entry = 6,
		.fw_hash = 6,
		.version_count = 3,
		.version = PFM_V2_FW_VER_IMG_TEST_2
	},
	{
		.fw = PFM_V2_IMG_TEST_DATA + 0x0850,
		.fw_len = 0x0008,
		.fw_id_str = PFM_V2_FIRMWARE_ID3,
		.fw_id_str_len = sizeof (PFM_V2_FIRMWARE_ID3) - 1,
		.fw_id_str_pad = PFM_V2_FIRMWARE_ID3_PAD,
		.fw_offset = 0x0850,
		.fw_entry = 10,
		.fw_hash = 7,
		.version_count = 3,
		.version = PFM_V2_FW_VER_IMG_TEST_3
	}
};

/**
 * Components of the test v2 PFM for image parsing tests.
 */
const struct pfm_v2_testing_data PFM_V2_IMG_TEST = {
	.manifest = {
		.raw = PFM_V2_IMG_TEST_DATA,
		.length = sizeof (PFM_V2_IMG_TEST_DATA),
		.hash = PFM_V2_IMG_TEST_HASH,
		.hash_len = sizeof (PFM_V2_IMG_TEST_HASH),
		.id = 18,
		.signature = PFM_V2_IMG_TEST_DATA + (sizeof (PFM_V2_IMG_TEST_DATA) - 73),
		.sig_len = 73,
		.sig_offset = (sizeof (PFM_V2_IMG_TEST_DATA) - 73),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = PFM_V2_IMG_TEST_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x0254,
		.toc_hash = PFM_V2_IMG_TEST_DATA + 0x0240,
		.toc_hash_len = 32,
		.toc_hash_offset = 0x0240,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 14,
		.toc_hashes = 14,
		.plat_id = PFM_V2_IMG_TEST_DATA + 0x0600,
		.plat_id_len = 0x0010,
		.plat_id_str = PFM_V2_PLATFORM_ID2,
		.plat_id_str_len = sizeof (PFM_V2_PLATFORM_ID2) - 1,
		.plat_id_str_pad = PFM_V2_PLATFORM_ID2_PAD,
		.plat_id_offset = 0x0600,
		.plat_id_entry = 5,
		.plat_id_hash = 4
	},
	.flash_dev = PFM_V2_IMG_TEST_DATA + 0x0260,
	.flash_dev_len = 4,
	.flash_dev_offset = 0x0260,
	.flash_dev_entry = 0,
	.flash_dev_hash = 0,
	.blank_byte = 0xff,
	.fw_count = 3,
	.fw = PFM_V2_FW_IMG_TEST
};

/**
 * Test PFM in v2 format.  Contains two images with bad region definitions.  The first has the end
 * addresses lower than the start.  The second has the start and end addresses the same.
 *
 * PLATFORM="PFM Test2" NUM_FW=2 BAD_REGIONS=1 ./generate_pfm.sh 19 ../../core/testing/keys/eccpriv.pem
 */
static const uint8_t PFM_V2_BAD_REGIONS_DATA[] = {
	0x39,0x02,0x6d,0x70,0x13,0x00,0x00,0x00,0x49,0x00,0x40,0x00,0x06,0x06,0x00,0x00,
	0x10,0xff,0x00,0x00,0x20,0x01,0x04,0x00,0x11,0xff,0x01,0x04,0x24,0x01,0x0c,0x00,
	0x12,0x11,0x01,0x01,0x30,0x01,0x48,0x00,0x00,0xff,0x01,0x03,0x78,0x01,0x10,0x00,
	0x11,0xff,0x01,0x05,0x88,0x01,0x10,0x00,0x12,0x11,0x01,0x02,0x98,0x01,0x58,0x00,
	0x9c,0x36,0x29,0xb0,0xe1,0xf5,0x54,0xa3,0x41,0xcf,0x0b,0xf0,0x7f,0xb0,0xcb,0x57,
	0x36,0xa7,0x3b,0xce,0x8c,0x4c,0xb4,0x52,0xea,0x0a,0x31,0xd9,0x9f,0xc5,0x02,0x83,
	0x24,0x2e,0x84,0x90,0x35,0x47,0xa3,0x1e,0x13,0xc8,0x20,0x71,0x3e,0x6d,0xa9,0x12,
	0xe5,0xe7,0x92,0x01,0x89,0x3f,0x00,0x56,0x73,0x46,0x77,0x54,0x87,0xe1,0xae,0x12,
	0xc1,0xae,0x9f,0x8a,0x15,0x15,0x21,0xf3,0x26,0x1f,0x05,0x09,0x1d,0x0b,0x3d,0x67,
	0x50,0xb5,0xc2,0xcd,0xfe,0x59,0x13,0xe6,0xc1,0xed,0x67,0x71,0xe6,0xdc,0x2a,0x9a,
	0x67,0x98,0x4a,0xa9,0x89,0x7c,0xed,0x76,0xe5,0x8a,0x8e,0x7f,0xec,0xa4,0x38,0xdc,
	0x7a,0x8f,0x2c,0x8b,0x33,0x0b,0x87,0x09,0x53,0xbb,0xd2,0x88,0x5f,0xee,0x0d,0xe8,
	0x13,0x48,0x15,0xa0,0xd1,0xfb,0x58,0x01,0xae,0x7a,0xa2,0x15,0xb4,0xf1,0x98,0x57,
	0xda,0x88,0x4d,0x95,0x99,0x18,0x27,0x0f,0x98,0x11,0xfe,0xe5,0xd4,0x0e,0x5b,0x6c,
	0xbf,0xa8,0xbe,0x1e,0x12,0xa0,0x18,0xd5,0x25,0xec,0xf8,0xc1,0x97,0x00,0xdb,0xd7,
	0xe8,0xaa,0x94,0x96,0x24,0xe9,0xde,0x93,0x00,0x0b,0x66,0x8b,0x5c,0x2e,0x96,0x37,
	0xc6,0xab,0xa6,0x78,0x86,0x79,0x49,0x82,0x9b,0x56,0x0b,0x0e,0xb9,0x6d,0x21,0xe2,
	0xbf,0x69,0x9d,0x96,0x0c,0x08,0x67,0x3b,0x1b,0xee,0x31,0x8d,0xf7,0x6c,0x47,0x5d,
	0xff,0x02,0x00,0x00,0x01,0x08,0x00,0x00,0x46,0x69,0x72,0x6d,0x77,0x61,0x72,0x65,
	0x01,0x01,0x07,0x00,0x45,0x23,0x01,0x00,0x54,0x65,0x73,0x74,0x69,0x6e,0x67,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0xff,0xff,0xff,0x01,0x00,0x01,0x01,0x00,
	0x75,0x5b,0x69,0x06,0x25,0x9f,0xed,0x5b,0x08,0x0c,0xbd,0xeb,0x3d,0x0d,0xc1,0x88,
	0x2a,0xeb,0x68,0x35,0x1d,0x94,0x71,0xcf,0xd9,0x87,0x7e,0x9f,0xc4,0x4a,0xc1,0x3f,
	0x00,0x00,0x00,0x01,0xff,0xff,0xff,0x00,0x09,0x00,0x00,0x00,0x50,0x46,0x4d,0x20,
	0x54,0x65,0x73,0x74,0x32,0x00,0x00,0x00,0x01,0x09,0x00,0x00,0x46,0x69,0x72,0x6d,
	0x77,0x61,0x72,0x65,0x32,0x00,0x00,0x00,0x01,0x01,0x08,0x00,0x45,0x23,0x11,0x01,
	0x54,0x65,0x73,0x74,0x69,0x6e,0x67,0x32,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x06,
	0x00,0x00,0x00,0x06,0x01,0x01,0x01,0x00,0xca,0xdc,0x17,0xb3,0x8e,0xf4,0x5a,0x2b,
	0xae,0xaa,0xb5,0x6a,0x39,0x6d,0x5e,0x90,0x15,0x86,0x4e,0xdd,0x83,0x5e,0x94,0x82,
	0x8f,0x27,0xc5,0x63,0x27,0xb4,0x24,0x27,0xed,0x43,0xed,0xbe,0x25,0xfa,0xa9,0xed,
	0x46,0x14,0xec,0x42,0x50,0x59,0x88,0xd9,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x04,
	0x30,0x45,0x02,0x21,0x00,0xe7,0x5d,0x89,0x60,0x6e,0x2d,0xf1,0x7c,0xfb,0xf8,0x20,
	0x87,0x39,0x46,0x78,0x58,0x8b,0x96,0xc8,0x9b,0x91,0x1e,0xb6,0x8c,0x94,0xa3,0xe0,
	0x71,0x59,0xf6,0x10,0xe4,0x02,0x20,0x2a,0xf9,0x96,0x01,0xaf,0x93,0x47,0x57,0xcb,
	0x81,0x59,0xf4,0xb1,0xbf,0x84,0x1f,0x87,0x75,0x45,0x23,0x04,0x2b,0xe0,0x10,0xc7,
	0xc1,0x98,0x3b,0x62,0x09,0x7a,0x9d,0x00,0x00
};

/**
 * PFM_V2_BAD_REGIONS_DATA hash for testing.
 *
 * head -c -73 pfm.img | openssl dgst -sha256
 */
static const uint8_t PFM_V2_BAD_REGIONS_HASH[] = {
	0x47,0xeb,0x72,0x26,0x94,0xe5,0x6d,0x6f,0xda,0x48,0x16,0x10,0xab,0x89,0xdb,0x18,
	0xbd,0x5b,0xc3,0xf7,0x3e,0x9b,0x76,0x25,0x87,0x7d,0x1c,0x41,0x9a,0x7b,0xb6,0xd3
};


/**
 * Bad image region for the first firmware component.
 */
static const struct pfm_v2_testing_data_region PFM_V2_BAD_REGIONS_IMG1_REGION[] = {
	{
		.start_addr = 0x1000000,
		.end_addr = 0x0ffffff,
	}
};

/**
 * First firmware image for the test v2 PFM with bad region definitions.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_BAD_REGIONS_1[] = {
	{
		.img_offset = 0x014c,
		.hash = PFM_V2_BAD_REGIONS_DATA + 0x0150,
		.hash_len = 32,
		.hash_type = HASH_TYPE_SHA256,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_BAD_REGIONS_IMG1_REGION
	}
};

/**
 * Bad R/W region for the first firmware component.
 */
static const struct pfm_v2_testing_data_rw PFM_V2_BAD_REGIONS_RW1[] = {
	{
		.start_addr = 0x2000000,
		.end_addr = 0x1ffffff,
		.flags = 0
	}
};

/**
 * First firmware version components of the test v2 PFM with bad region definitions.
 */
static const struct pfm_v2_testing_data_fw_ver PFM_V2_FW_VER_BAD_REGIONS_1[] = {
	{
		.fw_version = PFM_V2_BAD_REGIONS_DATA + 0x0130,
		.fw_version_len = 0x0048,
		.version_str = PFM_V2_FW_VERSION,
		.version_str_len = sizeof (PFM_V2_FW_VERSION) - 1,
		.version_str_pad = PFM_V2_FW_VERSION_PAD,
		.fw_version_offset = 0x0130,
		.fw_version_entry = 2,
		.fw_version_hash = 1,
		.version_addr = 0x012345,
		.rw_count = 1,
		.rw = PFM_V2_BAD_REGIONS_RW1,
		.img_count = 1,
		.img = PFM_V2_FW_IMG_BAD_REGIONS_1
	}
};

/**
 * Bad image region for the second firmware component.
 */
static const struct pfm_v2_testing_data_region PFM_V2_BAD_REGIONS_IMG2_REGION[] = {
	{
		.start_addr = 0x4000000,
		.end_addr = 0x4000000,
	}
};

/**
 * Second firmware image for the test v2 PFM with bad region definitions.
 */
static const struct pfm_v2_testing_data_image PFM_V2_FW_IMG_BAD_REGIONS_2[] = {
	{
		.img_offset = 0x01b4,
		.hash = PFM_V2_BAD_REGIONS_DATA + 0x01b8,
		.hash_len = 48,
		.hash_type = HASH_TYPE_SHA384,
		.flags = 1,
		.region_count = 1,
		.region = PFM_V2_BAD_REGIONS_IMG2_REGION
	}
};

/**
 * Bad R/W region for the second firmware component.
 */
static const struct pfm_v2_testing_data_rw PFM_V2_BAD_REGIONS_RW2[] = {
	{
		.start_addr = 0x6000000,
		.end_addr = 0x6000000,
		.flags = 1
	}
};

/**
 * Second firmware version components of the test v2 PFM with bad region definitions.
 */
static const struct pfm_v2_testing_data_fw_ver PFM_V2_FW_VER_BAD_REGIONS_2[] = {
	{
		.fw_version = PFM_V2_BAD_REGIONS_DATA + 0x0198,
		.fw_version_len = 0x0058,
		.version_str = PFM_V2_FW_VERSION2,
		.version_str_len = sizeof (PFM_V2_FW_VERSION2) - 1,
		.version_str_pad = PFM_V2_FW_VERSION2_PAD,
		.fw_version_offset = 0x0198,
		.fw_version_entry = 5,
		.fw_version_hash = 2,
		.version_addr = 0x112345,
		.rw_count = 1,
		.rw = PFM_V2_BAD_REGIONS_RW2,
		.img_count = 1,
		.img = PFM_V2_FW_IMG_BAD_REGIONS_2
	}
};

/**
 * Firmware components of the test v2 PFM with bad region definitions.
 */
static const struct pfm_v2_testing_data_fw PFM_V2_FW_BAD_REGIONS[] = {
	{
		.fw = PFM_V2_BAD_REGIONS_DATA + 0x0124,
		.fw_len = 0x000c,
		.fw_id_str = PFM_V2_FIRMWARE_ID,
		.fw_id_str_len = sizeof (PFM_V2_FIRMWARE_ID) - 1,
		.fw_id_str_pad = PFM_V2_FIRMWARE_ID_PAD,
		.fw_offset = 0x0124,
		.fw_entry = 1,
		.fw_hash = 4,
		.version_count = 1,
		.version = PFM_V2_FW_VER_BAD_REGIONS_1
	},
	{
		.fw = PFM_V2_BAD_REGIONS_DATA + 0x0188,
		.fw_len = 0x0010,
		.fw_id_str = PFM_V2_FIRMWARE_ID2,
		.fw_id_str_len = sizeof (PFM_V2_FIRMWARE_ID2) - 1,
		.fw_id_str_pad = PFM_V2_FIRMWARE_ID2_PAD,
		.fw_offset = 0x0188,
		.fw_entry = 4,
		.fw_hash = 5,
		.version_count = 1,
		.version = PFM_V2_FW_VER_BAD_REGIONS_2
	}
};

/**
 * Components of the test v2 PFM with bad region definitions.
 */
const struct pfm_v2_testing_data PFM_V2_BAD_REGIONS = {
	.manifest = {
		.raw = PFM_V2_BAD_REGIONS_DATA,
		.length = sizeof (PFM_V2_BAD_REGIONS_DATA),
		.hash = PFM_V2_BAD_REGIONS_HASH,
		.hash_len = sizeof (PFM_V2_BAD_REGIONS_HASH),
		.id = 3,
		.signature = PFM_V2_BAD_REGIONS_DATA + (sizeof (PFM_V2_BAD_REGIONS_DATA) - 73),
		.sig_len = 73,
		.sig_offset = (sizeof (PFM_V2_BAD_REGIONS_DATA) - 73),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = PFM_V2_BAD_REGIONS_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x0114,
		.toc_hash = PFM_V2_BAD_REGIONS_DATA + 0x0100,
		.toc_hash_len = 32,
		.toc_hash_offset = 0x0100,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 6,
		.toc_hashes = 6,
		.plat_id = PFM_V2_BAD_REGIONS_DATA + 0x0178,
		.plat_id_len = 0x0010,
		.plat_id_str = PFM_V2_PLATFORM_ID2,
		.plat_id_str_len = sizeof (PFM_V2_PLATFORM_ID2) - 1,
		.plat_id_str_pad = PFM_V2_PLATFORM_ID2_PAD,
		.plat_id_offset = 0x0178,
		.plat_id_entry = 3,
		.plat_id_hash = 3
	},
	.flash_dev = PFM_V2_BAD_REGIONS_DATA + 0x0120,
	.flash_dev_len = 4,
	.flash_dev_offset = 0x0120,
	.flash_dev_entry = 0,
	.flash_dev_hash = 0,
	.blank_byte = 0xff,
	.fw_count = 2,
	.fw = PFM_V2_FW_BAD_REGIONS
};


/**
 * Dependencies for testing v2 PFMs.
 */
struct pfm_flash_v2_testing {
	struct manifest_flash_v2_testing manifest;	/**< Common dependencies for manifest testing. */
	struct pfm_flash test;						/**< PFM instance under test. */
};

/**
 * Initialize PFM testing dependencies.
 *
 * @param test The testing framework.
 * @param pfm The testing components to initialize.
 * @param address The base address for the manifest data.
 */
static void pfm_flash_v2_testing_init_dependencies (CuTest *test, struct pfm_flash_v2_testing *pfm,
	uint32_t address)
{
	manifest_flash_v2_testing_init_dependencies (test, &pfm->manifest, address);
}

/**
 * Release test dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param pfm The testing components to release.
 */
static void pfm_flash_v2_testing_validate_and_release_dependencies (CuTest *test,
	struct pfm_flash_v2_testing *pfm)
{
	manifest_flash_v2_testing_validate_and_release_dependencies (test, &pfm->manifest);
}

/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param pfm The testing components to initialize.
 * @param address The base address for the PFM data.
 */
static void pfm_flash_v2_testing_init (CuTest *test, struct pfm_flash_v2_testing *pfm,
	uint32_t address)
{
	int status;

	pfm_flash_v2_testing_init_dependencies (test, pfm, 0x10000);
	manifest_flash_v2_testing_init_common (test, &pfm->manifest, 0x1000);

	status = pfm_flash_init (&pfm->test, &pfm->manifest.flash.base, &pfm->manifest.hash.base,
		0x10000, pfm->manifest.signature, sizeof (pfm->manifest.signature),
		pfm->manifest.platform_id, sizeof (pfm->manifest.platform_id));
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize testing dependencies.  The mocked hashing engine will be used.
 *
 * @param test The testing framework.
 * @param pfm The testing components to initialize.
 * @param address The base address for the PFM data.
 */
static void pfm_flash_v2_testing_init_mocked_hash (CuTest *test, struct pfm_flash_v2_testing *pfm,
	uint32_t address)
{
	int status;

	pfm_flash_v2_testing_init_dependencies (test, pfm, 0x10000);
	manifest_flash_v2_testing_init_common (test, &pfm->manifest, 0x1000);

	status = pfm_flash_init (&pfm->test, &pfm->manifest.flash.base, &pfm->manifest.hash_mock.base,
		0x10000, pfm->manifest.signature, sizeof (pfm->manifest.signature),
		pfm->manifest.platform_id, sizeof (pfm->manifest.platform_id));
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param pfm The testing components to release.
 */
static void pfm_flash_v2_testing_validate_and_release (CuTest *test,
	struct pfm_flash_v2_testing *pfm)
{
	pfm_flash_release (&pfm->test);

	pfm_flash_v2_testing_validate_and_release_dependencies (test, pfm);
}

/**
 * Set expecations on mocks for v2 PFM verification.
 *
 * @param test The testing framework.
 * @param pfm The components to test.
 * @param data Manifest data to test with.
 * @param sig_result Result of the signature verification call.
 */
static void pfm_flash_v2_testing_verify_pfm (CuTest *test, struct pfm_flash_v2_testing *pfm,
	const struct pfm_v2_testing_data *data, int sig_result)
{
	manifest_flash_v2_testing_verify_manifest (test, &pfm->manifest, &data->manifest, sig_result);

	if (sig_result == 0) {
		manifest_flash_v2_testing_read_element (test, &pfm->manifest, &data->manifest,
			data->flash_dev_entry, 0, data->flash_dev_hash, data->flash_dev_offset,
			data->flash_dev_len, PFM_V2_FLASH_DEV_SIZE, 0);
	}
}

/**
 * Set expecations on mocks for v2 PFM verification.  The mocked hashing engine will be used.
 *
 * @param test The testing framework.
 * @param pfm The components to test.
 * @param data Manifest data to test with.
 * @param sig_result Result of the signature verification call.
 * @param hash_result Result of the call to finalize the manifest hash.
 */
static void pfm_flash_v2_testing_verify_pfm_mocked_hash (CuTest *test,
	struct pfm_flash_v2_testing *pfm, const struct pfm_v2_testing_data *data, int sig_result,
	int hash_result)
{
	manifest_flash_v2_testing_verify_manifest_mocked_hash (test, &pfm->manifest, &data->manifest,
		sig_result, hash_result);

	if ((sig_result == 0) && (hash_result == 0)) {
		manifest_flash_v2_testing_read_element_mocked_hash (test, &pfm->manifest, &data->manifest,
			data->flash_dev_entry, 0, data->flash_dev_hash, data->flash_dev_offset,
			data->flash_dev_len, PFM_V2_FLASH_DEV_SIZE, 0);
	}
}

/**
 * Initialize a PFM for testing.  Run verification to load the PFM information.
 *
 * @param test The testing framework.
 * @param pfm The testing components to initialize.
 * @param address The base address for the manifest data.
 * @param data Manifest data for the test.
 * @param sig_result Result of the signature verification call.
 * @param use_mock true to use the mock hash engine.
 * @param hash_result Result of the final hash call when using the mock hash engine.
 */
static void pfm_flash_v2_testing_init_and_verify (CuTest *test, struct pfm_flash_v2_testing *pfm,
	uint32_t address, const struct pfm_v2_testing_data *data, int sig_result, bool use_mock,
	int hash_result)
{
	struct hash_engine *hash =
		(!use_mock) ? &pfm->manifest.hash.base : &pfm->manifest.hash_mock.base;
	int status;

	if (!use_mock) {
		pfm_flash_v2_testing_init (test, pfm, address);
		pfm_flash_v2_testing_verify_pfm (test, pfm, data, sig_result);
	}
	else {
		pfm_flash_v2_testing_init_mocked_hash (test, pfm, address);
		pfm_flash_v2_testing_verify_pfm_mocked_hash (test, pfm, data, sig_result, hash_result);
	}

	status = pfm->test.base.base.verify (&pfm->test.base.base, hash,
		&pfm->manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, sig_result, status);

	status = mock_validate (&pfm->manifest.flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&pfm->manifest.verification.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&pfm->manifest.hash_mock.mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Set up expectations for searching a manifest for a specific firmware element.
 *
 * @param test The testing framework.
 * @param pfm The components for testing.
 * @param data Manifest data for the test.
 * @param fw_index Index of the manifest firmware component to find.
 */
static void pfm_flash_v2_testing_find_firmware_entry (CuTest *test,
	struct pfm_flash_v2_testing *pfm, const struct pfm_v2_testing_data *data, int fw_index)
{
	int i;

	manifest_flash_v2_testing_read_element (test, &pfm->manifest, &data->manifest,
		data->fw[0].fw_entry, 0, data->fw[0].fw_hash, data->fw[0].fw_offset, data->fw[0].fw_len,
		sizeof (struct pfm_firmware_element), 0);

	for (i = 1; i <= fw_index; i++) {
		manifest_flash_v2_testing_read_element (test, &pfm->manifest, &data->manifest,
			data->fw[i].fw_entry, data->fw[i - 1].fw_entry + 1, data->fw[i].fw_hash,
			data->fw[i].fw_offset, data->fw[i].fw_len, sizeof (struct pfm_firmware_element), 0);
	}
}

/**
 * Set up expectations for searching a manifest for a specific firmware element.  The mocked hashing
 * engine will be used.
 *
 * @param test The testing framework.
 * @param pfm The components for testing.
 * @param data Manifest data for the test.
 * @param fw_index Index of the manifest firmware component to find.
 */
static void pfm_flash_v2_testing_find_firmware_entry_mocked_hash (CuTest *test,
	struct pfm_flash_v2_testing *pfm, const struct pfm_v2_testing_data *data, int fw_index)
{
	int i;

	manifest_flash_v2_testing_read_element_mocked_hash (test, &pfm->manifest, &data->manifest,
		data->fw[0].fw_entry, 0, data->fw[0].fw_hash, data->fw[0].fw_offset, data->fw[0].fw_len,
		sizeof (struct pfm_firmware_element), 0);

	for (i = 1; i <= fw_index; i++) {
		manifest_flash_v2_testing_read_element_mocked_hash (test, &pfm->manifest, &data->manifest,
			data->fw[i].fw_entry, data->fw[i - 1].fw_entry + 1, data->fw[i].fw_hash,
			data->fw[i].fw_offset, data->fw[i].fw_len, sizeof (struct pfm_firmware_element), 0);
	}
}

/**
 * Set up expectations for searching a manifest for a specific firmware version element.
 *
 * @param test The testing framework.
 * @param pfm The components for testing.
 * @param data Manifest data for the test.
 * @param fw_index Index of the manifest firmware component to find.
 * @param ver_index Index of the firmware version to find.
 */
static void pfm_flash_v2_testing_find_version_entry (CuTest *test,
	struct pfm_flash_v2_testing *pfm, const struct pfm_v2_testing_data *data, int fw_index,
	int ver_index)
{
	int i;

	pfm_flash_v2_testing_find_firmware_entry (test, pfm, data, fw_index);

	manifest_flash_v2_testing_read_element (test, &pfm->manifest, &data->manifest,
		data->fw[fw_index].version[0].fw_version_entry, data->fw[fw_index].fw_entry + 1,
		data->fw[fw_index].version[0].fw_version_hash,
		data->fw[fw_index].version[0].fw_version_offset,
		data->fw[fw_index].version[0].fw_version_len, sizeof (struct pfm_firmware_version_element),
		0);

	for (i = 1; i <= ver_index; i++) {
		manifest_flash_v2_testing_read_element (test, &pfm->manifest, &data->manifest,
			data->fw[fw_index].version[i].fw_version_entry,
			data->fw[fw_index].version[i - 1].fw_version_entry + 1,
			data->fw[fw_index].version[i].fw_version_hash,
			data->fw[fw_index].version[i].fw_version_offset,
			data->fw[fw_index].version[i].fw_version_len,
			sizeof (struct pfm_firmware_version_element), 0);
	}
}

/**
 * Set up expectations for searching a manifest for a specific firmware version element.  The mocked
 * hashing engine will be used.
 *
 * @param test The testing framework.
 * @param pfm The components for testing.
 * @param data Manifest data for the test.
 * @param fw_index Index of the manifest firmware component to find.
 * @param ver_index Index of the firmware version to find.
 */
static void pfm_flash_v2_testing_find_version_entry_mocked_hash (CuTest *test,
	struct pfm_flash_v2_testing *pfm, const struct pfm_v2_testing_data *data, int fw_index,
	int ver_index)
{
	int i;

	pfm_flash_v2_testing_find_firmware_entry_mocked_hash (test, pfm, data, fw_index);

	manifest_flash_v2_testing_read_element_mocked_hash (test, &pfm->manifest, &data->manifest,
		data->fw[fw_index].version[0].fw_version_entry, data->fw[fw_index].fw_entry + 1,
		data->fw[fw_index].version[0].fw_version_hash,
		data->fw[fw_index].version[0].fw_version_offset,
		data->fw[fw_index].version[0].fw_version_len, sizeof (struct pfm_firmware_version_element),
		0);

	for (i = 1; i <= ver_index; i++) {
		manifest_flash_v2_testing_read_element_mocked_hash (test, &pfm->manifest, &data->manifest,
			data->fw[fw_index].version[i].fw_version_entry,
			data->fw[fw_index].version[i - 1].fw_version_entry + 1,
			data->fw[fw_index].version[i].fw_version_hash,
			data->fw[fw_index].version[i].fw_version_offset,
			data->fw[fw_index].version[i].fw_version_len,
			sizeof (struct pfm_firmware_version_element), 0);
	}
}

/*******************
 * Test cases
 *******************/

static void pfm_flash_v2_test_verify (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	int status;

	TEST_START;

	pfm_flash_v2_testing_init (test, &pfm, 0x10000);

	pfm_flash_v2_testing_verify_pfm (test, &pfm, &PFM_V2, 0);

	status = pfm.test.base.base.verify (&pfm.test.base.base, &pfm.manifest.hash.base,
		&pfm.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_verify_with_mock_hash (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	int status;

	TEST_START;

	pfm_flash_v2_testing_init (test, &pfm, 0x10000);

	pfm_flash_v2_testing_verify_pfm_mocked_hash (test, &pfm, &PFM_V2, 0, 0);

	status = pfm.test.base.base.verify (&pfm.test.base.base, &pfm.manifest.hash_mock.base,
		&pfm.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_verify_two_firmware_types (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	int status;

	TEST_START;

	pfm_flash_v2_testing_init (test, &pfm, 0x10000);

	pfm_flash_v2_testing_verify_pfm (test, &pfm, &PFM_V2_TWO_FW, 0);

	status = pfm.test.base.base.verify (&pfm.test.base.base, &pfm.manifest.hash.base,
		&pfm.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_verify_no_flash_device_element (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	int status;

	TEST_START;

	pfm_flash_v2_testing_init (test, &pfm, 0x10000);

	pfm_flash_v2_testing_verify_pfm (test, &pfm, &PFM_V2_NO_FLASH_DEV, 0);

	status = pfm.test.base.base.verify (&pfm.test.base.base, &pfm.manifest.hash.base,
		&pfm.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_verify_empty_manifest (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	int status;

	TEST_START;

	pfm_flash_v2_testing_init (test, &pfm, 0x10000);

	pfm_flash_v2_testing_verify_pfm (test, &pfm, &PFM_V2_EMPTY, 0);

	status = pfm.test.base.base.verify (&pfm.test.base.base, &pfm.manifest.hash.base,
		&pfm.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_verify_no_firmware_entries (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	int status;

	TEST_START;

	pfm_flash_v2_testing_init (test, &pfm, 0x10000);

	pfm_flash_v2_testing_verify_pfm (test, &pfm, &PFM_V2_NO_FW, 0);

	status = pfm.test.base.base.verify (&pfm.test.base.base, &pfm.manifest.hash.base,
		&pfm.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_verify_three_firmware_no_versions (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	int status;

	TEST_START;

	pfm_flash_v2_testing_init (test, &pfm, 0x10000);

	pfm_flash_v2_testing_verify_pfm (test, &pfm, &PFM_V2_THREE_FW_NO_VER, 0);

	status = pfm.test.base.base.verify (&pfm.test.base.base, &pfm.manifest.hash.base,
		&pfm.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_verify_multiple_firmware_versions_regions (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	int status;

	TEST_START;

	pfm_flash_v2_testing_init (test, &pfm, 0x10000);

	pfm_flash_v2_testing_verify_pfm (test, &pfm, &PFM_V2_MULTIPLE, 0);

	status = pfm.test.base.base.verify (&pfm.test.base.base, &pfm.manifest.hash.base,
		&pfm.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_verify_max_firmware_versions (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	int status;

	TEST_START;

	pfm_flash_v2_testing_init (test, &pfm, 0x10000);

	pfm_flash_v2_testing_verify_pfm (test, &pfm, &PFM_V2_MAX_VERSION, 0);

	status = pfm.test.base.base.verify (&pfm.test.base.base, &pfm.manifest.hash.base,
		&pfm.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_verify_rw_test (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	int status;

	TEST_START;

	pfm_flash_v2_testing_init (test, &pfm, 0x10000);

	pfm_flash_v2_testing_verify_pfm (test, &pfm, &PFM_V2_RW_TEST, 0);

	status = pfm.test.base.base.verify (&pfm.test.base.base, &pfm.manifest.hash.base,
		&pfm.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_verify_three_firmware (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	int status;

	TEST_START;

	pfm_flash_v2_testing_init (test, &pfm, 0x10000);

	pfm_flash_v2_testing_verify_pfm (test, &pfm, &PFM_V2_THREE_FW, 0);

	status = pfm.test.base.base.verify (&pfm.test.base.base, &pfm.manifest.hash.base,
		&pfm.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_verify_multiple_image_regions (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	int status;

	TEST_START;

	pfm_flash_v2_testing_init (test, &pfm, 0x10000);

	pfm_flash_v2_testing_verify_pfm (test, &pfm, &PFM_V2_MULTI_IMG_REGION, 0);

	status = pfm.test.base.base.verify (&pfm.test.base.base, &pfm.manifest.hash.base,
		&pfm.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_verify_img_test (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	int status;

	TEST_START;

	pfm_flash_v2_testing_init (test, &pfm, 0x10000);

	pfm_flash_v2_testing_verify_pfm (test, &pfm, &PFM_V2_IMG_TEST, 0);

	status = pfm.test.base.base.verify (&pfm.test.base.base, &pfm.manifest.hash.base,
		&pfm.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_bad_regions_test (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	int status;

	TEST_START;

	pfm_flash_v2_testing_init (test, &pfm, 0x10000);

	pfm_flash_v2_testing_verify_pfm (test, &pfm, &PFM_V2_BAD_REGIONS, 0);

	status = pfm.test.base.base.verify (&pfm.test.base.base, &pfm.manifest.hash.base,
		&pfm.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_verify_null (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	int status;

	TEST_START;

	pfm_flash_v2_testing_init (test, &pfm, 0x10000);

	status = pfm.test.base.base.verify (NULL, &pfm.manifest.hash.base,
		&pfm.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);

	status = pfm.test.base.base.verify (&pfm.test.base.base, NULL,
		&pfm.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = pfm.test.base.base.verify (&pfm.test.base.base, &pfm.manifest.hash.base,
		NULL, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_verify_header_read_error (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	int status;

	TEST_START;

	pfm_flash_v2_testing_init (test, &pfm, 0x10000);

	status = mock_expect (&pfm.manifest.flash.mock, pfm.manifest.flash.base.read,
		&pfm.manifest.flash, FLASH_READ_FAILED, MOCK_ARG (pfm.manifest.addr), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.base.verify (&pfm.test.base.base, &pfm.manifest.hash.base,
		&pfm.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_verify_flash_device_element_read_error (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	int status;

	TEST_START;

	pfm_flash_v2_testing_init (test, &pfm, 0x10000);

	manifest_flash_v2_testing_verify_manifest (test, &pfm.manifest, &PFM_V2.manifest, 0);

	status = mock_expect (&pfm.manifest.flash.mock, pfm.manifest.flash.base.read,
		&pfm.manifest.flash, FLASH_READ_FAILED,
		MOCK_ARG (pfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.base.verify (&pfm.test.base.base, &pfm.manifest.hash.base,
		&pfm.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_verify_flash_device_element_bad_length (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	int status;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t last_entry = toc_entry_offset + MANIFEST_V2_TOC_ENTRY_SIZE;
	struct manifest_toc_entry bad_entry;
	uint8_t bad_data[3];

	TEST_START;

	bad_entry.type_id = 0x10;
	bad_entry.parent = 0xff;
	bad_entry.format = 0;
	bad_entry.hash_id = 0xff;
	bad_entry.offset = PFM_V2.flash_dev_offset;
	bad_entry.length = sizeof (bad_data);

	memset (bad_data, 0x55, sizeof (bad_data));

	pfm_flash_v2_testing_init (test, &pfm, 0x10000);

	manifest_flash_v2_testing_verify_manifest_mocked_hash (test, &pfm.manifest, &PFM_V2.manifest, 0,
		0);

	status = mock_expect (&pfm.manifest.hash_mock.mock, pfm.manifest.hash_mock.base.start_sha256,
		&pfm.manifest.hash_mock, 0);
	status |= mock_expect (&pfm.manifest.hash_mock.mock, pfm.manifest.hash_mock.base.update,
		&pfm.manifest.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (PFM_V2.manifest.toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status |= mock_expect (&pfm.manifest.flash.mock, pfm.manifest.flash.base.read,
		&pfm.manifest.flash, 0, MOCK_ARG (pfm.manifest.addr + toc_entry_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	status |= mock_expect_output (&pfm.manifest.flash.mock, 1, &bad_entry,
		MANIFEST_V2_TOC_ENTRY_SIZE, 2);

	status |= mock_expect (&pfm.manifest.hash_mock.mock, pfm.manifest.hash_mock.base.update,
		&pfm.manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (&bad_entry, MANIFEST_V2_TOC_ENTRY_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&pfm.manifest.flash, &pfm.manifest.hash_mock,
		pfm.manifest.addr + last_entry, PFM_V2.manifest.raw + last_entry,
		PFM_V2.manifest.toc_hash_offset - last_entry);

	status |= mock_expect (&pfm.manifest.hash_mock.mock, pfm.manifest.hash_mock.base.finish,
		&pfm.manifest.hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.manifest.hash_mock.mock, 0, PFM_V2.manifest.toc_hash,
		PFM_V2.manifest.toc_hash_len, 1);

	status |= mock_expect (&pfm.manifest.flash.mock, pfm.manifest.flash.base.read,
		&pfm.manifest.flash, 0, MOCK_ARG (pfm.manifest.addr + bad_entry.offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (bad_data)));
	status |= mock_expect_output (&pfm.manifest.flash.mock, 1, bad_data, sizeof (bad_data), 2);

	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.base.verify (&pfm.test.base.base, &pfm.manifest.hash_mock.base,
		&pfm.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, PFM_MALFORMED_FLASH_DEV_ELEMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_id (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	int status;
	uint32_t id;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, &PFM_V2, 0, false, 0);

	status = pfm.test.base.base.get_id (&pfm.test.base.base, &id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, PFM_V2.manifest.id, id);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_id_null (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	int status;
	uint32_t id;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, &PFM_V2, 0, false, 0);

	status = pfm.test.base.base.get_id (NULL, &id);
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);

	status = pfm.test.base.base.get_id (&pfm.test.base.base, NULL);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_id_after_verify_flash_device_element_read_error (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	int status;
	uint32_t id;

	TEST_START;

	pfm_flash_v2_testing_init (test, &pfm, 0x10000);

	manifest_flash_v2_testing_verify_manifest (test, &pfm.manifest, &PFM_V2.manifest, 0);

	status = mock_expect (&pfm.manifest.flash.mock, pfm.manifest.flash.base.read,
		&pfm.manifest.flash, FLASH_READ_FAILED,
		MOCK_ARG (pfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.base.verify (&pfm.test.base.base, &pfm.manifest.hash.base,
		&pfm.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = pfm.test.base.base.get_id (&pfm.test.base.base, &id);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_id_after_verify_flash_device_element_bad_length (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	int status;
	uint32_t id;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t last_entry = toc_entry_offset + MANIFEST_V2_TOC_ENTRY_SIZE;
	struct manifest_toc_entry bad_entry;
	uint8_t bad_data[3];

	TEST_START;

	bad_entry.type_id = 0x10;
	bad_entry.parent = 0xff;
	bad_entry.format = 0;
	bad_entry.hash_id = 0xff;
	bad_entry.offset = PFM_V2.flash_dev_offset;
	bad_entry.length = sizeof (bad_data);

	memset (bad_data, 0x55, sizeof (bad_data));

	pfm_flash_v2_testing_init (test, &pfm, 0x10000);

	manifest_flash_v2_testing_verify_manifest_mocked_hash (test, &pfm.manifest, &PFM_V2.manifest, 0,
		0);

	status = mock_expect (&pfm.manifest.hash_mock.mock, pfm.manifest.hash_mock.base.start_sha256,
		&pfm.manifest.hash_mock, 0);
	status |= mock_expect (&pfm.manifest.hash_mock.mock, pfm.manifest.hash_mock.base.update,
		&pfm.manifest.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (PFM_V2.manifest.toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status |= mock_expect (&pfm.manifest.flash.mock, pfm.manifest.flash.base.read,
		&pfm.manifest.flash, 0, MOCK_ARG (pfm.manifest.addr + toc_entry_offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	status |= mock_expect_output (&pfm.manifest.flash.mock, 1, &bad_entry,
		MANIFEST_V2_TOC_ENTRY_SIZE, 2);

	status |= mock_expect (&pfm.manifest.hash_mock.mock, pfm.manifest.hash_mock.base.update,
		&pfm.manifest.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (&bad_entry, MANIFEST_V2_TOC_ENTRY_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&pfm.manifest.flash, &pfm.manifest.hash_mock,
		pfm.manifest.addr + last_entry, PFM_V2.manifest.raw + last_entry,
		PFM_V2.manifest.toc_hash_offset - last_entry);

	status |= mock_expect (&pfm.manifest.hash_mock.mock, pfm.manifest.hash_mock.base.finish,
		&pfm.manifest.hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&pfm.manifest.hash_mock.mock, 0, PFM_V2.manifest.toc_hash,
		PFM_V2.manifest.toc_hash_len, 1);

	status |= mock_expect (&pfm.manifest.flash.mock, pfm.manifest.flash.base.read,
		&pfm.manifest.flash, 0, MOCK_ARG (pfm.manifest.addr + bad_entry.offset), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (bad_data)));
	status |= mock_expect_output (&pfm.manifest.flash.mock, 1, bad_data, sizeof (bad_data), 2);

	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.base.verify (&pfm.test.base.base, &pfm.manifest.hash_mock.base,
		&pfm.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, PFM_MALFORMED_FLASH_DEV_ELEMENT, status);

	status = pfm.test.base.base.get_id (&pfm.test.base.base, &id);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_platform_id (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	int status;
	char buffer[32];
	char *id = buffer;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, &PFM_V2, 0, false, 0);

	status = pfm.test.base.base.get_platform_id (&pfm.test.base.base, &id, sizeof (buffer));
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, buffer, id);
	CuAssertStrEquals (test, PFM_V2.manifest.plat_id_str, id);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_platform_id_manifest_allocation (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	int status;
	char *id = NULL;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, &PFM_V2, 0, false, 0);

	status = pfm.test.base.base.get_platform_id (&pfm.test.base.base, &id, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, id);
	CuAssertStrEquals (test, PFM_V2.manifest.plat_id_str, id);

	pfm.test.base.base.free_platform_id (&pfm.test.base.base, id);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_platform_id_null (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	int status;
	char *id = NULL;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, &PFM_V2, 0, false, 0);

	status = pfm.test.base.base.get_platform_id (NULL, &id, 0);
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);

	status = pfm.test.base.base.get_platform_id (&pfm.test.base.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_free_platform_id_null (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	int status;
	char *id = NULL;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, &PFM_V2, 0, false, 0);

	status = pfm.test.base.base.get_platform_id (&pfm.test.base.base, &id, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, id);

	pfm.test.base.base.free_platform_id (NULL, id);
	pfm.test.base.base.free_platform_id (&pfm.test.base.base, NULL);

	pfm.test.base.base.free_platform_id (&pfm.test.base.base, id);
	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_hash (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	int status;
	uint8_t hash_out[SHA256_HASH_LENGTH];

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, &PFM_V2, 0, false, 0);

	status = pfm.test.base.base.get_hash (&pfm.test.base.base, &pfm.manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, PFM_V2.manifest.hash_len, status);

	status = testing_validate_array (PFM_V2.manifest.hash, hash_out, status);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_hash_null (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	int status;
	uint8_t hash_out[SHA256_HASH_LENGTH];

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, &PFM_V2, 0, false, 0);

	status = pfm.test.base.base.get_hash (NULL, &pfm.manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);

	status = pfm.test.base.base.get_hash (&pfm.test.base.base, NULL, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = pfm.test.base.base.get_hash (&pfm.test.base.base, &pfm.manifest.hash.base, NULL,
		sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_signature (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	int status;
	uint8_t sig_out[PFM_V2.manifest.sig_len];

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, &PFM_V2, 0, false, 0);

	status = pfm.test.base.base.get_signature (&pfm.test.base.base, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, PFM_V2.manifest.sig_len, status);

	status = testing_validate_array (PFM_V2.manifest.signature, sig_out, status);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_signature_null (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	int status;
	uint8_t sig_out[PFM_V2.manifest.sig_len];

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, &PFM_V2, 0, false, 0);

	status = pfm.test.base.base.get_signature (NULL, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);

	status = pfm.test.base.base.get_signature (&pfm.test.base.base, NULL, sizeof (sig_out));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int status;
	struct pfm_firmware fw;
	int i;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest,
		test_pfm->fw[0].fw_entry, 0, test_pfm->fw[0].fw_hash, test_pfm->fw[0].fw_offset,
		test_pfm->fw[0].fw_len, test_pfm->fw[0].fw_len, 0);

	memset (&fw, 0, sizeof (fw));

	status = pfm.test.base.get_firmware (&pfm.test.base, &fw);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, test_pfm->fw_count, fw.count);
	CuAssertPtrNotNull (test, fw.ids);

	for (i = 0; i < test_pfm->fw_count; i++) {
		CuAssertPtrNotNull (test, fw.ids[i]);
		CuAssertStrEquals (test, test_pfm->fw[i].fw_id_str, fw.ids[i]);
	}

	pfm.test.base.free_firmware (&pfm.test.base, &fw);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_multiple (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_THREE_FW_NO_VER;
	int status;
	struct pfm_firmware fw;
	int i;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest,
		test_pfm->fw[0].fw_entry, 0, test_pfm->fw[0].fw_hash, test_pfm->fw[0].fw_offset,
		test_pfm->fw[0].fw_len, test_pfm->fw[0].fw_len, 0);

	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest,
		test_pfm->fw[1].fw_entry, test_pfm->fw[0].fw_entry + 1, test_pfm->fw[1].fw_hash,
		test_pfm->fw[1].fw_offset, test_pfm->fw[1].fw_len, test_pfm->fw[1].fw_len, 0);

	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest,
		test_pfm->fw[2].fw_entry, test_pfm->fw[1].fw_entry + 1, test_pfm->fw[2].fw_hash,
		test_pfm->fw[2].fw_offset, test_pfm->fw[2].fw_len, test_pfm->fw[2].fw_len, 0);

	memset (&fw, 0, sizeof (fw));

	status = pfm.test.base.get_firmware (&pfm.test.base, &fw);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, test_pfm->fw_count, fw.count);
	CuAssertPtrNotNull (test, fw.ids);

	for (i = 0; i < test_pfm->fw_count; i++) {
		CuAssertPtrNotNull (test, fw.ids[i]);
		CuAssertStrEquals (test, test_pfm->fw[i].fw_id_str, fw.ids[i]);
	}

	pfm.test.base.free_firmware (&pfm.test.base, &fw);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_no_flash_dev_element (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_NO_FLASH_DEV;
	int status;
	struct pfm_firmware fw;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	memset (&fw, 0, sizeof (fw));

	status = pfm.test.base.get_firmware (&pfm.test.base, &fw);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 0, fw.count);
	CuAssertPtrEquals (test, NULL, fw.ids);

	pfm.test.base.free_firmware (&pfm.test.base, &fw);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_no_firmware_entries (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_NO_FW;
	int status;
	struct pfm_firmware fw;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	memset (&fw, 0, sizeof (fw));

	status = pfm.test.base.get_firmware (&pfm.test.base, &fw);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 0, fw.count);
	CuAssertPtrEquals (test, NULL, fw.ids);

	pfm.test.base.free_firmware (&pfm.test.base, &fw);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_null (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int status;
	struct pfm_firmware fw;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	memset (&fw, 0, sizeof (fw));

	status = pfm.test.base.get_firmware (NULL, &fw);
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);

	status = pfm.test.base.get_firmware (&pfm.test.base, NULL);
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_verify_never_run (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	int status;
	struct pfm_firmware fw;

	TEST_START;

	pfm_flash_v2_testing_init (test, &pfm, 0x10000);

	memset (&fw, 0, sizeof (fw));

	status = pfm.test.base.get_firmware (&pfm.test.base, &fw);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_read_element_error (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int status;
	struct pfm_firmware fw;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	status = mock_expect (&pfm.manifest.flash.mock, pfm.manifest.flash.base.read,
		&pfm.manifest.flash, FLASH_READ_FAILED,
		MOCK_ARG (pfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	CuAssertIntEquals (test, 0, status);

	memset (&fw, 0, sizeof (fw));

	status = pfm.test.base.get_firmware (&pfm.test.base, &fw);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_bad_firmware_element_length_less_than_min (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int status;
	struct pfm_firmware fw;
	struct manifest_flash_v2_testing *manifest = &pfm.manifest;
	const struct manifest_v2_testing_data *data = &test_pfm->manifest;
	int start = 0;
	int entry = test_pfm->fw[0].fw_entry;
	uint32_t offset = test_pfm->fw[0].fw_offset;
	size_t read_len = PFM_V2_FIRMWARE_HDR_SIZE - 1;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;
	struct manifest_toc_entry bad_entry;

	TEST_START;

	memcpy (&bad_entry, &toc_entries[entry], sizeof (bad_entry));
	bad_entry.hash_id = 0xff;
	bad_entry.length = read_len;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, true, 0);

	status = mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.start_sha256,
		&manifest->hash_mock, 0);
	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i < entry; i++) {
		status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest->flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
			&manifest->hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	status |= mock_expect_output (&manifest->flash.mock, 1, &bad_entry, sizeof (bad_entry), 2);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&bad_entry, sizeof (bad_entry)),
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + last_entry, data->raw + last_entry, data->toc_hash_offset - last_entry);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.finish,
		&manifest->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest->hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (read_len));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->raw + offset,
		data->length - offset, 2);

	CuAssertIntEquals (test, 0, status);

	memset (&fw, 0, sizeof (fw));

	status = pfm.test.base.get_firmware (&pfm.test.base, &fw);
	CuAssertIntEquals (test, PFM_MALFORMED_FIRMWARE_ELEMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_bad_firmware_element_length_less_than_id (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int status;
	struct pfm_firmware fw;
	struct manifest_flash_v2_testing *manifest = &pfm.manifest;
	const struct manifest_v2_testing_data *data = &test_pfm->manifest;
	int start = 0;
	int entry = test_pfm->fw[0].fw_entry;
	uint32_t offset = test_pfm->fw[0].fw_offset;
	size_t read_len = test_pfm->fw[0].fw_len - 1;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;
	struct manifest_toc_entry bad_entry;

	TEST_START;

	memcpy (&bad_entry, &toc_entries[entry], sizeof (bad_entry));
	bad_entry.hash_id = 0xff;
	bad_entry.length = read_len;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, true, 0);

	status = mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.start_sha256,
		&manifest->hash_mock, 0);
	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i < entry; i++) {
		status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest->flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
			&manifest->hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	status |= mock_expect_output (&manifest->flash.mock, 1, &bad_entry, sizeof (bad_entry), 2);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&bad_entry, sizeof (bad_entry)),
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + last_entry, data->raw + last_entry, data->toc_hash_offset - last_entry);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.finish,
		&manifest->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest->hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (read_len));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->raw + offset,
		data->length - offset, 2);

	CuAssertIntEquals (test, 0, status);

	memset (&fw, 0, sizeof (fw));

	status = pfm.test.base.get_firmware (&pfm.test.base, &fw);
	CuAssertIntEquals (test, PFM_MALFORMED_FIRMWARE_ELEMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_supported_versions (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int status;
	struct pfm_firmware_versions ver_list;
	int i;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_firmware_entry (test, &pfm, test_pfm, fw_index);

	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest,
		test_pfm->fw[fw_index].version[0].fw_version_entry, test_pfm->fw[fw_index].fw_entry + 1,
		test_pfm->fw[fw_index].version[0].fw_version_hash,
		test_pfm->fw[fw_index].version[0].fw_version_offset,
		test_pfm->fw[fw_index].version[0].fw_version_len,
		test_pfm->fw[fw_index].version[0].fw_version_len, 0);

	status = pfm.test.base.get_supported_versions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		&ver_list);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, test_pfm->fw[fw_index].version_count, ver_list.count);
	CuAssertPtrNotNull (test, ver_list.versions);

	for (i = 0; i < test_pfm->fw[fw_index].version_count; i++) {
		CuAssertStrEquals (test, test_pfm->fw[fw_index].version[i].version_str,
			ver_list.versions[i].fw_version_id);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[i].version_addr,
			ver_list.versions[i].version_addr);
		CuAssertIntEquals (test, test_pfm->blank_byte, ver_list.versions[i].blank_byte);
	}

	pfm.test.base.free_fw_versions (&pfm.test.base, &ver_list);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_supported_versions_multiple_firmware (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_TWO_FW;
	int fw_index = 1;
	int status;
	struct pfm_firmware_versions ver_list;
	int i;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_firmware_entry (test, &pfm, test_pfm, fw_index);

	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest,
		test_pfm->fw[fw_index].version[0].fw_version_entry, test_pfm->fw[fw_index].fw_entry + 1,
		test_pfm->fw[fw_index].version[0].fw_version_hash,
		test_pfm->fw[fw_index].version[0].fw_version_offset,
		test_pfm->fw[fw_index].version[0].fw_version_len,
		test_pfm->fw[fw_index].version[0].fw_version_len, 0);

	status = pfm.test.base.get_supported_versions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		&ver_list);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, test_pfm->fw[fw_index].version_count, ver_list.count);
	CuAssertPtrNotNull (test, ver_list.versions);

	for (i = 0; i < test_pfm->fw[fw_index].version_count; i++) {
		CuAssertStrEquals (test, test_pfm->fw[fw_index].version[i].version_str,
			ver_list.versions[i].fw_version_id);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[i].version_addr,
			ver_list.versions[i].version_addr);
		CuAssertIntEquals (test, test_pfm->blank_byte, ver_list.versions[i].blank_byte);
	}

	pfm.test.base.free_fw_versions (&pfm.test.base, &ver_list);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_supported_versions_multiple_versions (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_MULTIPLE;
	int fw_index = 2;
	int status;
	struct pfm_firmware_versions ver_list;
	int i;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_firmware_entry (test, &pfm, test_pfm, fw_index);

	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest,
		test_pfm->fw[fw_index].version[0].fw_version_entry, test_pfm->fw[fw_index].fw_entry + 1,
		test_pfm->fw[fw_index].version[0].fw_version_hash,
		test_pfm->fw[fw_index].version[0].fw_version_offset,
		test_pfm->fw[fw_index].version[0].fw_version_len,
		test_pfm->fw[fw_index].version[0].fw_version_len, 0);

	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest,
		test_pfm->fw[fw_index].version[1].fw_version_entry,
		test_pfm->fw[fw_index].version[0].fw_version_entry + 1,
		test_pfm->fw[fw_index].version[1].fw_version_hash,
		test_pfm->fw[fw_index].version[1].fw_version_offset,
		test_pfm->fw[fw_index].version[1].fw_version_len,
		test_pfm->fw[fw_index].version[1].fw_version_len, 0);

	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest,
		test_pfm->fw[fw_index].version[2].fw_version_entry,
		test_pfm->fw[fw_index].version[1].fw_version_entry + 1,
		test_pfm->fw[fw_index].version[2].fw_version_hash,
		test_pfm->fw[fw_index].version[2].fw_version_offset,
		test_pfm->fw[fw_index].version[2].fw_version_len,
		test_pfm->fw[fw_index].version[2].fw_version_len, 0);

	status = pfm.test.base.get_supported_versions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		&ver_list);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, test_pfm->fw[fw_index].version_count, ver_list.count);
	CuAssertPtrNotNull (test, ver_list.versions);

	for (i = 0; i < test_pfm->fw[fw_index].version_count; i++) {
		CuAssertStrEquals (test, test_pfm->fw[fw_index].version[i].version_str,
			ver_list.versions[i].fw_version_id);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[i].version_addr,
			ver_list.versions[i].version_addr);
		CuAssertIntEquals (test, test_pfm->blank_byte, ver_list.versions[i].blank_byte);
	}

	pfm.test.base.free_fw_versions (&pfm.test.base, &ver_list);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_supported_versions_null_firmware_id (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_TWO_FW;
	int fw_index = 0;
	int status;
	struct pfm_firmware_versions ver_list;
	int i;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_firmware_entry (test, &pfm, test_pfm, fw_index);

	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest,
		test_pfm->fw[fw_index].version[0].fw_version_entry, test_pfm->fw[fw_index].fw_entry + 1,
		test_pfm->fw[fw_index].version[0].fw_version_hash,
		test_pfm->fw[fw_index].version[0].fw_version_offset,
		test_pfm->fw[fw_index].version[0].fw_version_len,
		test_pfm->fw[fw_index].version[0].fw_version_len, 0);

	status = pfm.test.base.get_supported_versions (&pfm.test.base, NULL, &ver_list);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, test_pfm->fw[fw_index].version_count, ver_list.count);
	CuAssertPtrNotNull (test, ver_list.versions);

	for (i = 0; i < test_pfm->fw[fw_index].version_count; i++) {
		CuAssertStrEquals (test, test_pfm->fw[fw_index].version[i].version_str,
			ver_list.versions[i].fw_version_id);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[i].version_addr,
			ver_list.versions[i].version_addr);
		CuAssertIntEquals (test, test_pfm->blank_byte, ver_list.versions[i].blank_byte);
	}

	pfm.test.base.free_fw_versions (&pfm.test.base, &ver_list);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_supported_versions_no_versions (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_THREE_FW_NO_VER;
	int fw_index = 2;
	int status;
	struct pfm_firmware_versions ver_list;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_firmware_entry (test, &pfm, test_pfm, fw_index);

	status = pfm.test.base.get_supported_versions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		&ver_list);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, test_pfm->fw[fw_index].version_count, ver_list.count);
	CuAssertPtrEquals (test, NULL, (void*) ver_list.versions);

	pfm.test.base.free_fw_versions (&pfm.test.base, &ver_list);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_supported_versions_no_flash_dev_element_null_firmware_id (
	CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_NO_FLASH_DEV;
	int status;
	struct pfm_firmware_versions ver_list;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	status = pfm.test.base.get_supported_versions (&pfm.test.base, NULL, &ver_list);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, ver_list.count);
	CuAssertPtrEquals (test, NULL, (void*) ver_list.versions);

	pfm.test.base.free_fw_versions (&pfm.test.base, &ver_list);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_supported_versions_no_firmware_entries_null_firmware_id (
	CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_EMPTY;
	int status;
	struct pfm_firmware_versions ver_list;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	status = pfm.test.base.get_supported_versions (&pfm.test.base, NULL, &ver_list);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, ver_list.count);
	CuAssertPtrEquals (test, NULL, (void*) ver_list.versions);

	pfm.test.base.free_fw_versions (&pfm.test.base, &ver_list);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_supported_versions_null (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int status;
	struct pfm_firmware_versions ver_list;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	status = pfm.test.base.get_supported_versions (NULL, test_pfm->fw[fw_index].fw_id_str,
		&ver_list);
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);

	status = pfm.test.base.get_supported_versions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		NULL);
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_supported_versions_verify_never_run (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int status;
	struct pfm_firmware_versions ver_list;

	TEST_START;

	pfm_flash_v2_testing_init (test, &pfm, 0x10000);

	status = pfm.test.base.get_supported_versions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		&ver_list);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);


	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_supported_versions_no_flash_dev_element (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_NO_FLASH_DEV;
	int fw_index = 0;
	int status;
	struct pfm_firmware_versions ver_list;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	status = pfm.test.base.get_supported_versions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		&ver_list);
	CuAssertIntEquals (test, PFM_UNKNOWN_FIRMWARE, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_supported_versions_no_firmware_entries (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_EMPTY;
	int status;
	struct pfm_firmware_versions ver_list;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	status = pfm.test.base.get_supported_versions (&pfm.test.base, "Empty", &ver_list);
	CuAssertIntEquals (test, PFM_UNKNOWN_FIRMWARE, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_supported_versions_unknown_firmware (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int status;
	struct pfm_firmware_versions ver_list;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_firmware_entry (test, &pfm, test_pfm, fw_index);
	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest, -1,
		test_pfm->fw[fw_index].fw_entry + 1, -1, 0, 0, 0, 0);

	status = pfm.test.base.get_supported_versions (&pfm.test.base, "Bad", &ver_list);
	CuAssertIntEquals (test, PFM_UNKNOWN_FIRMWARE, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_supported_versions_find_firmware_error (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int status;
	struct pfm_firmware_versions ver_list;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	status = mock_expect (&pfm.manifest.flash.mock, pfm.manifest.flash.base.read,
		&pfm.manifest.flash, FLASH_READ_FAILED,
		MOCK_ARG (pfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.get_supported_versions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		&ver_list);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_supported_versions_read_element_error (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int status;
	struct pfm_firmware_versions ver_list;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_firmware_entry (test, &pfm, test_pfm, fw_index);

	status = mock_expect (&pfm.manifest.flash.mock, pfm.manifest.flash.base.read,
		&pfm.manifest.flash, FLASH_READ_FAILED,
		MOCK_ARG (pfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE * (test_pfm->fw[fw_index].fw_entry + 1)));
	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.get_supported_versions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		&ver_list);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_supported_versions_bad_firmware_element_length_less_than_min (
	CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int status;
	struct pfm_firmware_versions ver_list;
	struct manifest_flash_v2_testing *manifest = &pfm.manifest;
	const struct manifest_v2_testing_data *data = &test_pfm->manifest;
	int start = 0;
	int entry = test_pfm->fw[fw_index].fw_entry;
	uint32_t offset = test_pfm->fw[fw_index].fw_offset;
	size_t read_len = PFM_V2_FIRMWARE_HDR_SIZE - 1;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;
	struct manifest_toc_entry bad_entry;

	TEST_START;

	memcpy (&bad_entry, &toc_entries[entry], sizeof (bad_entry));
	bad_entry.hash_id = 0xff;
	bad_entry.length = read_len;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, true, 0);

	status = mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.start_sha256,
		&manifest->hash_mock, 0);
	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i < entry; i++) {
		status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest->flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
			&manifest->hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	status |= mock_expect_output (&manifest->flash.mock, 1, &bad_entry, sizeof (bad_entry), 2);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&bad_entry, sizeof (bad_entry)),
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + last_entry, data->raw + last_entry, data->toc_hash_offset - last_entry);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.finish,
		&manifest->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest->hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (read_len));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->raw + offset,
		data->length - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.get_supported_versions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		&ver_list);
	CuAssertIntEquals (test, PFM_MALFORMED_FIRMWARE_ELEMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_supported_versions_bad_firmware_element_length_less_than_id (
	CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int status;
	struct pfm_firmware_versions ver_list;
	struct manifest_flash_v2_testing *manifest = &pfm.manifest;
	const struct manifest_v2_testing_data *data = &test_pfm->manifest;
	int start = 0;
	int entry = test_pfm->fw[fw_index].fw_entry;
	uint32_t offset = test_pfm->fw[fw_index].fw_offset;
	size_t read_len = test_pfm->fw[fw_index].fw_len - 1;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;
	struct manifest_toc_entry bad_entry;

	TEST_START;

	memcpy (&bad_entry, &toc_entries[entry], sizeof (bad_entry));
	bad_entry.hash_id = 0xff;
	bad_entry.length = read_len;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, true, 0);

	status = mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.start_sha256,
		&manifest->hash_mock, 0);
	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i < entry; i++) {
		status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest->flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
			&manifest->hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	status |= mock_expect_output (&manifest->flash.mock, 1, &bad_entry, sizeof (bad_entry), 2);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&bad_entry, sizeof (bad_entry)),
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + last_entry, data->raw + last_entry, data->toc_hash_offset - last_entry);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.finish,
		&manifest->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest->hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (read_len));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->raw + offset,
		data->length - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.get_supported_versions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		&ver_list);
	CuAssertIntEquals (test, PFM_MALFORMED_FIRMWARE_ELEMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_supported_versions_bad_fw_version_element_length_less_than_min (
	CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int status;
	struct pfm_firmware_versions ver_list;
	struct manifest_flash_v2_testing *manifest = &pfm.manifest;
	const struct manifest_v2_testing_data *data = &test_pfm->manifest;
	int start = test_pfm->fw[fw_index].fw_entry + 1;
	int entry = test_pfm->fw[fw_index].version[0].fw_version_entry;
	uint32_t offset = test_pfm->fw[fw_index].version[0].fw_version_offset;
	size_t read_len = PFM_V2_FW_VERSION_HDR_SIZE - 1;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;
	struct manifest_toc_entry bad_entry;

	TEST_START;

	memcpy (&bad_entry, &toc_entries[entry], sizeof (bad_entry));
	bad_entry.hash_id = 0xff;
	bad_entry.length = read_len;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, true, 0);

	pfm_flash_v2_testing_find_firmware_entry_mocked_hash (test, &pfm, test_pfm, fw_index);

	status = mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.start_sha256,
		&manifest->hash_mock, 0);
	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i < entry; i++) {
		status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest->flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
			&manifest->hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	status |= mock_expect_output (&manifest->flash.mock, 1, &bad_entry, sizeof (bad_entry), 2);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&bad_entry, sizeof (bad_entry)),
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + last_entry, data->raw + last_entry, data->toc_hash_offset - last_entry);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.finish,
		&manifest->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest->hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (read_len));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->raw + offset,
		data->length - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.get_supported_versions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		&ver_list);
	CuAssertIntEquals (test, PFM_MALFORMED_FW_VER_ELEMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_supported_versions_bad_fw_version_element_length_less_than_version (
	CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int status;
	struct pfm_firmware_versions ver_list;
	struct manifest_flash_v2_testing *manifest = &pfm.manifest;
	const struct manifest_v2_testing_data *data = &test_pfm->manifest;
	int start = test_pfm->fw[fw_index].fw_entry + 1;
	int entry = test_pfm->fw[fw_index].version[0].fw_version_entry;
	uint32_t offset = test_pfm->fw[fw_index].version[0].fw_version_offset;
	size_t read_len = PFM_V2_FW_VERSION_HDR_SIZE +
		test_pfm->fw[fw_index].version[0].version_str_len +
		test_pfm->fw[fw_index].version[0].version_str_pad - 1;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;
	struct manifest_toc_entry bad_entry;

	TEST_START;

	memcpy (&bad_entry, &toc_entries[entry], sizeof (bad_entry));
	bad_entry.hash_id = 0xff;
	bad_entry.length = read_len;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, true, 0);

	pfm_flash_v2_testing_find_firmware_entry_mocked_hash (test, &pfm, test_pfm, fw_index);

	status = mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.start_sha256,
		&manifest->hash_mock, 0);
	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i < entry; i++) {
		status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest->flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
			&manifest->hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	status |= mock_expect_output (&manifest->flash.mock, 1, &bad_entry, sizeof (bad_entry), 2);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&bad_entry, sizeof (bad_entry)),
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + last_entry, data->raw + last_entry, data->toc_hash_offset - last_entry);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.finish,
		&manifest->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest->hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (read_len));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->raw + offset,
		data->length - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.get_supported_versions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		&ver_list);
	CuAssertIntEquals (test, PFM_MALFORMED_FW_VER_ELEMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_supported_versions_bad_fw_version_element_length_less_than_rw (
	CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int status;
	struct pfm_firmware_versions ver_list;
	struct manifest_flash_v2_testing *manifest = &pfm.manifest;
	const struct manifest_v2_testing_data *data = &test_pfm->manifest;
	int start = test_pfm->fw[fw_index].fw_entry + 1;
	int entry = test_pfm->fw[fw_index].version[0].fw_version_entry;
	uint32_t offset = test_pfm->fw[fw_index].version[0].fw_version_offset;
	size_t read_len = PFM_V2_FW_VERSION_HDR_SIZE +
		test_pfm->fw[fw_index].version[0].version_str_len +
		test_pfm->fw[fw_index].version[0].version_str_pad +
		(PFM_V2_RW_REGION_SIZE * test_pfm->fw[fw_index].version[0].rw_count) - 1;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;
	struct manifest_toc_entry bad_entry;

	TEST_START;

	memcpy (&bad_entry, &toc_entries[entry], sizeof (bad_entry));
	bad_entry.hash_id = 0xff;
	bad_entry.length = read_len;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, true, 0);

	pfm_flash_v2_testing_find_firmware_entry_mocked_hash (test, &pfm, test_pfm, fw_index);

	status = mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.start_sha256,
		&manifest->hash_mock, 0);
	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i < entry; i++) {
		status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest->flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
			&manifest->hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	status |= mock_expect_output (&manifest->flash.mock, 1, &bad_entry, sizeof (bad_entry), 2);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&bad_entry, sizeof (bad_entry)),
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + last_entry, data->raw + last_entry, data->toc_hash_offset - last_entry);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.finish,
		&manifest->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest->hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (read_len));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->raw + offset,
		data->length - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.get_supported_versions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		&ver_list);
	CuAssertIntEquals (test, PFM_MALFORMED_FW_VER_ELEMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_read_write_regions (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int ver_index = 0;
	int status;
	struct pfm_read_write_regions writable;
	int i;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	status = pfm.test.base.get_read_write_regions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &writable);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].rw_count, writable.count);
	CuAssertPtrNotNull (test, writable.regions);
	CuAssertPtrNotNull (test, writable.properties);

	for (i = 0; i < test_pfm->fw[fw_index].version[ver_index].rw_count; i++) {
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].rw[i].start_addr,
			writable.regions[i].start_addr);
		CuAssertIntEquals (test,
			PFM_V2_TESTING_REGION_LENGTH (&test_pfm->fw[fw_index].version[ver_index].rw[i]),
			writable.regions[i].length);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].rw[i].flags,
			writable.properties[i].on_failure);
	}

	pfm.test.base.free_read_write_regions (&pfm.test.base, &writable);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_read_write_regions_multiple_firmware (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_TWO_FW;
	int fw_index = 1;
	int ver_index = 0;
	int status;
	struct pfm_read_write_regions writable;
	int i;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	status = pfm.test.base.get_read_write_regions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &writable);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].rw_count, writable.count);
	CuAssertPtrNotNull (test, writable.regions);
	CuAssertPtrNotNull (test, writable.properties);

	for (i = 0; i < test_pfm->fw[fw_index].version[ver_index].rw_count; i++) {
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].rw[i].start_addr,
			writable.regions[i].start_addr);
		CuAssertIntEquals (test,
			PFM_V2_TESTING_REGION_LENGTH (&test_pfm->fw[fw_index].version[ver_index].rw[i]),
			writable.regions[i].length);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].rw[i].flags,
			writable.properties[i].on_failure);
	}

	pfm.test.base.free_read_write_regions (&pfm.test.base, &writable);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_read_write_regions_multiple_versions (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_MULTIPLE;
	int fw_index = 1;
	int ver_index = 2;
	int status;
	struct pfm_read_write_regions writable;
	int i;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	status = pfm.test.base.get_read_write_regions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &writable);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].rw_count, writable.count);
	CuAssertPtrNotNull (test, writable.regions);
	CuAssertPtrNotNull (test, writable.properties);

	for (i = 0; i < test_pfm->fw[fw_index].version[ver_index].rw_count; i++) {
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].rw[i].start_addr,
			writable.regions[i].start_addr);
		CuAssertIntEquals (test,
			PFM_V2_TESTING_REGION_LENGTH (&test_pfm->fw[fw_index].version[ver_index].rw[i]),
			writable.regions[i].length);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].rw[i].flags,
			writable.properties[i].on_failure);
	}

	pfm.test.base.free_read_write_regions (&pfm.test.base, &writable);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_read_write_regions_multiple_regions (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_MULTIPLE;
	int fw_index = 0;
	int ver_index = 2;
	int status;
	struct pfm_read_write_regions writable;
	int i;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	status = pfm.test.base.get_read_write_regions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &writable);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].rw_count, writable.count);
	CuAssertPtrNotNull (test, writable.regions);
	CuAssertPtrNotNull (test, writable.properties);

	for (i = 0; i < test_pfm->fw[fw_index].version[ver_index].rw_count; i++) {
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].rw[i].start_addr,
			writable.regions[i].start_addr);
		CuAssertIntEquals (test,
			PFM_V2_TESTING_REGION_LENGTH (&test_pfm->fw[fw_index].version[ver_index].rw[i]),
			writable.regions[i].length);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].rw[i].flags,
			writable.properties[i].on_failure);
	}

	pfm.test.base.free_read_write_regions (&pfm.test.base, &writable);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_read_write_regions_null_firmware_id (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_TWO_FW;
	int fw_index = 0;
	int ver_index = 0;
	int status;
	struct pfm_read_write_regions writable;
	int i;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	status = pfm.test.base.get_read_write_regions (&pfm.test.base, NULL,
		test_pfm->fw[fw_index].version[ver_index].version_str, &writable);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].rw_count, writable.count);
	CuAssertPtrNotNull (test, writable.regions);
	CuAssertPtrNotNull (test, writable.properties);

	for (i = 0; i < test_pfm->fw[fw_index].version[ver_index].rw_count; i++) {
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].rw[i].start_addr,
			writable.regions[i].start_addr);
		CuAssertIntEquals (test,
			PFM_V2_TESTING_REGION_LENGTH (&test_pfm->fw[fw_index].version[ver_index].rw[i]),
			writable.regions[i].length);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].rw[i].flags,
			writable.properties[i].on_failure);
	}

	pfm.test.base.free_read_write_regions (&pfm.test.base, &writable);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_read_write_regions_no_regions (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_RW_TEST;
	int fw_index = 0;
	int ver_index = 0;
	int status;
	struct pfm_read_write_regions writable;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	status = pfm.test.base.get_read_write_regions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &writable);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, writable.count);
	CuAssertPtrEquals (test, NULL, (void*) writable.regions);
	CuAssertPtrEquals (test, NULL, (void*) writable.properties);

	pfm.test.base.free_read_write_regions (&pfm.test.base, &writable);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_read_write_regions_max_element_single_read (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_MAX_VERSION;
	int fw_index = 2;
	int ver_index = 0;
	int status;
	struct pfm_read_write_regions writable;
	int i;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	status = pfm.test.base.get_read_write_regions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &writable);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].rw_count, writable.count);
	CuAssertPtrNotNull (test, writable.regions);
	CuAssertPtrNotNull (test, writable.properties);

	for (i = 0; i < test_pfm->fw[fw_index].version[ver_index].rw_count; i++) {
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].rw[i].start_addr,
			writable.regions[i].start_addr);
		CuAssertIntEquals (test,
			PFM_V2_TESTING_REGION_LENGTH (&test_pfm->fw[fw_index].version[ver_index].rw[i]),
			writable.regions[i].length);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].rw[i].flags,
			writable.properties[i].on_failure);
	}

	pfm.test.base.free_read_write_regions (&pfm.test.base, &writable);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_read_write_regions_additional_element_read (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_MAX_VERSION;
	int fw_index = 1;
	int ver_index = 0;
	int status;
	struct pfm_read_write_regions writable;
	int i;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest,
		test_pfm->fw[fw_index].version[ver_index].fw_version_entry,
		test_pfm->fw[fw_index].version[ver_index].fw_version_entry,
		test_pfm->fw[fw_index].version[ver_index].fw_version_hash,
		test_pfm->fw[fw_index].version[ver_index].fw_version_offset,
		test_pfm->fw[fw_index].version[ver_index].fw_version_len,
		MANIFEST_MAX_STRING,
		PFM_V2_FW_VERSION_HDR_SIZE + test_pfm->fw[fw_index].version[ver_index].version_str_len +
			test_pfm->fw[fw_index].version[ver_index].version_str_pad);

	status = pfm.test.base.get_read_write_regions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &writable);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].rw_count, writable.count);
	CuAssertPtrNotNull (test, writable.regions);
	CuAssertPtrNotNull (test, writable.properties);

	for (i = 0; i < test_pfm->fw[fw_index].version[ver_index].rw_count; i++) {
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].rw[i].start_addr,
			writable.regions[i].start_addr);
		CuAssertIntEquals (test,
			PFM_V2_TESTING_REGION_LENGTH (&test_pfm->fw[fw_index].version[ver_index].rw[i]),
			writable.regions[i].length);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].rw[i].flags,
			writable.properties[i].on_failure);
	}

	pfm.test.base.free_read_write_regions (&pfm.test.base, &writable);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_read_write_regions_max_version_string (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_MAX_VERSION;
	int fw_index = 0;
	int ver_index = 0;
	int status;
	struct pfm_read_write_regions writable;
	int i;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest,
		test_pfm->fw[fw_index].version[ver_index].fw_version_entry,
		test_pfm->fw[fw_index].version[ver_index].fw_version_entry,
		test_pfm->fw[fw_index].version[ver_index].fw_version_hash,
		test_pfm->fw[fw_index].version[ver_index].fw_version_offset,
		test_pfm->fw[fw_index].version[ver_index].fw_version_len,
		MANIFEST_MAX_STRING,
		PFM_V2_FW_VERSION_HDR_SIZE + test_pfm->fw[fw_index].version[ver_index].version_str_len +
			test_pfm->fw[fw_index].version[ver_index].version_str_pad);

	status = pfm.test.base.get_read_write_regions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &writable);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].rw_count, writable.count);
	CuAssertPtrNotNull (test, writable.regions);
	CuAssertPtrNotNull (test, writable.properties);

	for (i = 0; i < test_pfm->fw[fw_index].version[ver_index].rw_count; i++) {
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].rw[i].start_addr,
			writable.regions[i].start_addr);
		CuAssertIntEquals (test,
			PFM_V2_TESTING_REGION_LENGTH (&test_pfm->fw[fw_index].version[ver_index].rw[i]),
			writable.regions[i].length);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].rw[i].flags,
			writable.properties[i].on_failure);
	}

	pfm.test.base.free_read_write_regions (&pfm.test.base, &writable);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_read_write_regions_max_rw_regions (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_RW_TEST;
	int fw_index = 1;
	int ver_index = 0;
	int status;
	struct pfm_read_write_regions writable;
	int i;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest,
		test_pfm->fw[fw_index].version[ver_index].fw_version_entry,
		test_pfm->fw[fw_index].version[ver_index].fw_version_entry,
		test_pfm->fw[fw_index].version[ver_index].fw_version_hash,
		test_pfm->fw[fw_index].version[ver_index].fw_version_offset,
		test_pfm->fw[fw_index].version[ver_index].fw_version_len,
		MANIFEST_MAX_STRING,
		PFM_V2_FW_VERSION_HDR_SIZE + test_pfm->fw[fw_index].version[ver_index].version_str_len +
			test_pfm->fw[fw_index].version[ver_index].version_str_pad);

	status = pfm.test.base.get_read_write_regions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &writable);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].rw_count, writable.count);
	CuAssertPtrNotNull (test, writable.regions);
	CuAssertPtrNotNull (test, writable.properties);

	for (i = 0; i < test_pfm->fw[fw_index].version[ver_index].rw_count; i++) {
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].rw[i].start_addr,
			writable.regions[i].start_addr);
		CuAssertIntEquals (test,
			PFM_V2_TESTING_REGION_LENGTH (&test_pfm->fw[fw_index].version[ver_index].rw[i]),
			writable.regions[i].length);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].rw[i].flags,
			writable.properties[i].on_failure);
	}

	pfm.test.base.free_read_write_regions (&pfm.test.base, &writable);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_read_write_regions_null (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int ver_index = 0;
	int status;
	struct pfm_read_write_regions writable;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	status = pfm.test.base.get_read_write_regions (NULL, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &writable);
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);

	status = pfm.test.base.get_read_write_regions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		NULL, &writable);
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);

	status = pfm.test.base.get_read_write_regions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, NULL);
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_read_write_regions_verify_never_run (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int ver_index = 0;
	int status;
	struct pfm_read_write_regions writable;

	TEST_START;

	pfm_flash_v2_testing_init (test, &pfm, 0x10000);

	status = pfm.test.base.get_read_write_regions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &writable);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_read_write_regions_no_flash_dev_element (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_NO_FLASH_DEV;
	int status;
	struct pfm_read_write_regions writable;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	status = pfm.test.base.get_read_write_regions (&pfm.test.base, "Empty", "None", &writable);
	CuAssertIntEquals (test, PFM_UNKNOWN_FIRMWARE, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_read_write_regions_no_firmware_entries (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_EMPTY;
	int status;
	struct pfm_read_write_regions writable;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	status = pfm.test.base.get_read_write_regions (&pfm.test.base, "Empty", "None", &writable);
	CuAssertIntEquals (test, PFM_UNKNOWN_FIRMWARE, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_read_write_regions_unknown_firmware (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int ver_index = 0;
	int status;
	struct pfm_read_write_regions writable;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_firmware_entry (test, &pfm, test_pfm, fw_index);
	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest, -1,
		test_pfm->fw[fw_index].fw_entry + 1, -1, 0, 0, 0, 0);

	status = pfm.test.base.get_read_write_regions (&pfm.test.base, "Bad",
		test_pfm->fw[fw_index].version[ver_index].version_str, &writable);
	CuAssertIntEquals (test, PFM_UNKNOWN_FIRMWARE, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_read_write_regions_find_firmware_error (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int ver_index = 0;
	int status;
	struct pfm_read_write_regions writable;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	status = mock_expect (&pfm.manifest.flash.mock, pfm.manifest.flash.base.read,
		&pfm.manifest.flash, FLASH_READ_FAILED,
		MOCK_ARG (pfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.get_read_write_regions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &writable);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_read_write_regions_unknown_version (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int ver_index = 0;
	int status;
	struct pfm_read_write_regions writable;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);
	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest, -1,
		test_pfm->fw[fw_index].version[ver_index].fw_version_entry + 1, -1, 0, 0, 0, 0);

	status = pfm.test.base.get_read_write_regions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		"Bad", &writable);
	CuAssertIntEquals (test, PFM_UNSUPPORTED_VERSION, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_read_write_regions_unknown_version_last_entry (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_TWO_FW;
	int fw_index = 1;
	int ver_index = 0;
	int status;
	struct pfm_read_write_regions writable;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	status = pfm.test.base.get_read_write_regions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		"Bad", &writable);
	CuAssertIntEquals (test, PFM_UNSUPPORTED_VERSION, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_read_write_regions_find_version_error (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int ver_index = 0;
	int status;
	struct pfm_read_write_regions writable;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_firmware_entry (test, &pfm, test_pfm, fw_index);

	status = mock_expect (&pfm.manifest.flash.mock, pfm.manifest.flash.base.read,
		&pfm.manifest.flash, FLASH_READ_FAILED,
		MOCK_ARG (pfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE * (test_pfm->fw[fw_index].fw_entry + 1)));
	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.get_read_write_regions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &writable);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_read_write_regions_too_many_rw_regions (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_RW_TEST;
	int fw_index = 2;
	int ver_index = 0;
	int status;
	struct pfm_read_write_regions writable;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	status = pfm.test.base.get_read_write_regions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &writable);
	CuAssertIntEquals (test, PFM_READ_WRITE_UNSUPPORTED, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_read_write_regions_additional_element_read_error (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_MAX_VERSION;
	int fw_index = 1;
	int ver_index = 0;
	int status;
	struct pfm_read_write_regions writable;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	status = mock_expect (&pfm.manifest.flash.mock, pfm.manifest.flash.base.read,
		&pfm.manifest.flash, FLASH_READ_FAILED,
		MOCK_ARG (pfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE *
			test_pfm->fw[fw_index].version[ver_index].fw_version_entry));
	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.get_read_write_regions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &writable);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_read_write_regions_bad_firmware_element_length_less_than_min (
	CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int ver_index = 0;
	int status;
	struct pfm_read_write_regions writable;
	struct manifest_flash_v2_testing *manifest = &pfm.manifest;
	const struct manifest_v2_testing_data *data = &test_pfm->manifest;
	int start = 0;
	int entry = test_pfm->fw[fw_index].fw_entry;
	uint32_t offset = test_pfm->fw[fw_index].fw_offset;
	size_t read_len = PFM_V2_FIRMWARE_HDR_SIZE - 1;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;
	struct manifest_toc_entry bad_entry;

	TEST_START;

	memcpy (&bad_entry, &toc_entries[entry], sizeof (bad_entry));
	bad_entry.hash_id = 0xff;
	bad_entry.length = read_len;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, true, 0);

	status = mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.start_sha256,
		&manifest->hash_mock, 0);
	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i < entry; i++) {
		status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest->flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
			&manifest->hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	status |= mock_expect_output (&manifest->flash.mock, 1, &bad_entry, sizeof (bad_entry), 2);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&bad_entry, sizeof (bad_entry)),
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + last_entry, data->raw + last_entry, data->toc_hash_offset - last_entry);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.finish,
		&manifest->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest->hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (read_len));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->raw + offset,
		data->length - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.get_read_write_regions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &writable);
	CuAssertIntEquals (test, PFM_MALFORMED_FIRMWARE_ELEMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_read_write_regions_bad_firmware_element_length_less_than_id (
	CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int ver_index = 0;
	int status;
	struct pfm_read_write_regions writable;
	struct manifest_flash_v2_testing *manifest = &pfm.manifest;
	const struct manifest_v2_testing_data *data = &test_pfm->manifest;
	int start = 0;
	int entry = test_pfm->fw[fw_index].fw_entry;
	uint32_t offset = test_pfm->fw[fw_index].fw_offset;
	size_t read_len = test_pfm->fw[fw_index].fw_len - 1;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;
	struct manifest_toc_entry bad_entry;

	TEST_START;

	memcpy (&bad_entry, &toc_entries[entry], sizeof (bad_entry));
	bad_entry.hash_id = 0xff;
	bad_entry.length = read_len;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, true, 0);

	status = mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.start_sha256,
		&manifest->hash_mock, 0);
	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i < entry; i++) {
		status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest->flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
			&manifest->hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	status |= mock_expect_output (&manifest->flash.mock, 1, &bad_entry, sizeof (bad_entry), 2);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&bad_entry, sizeof (bad_entry)),
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + last_entry, data->raw + last_entry, data->toc_hash_offset - last_entry);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.finish,
		&manifest->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest->hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (read_len));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->raw + offset,
		data->length - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.get_read_write_regions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &writable);
	CuAssertIntEquals (test, PFM_MALFORMED_FIRMWARE_ELEMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_read_write_regions_bad_fw_version_element_length_less_than_min (
	CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int ver_index = 0;
	int status;
	struct pfm_read_write_regions writable;
	struct manifest_flash_v2_testing *manifest = &pfm.manifest;
	const struct manifest_v2_testing_data *data = &test_pfm->manifest;
	int start = test_pfm->fw[fw_index].fw_entry + 1;
	int entry = test_pfm->fw[fw_index].version[ver_index].fw_version_entry;
	uint32_t offset = test_pfm->fw[fw_index].version[ver_index].fw_version_offset;
	size_t read_len = PFM_V2_FW_VERSION_HDR_SIZE - 1;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;
	struct manifest_toc_entry bad_entry;

	TEST_START;

	memcpy (&bad_entry, &toc_entries[entry], sizeof (bad_entry));
	bad_entry.hash_id = 0xff;
	bad_entry.length = read_len;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, true, 0);

	pfm_flash_v2_testing_find_firmware_entry_mocked_hash (test, &pfm, test_pfm, fw_index);

	status = mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.start_sha256,
		&manifest->hash_mock, 0);
	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i < entry; i++) {
		status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest->flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
			&manifest->hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	status |= mock_expect_output (&manifest->flash.mock, 1, &bad_entry, sizeof (bad_entry), 2);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&bad_entry, sizeof (bad_entry)),
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + last_entry, data->raw + last_entry, data->toc_hash_offset - last_entry);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.finish,
		&manifest->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest->hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (read_len));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->raw + offset,
		data->length - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.get_read_write_regions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &writable);
	CuAssertIntEquals (test, PFM_MALFORMED_FW_VER_ELEMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_read_write_regions_bad_fw_version_element_length_less_than_version (
	CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int ver_index = 0;
	int status;
	struct pfm_read_write_regions writable;
	struct manifest_flash_v2_testing *manifest = &pfm.manifest;
	const struct manifest_v2_testing_data *data = &test_pfm->manifest;
	int start = test_pfm->fw[fw_index].fw_entry + 1;
	int entry = test_pfm->fw[fw_index].version[ver_index].fw_version_entry;
	uint32_t offset = test_pfm->fw[fw_index].version[ver_index].fw_version_offset;
	size_t read_len = PFM_V2_FW_VERSION_HDR_SIZE +
		test_pfm->fw[fw_index].version[ver_index].version_str_len +
		test_pfm->fw[fw_index].version[ver_index].version_str_pad - 1;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;
	struct manifest_toc_entry bad_entry;

	TEST_START;

	memcpy (&bad_entry, &toc_entries[entry], sizeof (bad_entry));
	bad_entry.hash_id = 0xff;
	bad_entry.length = read_len;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, true, 0);

	pfm_flash_v2_testing_find_firmware_entry_mocked_hash (test, &pfm, test_pfm, fw_index);

	status = mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.start_sha256,
		&manifest->hash_mock, 0);
	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i < entry; i++) {
		status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest->flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
			&manifest->hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	status |= mock_expect_output (&manifest->flash.mock, 1, &bad_entry, sizeof (bad_entry), 2);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&bad_entry, sizeof (bad_entry)),
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + last_entry, data->raw + last_entry, data->toc_hash_offset - last_entry);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.finish,
		&manifest->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest->hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (read_len));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->raw + offset,
		data->length - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.get_read_write_regions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &writable);
	CuAssertIntEquals (test, PFM_MALFORMED_FW_VER_ELEMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_read_write_regions_bad_fw_version_element_length_less_than_rw (
	CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int ver_index = 0;
	int status;
	struct pfm_read_write_regions writable;
	struct manifest_flash_v2_testing *manifest = &pfm.manifest;
	const struct manifest_v2_testing_data *data = &test_pfm->manifest;
	int start = test_pfm->fw[fw_index].fw_entry + 1;
	int entry = test_pfm->fw[fw_index].version[ver_index].fw_version_entry;
	uint32_t offset = test_pfm->fw[fw_index].version[ver_index].fw_version_offset;
	size_t read_len = PFM_V2_FW_VERSION_HDR_SIZE +
		test_pfm->fw[fw_index].version[ver_index].version_str_len +
		test_pfm->fw[fw_index].version[ver_index].version_str_pad +
		(PFM_V2_RW_REGION_SIZE * test_pfm->fw[fw_index].version[ver_index].rw_count) - 1;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;
	struct manifest_toc_entry bad_entry;

	TEST_START;

	memcpy (&bad_entry, &toc_entries[entry], sizeof (bad_entry));
	bad_entry.hash_id = 0xff;
	bad_entry.length = read_len;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, true, 0);

	pfm_flash_v2_testing_find_firmware_entry_mocked_hash (test, &pfm, test_pfm, fw_index);

	status = mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.start_sha256,
		&manifest->hash_mock, 0);
	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i < entry; i++) {
		status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest->flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
			&manifest->hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	status |= mock_expect_output (&manifest->flash.mock, 1, &bad_entry, sizeof (bad_entry), 2);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&bad_entry, sizeof (bad_entry)),
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + last_entry, data->raw + last_entry, data->toc_hash_offset - last_entry);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.finish,
		&manifest->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest->hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (read_len));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->raw + offset,
		data->length - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.get_read_write_regions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &writable);
	CuAssertIntEquals (test, PFM_MALFORMED_FW_VER_ELEMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_read_write_regions_end_before_start (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_BAD_REGIONS;
	int fw_index = 0;
	int ver_index = 0;
	int status;
	struct pfm_read_write_regions writable;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	status = pfm.test.base.get_read_write_regions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &writable);
	CuAssertIntEquals (test, PFM_MALFORMED_FW_VER_ELEMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_read_write_regions_end_equals_start (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_BAD_REGIONS;
	int fw_index = 1;
	int ver_index = 0;
	int status;
	struct pfm_read_write_regions writable;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	status = pfm.test.base.get_read_write_regions (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &writable);
	CuAssertIntEquals (test, PFM_MALFORMED_FW_VER_ELEMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_sha256 (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int ver_index = 0;
	int status;
	struct pfm_image_list img_list;
	int i;
	int j;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &img_list);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img_count, img_list.count);
	CuAssertPtrNotNull (test, img_list.images_hash);
	CuAssertPtrEquals (test, NULL, (void*) img_list.images_sig);

	for (i = 0; i < test_pfm->fw[fw_index].version[ver_index].img_count; i++) {
		CuAssertPtrNotNull (test, img_list.images_hash[i].regions);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].region_count,
			img_list.images_hash[i].count);
		for (j = 0; j < test_pfm->fw[fw_index].version[ver_index].img[i].region_count; j++) {
			CuAssertIntEquals (test,
				test_pfm->fw[fw_index].version[ver_index].img[i].region[j].start_addr,
				img_list.images_hash[i].regions[j].start_addr);
			CuAssertIntEquals (test,
				PFM_V2_TESTING_REGION_LENGTH (
					&test_pfm->fw[fw_index].version[ver_index].img[i].region[j]),
				img_list.images_hash[i].regions[j].length);
		}

		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].hash_type,
			img_list.images_hash[i].hash_type);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].hash_len,
			img_list.images_hash[i].hash_length);

		status = testing_validate_array (test_pfm->fw[fw_index].version[ver_index].img[i].hash,
			img_list.images_hash[i].hash, img_list.images_hash[i].hash_length);
		CuAssertIntEquals (test, 0, status);

		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].flags & 0x01,
			img_list.images_hash[i].always_validate);
	}

	pfm.test.base.free_firmware_images (&pfm.test.base, &img_list);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_multiple_firmware_sha384 (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_TWO_FW;
	int fw_index = 1;
	int ver_index = 0;
	int status;
	struct pfm_image_list img_list;
	int i;
	int j;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &img_list);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img_count, img_list.count);
	CuAssertPtrNotNull (test, img_list.images_hash);
	CuAssertPtrEquals (test, NULL, (void*) img_list.images_sig);

	for (i = 0; i < test_pfm->fw[fw_index].version[ver_index].img_count; i++) {
		CuAssertPtrNotNull (test, img_list.images_hash[i].regions);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].region_count,
			img_list.images_hash[i].count);
		for (j = 0; j < test_pfm->fw[fw_index].version[ver_index].img[i].region_count; j++) {
			CuAssertIntEquals (test,
				test_pfm->fw[fw_index].version[ver_index].img[i].region[j].start_addr,
				img_list.images_hash[i].regions[j].start_addr);
			CuAssertIntEquals (test,
				PFM_V2_TESTING_REGION_LENGTH (
					&test_pfm->fw[fw_index].version[ver_index].img[i].region[j]),
				img_list.images_hash[i].regions[j].length);
		}

		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].hash_type,
			img_list.images_hash[i].hash_type);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].hash_len,
			img_list.images_hash[i].hash_length);

		status = testing_validate_array (test_pfm->fw[fw_index].version[ver_index].img[i].hash,
			img_list.images_hash[i].hash, img_list.images_hash[i].hash_length);
		CuAssertIntEquals (test, 0, status);

		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].flags & 0x01,
			img_list.images_hash[i].always_validate);
	}

	pfm.test.base.free_firmware_images (&pfm.test.base, &img_list);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_multiple_firmware_sha512 (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_THREE_FW;
	int fw_index = 2;
	int ver_index = 0;
	int status;
	struct pfm_image_list img_list;
	int i;
	int j;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &img_list);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img_count, img_list.count);
	CuAssertPtrNotNull (test, img_list.images_hash);
	CuAssertPtrEquals (test, NULL, (void*) img_list.images_sig);

	for (i = 0; i < test_pfm->fw[fw_index].version[ver_index].img_count; i++) {
		CuAssertPtrNotNull (test, img_list.images_hash[i].regions);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].region_count,
			img_list.images_hash[i].count);
		for (j = 0; j < test_pfm->fw[fw_index].version[ver_index].img[i].region_count; j++) {
			CuAssertIntEquals (test,
				test_pfm->fw[fw_index].version[ver_index].img[i].region[j].start_addr,
				img_list.images_hash[i].regions[j].start_addr);
			CuAssertIntEquals (test,
				PFM_V2_TESTING_REGION_LENGTH (
					&test_pfm->fw[fw_index].version[ver_index].img[i].region[j]),
				img_list.images_hash[i].regions[j].length);
		}

		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].hash_type,
			img_list.images_hash[i].hash_type);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].hash_len,
			img_list.images_hash[i].hash_length);

		status = testing_validate_array (test_pfm->fw[fw_index].version[ver_index].img[i].hash,
			img_list.images_hash[i].hash, img_list.images_hash[i].hash_length);
		CuAssertIntEquals (test, 0, status);

		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].flags & 0x01,
			img_list.images_hash[i].always_validate);
	}

	pfm.test.base.free_firmware_images (&pfm.test.base, &img_list);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_multiple_versions (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_MULTIPLE;
	int fw_index = 1;
	int ver_index = 2;
	int status;
	struct pfm_image_list img_list;
	int i;
	int j;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &img_list);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img_count, img_list.count);
	CuAssertPtrNotNull (test, img_list.images_hash);
	CuAssertPtrEquals (test, NULL, (void*) img_list.images_sig);

	for (i = 0; i < test_pfm->fw[fw_index].version[ver_index].img_count; i++) {
		CuAssertPtrNotNull (test, img_list.images_hash[i].regions);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].region_count,
			img_list.images_hash[i].count);
		for (j = 0; j < test_pfm->fw[fw_index].version[ver_index].img[i].region_count; j++) {
			CuAssertIntEquals (test,
				test_pfm->fw[fw_index].version[ver_index].img[i].region[j].start_addr,
				img_list.images_hash[i].regions[j].start_addr);
			CuAssertIntEquals (test,
				PFM_V2_TESTING_REGION_LENGTH (
					&test_pfm->fw[fw_index].version[ver_index].img[i].region[j]),
				img_list.images_hash[i].regions[j].length);
		}

		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].hash_type,
			img_list.images_hash[i].hash_type);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].hash_len,
			img_list.images_hash[i].hash_length);

		status = testing_validate_array (test_pfm->fw[fw_index].version[ver_index].img[i].hash,
			img_list.images_hash[i].hash, img_list.images_hash[i].hash_length);
		CuAssertIntEquals (test, 0, status);

		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].flags & 0x01,
			img_list.images_hash[i].always_validate);
	}

	pfm.test.base.free_firmware_images (&pfm.test.base, &img_list);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_multiple_images (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_MULTIPLE;
	int fw_index = 2;
	int ver_index = 0;
	int status;
	struct pfm_image_list img_list;
	int i;
	int j;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &img_list);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img_count, img_list.count);
	CuAssertPtrNotNull (test, img_list.images_hash);
	CuAssertPtrEquals (test, NULL, (void*) img_list.images_sig);

	for (i = 0; i < test_pfm->fw[fw_index].version[ver_index].img_count; i++) {
		CuAssertPtrNotNull (test, img_list.images_hash[i].regions);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].region_count,
			img_list.images_hash[i].count);
		for (j = 0; j < test_pfm->fw[fw_index].version[ver_index].img[i].region_count; j++) {
			CuAssertIntEquals (test,
				test_pfm->fw[fw_index].version[ver_index].img[i].region[j].start_addr,
				img_list.images_hash[i].regions[j].start_addr);
			CuAssertIntEquals (test,
				PFM_V2_TESTING_REGION_LENGTH (
					&test_pfm->fw[fw_index].version[ver_index].img[i].region[j]),
				img_list.images_hash[i].regions[j].length);
		}

		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].hash_type,
			img_list.images_hash[i].hash_type);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].hash_len,
			img_list.images_hash[i].hash_length);

		status = testing_validate_array (test_pfm->fw[fw_index].version[ver_index].img[i].hash,
			img_list.images_hash[i].hash, img_list.images_hash[i].hash_length);
		CuAssertIntEquals (test, 0, status);

		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].flags & 0x01,
			img_list.images_hash[i].always_validate);
	}

	pfm.test.base.free_firmware_images (&pfm.test.base, &img_list);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_multiple_regions (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_MULTI_IMG_REGION;
	int fw_index = 0;
	int ver_index = 0;
	int status;
	struct pfm_image_list img_list;
	int i;
	int j;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &img_list);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img_count, img_list.count);
	CuAssertPtrNotNull (test, img_list.images_hash);
	CuAssertPtrEquals (test, NULL, (void*) img_list.images_sig);

	for (i = 0; i < test_pfm->fw[fw_index].version[ver_index].img_count; i++) {
		CuAssertPtrNotNull (test, img_list.images_hash[i].regions);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].region_count,
			img_list.images_hash[i].count);
		for (j = 0; j < test_pfm->fw[fw_index].version[ver_index].img[i].region_count; j++) {
			CuAssertIntEquals (test,
				test_pfm->fw[fw_index].version[ver_index].img[i].region[j].start_addr,
				img_list.images_hash[i].regions[j].start_addr);
			CuAssertIntEquals (test,
				PFM_V2_TESTING_REGION_LENGTH (
					&test_pfm->fw[fw_index].version[ver_index].img[i].region[j]),
				img_list.images_hash[i].regions[j].length);
		}

		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].hash_type,
			img_list.images_hash[i].hash_type);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].hash_len,
			img_list.images_hash[i].hash_length);

		status = testing_validate_array (test_pfm->fw[fw_index].version[ver_index].img[i].hash,
			img_list.images_hash[i].hash, img_list.images_hash[i].hash_length);
		CuAssertIntEquals (test, 0, status);

		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].flags & 0x01,
			img_list.images_hash[i].always_validate);
	}

	pfm.test.base.free_firmware_images (&pfm.test.base, &img_list);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_multiple_images_multiple_regions (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_IMG_TEST;
	int fw_index = 1;
	int ver_index = 0;
	int status;
	struct pfm_image_list img_list;
	int i;
	int j;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &img_list);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img_count, img_list.count);
	CuAssertPtrNotNull (test, img_list.images_hash);
	CuAssertPtrEquals (test, NULL, (void*) img_list.images_sig);

	for (i = 0; i < test_pfm->fw[fw_index].version[ver_index].img_count; i++) {
		CuAssertPtrNotNull (test, img_list.images_hash[i].regions);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].region_count,
			img_list.images_hash[i].count);
		for (j = 0; j < test_pfm->fw[fw_index].version[ver_index].img[i].region_count; j++) {
			CuAssertIntEquals (test,
				test_pfm->fw[fw_index].version[ver_index].img[i].region[j].start_addr,
				img_list.images_hash[i].regions[j].start_addr);
			CuAssertIntEquals (test,
				PFM_V2_TESTING_REGION_LENGTH (
					&test_pfm->fw[fw_index].version[ver_index].img[i].region[j]),
				img_list.images_hash[i].regions[j].length);
		}

		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].hash_type,
			img_list.images_hash[i].hash_type);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].hash_len,
			img_list.images_hash[i].hash_length);

		status = testing_validate_array (test_pfm->fw[fw_index].version[ver_index].img[i].hash,
			img_list.images_hash[i].hash, img_list.images_hash[i].hash_length);
		CuAssertIntEquals (test, 0, status);

		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].flags & 0x01,
			img_list.images_hash[i].always_validate);
	}

	pfm.test.base.free_firmware_images (&pfm.test.base, &img_list);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_extra_flags (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_IMG_TEST;
	int fw_index = 0;
	int ver_index = 1;
	int status;
	struct pfm_image_list img_list;
	int i;
	int j;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &img_list);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img_count, img_list.count);
	CuAssertPtrNotNull (test, img_list.images_hash);
	CuAssertPtrEquals (test, NULL, (void*) img_list.images_sig);

	for (i = 0; i < test_pfm->fw[fw_index].version[ver_index].img_count; i++) {
		CuAssertPtrNotNull (test, img_list.images_hash[i].regions);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].region_count,
			img_list.images_hash[i].count);
		for (j = 0; j < test_pfm->fw[fw_index].version[ver_index].img[i].region_count; j++) {
			CuAssertIntEquals (test,
				test_pfm->fw[fw_index].version[ver_index].img[i].region[j].start_addr,
				img_list.images_hash[i].regions[j].start_addr);
			CuAssertIntEquals (test,
				PFM_V2_TESTING_REGION_LENGTH (
					&test_pfm->fw[fw_index].version[ver_index].img[i].region[j]),
				img_list.images_hash[i].regions[j].length);
		}

		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].hash_type,
			img_list.images_hash[i].hash_type);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].hash_len,
			img_list.images_hash[i].hash_length);

		status = testing_validate_array (test_pfm->fw[fw_index].version[ver_index].img[i].hash,
			img_list.images_hash[i].hash, img_list.images_hash[i].hash_length);
		CuAssertIntEquals (test, 0, status);

		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].flags & 0x01,
			img_list.images_hash[i].always_validate);
	}

	pfm.test.base.free_firmware_images (&pfm.test.base, &img_list);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_null_firmware_id (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_TWO_FW;
	int fw_index = 0;
	int ver_index = 0;
	int status;
	struct pfm_image_list img_list;
	int i;
	int j;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, NULL,
		test_pfm->fw[fw_index].version[ver_index].version_str, &img_list);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img_count, img_list.count);
	CuAssertPtrNotNull (test, img_list.images_hash);
	CuAssertPtrEquals (test, NULL, (void*) img_list.images_sig);

	for (i = 0; i < test_pfm->fw[fw_index].version[ver_index].img_count; i++) {
		CuAssertPtrNotNull (test, img_list.images_hash[i].regions);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].region_count,
			img_list.images_hash[i].count);
		for (j = 0; j < test_pfm->fw[fw_index].version[ver_index].img[i].region_count; j++) {
			CuAssertIntEquals (test,
				test_pfm->fw[fw_index].version[ver_index].img[i].region[j].start_addr,
				img_list.images_hash[i].regions[j].start_addr);
			CuAssertIntEquals (test,
				PFM_V2_TESTING_REGION_LENGTH (
					&test_pfm->fw[fw_index].version[ver_index].img[i].region[j]),
				img_list.images_hash[i].regions[j].length);
		}

		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].hash_type,
			img_list.images_hash[i].hash_type);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].hash_len,
			img_list.images_hash[i].hash_length);

		status = testing_validate_array (test_pfm->fw[fw_index].version[ver_index].img[i].hash,
			img_list.images_hash[i].hash, img_list.images_hash[i].hash_length);
		CuAssertIntEquals (test, 0, status);

		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].flags & 0x01,
			img_list.images_hash[i].always_validate);
	}

	pfm.test.base.free_firmware_images (&pfm.test.base, &img_list);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_max_element_single_read (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_IMG_TEST;
	int fw_index = 0;
	int ver_index = 0;
	int status;
	struct pfm_image_list img_list;
	int i;
	int j;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &img_list);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img_count, img_list.count);
	CuAssertPtrNotNull (test, img_list.images_hash);
	CuAssertPtrEquals (test, NULL, (void*) img_list.images_sig);

	for (i = 0; i < test_pfm->fw[fw_index].version[ver_index].img_count; i++) {
		CuAssertPtrNotNull (test, img_list.images_hash[i].regions);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].region_count,
			img_list.images_hash[i].count);
		for (j = 0; j < test_pfm->fw[fw_index].version[ver_index].img[i].region_count; j++) {
			CuAssertIntEquals (test,
				test_pfm->fw[fw_index].version[ver_index].img[i].region[j].start_addr,
				img_list.images_hash[i].regions[j].start_addr);
			CuAssertIntEquals (test,
				PFM_V2_TESTING_REGION_LENGTH (
					&test_pfm->fw[fw_index].version[ver_index].img[i].region[j]),
				img_list.images_hash[i].regions[j].length);
		}

		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].hash_type,
			img_list.images_hash[i].hash_type);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].hash_len,
			img_list.images_hash[i].hash_length);

		status = testing_validate_array (test_pfm->fw[fw_index].version[ver_index].img[i].hash,
			img_list.images_hash[i].hash, img_list.images_hash[i].hash_length);
		CuAssertIntEquals (test, 0, status);

		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].flags & 0x01,
			img_list.images_hash[i].always_validate);
	}

	pfm.test.base.free_firmware_images (&pfm.test.base, &img_list);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_additional_element_read (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_MAX_VERSION;
	int fw_index = 2;
	int ver_index = 0;
	int status;
	struct pfm_image_list img_list;
	int i;
	int j;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest,
		test_pfm->fw[fw_index].version[ver_index].fw_version_entry,
		test_pfm->fw[fw_index].version[ver_index].fw_version_entry,
		test_pfm->fw[fw_index].version[ver_index].fw_version_hash,
		test_pfm->fw[fw_index].version[ver_index].fw_version_offset,
		test_pfm->fw[fw_index].version[ver_index].fw_version_len,
		MANIFEST_MAX_STRING,
		test_pfm->fw[fw_index].version[ver_index].img[0].img_offset -
			test_pfm->fw[fw_index].version[ver_index].fw_version_offset);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &img_list);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img_count, img_list.count);
	CuAssertPtrNotNull (test, img_list.images_hash);
	CuAssertPtrEquals (test, NULL, (void*) img_list.images_sig);

	for (i = 0; i < test_pfm->fw[fw_index].version[ver_index].img_count; i++) {
		CuAssertPtrNotNull (test, img_list.images_hash[i].regions);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].region_count,
			img_list.images_hash[i].count);
		for (j = 0; j < test_pfm->fw[fw_index].version[ver_index].img[i].region_count; j++) {
			CuAssertIntEquals (test,
				test_pfm->fw[fw_index].version[ver_index].img[i].region[j].start_addr,
				img_list.images_hash[i].regions[j].start_addr);
			CuAssertIntEquals (test,
				PFM_V2_TESTING_REGION_LENGTH (
					&test_pfm->fw[fw_index].version[ver_index].img[i].region[j]),
				img_list.images_hash[i].regions[j].length);
		}

		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].hash_type,
			img_list.images_hash[i].hash_type);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].hash_len,
			img_list.images_hash[i].hash_length);

		status = testing_validate_array (test_pfm->fw[fw_index].version[ver_index].img[i].hash,
			img_list.images_hash[i].hash, img_list.images_hash[i].hash_length);
		CuAssertIntEquals (test, 0, status);

		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].flags & 0x01,
			img_list.images_hash[i].always_validate);
	}

	pfm.test.base.free_firmware_images (&pfm.test.base, &img_list);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_additional_element_read_rw_overflow (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_MAX_VERSION;
	int fw_index = 1;
	int ver_index = 0;
	int status;
	struct pfm_image_list img_list;
	int i;
	int j;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest,
		test_pfm->fw[fw_index].version[ver_index].fw_version_entry,
		test_pfm->fw[fw_index].version[ver_index].fw_version_entry,
		test_pfm->fw[fw_index].version[ver_index].fw_version_hash,
		test_pfm->fw[fw_index].version[ver_index].fw_version_offset,
		test_pfm->fw[fw_index].version[ver_index].fw_version_len,
		MANIFEST_MAX_STRING,
		test_pfm->fw[fw_index].version[ver_index].img[0].img_offset -
			test_pfm->fw[fw_index].version[ver_index].fw_version_offset);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &img_list);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img_count, img_list.count);
	CuAssertPtrNotNull (test, img_list.images_hash);
	CuAssertPtrEquals (test, NULL, (void*) img_list.images_sig);

	for (i = 0; i < test_pfm->fw[fw_index].version[ver_index].img_count; i++) {
		CuAssertPtrNotNull (test, img_list.images_hash[i].regions);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].region_count,
			img_list.images_hash[i].count);
		for (j = 0; j < test_pfm->fw[fw_index].version[ver_index].img[i].region_count; j++) {
			CuAssertIntEquals (test,
				test_pfm->fw[fw_index].version[ver_index].img[i].region[j].start_addr,
				img_list.images_hash[i].regions[j].start_addr);
			CuAssertIntEquals (test,
				PFM_V2_TESTING_REGION_LENGTH (
					&test_pfm->fw[fw_index].version[ver_index].img[i].region[j]),
				img_list.images_hash[i].regions[j].length);
		}

		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].hash_type,
			img_list.images_hash[i].hash_type);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].hash_len,
			img_list.images_hash[i].hash_length);

		status = testing_validate_array (test_pfm->fw[fw_index].version[ver_index].img[i].hash,
			img_list.images_hash[i].hash, img_list.images_hash[i].hash_length);
		CuAssertIntEquals (test, 0, status);

		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].flags & 0x01,
			img_list.images_hash[i].always_validate);
	}

	pfm.test.base.free_firmware_images (&pfm.test.base, &img_list);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_multiple_element_read (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_IMG_TEST;
	int fw_index = 2;
	int ver_index = 0;
	int status;
	struct pfm_image_list img_list;
	int i;
	int j;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest,
		test_pfm->fw[fw_index].version[ver_index].fw_version_entry,
		test_pfm->fw[fw_index].version[ver_index].fw_version_entry,
		test_pfm->fw[fw_index].version[ver_index].fw_version_hash,
		test_pfm->fw[fw_index].version[ver_index].fw_version_offset,
		test_pfm->fw[fw_index].version[ver_index].fw_version_len,
		MANIFEST_MAX_STRING,
		test_pfm->fw[fw_index].version[ver_index].img[1].img_offset -
			test_pfm->fw[fw_index].version[ver_index].fw_version_offset);

	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest,
		test_pfm->fw[fw_index].version[ver_index].fw_version_entry,
		test_pfm->fw[fw_index].version[ver_index].fw_version_entry,
		test_pfm->fw[fw_index].version[ver_index].fw_version_hash,
		test_pfm->fw[fw_index].version[ver_index].fw_version_offset,
		test_pfm->fw[fw_index].version[ver_index].fw_version_len,
		MANIFEST_MAX_STRING,
		test_pfm->fw[fw_index].version[ver_index].img[2].img_offset -
			test_pfm->fw[fw_index].version[ver_index].fw_version_offset);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &img_list);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img_count, img_list.count);
	CuAssertPtrNotNull (test, img_list.images_hash);
	CuAssertPtrEquals (test, NULL, (void*) img_list.images_sig);

	for (i = 0; i < test_pfm->fw[fw_index].version[ver_index].img_count; i++) {
		CuAssertPtrNotNull (test, img_list.images_hash[i].regions);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].region_count,
			img_list.images_hash[i].count);
		for (j = 0; j < test_pfm->fw[fw_index].version[ver_index].img[i].region_count; j++) {
			CuAssertIntEquals (test,
				test_pfm->fw[fw_index].version[ver_index].img[i].region[j].start_addr,
				img_list.images_hash[i].regions[j].start_addr);
			CuAssertIntEquals (test,
				PFM_V2_TESTING_REGION_LENGTH (
					&test_pfm->fw[fw_index].version[ver_index].img[i].region[j]),
				img_list.images_hash[i].regions[j].length);
		}

		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].hash_type,
			img_list.images_hash[i].hash_type);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].hash_len,
			img_list.images_hash[i].hash_length);

		status = testing_validate_array (test_pfm->fw[fw_index].version[ver_index].img[i].hash,
			img_list.images_hash[i].hash, img_list.images_hash[i].hash_length);
		CuAssertIntEquals (test, 0, status);

		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].flags & 0x01,
			img_list.images_hash[i].always_validate);
	}

	pfm.test.base.free_firmware_images (&pfm.test.base, &img_list);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_multiple_element_read_multiple_per_element (
	CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_IMG_TEST;
	int fw_index = 0;
	int ver_index = 2;
	int status;
	struct pfm_image_list img_list;
	int i;
	int j;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest,
		test_pfm->fw[fw_index].version[ver_index].fw_version_entry,
		test_pfm->fw[fw_index].version[ver_index].fw_version_entry,
		test_pfm->fw[fw_index].version[ver_index].fw_version_hash,
		test_pfm->fw[fw_index].version[ver_index].fw_version_offset,
		test_pfm->fw[fw_index].version[ver_index].fw_version_len,
		MANIFEST_MAX_STRING,
		test_pfm->fw[fw_index].version[ver_index].img[3].img_offset -
			test_pfm->fw[fw_index].version[ver_index].fw_version_offset);

	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest,
		test_pfm->fw[fw_index].version[ver_index].fw_version_entry,
		test_pfm->fw[fw_index].version[ver_index].fw_version_entry,
		test_pfm->fw[fw_index].version[ver_index].fw_version_hash,
		test_pfm->fw[fw_index].version[ver_index].fw_version_offset,
		test_pfm->fw[fw_index].version[ver_index].fw_version_len,
		MANIFEST_MAX_STRING,
		test_pfm->fw[fw_index].version[ver_index].img[6].img_offset -
			test_pfm->fw[fw_index].version[ver_index].fw_version_offset);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &img_list);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img_count, img_list.count);
	CuAssertPtrNotNull (test, img_list.images_hash);
	CuAssertPtrEquals (test, NULL, (void*) img_list.images_sig);

	for (i = 0; i < test_pfm->fw[fw_index].version[ver_index].img_count; i++) {
		CuAssertPtrNotNull (test, img_list.images_hash[i].regions);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].region_count,
			img_list.images_hash[i].count);
		for (j = 0; j < test_pfm->fw[fw_index].version[ver_index].img[i].region_count; j++) {
			CuAssertIntEquals (test,
				test_pfm->fw[fw_index].version[ver_index].img[i].region[j].start_addr,
				img_list.images_hash[i].regions[j].start_addr);
			CuAssertIntEquals (test,
				PFM_V2_TESTING_REGION_LENGTH (
					&test_pfm->fw[fw_index].version[ver_index].img[i].region[j]),
				img_list.images_hash[i].regions[j].length);
		}

		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].hash_type,
			img_list.images_hash[i].hash_type);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].hash_len,
			img_list.images_hash[i].hash_length);

		status = testing_validate_array (test_pfm->fw[fw_index].version[ver_index].img[i].hash,
			img_list.images_hash[i].hash, img_list.images_hash[i].hash_length);
		CuAssertIntEquals (test, 0, status);

		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].flags & 0x01,
			img_list.images_hash[i].always_validate);
	}

	pfm.test.base.free_firmware_images (&pfm.test.base, &img_list);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_max_version_string (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_MAX_VERSION;
	int fw_index = 0;
	int ver_index = 0;
	int status;
	struct pfm_image_list img_list;
	int i;
	int j;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest,
		test_pfm->fw[fw_index].version[ver_index].fw_version_entry,
		test_pfm->fw[fw_index].version[ver_index].fw_version_entry,
		test_pfm->fw[fw_index].version[ver_index].fw_version_hash,
		test_pfm->fw[fw_index].version[ver_index].fw_version_offset,
		test_pfm->fw[fw_index].version[ver_index].fw_version_len,
		MANIFEST_MAX_STRING,
		test_pfm->fw[fw_index].version[ver_index].img[0].img_offset -
			test_pfm->fw[fw_index].version[ver_index].fw_version_offset);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &img_list);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img_count, img_list.count);
	CuAssertPtrNotNull (test, img_list.images_hash);
	CuAssertPtrEquals (test, NULL, (void*) img_list.images_sig);

	for (i = 0; i < test_pfm->fw[fw_index].version[ver_index].img_count; i++) {
		CuAssertPtrNotNull (test, img_list.images_hash[i].regions);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].region_count,
			img_list.images_hash[i].count);
		for (j = 0; j < test_pfm->fw[fw_index].version[ver_index].img[i].region_count; j++) {
			CuAssertIntEquals (test,
				test_pfm->fw[fw_index].version[ver_index].img[i].region[j].start_addr,
				img_list.images_hash[i].regions[j].start_addr);
			CuAssertIntEquals (test,
				PFM_V2_TESTING_REGION_LENGTH (
					&test_pfm->fw[fw_index].version[ver_index].img[i].region[j]),
				img_list.images_hash[i].regions[j].length);
		}

		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].hash_type,
			img_list.images_hash[i].hash_type);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].hash_len,
			img_list.images_hash[i].hash_length);

		status = testing_validate_array (test_pfm->fw[fw_index].version[ver_index].img[i].hash,
			img_list.images_hash[i].hash, img_list.images_hash[i].hash_length);
		CuAssertIntEquals (test, 0, status);

		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].flags & 0x01,
			img_list.images_hash[i].always_validate);
	}

	pfm.test.base.free_firmware_images (&pfm.test.base, &img_list);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_max_image_regions (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_IMG_TEST;
	int fw_index = 2;
	int ver_index = 1;
	int status;
	struct pfm_image_list img_list;
	int i;
	int j;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest,
		test_pfm->fw[fw_index].version[ver_index].fw_version_entry,
		test_pfm->fw[fw_index].version[ver_index].fw_version_entry,
		test_pfm->fw[fw_index].version[ver_index].fw_version_hash,
		test_pfm->fw[fw_index].version[ver_index].fw_version_offset,
		test_pfm->fw[fw_index].version[ver_index].fw_version_len,
		MANIFEST_MAX_STRING,
		test_pfm->fw[fw_index].version[ver_index].img[0].img_offset -
			test_pfm->fw[fw_index].version[ver_index].fw_version_offset);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &img_list);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img_count, img_list.count);
	CuAssertPtrNotNull (test, img_list.images_hash);
	CuAssertPtrEquals (test, NULL, (void*) img_list.images_sig);

	for (i = 0; i < test_pfm->fw[fw_index].version[ver_index].img_count; i++) {
		CuAssertPtrNotNull (test, img_list.images_hash[i].regions);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].region_count,
			img_list.images_hash[i].count);
		for (j = 0; j < test_pfm->fw[fw_index].version[ver_index].img[i].region_count; j++) {
			CuAssertIntEquals (test,
				test_pfm->fw[fw_index].version[ver_index].img[i].region[j].start_addr,
				img_list.images_hash[i].regions[j].start_addr);
			CuAssertIntEquals (test,
				PFM_V2_TESTING_REGION_LENGTH (
					&test_pfm->fw[fw_index].version[ver_index].img[i].region[j]),
				img_list.images_hash[i].regions[j].length);
		}

		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].hash_type,
			img_list.images_hash[i].hash_type);
		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].hash_len,
			img_list.images_hash[i].hash_length);

		status = testing_validate_array (test_pfm->fw[fw_index].version[ver_index].img[i].hash,
			img_list.images_hash[i].hash, img_list.images_hash[i].hash_length);
		CuAssertIntEquals (test, 0, status);

		CuAssertIntEquals (test, test_pfm->fw[fw_index].version[ver_index].img[i].flags & 0x01,
			img_list.images_hash[i].always_validate);
	}

	pfm.test.base.free_firmware_images (&pfm.test.base, &img_list);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_null (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int ver_index = 0;
	int status;
	struct pfm_image_list img_list;

	TEST_START;

	pfm_flash_v2_testing_init (test, &pfm, 0x10000);

	status = pfm.test.base.get_firmware_images (NULL, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &img_list);
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		NULL, &img_list);
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, NULL);
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_verify_never_run (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int ver_index = 0;
	int status;
	struct pfm_image_list img_list;

	TEST_START;

	pfm_flash_v2_testing_init (test, &pfm, 0x10000);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &img_list);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_no_flash_dev_element (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_NO_FLASH_DEV;
	int status;
	struct pfm_image_list img_list;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, "Empty", "None", &img_list);
	CuAssertIntEquals (test, PFM_UNKNOWN_FIRMWARE, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_no_firmware_entries (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_EMPTY;
	int status;
	struct pfm_image_list img_list;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, "Empty", "None", &img_list);
	CuAssertIntEquals (test, PFM_UNKNOWN_FIRMWARE, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_unknown_firmware (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int ver_index = 0;
	int status;
	struct pfm_image_list img_list;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_firmware_entry (test, &pfm, test_pfm, fw_index);
	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest, -1,
		test_pfm->fw[fw_index].fw_entry + 1, -1, 0, 0, 0, 0);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, "Bad",
		test_pfm->fw[fw_index].version[ver_index].version_str, &img_list);
	CuAssertIntEquals (test, PFM_UNKNOWN_FIRMWARE, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_find_firmware_error (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int ver_index = 0;
	int status;
	struct pfm_image_list img_list;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	status = mock_expect (&pfm.manifest.flash.mock, pfm.manifest.flash.base.read,
		&pfm.manifest.flash, FLASH_READ_FAILED,
		MOCK_ARG (pfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &img_list);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_unknown_version (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int ver_index = 0;
	int status;
	struct pfm_image_list img_list;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);
	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest, -1,
		test_pfm->fw[fw_index].version[ver_index].fw_version_entry + 1, -1, 0, 0, 0, 0);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		"Bad", &img_list);
	CuAssertIntEquals (test, PFM_UNSUPPORTED_VERSION, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_find_version_error (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int ver_index = 0;
	int status;
	struct pfm_image_list img_list;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_firmware_entry (test, &pfm, test_pfm, fw_index);

	status = mock_expect (&pfm.manifest.flash.mock, pfm.manifest.flash.base.read,
		&pfm.manifest.flash, FLASH_READ_FAILED,
		MOCK_ARG (pfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE * (test_pfm->fw[fw_index].fw_entry + 1)));
	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &img_list);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_invalid_hash_type (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_IMG_TEST;
	int fw_index = 2;
	int ver_index = 2;
	int status;
	struct pfm_image_list img_list;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &img_list);
	CuAssertIntEquals (test, PFM_UNKNOWN_HASH_TYPE, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_no_regions (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_IMG_TEST;
	int fw_index = 1;
	int ver_index = 2;
	int status;
	struct pfm_image_list img_list;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &img_list);
	CuAssertIntEquals (test, PFM_FW_IMAGE_UNSUPPORTED, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_too_many_image_regions (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_IMG_TEST;
	int fw_index = 1;
	int ver_index = 1;
	int status;
	struct pfm_image_list img_list;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest,
		test_pfm->fw[fw_index].version[ver_index].fw_version_entry,
		test_pfm->fw[fw_index].version[ver_index].fw_version_entry,
		test_pfm->fw[fw_index].version[ver_index].fw_version_hash,
		test_pfm->fw[fw_index].version[ver_index].fw_version_offset,
		test_pfm->fw[fw_index].version[ver_index].fw_version_len,
		MANIFEST_MAX_STRING,
		test_pfm->fw[fw_index].version[ver_index].img[0].img_offset -
			test_pfm->fw[fw_index].version[ver_index].fw_version_offset);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &img_list);
	CuAssertIntEquals (test, PFM_FW_IMAGE_UNSUPPORTED, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_additional_element_read_error (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_MAX_VERSION;
	int fw_index = 2;
	int ver_index = 0;
	int status;
	struct pfm_image_list img_list;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	status = mock_expect (&pfm.manifest.flash.mock, pfm.manifest.flash.base.read,
		&pfm.manifest.flash, FLASH_READ_FAILED,
		MOCK_ARG (pfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE *
			test_pfm->fw[fw_index].version[ver_index].fw_version_entry));
	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &img_list);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_bad_firmware_element_length_less_than_min (
	CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int ver_index = 0;
	int status;
	struct pfm_image_list img_list;
	struct manifest_flash_v2_testing *manifest = &pfm.manifest;
	const struct manifest_v2_testing_data *data = &test_pfm->manifest;
	int start = 0;
	int entry = test_pfm->fw[fw_index].fw_entry;
	uint32_t offset = test_pfm->fw[fw_index].fw_offset;
	size_t read_len = PFM_V2_FIRMWARE_HDR_SIZE - 1;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;
	struct manifest_toc_entry bad_entry;

	TEST_START;

	memcpy (&bad_entry, &toc_entries[entry], sizeof (bad_entry));
	bad_entry.hash_id = 0xff;
	bad_entry.length = read_len;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, true, 0);

	status = mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.start_sha256,
		&manifest->hash_mock, 0);
	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i < entry; i++) {
		status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest->flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
			&manifest->hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	status |= mock_expect_output (&manifest->flash.mock, 1, &bad_entry, sizeof (bad_entry), 2);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&bad_entry, sizeof (bad_entry)),
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + last_entry, data->raw + last_entry, data->toc_hash_offset - last_entry);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.finish,
		&manifest->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest->hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (read_len));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->raw + offset,
		data->length - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &img_list);
	CuAssertIntEquals (test, PFM_MALFORMED_FIRMWARE_ELEMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_bad_firmware_element_length_less_than_id (
	CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int ver_index = 0;
	int status;
	struct pfm_image_list img_list;
	struct manifest_flash_v2_testing *manifest = &pfm.manifest;
	const struct manifest_v2_testing_data *data = &test_pfm->manifest;
	int start = 0;
	int entry = test_pfm->fw[fw_index].fw_entry;
	uint32_t offset = test_pfm->fw[fw_index].fw_offset;
	size_t read_len = test_pfm->fw[fw_index].fw_len - 1;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;
	struct manifest_toc_entry bad_entry;

	TEST_START;

	memcpy (&bad_entry, &toc_entries[entry], sizeof (bad_entry));
	bad_entry.hash_id = 0xff;
	bad_entry.length = read_len;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, true, 0);

	status = mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.start_sha256,
		&manifest->hash_mock, 0);
	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i < entry; i++) {
		status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest->flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
			&manifest->hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	status |= mock_expect_output (&manifest->flash.mock, 1, &bad_entry, sizeof (bad_entry), 2);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&bad_entry, sizeof (bad_entry)),
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + last_entry, data->raw + last_entry, data->toc_hash_offset - last_entry);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.finish,
		&manifest->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest->hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (read_len));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->raw + offset,
		data->length - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &img_list);
	CuAssertIntEquals (test, PFM_MALFORMED_FIRMWARE_ELEMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_bad_fw_version_element_length_less_than_min (
	CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int ver_index = 0;
	int status;
	struct pfm_image_list img_list;
	struct manifest_flash_v2_testing *manifest = &pfm.manifest;
	const struct manifest_v2_testing_data *data = &test_pfm->manifest;
	int start = test_pfm->fw[fw_index].fw_entry + 1;
	int entry = test_pfm->fw[fw_index].version[ver_index].fw_version_entry;
	uint32_t offset = test_pfm->fw[fw_index].version[ver_index].fw_version_offset;
	size_t read_len = PFM_V2_FW_VERSION_HDR_SIZE - 1;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;
	struct manifest_toc_entry bad_entry;

	TEST_START;

	memcpy (&bad_entry, &toc_entries[entry], sizeof (bad_entry));
	bad_entry.hash_id = 0xff;
	bad_entry.length = read_len;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, true, 0);

	pfm_flash_v2_testing_find_firmware_entry_mocked_hash (test, &pfm, test_pfm, fw_index);

	status = mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.start_sha256,
		&manifest->hash_mock, 0);
	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i < entry; i++) {
		status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest->flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
			&manifest->hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	status |= mock_expect_output (&manifest->flash.mock, 1, &bad_entry, sizeof (bad_entry), 2);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&bad_entry, sizeof (bad_entry)),
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + last_entry, data->raw + last_entry, data->toc_hash_offset - last_entry);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.finish,
		&manifest->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest->hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (read_len));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->raw + offset,
		data->length - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &img_list);
	CuAssertIntEquals (test, PFM_MALFORMED_FW_VER_ELEMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_bad_fw_version_element_length_less_than_version (
	CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int ver_index = 0;
	int status;
	struct pfm_image_list img_list;
	struct manifest_flash_v2_testing *manifest = &pfm.manifest;
	const struct manifest_v2_testing_data *data = &test_pfm->manifest;
	int start = test_pfm->fw[fw_index].fw_entry + 1;
	int entry = test_pfm->fw[fw_index].version[ver_index].fw_version_entry;
	uint32_t offset = test_pfm->fw[fw_index].version[ver_index].fw_version_offset;
	size_t read_len = PFM_V2_FW_VERSION_HDR_SIZE +
		test_pfm->fw[fw_index].version[ver_index].version_str_len +
		test_pfm->fw[fw_index].version[ver_index].version_str_pad - 1;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;
	struct manifest_toc_entry bad_entry;

	TEST_START;

	memcpy (&bad_entry, &toc_entries[entry], sizeof (bad_entry));
	bad_entry.hash_id = 0xff;
	bad_entry.length = read_len;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, true, 0);

	pfm_flash_v2_testing_find_firmware_entry_mocked_hash (test, &pfm, test_pfm, fw_index);

	status = mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.start_sha256,
		&manifest->hash_mock, 0);
	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i < entry; i++) {
		status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest->flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
			&manifest->hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	status |= mock_expect_output (&manifest->flash.mock, 1, &bad_entry, sizeof (bad_entry), 2);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&bad_entry, sizeof (bad_entry)),
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + last_entry, data->raw + last_entry, data->toc_hash_offset - last_entry);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.finish,
		&manifest->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest->hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (read_len));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->raw + offset,
		data->length - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &img_list);
	CuAssertIntEquals (test, PFM_MALFORMED_FW_VER_ELEMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_bad_fw_version_element_length_less_than_rw (
	CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int ver_index = 0;
	int status;
	struct pfm_image_list img_list;
	struct manifest_flash_v2_testing *manifest = &pfm.manifest;
	const struct manifest_v2_testing_data *data = &test_pfm->manifest;
	int start = test_pfm->fw[fw_index].fw_entry + 1;
	int entry = test_pfm->fw[fw_index].version[ver_index].fw_version_entry;
	uint32_t offset = test_pfm->fw[fw_index].version[ver_index].fw_version_offset;
	size_t read_len = PFM_V2_FW_VERSION_HDR_SIZE +
		test_pfm->fw[fw_index].version[ver_index].version_str_len +
		test_pfm->fw[fw_index].version[ver_index].version_str_pad +
		(PFM_V2_RW_REGION_SIZE * test_pfm->fw[fw_index].version[ver_index].rw_count) - 1;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;
	struct manifest_toc_entry bad_entry;

	TEST_START;

	memcpy (&bad_entry, &toc_entries[entry], sizeof (bad_entry));
	bad_entry.hash_id = 0xff;
	bad_entry.length = read_len;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, true, 0);

	pfm_flash_v2_testing_find_firmware_entry_mocked_hash (test, &pfm, test_pfm, fw_index);

	status = mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.start_sha256,
		&manifest->hash_mock, 0);
	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i < entry; i++) {
		status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest->flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
			&manifest->hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	status |= mock_expect_output (&manifest->flash.mock, 1, &bad_entry, sizeof (bad_entry), 2);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&bad_entry, sizeof (bad_entry)),
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + last_entry, data->raw + last_entry, data->toc_hash_offset - last_entry);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.finish,
		&manifest->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest->hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (read_len));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->raw + offset,
		data->length - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &img_list);
	CuAssertIntEquals (test, PFM_MALFORMED_FW_VER_ELEMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_bad_fw_version_element_length_less_than_img_min (
	CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int ver_index = 0;
	int status;
	struct pfm_image_list img_list;
	struct manifest_flash_v2_testing *manifest = &pfm.manifest;
	const struct manifest_v2_testing_data *data = &test_pfm->manifest;
	int start = test_pfm->fw[fw_index].fw_entry + 1;
	int entry = test_pfm->fw[fw_index].version[ver_index].fw_version_entry;
	uint32_t offset = test_pfm->fw[fw_index].version[ver_index].fw_version_offset;
	size_t read_len = PFM_V2_FW_VERSION_HDR_SIZE +
		test_pfm->fw[fw_index].version[ver_index].version_str_len +
		test_pfm->fw[fw_index].version[ver_index].version_str_pad +
		(PFM_V2_RW_REGION_SIZE * test_pfm->fw[fw_index].version[ver_index].rw_count) +
		PFM_V2_IMG_HDR_SIZE - 1;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;
	struct manifest_toc_entry bad_entry;

	TEST_START;

	memcpy (&bad_entry, &toc_entries[entry], sizeof (bad_entry));
	bad_entry.hash_id = 0xff;
	bad_entry.length = read_len;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, true, 0);

	pfm_flash_v2_testing_find_firmware_entry_mocked_hash (test, &pfm, test_pfm, fw_index);

	status = mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.start_sha256,
		&manifest->hash_mock, 0);
	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i < entry; i++) {
		status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest->flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
			&manifest->hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	status |= mock_expect_output (&manifest->flash.mock, 1, &bad_entry, sizeof (bad_entry), 2);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&bad_entry, sizeof (bad_entry)),
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + last_entry, data->raw + last_entry, data->toc_hash_offset - last_entry);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.finish,
		&manifest->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest->hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (read_len));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->raw + offset,
		data->length - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &img_list);
	CuAssertIntEquals (test, PFM_MALFORMED_FW_VER_ELEMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_bad_fw_version_element_length_less_than_img (
	CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int ver_index = 0;
	int status;
	struct pfm_image_list img_list;
	struct manifest_flash_v2_testing *manifest = &pfm.manifest;
	const struct manifest_v2_testing_data *data = &test_pfm->manifest;
	int start = test_pfm->fw[fw_index].fw_entry + 1;
	int entry = test_pfm->fw[fw_index].version[ver_index].fw_version_entry;
	uint32_t offset = test_pfm->fw[fw_index].version[ver_index].fw_version_offset;
	size_t read_len = PFM_V2_FW_VERSION_HDR_SIZE +
		test_pfm->fw[fw_index].version[ver_index].version_str_len +
		test_pfm->fw[fw_index].version[ver_index].version_str_pad +
		(PFM_V2_RW_REGION_SIZE * test_pfm->fw[fw_index].version[ver_index].rw_count) +
		PFM_V2_TESTING_IMG_LENGTH (&test_pfm->fw[fw_index].version[ver_index].img[0]) - 1;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;
	struct manifest_toc_entry bad_entry;

	TEST_START;

	memcpy (&bad_entry, &toc_entries[entry], sizeof (bad_entry));
	bad_entry.hash_id = 0xff;
	bad_entry.length = read_len;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, true, 0);

	pfm_flash_v2_testing_find_firmware_entry_mocked_hash (test, &pfm, test_pfm, fw_index);

	status = mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.start_sha256,
		&manifest->hash_mock, 0);
	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i < entry; i++) {
		status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest->flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
			&manifest->hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	status |= mock_expect_output (&manifest->flash.mock, 1, &bad_entry, sizeof (bad_entry), 2);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&bad_entry, sizeof (bad_entry)),
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + last_entry, data->raw + last_entry, data->toc_hash_offset - last_entry);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.finish,
		&manifest->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest->hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (read_len));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->raw + offset,
		data->length - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &img_list);
	CuAssertIntEquals (test, PFM_MALFORMED_FW_VER_ELEMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_additional_element_read_bad_fw_version_element_length_less_than_img_min (
	CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_MAX_VERSION;
	int fw_index = 2;
	int ver_index = 0;
	int status;
	struct pfm_image_list img_list;
	struct manifest_flash_v2_testing *manifest = &pfm.manifest;
	const struct manifest_v2_testing_data *data = &test_pfm->manifest;
	int start = test_pfm->fw[fw_index].version[ver_index].fw_version_entry;
	int entry = test_pfm->fw[fw_index].version[ver_index].fw_version_entry;
	uint32_t offset = test_pfm->fw[fw_index].version[ver_index].img[0].img_offset;
	size_t read_len = PFM_V2_IMG_HDR_SIZE - 1;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	struct manifest_toc_entry bad_entry;

	TEST_START;

	memcpy (&bad_entry, &toc_entries[entry], sizeof (bad_entry));
	bad_entry.hash_id = 0xff;
	bad_entry.length = (offset - test_pfm->fw[fw_index].version[ver_index].fw_version_offset) +
		read_len;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, true, 0);

	pfm_flash_v2_testing_find_version_entry_mocked_hash (test, &pfm, test_pfm, fw_index, ver_index);

	status = mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.start_sha256,
		&manifest->hash_mock, 0);
	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (entry * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	status |= mock_expect_output (&manifest->flash.mock, 1, &bad_entry, sizeof (bad_entry), 2);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&bad_entry, sizeof (bad_entry)),
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + last_entry, data->raw + last_entry, data->toc_hash_offset - last_entry);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.finish,
		&manifest->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest->hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (read_len));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->raw + offset,
		data->length - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &img_list);
	CuAssertIntEquals (test, PFM_MALFORMED_FW_VER_ELEMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_additional_element_read_bad_fw_version_element_length_less_than_img (
	CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_MAX_VERSION;
	int fw_index = 2;
	int ver_index = 0;
	int status;
	struct pfm_image_list img_list;
	struct manifest_flash_v2_testing *manifest = &pfm.manifest;
	const struct manifest_v2_testing_data *data = &test_pfm->manifest;
	int start = test_pfm->fw[fw_index].version[ver_index].fw_version_entry;
	int entry = test_pfm->fw[fw_index].version[ver_index].fw_version_entry;
	uint32_t offset = test_pfm->fw[fw_index].version[ver_index].img[0].img_offset;
	size_t read_len =
		PFM_V2_TESTING_IMG_LENGTH (&test_pfm->fw[fw_index].version[ver_index].img[0]) - 1;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	struct manifest_toc_entry bad_entry;

	TEST_START;

	memcpy (&bad_entry, &toc_entries[entry], sizeof (bad_entry));
	bad_entry.hash_id = 0xff;
	bad_entry.length = (offset - test_pfm->fw[fw_index].version[ver_index].fw_version_offset) +
		read_len;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, true, 0);

	pfm_flash_v2_testing_find_version_entry_mocked_hash (test, &pfm, test_pfm, fw_index, ver_index);

	status = mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.start_sha256,
		&manifest->hash_mock, 0);
	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (entry * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	status |= mock_expect_output (&manifest->flash.mock, 1, &bad_entry, sizeof (bad_entry), 2);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&bad_entry, sizeof (bad_entry)),
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + last_entry, data->raw + last_entry, data->toc_hash_offset - last_entry);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.finish,
		&manifest->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest->hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (read_len));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->raw + offset,
		data->length - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &img_list);
	CuAssertIntEquals (test, PFM_MALFORMED_FW_VER_ELEMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_region_end_before_start (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_BAD_REGIONS;
	int fw_index = 0;
	int ver_index = 0;
	int status;
	struct pfm_image_list img_list;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &img_list);
	CuAssertIntEquals (test, PFM_MALFORMED_FW_VER_ELEMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_get_firmware_images_region_end_equals_start (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_BAD_REGIONS;
	int fw_index = 1;
	int ver_index = 0;
	int status;
	struct pfm_image_list img_list;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, fw_index, ver_index);

	status = pfm.test.base.get_firmware_images (&pfm.test.base, test_pfm->fw[fw_index].fw_id_str,
		test_pfm->fw[fw_index].version[ver_index].version_str, &img_list);
	CuAssertIntEquals (test, PFM_MALFORMED_FW_VER_ELEMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_buffer_supported_versions (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int status;
	uint8_t ver_list[256];
	uint8_t expected[256];
	int expected_len = 0;
	int i;

	TEST_START;

	for (i = 0; i < test_pfm->fw[fw_index].version_count; i++) {
		strcpy ((char*) &expected[expected_len], test_pfm->fw[fw_index].version[i].version_str);
		expected_len += test_pfm->fw[fw_index].version[i].version_str_len + 1;
	}

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_firmware_entry (test, &pfm, test_pfm, fw_index);

	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest,
		test_pfm->fw[fw_index].version[0].fw_version_entry, test_pfm->fw[fw_index].fw_entry + 1,
		test_pfm->fw[fw_index].version[0].fw_version_hash,
		test_pfm->fw[fw_index].version[0].fw_version_offset,
		test_pfm->fw[fw_index].version[0].fw_version_len,
		test_pfm->fw[fw_index].version[0].fw_version_len, 0);

	status = pfm.test.base.buffer_supported_versions (&pfm.test.base,
		test_pfm->fw[fw_index].fw_id_str, 0, sizeof (ver_list), ver_list);
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (expected, ver_list, status);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_buffer_supported_versions_multiple_fw (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_TWO_FW;
	int fw_index = 1;
	int status;
	uint8_t ver_list[256];
	uint8_t expected[256];
	int expected_len = 0;
	int i;

	TEST_START;

	for (i = 0; i < test_pfm->fw[fw_index].version_count; i++) {
		strcpy ((char*) &expected[expected_len], test_pfm->fw[fw_index].version[i].version_str);
		expected_len += test_pfm->fw[fw_index].version[i].version_str_len + 1;
	}

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_firmware_entry (test, &pfm, test_pfm, fw_index);

	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest,
		test_pfm->fw[fw_index].version[0].fw_version_entry, test_pfm->fw[fw_index].fw_entry + 1,
		test_pfm->fw[fw_index].version[0].fw_version_hash,
		test_pfm->fw[fw_index].version[0].fw_version_offset,
		test_pfm->fw[fw_index].version[0].fw_version_len,
		test_pfm->fw[fw_index].version[0].fw_version_len, 0);

	status = pfm.test.base.buffer_supported_versions (&pfm.test.base,
		test_pfm->fw[fw_index].fw_id_str, 0, sizeof (ver_list), ver_list);
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (expected, ver_list, status);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_buffer_supported_versions_multiple_versions (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_MULTIPLE;
	int fw_index = 2;
	int status;
	uint8_t ver_list[256];
	uint8_t expected[256];
	int expected_len = 0;
	int i;

	TEST_START;

	for (i = 0; i < test_pfm->fw[fw_index].version_count; i++) {
		strcpy ((char*) &expected[expected_len], test_pfm->fw[fw_index].version[i].version_str);
		expected_len += test_pfm->fw[fw_index].version[i].version_str_len + 1;
	}

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_firmware_entry (test, &pfm, test_pfm, fw_index);

	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest,
		test_pfm->fw[fw_index].version[0].fw_version_entry, test_pfm->fw[fw_index].fw_entry + 1,
		test_pfm->fw[fw_index].version[0].fw_version_hash,
		test_pfm->fw[fw_index].version[0].fw_version_offset,
		test_pfm->fw[fw_index].version[0].fw_version_len,
		test_pfm->fw[fw_index].version[0].fw_version_len, 0);

	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest,
		test_pfm->fw[fw_index].version[1].fw_version_entry,
		test_pfm->fw[fw_index].version[0].fw_version_entry + 1,
		test_pfm->fw[fw_index].version[1].fw_version_hash,
		test_pfm->fw[fw_index].version[1].fw_version_offset,
		test_pfm->fw[fw_index].version[1].fw_version_len,
		test_pfm->fw[fw_index].version[1].fw_version_len, 0);

	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest,
		test_pfm->fw[fw_index].version[2].fw_version_entry,
		test_pfm->fw[fw_index].version[1].fw_version_entry + 1,
		test_pfm->fw[fw_index].version[2].fw_version_hash,
		test_pfm->fw[fw_index].version[2].fw_version_offset,
		test_pfm->fw[fw_index].version[2].fw_version_len,
		test_pfm->fw[fw_index].version[2].fw_version_len, 0);

	status = pfm.test.base.buffer_supported_versions (&pfm.test.base,
		test_pfm->fw[fw_index].fw_id_str, 0, sizeof (ver_list), ver_list);
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (expected, ver_list, status);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_buffer_supported_versions_no_versions (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_THREE_FW_NO_VER;
	int fw_index = 2;
	int status;
	uint8_t ver_list[256];

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_firmware_entry (test, &pfm, test_pfm, fw_index);

	status = pfm.test.base.buffer_supported_versions (&pfm.test.base,
		test_pfm->fw[fw_index].fw_id_str, 0, sizeof (ver_list), ver_list);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_buffer_supported_versions_partial (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int status;
	uint8_t ver_list[256];
	uint8_t expected[256];
	int expected_len = 2;

	TEST_START;

	memcpy (expected, &test_pfm->fw[fw_index].version[0].version_str[1], 2);

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_firmware_entry (test, &pfm, test_pfm, fw_index);

	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest,
		test_pfm->fw[fw_index].version[0].fw_version_entry, test_pfm->fw[fw_index].fw_entry + 1,
		test_pfm->fw[fw_index].version[0].fw_version_hash,
		test_pfm->fw[fw_index].version[0].fw_version_offset,
		test_pfm->fw[fw_index].version[0].fw_version_len,
		test_pfm->fw[fw_index].version[0].fw_version_len, 0);

	status = pfm.test.base.buffer_supported_versions (&pfm.test.base,
		test_pfm->fw[fw_index].fw_id_str, 1, 2, ver_list);
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (expected, ver_list, status);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_buffer_supported_versions_multiple_versions_partial (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_MULTIPLE;
	int fw_index = 2;
	int status;
	uint8_t ver_list[256];
	uint8_t expected[256];
	int expected_len = 4;

	TEST_START;

	memcpy (expected, &test_pfm->fw[fw_index].version[1].version_str[1], 4);

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_firmware_entry (test, &pfm, test_pfm, fw_index);

	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest,
		test_pfm->fw[fw_index].version[0].fw_version_entry, test_pfm->fw[fw_index].fw_entry + 1,
		test_pfm->fw[fw_index].version[0].fw_version_hash,
		test_pfm->fw[fw_index].version[0].fw_version_offset,
		test_pfm->fw[fw_index].version[0].fw_version_len,
		test_pfm->fw[fw_index].version[0].fw_version_len, 0);

	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest,
		test_pfm->fw[fw_index].version[1].fw_version_entry,
		test_pfm->fw[fw_index].version[0].fw_version_entry + 1,
		test_pfm->fw[fw_index].version[1].fw_version_hash,
		test_pfm->fw[fw_index].version[1].fw_version_offset,
		test_pfm->fw[fw_index].version[1].fw_version_len,
		test_pfm->fw[fw_index].version[1].fw_version_len, 0);

	status = pfm.test.base.buffer_supported_versions (&pfm.test.base,
		test_pfm->fw[fw_index].fw_id_str, test_pfm->fw[fw_index].version[0].version_str_len + 1 + 1,
		4, ver_list);
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (expected, ver_list, status);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_buffer_supported_versions_null_firmware_id (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_TWO_FW;
	int status;
	uint8_t ver_list[256];
	uint8_t expected[256];
	int expected_len = 0;
	int i;
	int j;

	TEST_START;

	for (i = 0; i < test_pfm->fw_count; i++) {
		strcpy ((char*) &expected[expected_len], test_pfm->fw[i].fw_id_str);
		expected_len += test_pfm->fw[i].fw_id_str_len + 1;

		for (j = 0; j < test_pfm->fw[i].version_count; j++) {
			strcpy ((char*) &expected[expected_len], test_pfm->fw[i].version[j].version_str);
			expected_len += test_pfm->fw[i].version[j].version_str_len + 1;
		}
	}

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	/* Get the list of all FW entries. */
	pfm_flash_v2_testing_find_firmware_entry (test, &pfm, test_pfm, test_pfm->fw_count - 1);

	for (i = 0; i < test_pfm->fw_count; i++) {
		/* Read all version for each firmware component. */
		pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, i,
			test_pfm->fw[i].version_count - 1);
	}

	status = pfm.test.base.buffer_supported_versions (&pfm.test.base, NULL, 0, sizeof (ver_list),
		ver_list);
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (expected, ver_list, status);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_buffer_supported_versions_null_firmware_id_multiple_versions (
	CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_MULTIPLE;
	int status;
	uint8_t ver_list[256];
	uint8_t expected[256];
	int expected_len = 0;
	int i;
	int j;

	TEST_START;

	for (i = 0; i < test_pfm->fw_count; i++) {
		strcpy ((char*) &expected[expected_len], test_pfm->fw[i].fw_id_str);
		expected_len += test_pfm->fw[i].fw_id_str_len + 1;

		for (j = 0; j < test_pfm->fw[i].version_count; j++) {
			strcpy ((char*) &expected[expected_len], test_pfm->fw[i].version[j].version_str);
			expected_len += test_pfm->fw[i].version[j].version_str_len + 1;
		}
	}

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	/* Get the list of all FW entries. */
	pfm_flash_v2_testing_find_firmware_entry (test, &pfm, test_pfm, test_pfm->fw_count - 1);

	for (i = 0; i < test_pfm->fw_count; i++) {
		/* Read all version for each firmware component. */
		pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, i,
			test_pfm->fw[i].version_count - 1);
	}

	status = pfm.test.base.buffer_supported_versions (&pfm.test.base, NULL, 0, sizeof (ver_list),
		ver_list);
	CuAssertIntEquals (test, expected_len, status);

	status = testing_validate_array (expected, ver_list, status);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_buffer_supported_versions_no_flash_dev_element_null_firmware_id (
	CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_NO_FLASH_DEV;
	int status;
	uint8_t ver_list[256];

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	status = pfm.test.base.buffer_supported_versions (&pfm.test.base, NULL, 0, sizeof (ver_list),
		ver_list);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_buffer_supported_versions_no_firmware_entries_null_firmware_id (
	CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_EMPTY;
	int status;
	uint8_t ver_list[256];

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	status = pfm.test.base.buffer_supported_versions (&pfm.test.base, NULL, 0, sizeof (ver_list),
		ver_list);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_buffer_supported_versions_null_firmware_id_partial (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_TWO_FW;
	int status;
	uint8_t ver_list[256];
	uint8_t expected[256];
	int offset = 0;
	int i;

	TEST_START;

	memcpy (expected, &test_pfm->fw[1].fw_id_str[1], test_pfm->fw[1].fw_id_str_len - 2);

	offset += test_pfm->fw[0].fw_id_str_len + 1;
	for (i = 0; i < test_pfm->fw[i].version_count; i++) {
		offset += test_pfm->fw[0].version[i].version_str_len + 1;
	}
	offset++;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	/* Get the list of all FW entries. */
	pfm_flash_v2_testing_find_firmware_entry (test, &pfm, test_pfm, test_pfm->fw_count - 1);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, 0,
		test_pfm->fw[0].version_count - 1);

	status = pfm.test.base.buffer_supported_versions (&pfm.test.base, NULL, offset,
		test_pfm->fw[1].fw_id_str_len - 2, ver_list);
	CuAssertIntEquals (test, test_pfm->fw[1].fw_id_str_len - 2, status);

	status = testing_validate_array (expected, ver_list, status);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_buffer_supported_versions_null_firmware_id_multiple_versions_partial (
	CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_MULTIPLE;
	int status;
	uint8_t ver_list[256];
	uint8_t expected[256];
	int offset = 0;
	int i;
	int j;

	TEST_START;

	memcpy (expected, &test_pfm->fw[1].version[1].version_str[1],
		test_pfm->fw[1].version[1].version_str_len - 2);

	for (i = 0; i < 2; i++) {
		offset += test_pfm->fw[i].fw_id_str_len + 1;
		for (j = 0; j < ((i == 1) ? 1 : test_pfm->fw[i].version_count); j++) {
			offset += test_pfm->fw[i].version[j].version_str_len + 1;
		}
	}
	offset++;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	/* Get the list of all FW entries. */
	pfm_flash_v2_testing_find_firmware_entry (test, &pfm, test_pfm, test_pfm->fw_count - 1);

	pfm_flash_v2_testing_find_version_entry (test, &pfm, test_pfm, 0,
		test_pfm->fw[0].version_count - 1);

	pfm_flash_v2_testing_find_firmware_entry (test, &pfm, test_pfm, 1);

	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest,
		test_pfm->fw[1].version[0].fw_version_entry, test_pfm->fw[1].fw_entry + 1,
		test_pfm->fw[1].version[0].fw_version_hash,
		test_pfm->fw[1].version[0].fw_version_offset,
		test_pfm->fw[1].version[0].fw_version_len,
		test_pfm->fw[1].version[0].fw_version_len, 0);

	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest,
		test_pfm->fw[1].version[1].fw_version_entry,
		test_pfm->fw[1].version[0].fw_version_entry + 1,
		test_pfm->fw[1].version[1].fw_version_hash,
		test_pfm->fw[1].version[1].fw_version_offset,
		test_pfm->fw[1].version[1].fw_version_len,
		test_pfm->fw[1].version[1].fw_version_len, 0);

	status = pfm.test.base.buffer_supported_versions (&pfm.test.base, NULL, offset,
		test_pfm->fw[1].version[1].version_str_len - 2, ver_list);
	CuAssertIntEquals (test, test_pfm->fw[1].version[1].version_str_len - 2, status);

	status = testing_validate_array (expected, ver_list, status);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_buffer_supported_versions_null (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int status;
	uint8_t ver_list[256];

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	status = pfm.test.base.buffer_supported_versions (NULL,
		test_pfm->fw[fw_index].fw_id_str, 0, sizeof (ver_list), ver_list);
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);

	status = pfm.test.base.buffer_supported_versions (&pfm.test.base,
		test_pfm->fw[fw_index].fw_id_str, 0, sizeof (ver_list), NULL);
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_buffer_supported_versions_verify_never_run (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int status;
	uint8_t ver_list[256];

	TEST_START;

	pfm_flash_v2_testing_init (test, &pfm, 0x10000);

	status = pfm.test.base.buffer_supported_versions (&pfm.test.base,
		test_pfm->fw[fw_index].fw_id_str, 0, sizeof (ver_list), ver_list);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_buffer_supported_versions_no_flash_dev_element (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_NO_FLASH_DEV;
	int fw_index = 0;
	int status;
	uint8_t ver_list[256];

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	status = pfm.test.base.buffer_supported_versions (&pfm.test.base,
		test_pfm->fw[fw_index].fw_id_str, 0, sizeof (ver_list), ver_list);
	CuAssertIntEquals (test, PFM_UNKNOWN_FIRMWARE, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_buffer_supported_versions_no_firmware_entries (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_EMPTY;
	int status;
	uint8_t ver_list[256];

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	status = pfm.test.base.buffer_supported_versions (&pfm.test.base, "Empty", 0, sizeof (ver_list),
		ver_list);
	CuAssertIntEquals (test, PFM_UNKNOWN_FIRMWARE, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_buffer_supported_versions_unknown_firmware (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int status;
	uint8_t ver_list[256];

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_firmware_entry (test, &pfm, test_pfm, fw_index);
	manifest_flash_v2_testing_read_element (test, &pfm.manifest, &test_pfm->manifest, -1,
		test_pfm->fw[fw_index].fw_entry + 1, -1, 0, 0, 0, 0);

	status = pfm.test.base.buffer_supported_versions (&pfm.test.base, "Bad", 0, sizeof (ver_list),
		ver_list);
	CuAssertIntEquals (test, PFM_UNKNOWN_FIRMWARE, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_buffer_supported_versions_find_firmware_error (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int status;
	uint8_t ver_list[256];

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	status = mock_expect (&pfm.manifest.flash.mock, pfm.manifest.flash.base.read,
		&pfm.manifest.flash, FLASH_READ_FAILED,
		MOCK_ARG (pfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.buffer_supported_versions (&pfm.test.base,
		test_pfm->fw[fw_index].fw_id_str, 0, sizeof (ver_list), ver_list);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_buffer_supported_versions_read_element_error (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int status;
	uint8_t ver_list[256];

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	pfm_flash_v2_testing_find_firmware_entry (test, &pfm, test_pfm, fw_index);

	status = mock_expect (&pfm.manifest.flash.mock, pfm.manifest.flash.base.read,
		&pfm.manifest.flash, FLASH_READ_FAILED,
		MOCK_ARG (pfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE * (test_pfm->fw[fw_index].fw_entry + 1)));
	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.buffer_supported_versions (&pfm.test.base,
		test_pfm->fw[fw_index].fw_id_str, 0, sizeof (ver_list), ver_list);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_buffer_supported_versions_bad_firmware_element_length_less_than_min (
	CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int status;
	uint8_t ver_list[256];
	struct manifest_flash_v2_testing *manifest = &pfm.manifest;
	const struct manifest_v2_testing_data *data = &test_pfm->manifest;
	int start = 0;
	int entry = test_pfm->fw[fw_index].fw_entry;
	uint32_t offset = test_pfm->fw[fw_index].fw_offset;
	size_t read_len = PFM_V2_FIRMWARE_HDR_SIZE - 1;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;
	struct manifest_toc_entry bad_entry;

	TEST_START;

	memcpy (&bad_entry, &toc_entries[entry], sizeof (bad_entry));
	bad_entry.hash_id = 0xff;
	bad_entry.length = read_len;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, true, 0);

	status = mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.start_sha256,
		&manifest->hash_mock, 0);
	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i < entry; i++) {
		status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest->flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
			&manifest->hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	status |= mock_expect_output (&manifest->flash.mock, 1, &bad_entry, sizeof (bad_entry), 2);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&bad_entry, sizeof (bad_entry)),
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + last_entry, data->raw + last_entry, data->toc_hash_offset - last_entry);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.finish,
		&manifest->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest->hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (read_len));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->raw + offset,
		data->length - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.buffer_supported_versions (&pfm.test.base,
		test_pfm->fw[fw_index].fw_id_str, 0, sizeof (ver_list), ver_list);
	CuAssertIntEquals (test, PFM_MALFORMED_FIRMWARE_ELEMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_buffer_supported_versions_bad_firmware_element_length_less_than_id (
	CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int status;
	uint8_t ver_list[256];
	struct manifest_flash_v2_testing *manifest = &pfm.manifest;
	const struct manifest_v2_testing_data *data = &test_pfm->manifest;
	int start = 0;
	int entry = test_pfm->fw[fw_index].fw_entry;
	uint32_t offset = test_pfm->fw[fw_index].fw_offset;
	size_t read_len = test_pfm->fw[fw_index].fw_len - 1;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;
	struct manifest_toc_entry bad_entry;

	TEST_START;

	memcpy (&bad_entry, &toc_entries[entry], sizeof (bad_entry));
	bad_entry.hash_id = 0xff;
	bad_entry.length = read_len;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, true, 0);

	status = mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.start_sha256,
		&manifest->hash_mock, 0);
	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i < entry; i++) {
		status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest->flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
			&manifest->hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	status |= mock_expect_output (&manifest->flash.mock, 1, &bad_entry, sizeof (bad_entry), 2);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&bad_entry, sizeof (bad_entry)),
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + last_entry, data->raw + last_entry, data->toc_hash_offset - last_entry);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.finish,
		&manifest->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest->hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (read_len));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->raw + offset,
		data->length - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.buffer_supported_versions (&pfm.test.base,
		test_pfm->fw[fw_index].fw_id_str, 0, sizeof (ver_list), ver_list);
	CuAssertIntEquals (test, PFM_MALFORMED_FIRMWARE_ELEMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_buffer_supported_versions_bad_fw_version_element_length_less_than_min (
	CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int status;
	uint8_t ver_list[256];
	struct manifest_flash_v2_testing *manifest = &pfm.manifest;
	const struct manifest_v2_testing_data *data = &test_pfm->manifest;
	int start = test_pfm->fw[fw_index].fw_entry + 1;
	int entry = test_pfm->fw[fw_index].version[0].fw_version_entry;
	uint32_t offset = test_pfm->fw[fw_index].version[0].fw_version_offset;
	size_t read_len = PFM_V2_FW_VERSION_HDR_SIZE - 1;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;
	struct manifest_toc_entry bad_entry;

	TEST_START;

	memcpy (&bad_entry, &toc_entries[entry], sizeof (bad_entry));
	bad_entry.hash_id = 0xff;
	bad_entry.length = read_len;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, true, 0);

	pfm_flash_v2_testing_find_firmware_entry_mocked_hash (test, &pfm, test_pfm, fw_index);

	status = mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.start_sha256,
		&manifest->hash_mock, 0);
	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i < entry; i++) {
		status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest->flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
			&manifest->hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	status |= mock_expect_output (&manifest->flash.mock, 1, &bad_entry, sizeof (bad_entry), 2);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&bad_entry, sizeof (bad_entry)),
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + last_entry, data->raw + last_entry, data->toc_hash_offset - last_entry);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.finish,
		&manifest->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest->hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (read_len));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->raw + offset,
		data->length - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.buffer_supported_versions (&pfm.test.base,
		test_pfm->fw[fw_index].fw_id_str, 0, sizeof (ver_list), ver_list);
	CuAssertIntEquals (test, PFM_MALFORMED_FW_VER_ELEMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_buffer_supported_versions_bad_fw_version_element_length_less_than_version (
	CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int status;
	uint8_t ver_list[256];
	struct manifest_flash_v2_testing *manifest = &pfm.manifest;
	const struct manifest_v2_testing_data *data = &test_pfm->manifest;
	int start = test_pfm->fw[fw_index].fw_entry + 1;
	int entry = test_pfm->fw[fw_index].version[0].fw_version_entry;
	uint32_t offset = test_pfm->fw[fw_index].version[0].fw_version_offset;
	size_t read_len = PFM_V2_FW_VERSION_HDR_SIZE +
		test_pfm->fw[fw_index].version[0].version_str_len +
		test_pfm->fw[fw_index].version[0].version_str_pad - 1;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;
	struct manifest_toc_entry bad_entry;

	TEST_START;

	memcpy (&bad_entry, &toc_entries[entry], sizeof (bad_entry));
	bad_entry.hash_id = 0xff;
	bad_entry.length = read_len;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, true, 0);

	pfm_flash_v2_testing_find_firmware_entry_mocked_hash (test, &pfm, test_pfm, fw_index);

	status = mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.start_sha256,
		&manifest->hash_mock, 0);
	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i < entry; i++) {
		status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest->flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
			&manifest->hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	status |= mock_expect_output (&manifest->flash.mock, 1, &bad_entry, sizeof (bad_entry), 2);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&bad_entry, sizeof (bad_entry)),
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + last_entry, data->raw + last_entry, data->toc_hash_offset - last_entry);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.finish,
		&manifest->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest->hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (read_len));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->raw + offset,
		data->length - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.buffer_supported_versions (&pfm.test.base,
		test_pfm->fw[fw_index].fw_id_str, 0, sizeof (ver_list), ver_list);
	CuAssertIntEquals (test, PFM_MALFORMED_FW_VER_ELEMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_buffer_supported_versions_bad_fw_version_element_length_less_than_rw (
	CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int fw_index = 0;
	int status;
	uint8_t ver_list[256];
	struct manifest_flash_v2_testing *manifest = &pfm.manifest;
	const struct manifest_v2_testing_data *data = &test_pfm->manifest;
	int start = test_pfm->fw[fw_index].fw_entry + 1;
	int entry = test_pfm->fw[fw_index].version[0].fw_version_entry;
	uint32_t offset = test_pfm->fw[fw_index].version[0].fw_version_offset;
	size_t read_len = PFM_V2_FW_VERSION_HDR_SIZE +
		test_pfm->fw[fw_index].version[0].version_str_len +
		test_pfm->fw[fw_index].version[0].version_str_pad +
		(PFM_V2_RW_REGION_SIZE * test_pfm->fw[fw_index].version[0].rw_count) - 1;
	uint32_t toc_entry_offset = MANIFEST_V2_TOC_ENTRY_OFFSET;
	uint32_t first_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * start);
	uint32_t last_entry = toc_entry_offset + (MANIFEST_V2_TOC_ENTRY_SIZE * (entry + 1));
	const struct manifest_toc_entry *toc_entries =
		(struct manifest_toc_entry*) (data->raw + toc_entry_offset);
	int i;
	struct manifest_toc_entry bad_entry;

	TEST_START;

	memcpy (&bad_entry, &toc_entries[entry], sizeof (bad_entry));
	bad_entry.hash_id = 0xff;
	bad_entry.length = read_len;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, true, 0);

	pfm_flash_v2_testing_find_firmware_entry_mocked_hash (test, &pfm, test_pfm, fw_index);

	status = mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.start_sha256,
		&manifest->hash_mock, 0);
	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0, MOCK_ARG_PTR_CONTAINS (data->toc, MANIFEST_V2_TOC_HEADER_SIZE),
		MOCK_ARG (MANIFEST_V2_TOC_HEADER_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + toc_entry_offset, data->raw + toc_entry_offset,
		first_entry - toc_entry_offset);

	for (i = start; i < entry; i++) {
		status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&manifest->flash.mock, 1, &toc_entries[i],
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);

		status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
			&manifest->hash_mock, 0,
			MOCK_ARG_PTR_CONTAINS (&toc_entries[i], MANIFEST_V2_TOC_ENTRY_SIZE),
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	}

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash,
			0, MOCK_ARG (manifest->addr + toc_entry_offset + (i * MANIFEST_V2_TOC_ENTRY_SIZE)),
			MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	status |= mock_expect_output (&manifest->flash.mock, 1, &bad_entry, sizeof (bad_entry), 2);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.update,
		&manifest->hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (&bad_entry, sizeof (bad_entry)),
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));

	status |= flash_mock_expect_verify_flash_and_hash (&manifest->flash, &manifest->hash_mock,
		manifest->addr + last_entry, data->raw + last_entry, data->toc_hash_offset - last_entry);

	status |= mock_expect (&manifest->hash_mock.mock, manifest->hash_mock.base.finish,
		&manifest->hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&manifest->hash_mock.mock, 0, data->toc_hash, data->toc_hash_len,
		1);

	status |= mock_expect (&manifest->flash.mock, manifest->flash.base.read, &manifest->flash, 0,
		MOCK_ARG (manifest->addr + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (read_len));
	status |= mock_expect_output (&manifest->flash.mock, 1, data->raw + offset,
		data->length - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.buffer_supported_versions (&pfm.test.base,
		test_pfm->fw[fw_index].fw_id_str, 0, sizeof (ver_list), ver_list);
	CuAssertIntEquals (test, PFM_MALFORMED_FW_VER_ELEMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_buffer_supported_versions_null_firmware_id_fw_list_error (
		CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_TWO_FW;
	int status;
	uint8_t ver_list[256];

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	status = mock_expect (&pfm.manifest.flash.mock, pfm.manifest.flash.base.read,
		&pfm.manifest.flash, FLASH_READ_FAILED,
		MOCK_ARG (pfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.buffer_supported_versions (&pfm.test.base, NULL, 0, sizeof (ver_list),
		ver_list);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_buffer_supported_versions_null_firmware_id_read_element_error (
	CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_TWO_FW;
	int fw_index = 0;
	int status;
	uint8_t ver_list[256];

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	/* Get the list of all FW entries. */
	pfm_flash_v2_testing_find_firmware_entry (test, &pfm, test_pfm, test_pfm->fw_count - 1);

	pfm_flash_v2_testing_find_firmware_entry (test, &pfm, test_pfm, fw_index);

	status = mock_expect (&pfm.manifest.flash.mock, pfm.manifest.flash.base.read,
		&pfm.manifest.flash, FLASH_READ_FAILED,
		MOCK_ARG (pfm.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE * (test_pfm->fw[fw_index].fw_entry + 1)));
	CuAssertIntEquals (test, 0, status);

	status = pfm.test.base.buffer_supported_versions (&pfm.test.base, NULL, 0, sizeof (ver_list),
		ver_list);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_is_empty (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int status;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	status = pfm.test.base.base.is_empty (&pfm.test.base.base);
	CuAssertIntEquals (test, 0, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_is_empty_no_flash_dev_element (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_NO_FLASH_DEV;
	int status;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	status = pfm.test.base.base.is_empty (&pfm.test.base.base);
	CuAssertIntEquals (test, 1, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_is_empty_no_firmware_entries (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2_EMPTY;
	int status;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	status = pfm.test.base.base.is_empty (&pfm.test.base.base);
	CuAssertIntEquals (test, 1, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_is_empty_null (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	const struct pfm_v2_testing_data *test_pfm = &PFM_V2;
	int status;

	TEST_START;

	pfm_flash_v2_testing_init_and_verify (test, &pfm, 0x10000, test_pfm, 0, false, 0);

	status = pfm.test.base.base.is_empty (NULL);
	CuAssertIntEquals (test, PFM_INVALID_ARGUMENT, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}

static void pfm_flash_v2_test_is_empty_verify_never_run (CuTest *test)
{
	struct pfm_flash_v2_testing pfm;
	int status;

	TEST_START;

	pfm_flash_v2_testing_init (test, &pfm, 0x10000);

	status = pfm.test.base.base.is_empty (&pfm.test.base.base);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	pfm_flash_v2_testing_validate_and_release (test, &pfm);
}


TEST_SUITE_START (pfm_flash_v2);

TEST (pfm_flash_v2_test_verify);
TEST (pfm_flash_v2_test_verify_with_mock_hash);
TEST (pfm_flash_v2_test_verify_two_firmware_types);
TEST (pfm_flash_v2_test_verify_no_flash_device_element);
TEST (pfm_flash_v2_test_verify_empty_manifest);
TEST (pfm_flash_v2_test_verify_no_firmware_entries);
TEST (pfm_flash_v2_test_verify_three_firmware_no_versions);
TEST (pfm_flash_v2_test_verify_multiple_firmware_versions_regions);
TEST (pfm_flash_v2_test_verify_max_firmware_versions);
TEST (pfm_flash_v2_test_verify_rw_test);
TEST (pfm_flash_v2_test_verify_three_firmware);
TEST (pfm_flash_v2_test_verify_multiple_image_regions);
TEST (pfm_flash_v2_test_verify_img_test);
TEST (pfm_flash_v2_test_bad_regions_test);
TEST (pfm_flash_v2_test_verify_null);
TEST (pfm_flash_v2_test_verify_header_read_error);
TEST (pfm_flash_v2_test_verify_flash_device_element_read_error);
TEST (pfm_flash_v2_test_verify_flash_device_element_bad_length);
TEST (pfm_flash_v2_test_get_id);
TEST (pfm_flash_v2_test_get_id_null);
TEST (pfm_flash_v2_test_get_id_after_verify_flash_device_element_read_error);
TEST (pfm_flash_v2_test_get_id_after_verify_flash_device_element_bad_length);
TEST (pfm_flash_v2_test_get_platform_id);
TEST (pfm_flash_v2_test_get_platform_id_manifest_allocation);
TEST (pfm_flash_v2_test_get_platform_id_null);
TEST (pfm_flash_v2_test_free_platform_id_null);
TEST (pfm_flash_v2_test_get_hash);
TEST (pfm_flash_v2_test_get_hash_null);
TEST (pfm_flash_v2_test_get_signature);
TEST (pfm_flash_v2_test_get_signature_null);
TEST (pfm_flash_v2_test_get_firmware);
TEST (pfm_flash_v2_test_get_firmware_multiple);
TEST (pfm_flash_v2_test_get_firmware_no_flash_dev_element);
TEST (pfm_flash_v2_test_get_firmware_no_firmware_entries);
TEST (pfm_flash_v2_test_get_firmware_null);
TEST (pfm_flash_v2_test_get_firmware_verify_never_run);
TEST (pfm_flash_v2_test_get_firmware_read_element_error);
TEST (pfm_flash_v2_test_get_firmware_bad_firmware_element_length_less_than_min);
TEST (pfm_flash_v2_test_get_firmware_bad_firmware_element_length_less_than_id);
TEST (pfm_flash_v2_test_get_supported_versions);
TEST (pfm_flash_v2_test_get_supported_versions_multiple_firmware);
TEST (pfm_flash_v2_test_get_supported_versions_multiple_versions);
TEST (pfm_flash_v2_test_get_supported_versions_null_firmware_id);
TEST (pfm_flash_v2_test_get_supported_versions_no_versions);
TEST (pfm_flash_v2_test_get_supported_versions_no_flash_dev_element_null_firmware_id);
TEST (pfm_flash_v2_test_get_supported_versions_no_firmware_entries_null_firmware_id);
TEST (pfm_flash_v2_test_get_supported_versions_null);
TEST (pfm_flash_v2_test_get_supported_versions_verify_never_run);
TEST (pfm_flash_v2_test_get_supported_versions_no_flash_dev_element);
TEST (pfm_flash_v2_test_get_supported_versions_no_firmware_entries);
TEST (pfm_flash_v2_test_get_supported_versions_unknown_firmware);
TEST (pfm_flash_v2_test_get_supported_versions_find_firmware_error);
TEST (pfm_flash_v2_test_get_supported_versions_read_element_error);
TEST (pfm_flash_v2_test_get_supported_versions_bad_firmware_element_length_less_than_min);
TEST (pfm_flash_v2_test_get_supported_versions_bad_firmware_element_length_less_than_id);
TEST (pfm_flash_v2_test_get_supported_versions_bad_fw_version_element_length_less_than_min);
TEST (pfm_flash_v2_test_get_supported_versions_bad_fw_version_element_length_less_than_version);
TEST (pfm_flash_v2_test_get_supported_versions_bad_fw_version_element_length_less_than_rw);
TEST (pfm_flash_v2_test_get_read_write_regions);
TEST (pfm_flash_v2_test_get_read_write_regions_multiple_firmware);
TEST (pfm_flash_v2_test_get_read_write_regions_multiple_versions);
TEST (pfm_flash_v2_test_get_read_write_regions_multiple_regions);
TEST (pfm_flash_v2_test_get_read_write_regions_null_firmware_id);
TEST (pfm_flash_v2_test_get_read_write_regions_no_regions);
TEST (pfm_flash_v2_test_get_read_write_regions_max_element_single_read);
TEST (pfm_flash_v2_test_get_read_write_regions_additional_element_read);
TEST (pfm_flash_v2_test_get_read_write_regions_max_version_string);
TEST (pfm_flash_v2_test_get_read_write_regions_max_rw_regions);
TEST (pfm_flash_v2_test_get_read_write_regions_null);
TEST (pfm_flash_v2_test_get_read_write_regions_verify_never_run);
TEST (pfm_flash_v2_test_get_read_write_regions_no_flash_dev_element);
TEST (pfm_flash_v2_test_get_read_write_regions_no_firmware_entries);
TEST (pfm_flash_v2_test_get_read_write_regions_unknown_firmware);
TEST (pfm_flash_v2_test_get_read_write_regions_find_firmware_error);
TEST (pfm_flash_v2_test_get_read_write_regions_unknown_version);
TEST (pfm_flash_v2_test_get_read_write_regions_unknown_version_last_entry);
TEST (pfm_flash_v2_test_get_read_write_regions_find_version_error);
TEST (pfm_flash_v2_test_get_read_write_regions_too_many_rw_regions);
TEST (pfm_flash_v2_test_get_read_write_regions_additional_element_read_error);
TEST (pfm_flash_v2_test_get_read_write_regions_bad_firmware_element_length_less_than_min);
TEST (pfm_flash_v2_test_get_read_write_regions_bad_firmware_element_length_less_than_id);
TEST (pfm_flash_v2_test_get_read_write_regions_bad_fw_version_element_length_less_than_min);
TEST (pfm_flash_v2_test_get_read_write_regions_bad_fw_version_element_length_less_than_version);
TEST (pfm_flash_v2_test_get_read_write_regions_bad_fw_version_element_length_less_than_rw);
TEST (pfm_flash_v2_test_get_read_write_regions_end_before_start);
TEST (pfm_flash_v2_test_get_read_write_regions_end_equals_start);
TEST (pfm_flash_v2_test_get_firmware_images_sha256);
TEST (pfm_flash_v2_test_get_firmware_images_multiple_firmware_sha384);
TEST (pfm_flash_v2_test_get_firmware_images_multiple_firmware_sha512);
TEST (pfm_flash_v2_test_get_firmware_images_multiple_versions);
TEST (pfm_flash_v2_test_get_firmware_images_multiple_images);
TEST (pfm_flash_v2_test_get_firmware_images_multiple_regions);
TEST (pfm_flash_v2_test_get_firmware_images_multiple_images_multiple_regions);
TEST (pfm_flash_v2_test_get_firmware_images_extra_flags);
TEST (pfm_flash_v2_test_get_firmware_images_null_firmware_id);
TEST (pfm_flash_v2_test_get_firmware_images_max_element_single_read);
TEST (pfm_flash_v2_test_get_firmware_images_additional_element_read);
TEST (pfm_flash_v2_test_get_firmware_images_additional_element_read_rw_overflow);
TEST (pfm_flash_v2_test_get_firmware_images_multiple_element_read);
TEST (pfm_flash_v2_test_get_firmware_images_multiple_element_read_multiple_per_element);
TEST (pfm_flash_v2_test_get_firmware_images_max_version_string);
TEST (pfm_flash_v2_test_get_firmware_images_max_image_regions);
TEST (pfm_flash_v2_test_get_firmware_images_null);
TEST (pfm_flash_v2_test_get_firmware_images_verify_never_run);
TEST (pfm_flash_v2_test_get_firmware_images_no_flash_dev_element);
TEST (pfm_flash_v2_test_get_firmware_images_no_firmware_entries);
TEST (pfm_flash_v2_test_get_firmware_images_unknown_firmware);
TEST (pfm_flash_v2_test_get_firmware_images_find_firmware_error);
TEST (pfm_flash_v2_test_get_firmware_images_unknown_version);
TEST (pfm_flash_v2_test_get_firmware_images_find_version_error);
TEST (pfm_flash_v2_test_get_firmware_images_invalid_hash_type);
TEST (pfm_flash_v2_test_get_firmware_images_no_regions);
TEST (pfm_flash_v2_test_get_firmware_images_too_many_image_regions);
TEST (pfm_flash_v2_test_get_firmware_images_additional_element_read_error);
TEST (pfm_flash_v2_test_get_firmware_images_bad_firmware_element_length_less_than_min);
TEST (pfm_flash_v2_test_get_firmware_images_bad_firmware_element_length_less_than_id);
TEST (pfm_flash_v2_test_get_firmware_images_bad_fw_version_element_length_less_than_min);
TEST (pfm_flash_v2_test_get_firmware_images_bad_fw_version_element_length_less_than_version);
TEST (pfm_flash_v2_test_get_firmware_images_bad_fw_version_element_length_less_than_rw);
TEST (pfm_flash_v2_test_get_firmware_images_bad_fw_version_element_length_less_than_img_min);
TEST (pfm_flash_v2_test_get_firmware_images_bad_fw_version_element_length_less_than_img);
TEST (pfm_flash_v2_test_get_firmware_images_additional_element_read_bad_fw_version_element_length_less_than_img_min);
TEST (pfm_flash_v2_test_get_firmware_images_additional_element_read_bad_fw_version_element_length_less_than_img);
TEST (pfm_flash_v2_test_get_firmware_images_region_end_before_start);
TEST (pfm_flash_v2_test_get_firmware_images_region_end_equals_start);
TEST (pfm_flash_v2_test_buffer_supported_versions);
TEST (pfm_flash_v2_test_buffer_supported_versions_multiple_fw);
TEST (pfm_flash_v2_test_buffer_supported_versions_multiple_versions);
TEST (pfm_flash_v2_test_buffer_supported_versions_no_versions);
TEST (pfm_flash_v2_test_buffer_supported_versions_partial);
TEST (pfm_flash_v2_test_buffer_supported_versions_multiple_versions_partial);
TEST (pfm_flash_v2_test_buffer_supported_versions_null_firmware_id);
TEST (pfm_flash_v2_test_buffer_supported_versions_null_firmware_id_multiple_versions);
TEST (pfm_flash_v2_test_buffer_supported_versions_no_flash_dev_element_null_firmware_id);
TEST (pfm_flash_v2_test_buffer_supported_versions_no_firmware_entries_null_firmware_id);
TEST (pfm_flash_v2_test_buffer_supported_versions_null_firmware_id_partial);
TEST (pfm_flash_v2_test_buffer_supported_versions_null_firmware_id_multiple_versions_partial);
TEST (pfm_flash_v2_test_buffer_supported_versions_null);
TEST (pfm_flash_v2_test_buffer_supported_versions_verify_never_run);
TEST (pfm_flash_v2_test_buffer_supported_versions_no_flash_dev_element);
TEST (pfm_flash_v2_test_buffer_supported_versions_no_firmware_entries);
TEST (pfm_flash_v2_test_buffer_supported_versions_unknown_firmware);
TEST (pfm_flash_v2_test_buffer_supported_versions_find_firmware_error);
TEST (pfm_flash_v2_test_buffer_supported_versions_read_element_error);
TEST (pfm_flash_v2_test_buffer_supported_versions_bad_firmware_element_length_less_than_min);
TEST (pfm_flash_v2_test_buffer_supported_versions_bad_firmware_element_length_less_than_id);
TEST (pfm_flash_v2_test_buffer_supported_versions_bad_fw_version_element_length_less_than_min);
TEST (pfm_flash_v2_test_buffer_supported_versions_bad_fw_version_element_length_less_than_version);
TEST (pfm_flash_v2_test_buffer_supported_versions_bad_fw_version_element_length_less_than_rw);
TEST (pfm_flash_v2_test_buffer_supported_versions_null_firmware_id_fw_list_error);
TEST (pfm_flash_v2_test_buffer_supported_versions_null_firmware_id_read_element_error);
TEST (pfm_flash_v2_test_is_empty);
TEST (pfm_flash_v2_test_is_empty_no_flash_dev_element);
TEST (pfm_flash_v2_test_is_empty_no_firmware_entries);
TEST (pfm_flash_v2_test_is_empty_null);
TEST (pfm_flash_v2_test_is_empty_verify_never_run);

TEST_SUITE_END;
