// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "cmd_interface/device_manager.h"
#include "common/array_size.h"
#include "flash/flash.h"
#include "manifest/pcd/pcd_flash.h"
#include "manifest/pcd/pcd_flash_static.h"
#include "manifest/pcd/pcd_format.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/manifest/manifest_flash_v2_testing.h"
#include "testing/manifest/pcd/pcd_testing.h"
#include "testing/mock/crypto/signature_verification_mock.h"


TEST_SUITE_LABEL ("pcd_flash");


/**
 * V1 PCD with ID 0x1A for backwards compatibility testing.
 */
const uint8_t PCD_DATA_V1[] = {
	0x9c, 0x02, 0x29, 0x10, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x07, 0x07, 0x00, 0x00,
	0x00, 0xff, 0x01, 0x00, 0x48, 0x01, 0x08, 0x00, 0x42, 0xff, 0x01, 0x01, 0x50, 0x01, 0x0c, 0x00,
	0x43, 0xff, 0x01, 0x02, 0x5c, 0x01, 0x14, 0x00, 0x44, 0xff, 0x01, 0x03, 0x70, 0x01, 0x14, 0x00,
	0x40, 0xff, 0x01, 0x04, 0x84, 0x01, 0x08, 0x00, 0x41, 0x40, 0x01, 0x05, 0x8c, 0x01, 0x08, 0x00,
	0x41, 0x40, 0x01, 0x06, 0x94, 0x01, 0x08, 0x00, 0x13, 0xe9, 0x1c, 0x16, 0x0e, 0xcf, 0xd2, 0xbb,
	0x3a, 0x86, 0x83, 0xb6, 0x01, 0xc4, 0xba, 0xcb, 0x04, 0xf0, 0xa5, 0x18, 0x9b, 0x97, 0xd9, 0x2d,
	0x67, 0xf4, 0x6d, 0x69, 0xea, 0x1e, 0x25, 0x36, 0x4d, 0x9a, 0x65, 0x85, 0x38, 0xe7, 0x61, 0xba,
	0xbb, 0xb3, 0xdc, 0x6a, 0x01, 0x3f, 0xb4, 0x11, 0x77, 0x16, 0x30, 0x68, 0x93, 0x9c, 0xc5, 0x89,
	0xf1, 0xd1, 0x9a, 0x66, 0xab, 0xc9, 0x09, 0x7f, 0x1e, 0x1d, 0x1a, 0xe3, 0x7c, 0xef, 0x8e, 0xdd,
	0x91, 0x64, 0x59, 0x14, 0x19, 0xf4, 0x5d, 0x67, 0x74, 0xc3, 0x8d, 0x5e, 0xc9, 0x77, 0x2e, 0xf2,
	0xc8, 0x79, 0xac, 0x7f, 0x2d, 0x5e, 0x78, 0x52, 0x76, 0x05, 0xa2, 0x2a, 0xcd, 0x69, 0xcd, 0x01,
	0xf7, 0x2c, 0x5e, 0x18, 0xc7, 0xe1, 0xbb, 0x27, 0x77, 0xed, 0x3d, 0x11, 0xd9, 0x2b, 0xe4, 0x3d,
	0xbd, 0x58, 0x28, 0x98, 0xf3, 0x2b, 0x63, 0xc1, 0x26, 0x68, 0x8f, 0x48, 0xef, 0xdf, 0x2c, 0x20,
	0xf7, 0xe5, 0x49, 0xea, 0x14, 0x17, 0x44, 0x8e, 0x82, 0xc3, 0x96, 0x38, 0xbf, 0x9a, 0xb9, 0x53,
	0xd2, 0xa1, 0xc0, 0x94, 0x27, 0xf5, 0xa9, 0x60, 0xd8, 0xa8, 0xa9, 0xa2, 0x83, 0xe3, 0x96, 0x44,
	0x4f, 0xe0, 0x88, 0x64, 0x32, 0x82, 0xd2, 0x36, 0xd9, 0xac, 0x81, 0x15, 0x30, 0x9d, 0x10, 0x51,
	0xc9, 0x73, 0x14, 0xa7, 0xc1, 0x85, 0xeb, 0x2b, 0x1a, 0x12, 0xc0, 0x2d, 0x58, 0x70, 0x5e, 0x4c,
	0xc1, 0x0a, 0x6f, 0xff, 0x25, 0x23, 0x1b, 0x60, 0x26, 0x11, 0x30, 0xc1, 0x83, 0xf3, 0x08, 0x24,
	0xdb, 0x1b, 0x97, 0x6a, 0xcd, 0xc5, 0xde, 0xa5, 0x62, 0xbc, 0xfb, 0x2c, 0xb5, 0xf6, 0x05, 0x81,
	0xfc, 0xc5, 0x0d, 0x37, 0xe5, 0x34, 0xc4, 0xdc, 0xe9, 0xee, 0xc5, 0x28, 0x41, 0x62, 0x1d, 0xd8,
	0xc7, 0x06, 0x6d, 0x23, 0xca, 0x9b, 0x6a, 0x45, 0x04, 0x00, 0x00, 0x00, 0x53, 0x4b, 0x55, 0x31,
	0x02, 0x02, 0x22, 0x14, 0x66, 0x07, 0x00, 0x00, 0x45, 0x04, 0x00, 0x00, 0x00, 0x50, 0xe0, 0x05,
	0x41, 0x6c, 0x70, 0x68, 0x61, 0x00, 0x00, 0x00, 0x01, 0x03, 0x75, 0x77, 0x55, 0x03, 0x00, 0x00,
	0x00, 0x70, 0xf0, 0x04, 0x42, 0x65, 0x74, 0x61, 0x0a, 0x00, 0x0b, 0x00, 0x0c, 0x00, 0x0d, 0x00,
	0x02, 0x30, 0x00, 0x00, 0x00, 0x02, 0x02, 0x41, 0x0b, 0x10, 0x0a, 0x00, 0x00, 0x31, 0x00, 0x00,
	0x00, 0x48, 0xe8, 0x01, 0x01, 0x04, 0x01, 0x0a, 0x00, 0x90, 0xd0, 0x03, 0x21, 0x7e, 0x4b, 0xd3,
	0x2d, 0xf8, 0x1f, 0x06, 0x61, 0x25, 0xa8, 0x6e, 0x5b, 0xb2, 0xe3, 0xa1, 0x46, 0xb1, 0xe5, 0x95,
	0x0e, 0x9e, 0x7a, 0x19, 0x9b, 0x74, 0x86, 0xbe, 0x2a, 0x12, 0xe4, 0xcc, 0x8f, 0x91, 0x3e, 0x7c,
	0x1f, 0x7a, 0x4d, 0xa4, 0x38, 0xbc, 0x5a, 0xce, 0xaa, 0xb1, 0xd2, 0x4f, 0xe8, 0xa9, 0x8c, 0x14,
	0xda, 0x6b, 0x46, 0x28, 0x76, 0x09, 0x7d, 0xbc, 0x35, 0xac, 0x3c, 0x87, 0xfd, 0x5f, 0x96, 0x8a,
	0x95, 0xae, 0x1d, 0x83, 0xca, 0x0e, 0x75, 0xaf, 0x55, 0x15, 0xfa, 0x83, 0x92, 0xda, 0xd3, 0x90,
	0x75, 0xea, 0x8a, 0x20, 0x91, 0x33, 0x9b, 0xa7, 0xee, 0x08, 0x75, 0x64, 0x36, 0xaa, 0x56, 0x11,
	0x51, 0x65, 0x5e, 0xd6, 0x47, 0x9a, 0xfd, 0xe4, 0xfa, 0xa4, 0xfe, 0x0e, 0x99, 0x81, 0x22, 0x5c,
	0x67, 0x15, 0x97, 0x7c, 0xef, 0xa6, 0x45, 0x86, 0xcf, 0xde, 0x94, 0x21, 0xd6, 0x6b, 0x1b, 0x0f,
	0x3c, 0x2e, 0x16, 0x17, 0x41, 0x30, 0xb9, 0xab, 0xa1, 0x60, 0x30, 0x47, 0x57, 0x68, 0x3e, 0xc2,
	0x3a, 0xd8, 0x13, 0xe5, 0xe9, 0xce, 0xb6, 0x43, 0x64, 0xfa, 0xa9, 0x64, 0x15, 0xd7, 0x8e, 0x27,
	0x07, 0x0d, 0x5b, 0x97, 0xd0, 0x8a, 0x51, 0xb6, 0x66, 0x80, 0xf3, 0x0f, 0x47, 0xf0, 0xf0, 0x4b,
	0x23, 0xff, 0x70, 0xb5, 0xe0, 0x03, 0xb1, 0xb5, 0x5b, 0x1f, 0x44, 0xe8, 0x02, 0xdb, 0x3f, 0xb0,
	0xc2, 0xdb, 0x4f, 0x68, 0xcf, 0x72, 0xc0, 0x7f, 0xef, 0xcc, 0xf5, 0xc3, 0x81, 0x31, 0x8a, 0xd3,
	0xe9, 0x2c, 0x57, 0x8b, 0x53, 0x97, 0x1d, 0x08, 0xe6, 0x4c, 0x38, 0xd0, 0xdd, 0x36, 0x3f, 0x6b,
	0x69, 0x22, 0x64, 0x7c, 0x3b, 0x28, 0xbc, 0x0d, 0xf4, 0xa8, 0x21, 0x51, 0x97, 0x5c, 0x38, 0xff,
	0x5c, 0xed, 0xf4, 0x4d, 0x8b, 0x99, 0xc5, 0xda, 0x27, 0x4f, 0xd6, 0x7f
};

/**
 * Length of the testing PCD.
 */
const uint32_t PCD_DATA_V1_LEN = sizeof (PCD_DATA_V1);

/**
 * PCD_DATA_V1 hash for testing.
 */
const uint8_t PCD_V1_HASH[] = {
	0xb3, 0xdb, 0xed, 0xb3, 0x02, 0xc2, 0x19, 0xd7, 0x56, 0xf1, 0x30, 0xed, 0xad, 0xc6, 0x9a, 0xc2,
	0x75, 0xd6, 0xe8, 0x55, 0x71, 0x90, 0xb6, 0xcb, 0xda, 0x19, 0xf8, 0x1b, 0xee, 0xba, 0x23, 0xb2
};

/**
 * The platform ID for the V1 PCD.
 */
const char PCD_V1_PLATFORM_ID[] = "SKU1";

/**
 * Components of the test V1 PCD.
 */
const struct pcd_testing_data PCD_V1_TESTING = {
	.manifest = {
		.raw = PCD_DATA_V1,
		.length = sizeof (PCD_DATA_V1),
		.hash = PCD_V1_HASH,
		.hash_len = sizeof (PCD_V1_HASH),
		.id = 0x1a,
		.signature = PCD_DATA_V1 + (sizeof (PCD_DATA_V1) - 256),
		.sig_len = 256,
		.sig_offset = (sizeof (PCD_DATA_V1) - 256),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = PCD_DATA_V1 + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x013c,
		.toc_hash = PCD_DATA_V1 + 0x0128,
		.toc_hash_len = 32,
		.toc_hash_offset = 0x0128,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 7,
		.toc_hashes = 7,
		.plat_id = PCD_DATA_V1 + 0x0148,
		.plat_id_len = 0x0008,
		.plat_id_str = PCD_V1_PLATFORM_ID,
		.plat_id_str_len = sizeof (PCD_V1_PLATFORM_ID) - 1,
		.plat_id_str_pad = 0,
		.plat_id_offset = 0x0148,
		.plat_id_entry = 0,
		.plat_id_hash = 0
	},
	.rot_len = 0x0008,
	.rot_offset = 0x0184,
	.rot_entry = 4,
	.rot_hash = 4,
	.power_ctrl_len = 0x000c,
	.power_ctrl_offset = 0x0150,
	.power_ctrl_entry = 1,
	.power_ctrl_hash = 1,
	.bridge_component_len = 0x0014,
	.bridge_component_offset = 0x0170,
	.bridge_component_entry = 3,
	.bridge_component_hash = 3,
	.direct_component_len = 0x0014,
	.direct_component_offset = 0x015c,
	.direct_component_entry = 2,
	.direct_component_hash = 2,
	.port_len = 0x0008,
	.port_offset = 0x018c,
	.port_entry = 5,
	.port_hash = 5,
	.num_optional_elements = 5,
};

/**
 * PCD with ID 0x1A for testing.
 *
 * PCD file: pcd.xml
 *
 * python3 pcd_generator.py pcd_generator.config
 * to_array.sh <output pcd bin>
 */
const uint8_t PCD_DATA[] = {
	0xb8, 0x02, 0x29, 0x10, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x07, 0x07, 0x00, 0x00,
	0x00, 0xff, 0x01, 0x00, 0x48, 0x01, 0x08, 0x00, 0x42, 0xff, 0x01, 0x01, 0x50, 0x01, 0x0c, 0x00,
	0x43, 0xff, 0x02, 0x02, 0x5c, 0x01, 0x10, 0x00, 0x44, 0xff, 0x02, 0x03, 0x6c, 0x01, 0x14, 0x00,
	0x40, 0xff, 0x02, 0x04, 0x80, 0x01, 0x28, 0x00, 0x41, 0x40, 0x01, 0x05, 0xa8, 0x01, 0x08, 0x00,
	0x41, 0x40, 0x01, 0x06, 0xb0, 0x01, 0x08, 0x00, 0x13, 0xe9, 0x1c, 0x16, 0x0e, 0xcf, 0xd2, 0xbb,
	0x3a, 0x86, 0x83, 0xb6, 0x01, 0xc4, 0xba, 0xcb, 0x04, 0xf0, 0xa5, 0x18, 0x9b, 0x97, 0xd9, 0x2d,
	0x67, 0xf4, 0x6d, 0x69, 0xea, 0x1e, 0x25, 0x36, 0x4d, 0x9a, 0x65, 0x85, 0x38, 0xe7, 0x61, 0xba,
	0xbb, 0xb3, 0xdc, 0x6a, 0x01, 0x3f, 0xb4, 0x11, 0x77, 0x16, 0x30, 0x68, 0x93, 0x9c, 0xc5, 0x89,
	0xf1, 0xd1, 0x9a, 0x66, 0xab, 0xc9, 0x09, 0x7f, 0x18, 0x72, 0x54, 0x75, 0xd8, 0xc5, 0x2b, 0xa3,
	0xa3, 0x39, 0x56, 0x0c, 0xb8, 0x74, 0x5e, 0x0f, 0xfc, 0x5a, 0x81, 0xa7, 0x4e, 0x0e, 0x12, 0x6b,
	0x16, 0x5a, 0x34, 0xcf, 0xd8, 0x55, 0x76, 0xcb, 0x2f, 0x93, 0x32, 0xcb, 0xf8, 0x59, 0xaa, 0xe2,
	0xce, 0xc4, 0x66, 0x1b, 0xf7, 0x2b, 0x10, 0xd4, 0xe7, 0x3f, 0xf4, 0x4f, 0x97, 0x2a, 0x1c, 0xc0,
	0x4d, 0x5b, 0xe2, 0x2f, 0x07, 0xb5, 0xdd, 0x76, 0xd2, 0xfd, 0x90, 0x9a, 0x37, 0x65, 0x98, 0xa2,
	0x5e, 0x96, 0x8f, 0x3f, 0x0d, 0x35, 0x45, 0x64, 0x5a, 0x9e, 0x1b, 0xee, 0x79, 0xf0, 0xd1, 0x44,
	0xd3, 0x39, 0x78, 0xe0, 0x6b, 0xb3, 0x06, 0x91, 0x40, 0x70, 0x82, 0x5f, 0x31, 0x32, 0x8b, 0xb4,
	0xc1, 0x45, 0x5e, 0x9f, 0x9d, 0x37, 0x2a, 0x83, 0xf0, 0x22, 0x12, 0x84, 0x05, 0x1a, 0xf9, 0xc4,
	0xb2, 0xd1, 0x41, 0x9d, 0xf4, 0x0b, 0x12, 0x2e, 0x1a, 0x12, 0xc0, 0x2d, 0x58, 0x70, 0x5e, 0x4c,
	0xc1, 0x0a, 0x6f, 0xff, 0x25, 0x23, 0x1b, 0x60, 0x26, 0x11, 0x30, 0xc1, 0x83, 0xf3, 0x08, 0x24,
	0xdb, 0x1b, 0x97, 0x6a, 0xcd, 0xc5, 0xde, 0xa5, 0x04, 0x88, 0x0b, 0x83, 0x9b, 0x2a, 0x23, 0x93,
	0x0f, 0xd4, 0xb8, 0xf8, 0xeb, 0x26, 0x6a, 0x2c, 0x04, 0x42, 0x5b, 0x73, 0x34, 0xe6, 0x0c, 0x77,
	0x46, 0xdf, 0x0d, 0xbf, 0x83, 0x49, 0xff, 0x18, 0x04, 0x00, 0x00, 0x00, 0x53, 0x4b, 0x55, 0x31,
	0x02, 0x02, 0x22, 0x14, 0x66, 0x07, 0x00, 0x00, 0x45, 0x04, 0x00, 0x00, 0x00, 0x50, 0xe0, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x75, 0x77, 0x55, 0x03, 0x00, 0x00, 0x00, 0x70, 0xf0, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x0b, 0x00, 0x0c, 0x00, 0x0d, 0x00, 0x02, 0x30, 0x00, 0x00,
	0x00, 0x02, 0x02, 0x41, 0x0b, 0x10, 0x0a, 0x00, 0x00, 0x5c, 0x26, 0x05, 0x10, 0x27, 0x00, 0x00,
	0x10, 0x27, 0x00, 0x00, 0xd0, 0x07, 0x00, 0x00, 0xb8, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xe8, 0x03, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x71, 0x00, 0x00, 0x00, 0x48, 0xe8, 0x01,
	0x01, 0x04, 0x01, 0x0a, 0x00, 0x90, 0xd0, 0x03, 0x79, 0xfa, 0xf8, 0x0c, 0x6d, 0x67, 0x47, 0xb4,
	0x74, 0x8d, 0xf4, 0xf2, 0x32, 0x36, 0x41, 0x26, 0x8b, 0xa6, 0xd2, 0x36, 0xa6, 0xa2, 0x33, 0xfa,
	0x5f, 0x2f, 0x84, 0x18, 0x56, 0x4e, 0x12, 0x43, 0xb8, 0xb4, 0xf0, 0x5c, 0x88, 0xe3, 0x58, 0xdd,
	0x34, 0x93, 0x07, 0xe9, 0x31, 0xa5, 0x70, 0x2a, 0x71, 0x71, 0x7c, 0xc6, 0xa4, 0x62, 0xf7, 0x89,
	0x69, 0xb6, 0xe9, 0x5a, 0xe5, 0xb6, 0x35, 0x57, 0x67, 0xb6, 0xc7, 0x6b, 0x6e, 0x76, 0xd8, 0x0e,
	0x0f, 0xd7, 0xa9, 0xea, 0xe7, 0xf3, 0x09, 0x8d, 0xeb, 0x9e, 0x2e, 0x8c, 0xbe, 0xae, 0xef, 0xc9,
	0x93, 0x98, 0x73, 0x3b, 0x5c, 0x67, 0x6c, 0xa7, 0xa0, 0x55, 0x9a, 0xbb, 0x0d, 0x50, 0xc7, 0x2a,
	0xe7, 0x20, 0xd5, 0x80, 0xb3, 0x80, 0xd8, 0xdf, 0x53, 0x11, 0xc0, 0x6e, 0x96, 0xb8, 0x76, 0x74,
	0x81, 0xcc, 0x0b, 0x00, 0x10, 0xd7, 0x0c, 0xdd, 0x5b, 0x35, 0x93, 0x14, 0x42, 0xbe, 0xae, 0xbe,
	0xc1, 0x41, 0xb9, 0x0c, 0x0a, 0xa7, 0x3d, 0x69, 0x98, 0x22, 0x95, 0x71, 0xd5, 0xd8, 0xbc, 0x14,
	0xd1, 0x24, 0x56, 0x4e, 0xdc, 0xc2, 0xf9, 0x4c, 0x3e, 0xb7, 0xfb, 0xad, 0x2a, 0x10, 0x0f, 0x3d,
	0xc6, 0xb4, 0x21, 0x7d, 0xb2, 0x30, 0x22, 0x14, 0x0c, 0x65, 0x55, 0x64, 0x3b, 0x6b, 0x14, 0x2b,
	0x24, 0x0a, 0x13, 0xd9, 0x12, 0xf3, 0x49, 0x99, 0xd1, 0xd7, 0xfd, 0x0b, 0x6b, 0x77, 0xf3, 0x4e,
	0x04, 0x4d, 0xf6, 0x8c, 0xdb, 0x99, 0x03, 0x5c, 0x77, 0x33, 0x26, 0xce, 0x77, 0x51, 0x66, 0xd4,
	0xa0, 0x56, 0x86, 0xb9, 0x9b, 0x5d, 0x32, 0xed, 0xb7, 0xe6, 0xf0, 0x4e, 0x59, 0xa9, 0x76, 0x87,
	0x6b, 0x60, 0xcd, 0x46, 0xda, 0xc2, 0x71, 0x08, 0xcb, 0x39, 0xeb, 0xda, 0x4a, 0x4f, 0x6f, 0xb5,
	0xbe, 0xa2, 0x86, 0x24, 0x28, 0xff, 0x4a, 0xba
};

/**
 * Length of the testing PCD.
 */
const uint32_t PCD_DATA_LEN = sizeof (PCD_DATA);

/**
 * PCD_DATA hash for testing.
 *
 * head -c -256 <file> | openssl dgst -sha256 -binary | to_array.sh -
 */
const uint8_t PCD_HASH[] = {
	0xd3, 0x4b, 0x00, 0xb2, 0x9a, 0xaa, 0xb7, 0xa1, 0x0d, 0x3c, 0xd1, 0x28, 0x2c, 0x86, 0x77, 0x32,
	0x6a, 0x85, 0xb1, 0x53, 0xd4, 0x34, 0x48, 0x7a, 0xf2, 0xe3, 0x90, 0x78, 0x3f, 0xd7, 0x40, 0xa0
};

/**
 * The platform ID for the PCD.
 */
const char PCD_PLATFORM_ID[] = "SKU1";

/**
 * Components of the test PCD.
 */
const struct pcd_testing_data PCD_TESTING = {
	.manifest = {
		.raw = PCD_DATA,
		.length = sizeof (PCD_DATA),
		.hash = PCD_HASH,
		.hash_len = sizeof (PCD_HASH),
		.id = 0x1a,
		.signature = PCD_DATA + (sizeof (PCD_DATA) - 256),
		.sig_len = 256,
		.sig_offset = (sizeof (PCD_DATA) - 256),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = PCD_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x013c,
		.toc_hash = PCD_DATA + 0x0128,
		.toc_hash_len = 32,
		.toc_hash_offset = 0x0128,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 7,
		.toc_hashes = 7,
		.plat_id = PCD_DATA + 0x0148,
		.plat_id_len = 0x0008,
		.plat_id_str = PCD_PLATFORM_ID,
		.plat_id_str_len = sizeof (PCD_PLATFORM_ID) - 1,
		.plat_id_str_pad = 0,
		.plat_id_offset = 0x0148,
		.plat_id_entry = 0,
		.plat_id_hash = 0
	},
	.rot_len = 0x0028,
	.rot_offset = 0x0180,
	.rot_entry = 4,
	.rot_hash = 4,
	.power_ctrl_len = 0x000c,
	.power_ctrl_offset = 0x0150,
	.power_ctrl_entry = 1,
	.power_ctrl_hash = 1,
	.bridge_component_len = 0x0014,
	.bridge_component_offset = 0x016c,
	.bridge_component_entry = 3,
	.bridge_component_hash = 3,
	.direct_component_len = 0x0010,
	.direct_component_offset = 0x015c,
	.direct_component_entry = 2,
	.direct_component_hash = 2,
	.port_len = 0x0008,
	.port_offset = 0x01a8,
	.port_entry = 5,
	.port_hash = 5,
	.num_optional_elements = 5,
};

/**
 * PCD with ID 0x1B, platform ID SKU1-Specific for testing.
 *
 * PCD file: pcd_sku_specific.xml
 *
 * python3 pcd_generator.py pcd_generator.config
 * to_array.sh <output pcd bin>
 */
const uint8_t PCD_SKU_SPECIFIC_DATA[] = {
	0xc4, 0x02, 0x29, 0x10, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x07, 0x07, 0x00, 0x00,
	0x00, 0xff, 0x01, 0x00, 0x48, 0x01, 0x14, 0x00, 0x42, 0xff, 0x01, 0x01, 0x5c, 0x01, 0x0c, 0x00,
	0x43, 0xff, 0x01, 0x02, 0x68, 0x01, 0x10, 0x00, 0x44, 0xff, 0x01, 0x03, 0x78, 0x01, 0x14, 0x00,
	0x40, 0xff, 0x01, 0x04, 0x8c, 0x01, 0x28, 0x00, 0x41, 0x40, 0x01, 0x05, 0xb4, 0x01, 0x08, 0x00,
	0x41, 0x40, 0x01, 0x06, 0xbc, 0x01, 0x08, 0x00, 0xe4, 0xc5, 0x49, 0x98, 0xd4, 0x44, 0xf5, 0xcd,
	0x14, 0x74, 0x83, 0xe3, 0xb0, 0x2c, 0x87, 0xf0, 0xf9, 0x54, 0xaf, 0x79, 0xa1, 0xa0, 0x6e, 0xad,
	0xe1, 0x57, 0xfb, 0xfb, 0xd8, 0xd0, 0xdb, 0xba, 0x4d, 0x9a, 0x65, 0x85, 0x38, 0xe7, 0x61, 0xba,
	0xbb, 0xb3, 0xdc, 0x6a, 0x01, 0x3f, 0xb4, 0x11, 0x77, 0x16, 0x30, 0x68, 0x93, 0x9c, 0xc5, 0x89,
	0xf1, 0xd1, 0x9a, 0x66, 0xab, 0xc9, 0x09, 0x7f, 0x18, 0x72, 0x54, 0x75, 0xd8, 0xc5, 0x2b, 0xa3,
	0xa3, 0x39, 0x56, 0x0c, 0xb8, 0x74, 0x5e, 0x0f, 0xfc, 0x5a, 0x81, 0xa7, 0x4e, 0x0e, 0x12, 0x6b,
	0x16, 0x5a, 0x34, 0xcf, 0xd8, 0x55, 0x76, 0xcb, 0x2f, 0x93, 0x32, 0xcb, 0xf8, 0x59, 0xaa, 0xe2,
	0xce, 0xc4, 0x66, 0x1b, 0xf7, 0x2b, 0x10, 0xd4, 0xe7, 0x3f, 0xf4, 0x4f, 0x97, 0x2a, 0x1c, 0xc0,
	0x4d, 0x5b, 0xe2, 0x2f, 0x07, 0xb5, 0xdd, 0x76, 0xd2, 0xfd, 0x90, 0x9a, 0x37, 0x65, 0x98, 0xa2,
	0x5e, 0x96, 0x8f, 0x3f, 0x0d, 0x35, 0x45, 0x64, 0x5a, 0x9e, 0x1b, 0xee, 0x79, 0xf0, 0xd1, 0x44,
	0xd3, 0x39, 0x78, 0xe0, 0x6b, 0xb3, 0x06, 0x91, 0xd8, 0xa8, 0xa9, 0xa2, 0x83, 0xe3, 0x96, 0x44,
	0x4f, 0xe0, 0x88, 0x64, 0x32, 0x82, 0xd2, 0x36, 0xd9, 0xac, 0x81, 0x15, 0x30, 0x9d, 0x10, 0x51,
	0xc9, 0x73, 0x14, 0xa7, 0xc1, 0x85, 0xeb, 0x2b, 0x1a, 0x12, 0xc0, 0x2d, 0x58, 0x70, 0x5e, 0x4c,
	0xc1, 0x0a, 0x6f, 0xff, 0x25, 0x23, 0x1b, 0x60, 0x26, 0x11, 0x30, 0xc1, 0x83, 0xf3, 0x08, 0x24,
	0xdb, 0x1b, 0x97, 0x6a, 0xcd, 0xc5, 0xde, 0xa5, 0x2e, 0x7a, 0xba, 0x90, 0xdf, 0x1b, 0x63, 0xd2,
	0x03, 0x73, 0x99, 0x8f, 0x00, 0x96, 0xd6, 0x17, 0x8c, 0x94, 0xac, 0x3e, 0x32, 0x5b, 0x50, 0xd4,
	0x9a, 0x2a, 0xf6, 0x25, 0x27, 0xa7, 0x3d, 0x39, 0x0d, 0x00, 0x00, 0x00, 0x53, 0x4b, 0x55, 0x31,
	0x2d, 0x53, 0x70, 0x65, 0x63, 0x69, 0x66, 0x69, 0x63, 0x00, 0x00, 0x00, 0x02, 0x02, 0x22, 0x14,
	0x66, 0x07, 0x00, 0x00, 0x45, 0x04, 0x00, 0x00, 0x00, 0x50, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x03, 0x75, 0x77, 0x55, 0x03, 0x00, 0x00, 0x00, 0x70, 0xf0, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x0a, 0x00, 0x0b, 0x00, 0x0c, 0x00, 0x0d, 0x00, 0x02, 0x30, 0x00, 0x00, 0x00, 0x02, 0x02, 0x41,
	0x0b, 0x10, 0x0a, 0x00, 0x00, 0x5c, 0x26, 0x05, 0x10, 0x27, 0x00, 0x00, 0x10, 0x27, 0x00, 0x00,
	0xd0, 0x07, 0x00, 0x00, 0xb8, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe8, 0x03, 0x00, 0x00,
	0x03, 0x00, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 0x48, 0xe8, 0x01, 0x01, 0x04, 0x01, 0x0a,
	0x00, 0x90, 0xd0, 0x03, 0x74, 0xf5, 0xb2, 0x3e, 0x69, 0xb7, 0xa1, 0x84, 0x60, 0x6e, 0x84, 0x22,
	0xb9, 0xd3, 0xe9, 0x1d, 0xf4, 0xfb, 0xbd, 0x47, 0xc0, 0x86, 0xda, 0x0a, 0x84, 0xb3, 0x3a, 0x91,
	0x0d, 0x0c, 0x6b, 0xb9, 0xf8, 0xdc, 0x0b, 0xa3, 0xc5, 0xd8, 0xe7, 0xea, 0xa7, 0x68, 0xcb, 0x35,
	0x97, 0xd3, 0xe3, 0xcd, 0x72, 0x01, 0x6c, 0xd1, 0x62, 0x61, 0x27, 0xa4, 0xd7, 0x27, 0xe3, 0x06,
	0xc6, 0xbd, 0xc7, 0xad, 0x74, 0x81, 0xaf, 0xe6, 0x47, 0xdd, 0xec, 0x17, 0x9c, 0x02, 0x56, 0x04,
	0x33, 0xbf, 0x3e, 0x44, 0xea, 0x0a, 0xf9, 0x39, 0xc1, 0xf6, 0x03, 0x17, 0x8f, 0xe2, 0x04, 0x6c,
	0xcc, 0xde, 0x72, 0xfb, 0x76, 0xe4, 0x03, 0x24, 0xf3, 0xca, 0xfa, 0xce, 0xb1, 0xe9, 0x08, 0xd5,
	0xeb, 0x41, 0x68, 0x02, 0x1b, 0x68, 0x74, 0xe5, 0xcc, 0xef, 0x35, 0xe3, 0x3a, 0x19, 0x08, 0xba,
	0x8d, 0x6c, 0x20, 0xdb, 0x69, 0x8d, 0x71, 0x51, 0x6e, 0xe8, 0x53, 0x8e, 0x72, 0x30, 0xa1, 0x6e,
	0xe5, 0x32, 0x37, 0x81, 0x22, 0xd1, 0x4e, 0x7d, 0xfb, 0xec, 0x91, 0x13, 0x73, 0x51, 0xe0, 0xec,
	0xdb, 0x6e, 0x72, 0xd8, 0xc2, 0x65, 0xaf, 0x4f, 0x33, 0x05, 0xc5, 0x99, 0x26, 0x8b, 0xbb, 0xfa,
	0x47, 0x53, 0xd7, 0xc0, 0x87, 0x8a, 0xc1, 0x0a, 0xaa, 0xda, 0xfa, 0xed, 0x64, 0x01, 0x7d, 0xb7,
	0x0d, 0x2b, 0x5e, 0x31, 0x14, 0x1a, 0x43, 0x3c, 0x0a, 0xd0, 0x47, 0x4e, 0x9c, 0x02, 0x76, 0x43,
	0x97, 0xab, 0xae, 0x56, 0xb0, 0xc0, 0x3e, 0xb0, 0xbb, 0x93, 0x16, 0x83, 0x31, 0x78, 0x85, 0xcb,
	0x38, 0x47, 0x48, 0xd3, 0xde, 0x32, 0x32, 0xbf, 0xc9, 0x7d, 0xa9, 0x55, 0xab, 0xc4, 0x39, 0xdb,
	0xc0, 0xdd, 0xbb, 0x44, 0x9e, 0xd7, 0x8c, 0xc5, 0x01, 0xae, 0x58, 0x23, 0x5c, 0x54, 0xaf, 0x38,
	0xcb, 0xdd, 0xfc, 0xba
};

/**
 * Length of the testing PCD.
 */
const uint32_t PCD_SKU_SPECIFIC_DATA_LEN = sizeof (PCD_SKU_SPECIFIC_DATA);

/**
 * PCD_SKU_SPECIFIC_DATA hash for testing.
 *
 * head -c -256 <file> | openssl dgst -sha256 -binary | to_array.sh -
 */
const uint8_t PCD_SKU_SPECIFIC_HASH[] = {
	0x44, 0x37, 0xa4, 0x08, 0x89, 0xc1, 0xcf, 0x0c, 0x8c, 0x86, 0x4b, 0x2a, 0xdb, 0x02, 0x9c, 0x07,
	0x93, 0xdd, 0xb1, 0x4e, 0xa3, 0x26, 0xa2, 0xa3, 0xb6, 0x31, 0xbf, 0xfe, 0xdf, 0x90, 0xb0, 0x17
};


/**
 * The platform ID for the PCD.
 */
const char PCD_SKU_SPECIFIC_PLATFORM_ID[] = "SKU1-Specific";

/**
 * Components of the test PCD.
 */
const struct pcd_testing_data PCD_SKU_SPECIFIC_TESTING = {
	.manifest = {
		.raw = PCD_SKU_SPECIFIC_DATA,
		.length = sizeof (PCD_SKU_SPECIFIC_DATA),
		.hash = PCD_SKU_SPECIFIC_HASH,
		.hash_len = sizeof (PCD_SKU_SPECIFIC_HASH),
		.id = 0x1b,
		.signature = PCD_SKU_SPECIFIC_DATA + (sizeof (PCD_SKU_SPECIFIC_DATA) - 256),
		.sig_len = 256,
		.sig_offset = (sizeof (PCD_SKU_SPECIFIC_DATA) - 256),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = PCD_SKU_SPECIFIC_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x013c,
		.toc_hash = PCD_SKU_SPECIFIC_DATA + 0x0128,
		.toc_hash_len = 32,
		.toc_hash_offset = 0x0128,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 7,
		.toc_hashes = 7,
		.plat_id = PCD_SKU_SPECIFIC_DATA + 0x0148,
		.plat_id_len = 0x0014,
		.plat_id_str = PCD_SKU_SPECIFIC_PLATFORM_ID,
		.plat_id_str_len = sizeof (PCD_SKU_SPECIFIC_PLATFORM_ID) - 1,
		.plat_id_str_pad = 0,
		.plat_id_offset = 0x0148,
		.plat_id_entry = 0,
		.plat_id_hash = 0
	},
	.rot_len = 0x0028,
	.rot_offset = 0x018c,
	.rot_entry = 4,
	.rot_hash = 4,
	.power_ctrl_len = 0x000c,
	.power_ctrl_offset = 0x015c,
	.power_ctrl_entry = 1,
	.power_ctrl_hash = 1,
	.bridge_component_len = 0x0014,
	.bridge_component_offset = 0x0178,
	.bridge_component_entry = 3,
	.bridge_component_hash = 3,
	.direct_component_len = 0x0010,
	.direct_component_offset = 0x0168,
	.direct_component_entry = 2,
	.direct_component_hash = 2,
	.port_len = 0x0008,
	.port_offset = 0x01b4,
	.port_entry = 5,
	.port_hash = 5,
	.num_optional_elements = 5,
};

/**
 * PCD with no POWER_CONTROLLER for testing.
 *
 * PCD file: pcd_no_power_controller.xml
 *
 * python3 pcd_generator.py pcd_generator.config
 * to_array.sh <output pcd bin>
 */
const uint8_t PCD_NO_POWER_CONTROLLER_DATA[] = {
	0x84, 0x02, 0x29, 0x10, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x06, 0x06, 0x00, 0x00,
	0x00, 0xff, 0x01, 0x00, 0x20, 0x01, 0x08, 0x00, 0x43, 0xff, 0x01, 0x01, 0x28, 0x01, 0x10, 0x00,
	0x44, 0xff, 0x01, 0x02, 0x38, 0x01, 0x14, 0x00, 0x40, 0xff, 0x01, 0x03, 0x4c, 0x01, 0x28, 0x00,
	0x41, 0x40, 0x01, 0x04, 0x74, 0x01, 0x08, 0x00, 0x41, 0x40, 0x01, 0x05, 0x7c, 0x01, 0x08, 0x00,
	0x13, 0xe9, 0x1c, 0x16, 0x0e, 0xcf, 0xd2, 0xbb, 0x3a, 0x86, 0x83, 0xb6, 0x01, 0xc4, 0xba, 0xcb,
	0x04, 0xf0, 0xa5, 0x18, 0x9b, 0x97, 0xd9, 0x2d, 0x67, 0xf4, 0x6d, 0x69, 0xea, 0x1e, 0x25, 0x36,
	0x18, 0x72, 0x54, 0x75, 0xd8, 0xc5, 0x2b, 0xa3, 0xa3, 0x39, 0x56, 0x0c, 0xb8, 0x74, 0x5e, 0x0f,
	0xfc, 0x5a, 0x81, 0xa7, 0x4e, 0x0e, 0x12, 0x6b, 0x16, 0x5a, 0x34, 0xcf, 0xd8, 0x55, 0x76, 0xcb,
	0x2f, 0x93, 0x32, 0xcb, 0xf8, 0x59, 0xaa, 0xe2, 0xce, 0xc4, 0x66, 0x1b, 0xf7, 0x2b, 0x10, 0xd4,
	0xe7, 0x3f, 0xf4, 0x4f, 0x97, 0x2a, 0x1c, 0xc0, 0x4d, 0x5b, 0xe2, 0x2f, 0x07, 0xb5, 0xdd, 0x76,
	0xd2, 0xfd, 0x90, 0x9a, 0x37, 0x65, 0x98, 0xa2, 0x5e, 0x96, 0x8f, 0x3f, 0x0d, 0x35, 0x45, 0x64,
	0x5a, 0x9e, 0x1b, 0xee, 0x79, 0xf0, 0xd1, 0x44, 0xd3, 0x39, 0x78, 0xe0, 0x6b, 0xb3, 0x06, 0x91,
	0xd8, 0xa8, 0xa9, 0xa2, 0x83, 0xe3, 0x96, 0x44, 0x4f, 0xe0, 0x88, 0x64, 0x32, 0x82, 0xd2, 0x36,
	0xd9, 0xac, 0x81, 0x15, 0x30, 0x9d, 0x10, 0x51, 0xc9, 0x73, 0x14, 0xa7, 0xc1, 0x85, 0xeb, 0x2b,
	0x1a, 0x12, 0xc0, 0x2d, 0x58, 0x70, 0x5e, 0x4c, 0xc1, 0x0a, 0x6f, 0xff, 0x25, 0x23, 0x1b, 0x60,
	0x26, 0x11, 0x30, 0xc1, 0x83, 0xf3, 0x08, 0x24, 0xdb, 0x1b, 0x97, 0x6a, 0xcd, 0xc5, 0xde, 0xa5,
	0x6d, 0xcb, 0x29, 0x29, 0x81, 0xa6, 0x4e, 0xf7, 0xd4, 0xc4, 0x2f, 0xbe, 0x86, 0x90, 0x7e, 0xd7,
	0x68, 0x82, 0x6d, 0x53, 0x8f, 0x35, 0xba, 0x27, 0x46, 0x2a, 0xf1, 0xdf, 0x5f, 0xf9, 0x08, 0x30,
	0x04, 0x00, 0x00, 0x00, 0x53, 0x4b, 0x55, 0x31, 0x00, 0x50, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x03, 0x75, 0x77, 0x55, 0x03, 0x00, 0x00, 0x00, 0x70, 0xf0, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x0a, 0x00, 0x0b, 0x00, 0x0c, 0x00, 0x0d, 0x00, 0x02, 0x30, 0x00, 0x00, 0x00, 0x02, 0x02, 0x41,
	0x0b, 0x10, 0x0a, 0x00, 0x00, 0x5c, 0x26, 0x05, 0x10, 0x27, 0x00, 0x00, 0x10, 0x27, 0x00, 0x00,
	0xd0, 0x07, 0x00, 0x00, 0xb8, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe8, 0x03, 0x00, 0x00,
	0x03, 0x00, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 0x48, 0xe8, 0x01, 0x01, 0x04, 0x01, 0x0a,
	0x00, 0x90, 0xd0, 0x03, 0xa6, 0x07, 0x57, 0x6b, 0x6c, 0x7f, 0xbc, 0xad, 0xfd, 0xc4, 0xa2, 0x1d,
	0x92, 0x12, 0x91, 0x5d, 0x0c, 0x04, 0x28, 0xa4, 0x54, 0x6b, 0xf5, 0x9b, 0xbb, 0x15, 0x8f, 0x5d,
	0xd3, 0x82, 0x82, 0x39, 0xf7, 0xe8, 0x65, 0x22, 0xec, 0x11, 0x6d, 0xd8, 0xa4, 0x01, 0x1a, 0x71,
	0x75, 0xc8, 0x7a, 0x2f, 0x97, 0xc0, 0xe7, 0x0a, 0x58, 0xa8, 0x29, 0x61, 0x6d, 0x6d, 0x73, 0x4d,
	0xdd, 0x51, 0x50, 0x50, 0x24, 0x4c, 0x1a, 0x05, 0x3c, 0x70, 0xa4, 0x13, 0x39, 0xa4, 0x9f, 0xac,
	0xbe, 0x2e, 0x89, 0x3e, 0x55, 0x58, 0x75, 0xb4, 0x99, 0x2f, 0xba, 0x16, 0xc1, 0x83, 0xb9, 0xff,
	0x16, 0x5c, 0x8e, 0xd9, 0x0f, 0xb5, 0xb7, 0x55, 0xf8, 0x33, 0x11, 0xa8, 0xc7, 0x85, 0x21, 0x77,
	0x2f, 0xe0, 0x00, 0x5c, 0x25, 0xee, 0x51, 0xab, 0x2b, 0x5f, 0x92, 0x33, 0xea, 0x75, 0xf0, 0x0f,
	0x59, 0xb7, 0xcf, 0x12, 0xef, 0xb1, 0xad, 0x3c, 0x2e, 0x9e, 0x0d, 0x0b, 0x21, 0x7a, 0x9a, 0xf7,
	0xae, 0x0c, 0x92, 0x73, 0xa5, 0x94, 0x31, 0x76, 0xc9, 0x9c, 0x41, 0x65, 0x9c, 0x6c, 0x8b, 0x23,
	0x28, 0x2a, 0x11, 0x9d, 0x28, 0x1b, 0xe9, 0x89, 0xb3, 0x3b, 0x80, 0xf4, 0xbe, 0x97, 0xc4, 0xec,
	0x2a, 0x80, 0x02, 0x06, 0xb8, 0x0e, 0xd1, 0x09, 0xcb, 0x02, 0xdd, 0xa5, 0xd5, 0x0e, 0x7d, 0xfa,
	0xa4, 0xe4, 0xf9, 0x12, 0x26, 0x23, 0x47, 0x52, 0xe1, 0x02, 0x64, 0x91, 0xf5, 0x24, 0x1a, 0x08,
	0xb4, 0xcb, 0x4e, 0xc8, 0xe9, 0x31, 0x03, 0xa6, 0x2c, 0xaf, 0xea, 0xf7, 0x3a, 0x6d, 0x3e, 0x12,
	0x69, 0xa9, 0x6e, 0x51, 0x90, 0x4a, 0xc9, 0x32, 0x3b, 0x27, 0x1b, 0x81, 0xff, 0x2c, 0xa8, 0x51,
	0x96, 0xa2, 0xdb, 0x20, 0x8d, 0xec, 0x28, 0x18, 0xaa, 0xc0, 0x2e, 0x65, 0xb7, 0xe4, 0x84, 0x22,
	0xbd, 0x3f, 0x7d, 0x31
};

/**
 * Length of the testing PCD with no power controller.
 */
const uint32_t PCD_NO_POWER_CONTROLLER_DATA_LEN = sizeof (PCD_NO_POWER_CONTROLLER_DATA);

/**
 * PCD_NO_POWER_CONTROLLER_DATA hash for testing.
 *
 * head -c -256 <file> | openssl dgst -sha256 -binary | to_array.sh -
 */
const uint8_t PCD_NO_POWER_CONTROLLER_HASH[] = {
	0xe3, 0x4b, 0x6d, 0x40, 0x0b, 0x84, 0x9e, 0x65, 0xd3, 0xf7, 0xc4, 0x5a, 0x3c, 0xc1, 0xda, 0x8e,
	0x7f, 0x96, 0xdd, 0xa9, 0x48, 0xd1, 0xeb, 0x02, 0x27, 0xdd, 0x17, 0x63, 0xcc, 0xb7, 0x45, 0x26
};

/**
 * The platform ID for the PCD with no power controller.
 */
const char PCD_NO_POWER_CONTROLLER_PLATFORM_ID[] = "SKU1";

/**
 * Components of the no power controller PCD.
 */
static struct pcd_testing_data PCD_NO_POWER_CONTROLLER_TESTING = {
	.manifest = {
		.raw = PCD_NO_POWER_CONTROLLER_DATA,
		.length = sizeof (PCD_NO_POWER_CONTROLLER_DATA),
		.hash = PCD_NO_POWER_CONTROLLER_HASH,
		.hash_len = sizeof (PCD_NO_POWER_CONTROLLER_HASH),
		.id = 0x1a,
		.signature = PCD_NO_POWER_CONTROLLER_DATA + (sizeof (PCD_NO_POWER_CONTROLLER_DATA) - 256),
		.sig_len = 256,
		.sig_offset = (sizeof (PCD_NO_POWER_CONTROLLER_DATA) - 256),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = PCD_NO_POWER_CONTROLLER_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x0114,
		.toc_hash = PCD_NO_POWER_CONTROLLER_DATA + 0x0100,
		.toc_hash_len = 32,
		.toc_hash_offset = 0x0100,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 6,
		.toc_hashes = 6,
		.plat_id = PCD_NO_POWER_CONTROLLER_DATA + 0x0120,
		.plat_id_len = 0x0008,
		.plat_id_str = PCD_NO_POWER_CONTROLLER_PLATFORM_ID,
		.plat_id_str_len = sizeof (PCD_NO_POWER_CONTROLLER_PLATFORM_ID) - 1,
		.plat_id_str_pad = 0,
		.plat_id_offset = 0x0120,
		.plat_id_entry = 0,
		.plat_id_hash = 0
	},
	.rot_len = 0x0028,
	.rot_offset = 0x014c,
	.rot_entry = 3,
	.rot_hash = 3,
	.power_ctrl_len = 0,
	.power_ctrl_offset = 0,
	.power_ctrl_entry = -1,
	.power_ctrl_hash = -1,
	.bridge_component_len = 0x0014,
	.bridge_component_offset = 0x0138,
	.bridge_component_entry = 2,
	.bridge_component_hash = 2,
	.direct_component_len = 0x0010,
	.direct_component_offset = 0x0128,
	.direct_component_entry = 1,
	.direct_component_hash = 1,
	.port_len = 0x0008,
	.port_offset = 0x0174,
	.port_entry = 4,
	.port_hash = 4,
	.num_optional_elements = 4,
};

/**
 * PCD with no components and platform ID SKU2 for testing.
 *
 * PCD file: pcd_no_components.xml
 *
 * python3 pcd_generator.py pcd_generator.config
 * to_array.sh <output pcd bin>
 */
const uint8_t PCD_NO_COMPONENTS_DATA[] = {
	0x44, 0x02, 0x29, 0x10, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x05, 0x05, 0x00, 0x00,
	0x00, 0xff, 0x01, 0x00, 0xf8, 0x00, 0x08, 0x00, 0x42, 0xff, 0x01, 0x01, 0x00, 0x01, 0x0c, 0x00,
	0x40, 0xff, 0x01, 0x02, 0x0c, 0x01, 0x28, 0x00, 0x41, 0x40, 0x01, 0x03, 0x34, 0x01, 0x08, 0x00,
	0x41, 0x40, 0x01, 0x04, 0x3c, 0x01, 0x08, 0x00, 0x64, 0x40, 0x93, 0x61, 0xef, 0x95, 0x6e, 0xd9,
	0x47, 0xd0, 0x56, 0x1d, 0x4c, 0x48, 0x57, 0x8e, 0x26, 0xd4, 0x7a, 0xb2, 0x4c, 0x77, 0x20, 0x1b,
	0x2b, 0x8f, 0x67, 0x27, 0x87, 0xad, 0xf1, 0x0d, 0x4d, 0x9a, 0x65, 0x85, 0x38, 0xe7, 0x61, 0xba,
	0xbb, 0xb3, 0xdc, 0x6a, 0x01, 0x3f, 0xb4, 0x11, 0x77, 0x16, 0x30, 0x68, 0x93, 0x9c, 0xc5, 0x89,
	0xf1, 0xd1, 0x9a, 0x66, 0xab, 0xc9, 0x09, 0x7f, 0x7e, 0xed, 0x23, 0x1b, 0x26, 0x70, 0x21, 0x22,
	0x01, 0x8e, 0x38, 0xca, 0xac, 0x68, 0x86, 0x8d, 0x66, 0x73, 0x82, 0xd3, 0xd1, 0x56, 0x4b, 0x67,
	0x5b, 0x02, 0xe3, 0x1a, 0x59, 0x8a, 0x36, 0x4f, 0xd8, 0xa8, 0xa9, 0xa2, 0x83, 0xe3, 0x96, 0x44,
	0x4f, 0xe0, 0x88, 0x64, 0x32, 0x82, 0xd2, 0x36, 0xd9, 0xac, 0x81, 0x15, 0x30, 0x9d, 0x10, 0x51,
	0xc9, 0x73, 0x14, 0xa7, 0xc1, 0x85, 0xeb, 0x2b, 0x1a, 0x12, 0xc0, 0x2d, 0x58, 0x70, 0x5e, 0x4c,
	0xc1, 0x0a, 0x6f, 0xff, 0x25, 0x23, 0x1b, 0x60, 0x26, 0x11, 0x30, 0xc1, 0x83, 0xf3, 0x08, 0x24,
	0xdb, 0x1b, 0x97, 0x6a, 0xcd, 0xc5, 0xde, 0xa5, 0x1f, 0xb0, 0xc3, 0x01, 0x12, 0xef, 0x10, 0x21,
	0xd4, 0x21, 0x39, 0x6a, 0x20, 0x6c, 0xd5, 0xe9, 0x5d, 0xab, 0x75, 0xb1, 0xd4, 0x14, 0x8d, 0xe8,
	0x25, 0xd3, 0xcd, 0xa3, 0x7a, 0xa7, 0xc8, 0x73, 0x04, 0x00, 0x00, 0x00, 0x53, 0x4b, 0x55, 0x32,
	0x02, 0x02, 0x22, 0x14, 0x66, 0x07, 0x00, 0x00, 0x45, 0x04, 0x00, 0x00, 0x00, 0x02, 0x00, 0x41,
	0x0b, 0x10, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xd0, 0x07, 0x00, 0x00, 0xb8, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 0x48, 0xe8, 0x01, 0x01, 0x04, 0x01, 0x0a,
	0x00, 0x90, 0xd0, 0x03, 0x9c, 0x36, 0xde, 0x56, 0x80, 0x92, 0x24, 0x4a, 0xdc, 0x0a, 0x85, 0xa2,
	0xed, 0x81, 0xfd, 0xb4, 0x35, 0x37, 0xbb, 0x15, 0x47, 0x47, 0xb6, 0x5b, 0xb4, 0x91, 0xba, 0xa5,
	0x84, 0xb3, 0xa6, 0x83, 0x72, 0x5a, 0x24, 0xbf, 0x6e, 0xe4, 0x3e, 0xbd, 0xd5, 0xb7, 0xd5, 0x1f,
	0x08, 0x1b, 0xe3, 0x18, 0xcf, 0xe0, 0xf1, 0xa1, 0xf5, 0xb9, 0xc9, 0x57, 0x6e, 0x66, 0x9b, 0xe9,
	0x4d, 0x03, 0x0c, 0x3a, 0x09, 0x34, 0x48, 0x9c, 0x1c, 0xb2, 0x43, 0xd3, 0x7b, 0x22, 0x0f, 0xa4,
	0xa7, 0xbc, 0x6f, 0xb3, 0x50, 0xa1, 0x41, 0x99, 0x86, 0x75, 0x68, 0xf0, 0xab, 0x1a, 0x37, 0xc2,
	0xbd, 0x25, 0x3f, 0xd3, 0x87, 0xce, 0x58, 0xbb, 0x58, 0x38, 0x9c, 0xac, 0x55, 0xff, 0x17, 0x48,
	0x05, 0xa7, 0xdc, 0x8b, 0x86, 0xce, 0x70, 0x0b, 0x21, 0xbf, 0xf8, 0xab, 0x6d, 0x4e, 0x0c, 0xd5,
	0x1c, 0x44, 0x3c, 0xba, 0xb7, 0xeb, 0xac, 0x76, 0xd9, 0xf3, 0xa9, 0x60, 0xa6, 0x56, 0x68, 0x43,
	0x61, 0x12, 0xe5, 0x47, 0x0a, 0x56, 0x92, 0xce, 0x5e, 0x3b, 0xfe, 0xf3, 0x78, 0x64, 0x7f, 0x13,
	0x6d, 0xb5, 0xf2, 0xcd, 0xb5, 0x76, 0xfd, 0x9f, 0x5c, 0x95, 0x86, 0x72, 0x79, 0x08, 0xaa, 0x70,
	0x3d, 0xfc, 0x0b, 0x4f, 0xc6, 0x4f, 0x3a, 0x63, 0x93, 0x26, 0x84, 0x3f, 0x77, 0x54, 0x0f, 0x5d,
	0x38, 0xa3, 0x81, 0xd7, 0x01, 0x02, 0x40, 0x3d, 0x17, 0xe3, 0xdf, 0xf1, 0x3b, 0xff, 0xbd, 0x4c,
	0xff, 0x42, 0xe5, 0x42, 0xc4, 0x21, 0xa3, 0x95, 0x5c, 0x18, 0xc8, 0xe7, 0xfa, 0x3b, 0xdc, 0xce,
	0x40, 0x8c, 0xfe, 0x77, 0x24, 0xbe, 0x74, 0xa1, 0xe3, 0xbc, 0xa5, 0x26, 0xe2, 0xe8, 0xa1, 0x8c,
	0xc3, 0x87, 0x5d, 0xb7, 0x4b, 0x2f, 0x1a, 0x10, 0x40, 0x87, 0x5a, 0x99, 0xcc, 0xf1, 0x78, 0xb9,
	0x88, 0x2b, 0x1e, 0xe3
};

/**
 * Length of the testing PCD with no components and platform ID SKU2.
 */
const uint32_t PCD_NO_COMPONENTS_DATA_LEN = sizeof (PCD_NO_COMPONENTS_DATA);

/**
 * PCD_NO_COMPONENTS_DATA hash for testing.
 *
 * head -c -256 <file> | openssl dgst -sha256 -binary | to_array.sh -
 */
const uint8_t PCD_NO_COMPONENTS_HASH[] = {
	0x04, 0xff, 0xae, 0xbb, 0xd3, 0xdf, 0x70, 0x48, 0xcc, 0x2a, 0xb9, 0xad, 0x3f, 0xb6, 0x34, 0xd9,
	0x13, 0x86, 0xfb, 0x20, 0x6a, 0x04, 0x5c, 0x5e, 0x8c, 0x9b, 0x10, 0xbc, 0x37, 0x1e, 0x34, 0x47
};

/**
 * The platform ID for the PCD with no components.
 */
const char PCD_NO_COMPONENTS_PLATFORM_ID[] = "SKU2";

/**
 * Components of the PCD with no components and platform ID SKU2.
 */
const struct pcd_testing_data PCD_NO_COMPONENTS_TESTING = {
	.manifest = {
		.raw = PCD_NO_COMPONENTS_DATA,
		.length = sizeof (PCD_NO_COMPONENTS_DATA),
		.hash = PCD_NO_COMPONENTS_HASH,
		.hash_len = sizeof (PCD_NO_COMPONENTS_HASH),
		.id = 0x1a,
		.signature = PCD_NO_COMPONENTS_DATA + (sizeof (PCD_NO_COMPONENTS_DATA) - 256),
		.sig_len = 256,
		.sig_offset = (sizeof (PCD_NO_COMPONENTS_DATA) - 256),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = PCD_NO_COMPONENTS_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x00ec,
		.toc_hash = PCD_NO_COMPONENTS_DATA + 0x00d8,
		.toc_hash_len = 32,
		.toc_hash_offset = 0x00d8,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 5,
		.toc_hashes = 5,
		.plat_id = PCD_NO_COMPONENTS_DATA + 0x00f8,
		.plat_id_len = 0x0008,
		.plat_id_str = PCD_NO_COMPONENTS_PLATFORM_ID,
		.plat_id_str_len = sizeof (PCD_NO_COMPONENTS_PLATFORM_ID) - 1,
		.plat_id_str_pad = 0,
		.plat_id_offset = 0x00f8,
		.plat_id_entry = 0,
		.plat_id_hash = 0
	},
	.rot_len = 0x0028,
	.rot_offset = 0x010c,
	.rot_entry = 2,
	.rot_hash = 2,
	.power_ctrl_len = 0x000c,
	.power_ctrl_offset = 0x0100,
	.power_ctrl_entry = 1,
	.power_ctrl_hash = 1,
	.bridge_component_len = 0,
	.bridge_component_offset = 0,
	.bridge_component_entry = -1,
	.bridge_component_hash = -1,
	.direct_component_len = 0,
	.direct_component_offset = 0,
	.direct_component_entry = -1,
	.direct_component_hash = -1,
	.port_len = 0x0008,
	.port_offset = 0x0134,
	.port_entry = 3,
	.port_hash = 3,
	.num_optional_elements = 3,
};

/**
 * PCD with no ports and ID 0x9B for testing.
 *
 * PCD file: pcd_no_ports.xml
 *
 * python3 pcd_generator.py pcd_generator.config
 * to_array.sh <output pcd bin>
 */
const uint8_t PCD_NO_PORTS_DATA[] = {
	0x58, 0x02, 0x29, 0x10, 0x9b, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x05, 0x05, 0x00, 0x00,
	0x00, 0xff, 0x01, 0x00, 0xf8, 0x00, 0x08, 0x00, 0x42, 0xff, 0x01, 0x01, 0x00, 0x01, 0x0c, 0x00,
	0x43, 0xff, 0x01, 0x02, 0x0c, 0x01, 0x10, 0x00, 0x44, 0xff, 0x01, 0x03, 0x1c, 0x01, 0x14, 0x00,
	0x40, 0xff, 0x01, 0x04, 0x30, 0x01, 0x28, 0x00, 0x13, 0xe9, 0x1c, 0x16, 0x0e, 0xcf, 0xd2, 0xbb,
	0x3a, 0x86, 0x83, 0xb6, 0x01, 0xc4, 0xba, 0xcb, 0x04, 0xf0, 0xa5, 0x18, 0x9b, 0x97, 0xd9, 0x2d,
	0x67, 0xf4, 0x6d, 0x69, 0xea, 0x1e, 0x25, 0x36, 0x4d, 0x9a, 0x65, 0x85, 0x38, 0xe7, 0x61, 0xba,
	0xbb, 0xb3, 0xdc, 0x6a, 0x01, 0x3f, 0xb4, 0x11, 0x77, 0x16, 0x30, 0x68, 0x93, 0x9c, 0xc5, 0x89,
	0xf1, 0xd1, 0x9a, 0x66, 0xab, 0xc9, 0x09, 0x7f, 0x18, 0x72, 0x54, 0x75, 0xd8, 0xc5, 0x2b, 0xa3,
	0xa3, 0x39, 0x56, 0x0c, 0xb8, 0x74, 0x5e, 0x0f, 0xfc, 0x5a, 0x81, 0xa7, 0x4e, 0x0e, 0x12, 0x6b,
	0x16, 0x5a, 0x34, 0xcf, 0xd8, 0x55, 0x76, 0xcb, 0x2f, 0x93, 0x32, 0xcb, 0xf8, 0x59, 0xaa, 0xe2,
	0xce, 0xc4, 0x66, 0x1b, 0xf7, 0x2b, 0x10, 0xd4, 0xe7, 0x3f, 0xf4, 0x4f, 0x97, 0x2a, 0x1c, 0xc0,
	0x4d, 0x5b, 0xe2, 0x2f, 0x07, 0xb5, 0xdd, 0x76, 0x2d, 0xb0, 0x77, 0x74, 0xad, 0x98, 0x0e, 0x95,
	0x23, 0xf1, 0xad, 0x6f, 0x1a, 0x73, 0x59, 0xdd, 0xc2, 0x1b, 0xf9, 0x1f, 0xad, 0x9b, 0x02, 0x4b,
	0xb8, 0x65, 0xc7, 0x05, 0xac, 0x9c, 0x76, 0x6a, 0x8f, 0xea, 0x2a, 0x6f, 0x21, 0xcb, 0x87, 0x4e,
	0xf3, 0x7b, 0x83, 0x49, 0x6d, 0x68, 0x20, 0x3f, 0xb5, 0x05, 0x9d, 0xbd, 0x75, 0x62, 0x09, 0xb0,
	0xf1, 0xd4, 0x2c, 0x8c, 0xbf, 0x19, 0xe8, 0x18, 0x04, 0x00, 0x00, 0x00, 0x53, 0x4b, 0x55, 0x31,
	0x02, 0x02, 0x22, 0x14, 0x66, 0x07, 0x00, 0x00, 0x45, 0x04, 0x00, 0x00, 0x00, 0x50, 0xe0, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x75, 0x77, 0x55, 0x03, 0x00, 0x00, 0x00, 0x70, 0xf0, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x0b, 0x00, 0x0c, 0x00, 0x0d, 0x00, 0x02, 0x30, 0x00, 0x00,
	0x00, 0x00, 0x02, 0x41, 0x0b, 0x10, 0x0a, 0x00, 0x00, 0x5c, 0x26, 0x05, 0x10, 0x27, 0x00, 0x00,
	0x10, 0x27, 0x00, 0x00, 0xd0, 0x07, 0x00, 0x00, 0xb8, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xe8, 0x03, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x2f, 0xbe, 0x9d, 0xa5, 0x48, 0x68, 0x09, 0x52,
	0x9e, 0x7e, 0xe3, 0x17, 0x1b, 0x4f, 0x0e, 0x1b, 0xc3, 0x08, 0xcc, 0x36, 0x95, 0xfc, 0xa4, 0x24,
	0x7c, 0xa3, 0xae, 0x75, 0xe1, 0x7a, 0xf2, 0x90, 0x96, 0x08, 0xc0, 0x4a, 0x18, 0x61, 0x66, 0x54,
	0x0e, 0x59, 0xd1, 0x40, 0x1d, 0xdd, 0x29, 0x1a, 0x12, 0x98, 0xb9, 0xf9, 0xac, 0x19, 0x58, 0xb1,
	0x48, 0xd8, 0x40, 0xa5, 0x8a, 0x53, 0x99, 0x4b, 0xa0, 0xa4, 0x07, 0xb4, 0xa7, 0xa2, 0xf9, 0x25,
	0x5d, 0x76, 0xd1, 0x0e, 0x3b, 0xde, 0x89, 0x5e, 0x0c, 0xd5, 0xd6, 0x3a, 0x85, 0x04, 0xe6, 0x38,
	0xa8, 0xd8, 0x98, 0xac, 0xdd, 0xc5, 0x58, 0xf4, 0x10, 0xf9, 0xc4, 0x6d, 0x3c, 0x3d, 0x13, 0x66,
	0xa0, 0xfa, 0x70, 0x2d, 0x21, 0x66, 0x9a, 0xf1, 0x06, 0x37, 0x64, 0x41, 0x2b, 0x0a, 0xe8, 0xbd,
	0x43, 0xc7, 0xa8, 0x46, 0x0b, 0x57, 0x27, 0x07, 0xd0, 0xa9, 0xe4, 0xe2, 0xdc, 0x90, 0x62, 0x32,
	0x86, 0xdc, 0xaa, 0xd2, 0xb8, 0xda, 0xdb, 0xbb, 0xec, 0xc6, 0xeb, 0xe0, 0x75, 0x1b, 0xd2, 0x79,
	0xb0, 0x5f, 0x3d, 0x4b, 0x74, 0xd9, 0x5c, 0xa3, 0x20, 0xda, 0xf2, 0x22, 0xbf, 0x6a, 0xb4, 0xd5,
	0x70, 0x41, 0x61, 0x02, 0x9a, 0xe6, 0xa8, 0x6e, 0xc6, 0x18, 0x1d, 0x42, 0x72, 0xdf, 0x20, 0x1a,
	0x53, 0xda, 0x16, 0x5c, 0xad, 0xc0, 0x0d, 0xf8, 0x81, 0xfb, 0xd3, 0xf6, 0x9f, 0xa3, 0xf3, 0x48,
	0x39, 0x30, 0x0c, 0xbf, 0x1c, 0x64, 0x73, 0xbf, 0xd9, 0x3c, 0x67, 0xa6, 0x2d, 0xa3, 0x92, 0xe2,
	0x80, 0xfe, 0xa2, 0xe8, 0xd5, 0x8e, 0xd3, 0xe9, 0xf8, 0x1f, 0x7c, 0xb4, 0x48, 0x62, 0x55, 0x71,
	0x55, 0x68, 0xda, 0x0d, 0x84, 0x0f, 0x95, 0xfd, 0xab, 0x38, 0x7a, 0x1b, 0x84, 0x33, 0x55, 0x7f,
	0x3d, 0x6a, 0x58, 0x50, 0x50, 0xb3, 0x1c, 0xfe
};

/**
 * Length of the testing PCD with no ports and ID 0x9B.
 */
const uint32_t PCD_NO_PORTS_DATA_LEN = sizeof (PCD_NO_PORTS_DATA);

/**
 * PCD_NO_PORTS_DATA hash for testing.
 *
 * head -c -256 <file> | openssl dgst -sha256 -binary | to_array.sh -
 */
const uint8_t PCD_NO_PORTS_HASH[] = {
	0xcf, 0xe9, 0xde, 0xad, 0xe1, 0xf4, 0x40, 0x88, 0x78, 0x53, 0x5d, 0x8b, 0x89, 0x50, 0x58, 0x14,
	0xe4, 0x5a, 0x4a, 0x71, 0x68, 0xe3, 0x7a, 0x63, 0xd0, 0xe3, 0xbb, 0x71, 0x1b, 0xef, 0x80, 0x01
};

/**
 * The platform ID for the PCD with no ports and ID 0x9B.
 */
const char PCD_NO_PORTS_PLATFORM_ID[] = "SKU1";

/**
 * Components of the no ports and ID 0x9B PCD.
 */
const struct pcd_testing_data PCD_NO_PORTS_TESTING = {
	.manifest = {
		.raw = PCD_NO_PORTS_DATA,
		.length = sizeof (PCD_NO_PORTS_DATA),
		.hash = PCD_NO_PORTS_HASH,
		.hash_len = sizeof (PCD_NO_PORTS_HASH),
		.id = 0x9b,
		.signature = PCD_NO_PORTS_DATA + (sizeof (PCD_NO_PORTS_DATA) - 256),
		.sig_len = 256,
		.sig_offset = (sizeof (PCD_NO_PORTS_DATA) - 256),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = PCD_NO_PORTS_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x00ec,
		.toc_hash = PCD_NO_PORTS_DATA + 0x00d8,
		.toc_hash_len = 32,
		.toc_hash_offset = 0x00d8,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 5,
		.toc_hashes = 5,
		.plat_id = PCD_NO_PORTS_DATA + 0x00f8,
		.plat_id_len = 0x0008,
		.plat_id_str = PCD_NO_PORTS_PLATFORM_ID,
		.plat_id_str_len = sizeof (PCD_NO_PORTS_PLATFORM_ID) - 1,
		.plat_id_str_pad = 0,
		.plat_id_offset = 0x00f8,
		.plat_id_entry = 0,
		.plat_id_hash = 0
	},
	.rot_len = 0x0028,
	.rot_offset = 0x0130,
	.rot_entry = 4,
	.rot_hash = 4,
	.power_ctrl_len = 0x000c,
	.power_ctrl_offset = 0x0100,
	.power_ctrl_entry = 1,
	.power_ctrl_hash = 1,
	.bridge_component_len = 0x0014,
	.bridge_component_offset = 0x011c,
	.bridge_component_entry = 3,
	.bridge_component_hash = 3,
	.direct_component_len = 0x0010,
	.direct_component_offset = 0x010c,
	.direct_component_entry = 2,
	.direct_component_hash = 2,
	.port_len = 0,
	.port_offset = 0,
	.port_entry = -1,
	.port_hash = -1,
	.num_optional_elements = 3,
};

/**
 * PCD with no ports, no power controller, and no components for testing.
 *
 * PCD file: pcd_no_ports_power_controller_components.xml
 *
 * python3 pcd_generator.py pcd_generator.config
 * to_array.sh <output pcd bin>
 */
const uint8_t PCD_NO_PORTS_POWER_CONTROLLER_COMPONENTS_DATA[] = {
	0xb0, 0x01, 0x29, 0x10, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x00, 0x00,
	0x00, 0xff, 0x01, 0x00, 0x80, 0x00, 0x08, 0x00, 0x40, 0xff, 0x01, 0x01, 0x88, 0x00, 0x28, 0x00,
	0x13, 0xe9, 0x1c, 0x16, 0x0e, 0xcf, 0xd2, 0xbb, 0x3a, 0x86, 0x83, 0xb6, 0x01, 0xc4, 0xba, 0xcb,
	0x04, 0xf0, 0xa5, 0x18, 0x9b, 0x97, 0xd9, 0x2d, 0x67, 0xf4, 0x6d, 0x69, 0xea, 0x1e, 0x25, 0x36,
	0x34, 0x6c, 0xfe, 0x40, 0x4e, 0xcd, 0x30, 0xe5, 0xf3, 0xf3, 0x4f, 0xce, 0x76, 0xb8, 0xfc, 0x26,
	0xc8, 0xcf, 0x7c, 0x77, 0x1d, 0x25, 0x3d, 0xe4, 0x46, 0xd3, 0x04, 0xf7, 0xa8, 0x39, 0x46, 0x7c,
	0x47, 0xeb, 0x73, 0x59, 0xbd, 0x63, 0xe6, 0x25, 0xda, 0x1c, 0xbc, 0xa6, 0x1c, 0x6c, 0x91, 0x9d,
	0x7e, 0x12, 0x42, 0x37, 0xf6, 0xb3, 0x64, 0x7b, 0xb1, 0x47, 0xe4, 0xff, 0x99, 0x38, 0x8d, 0x3c,
	0x04, 0x00, 0x00, 0x00, 0x53, 0x4b, 0x55, 0x31, 0x00, 0x00, 0x00, 0x41, 0x0b, 0x10, 0x0a, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x07, 0x00, 0x00,
	0xb8, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x49, 0xd6, 0xbd, 0xba, 0x28, 0x4d, 0x8b, 0x37, 0xaf, 0xa1, 0xc6, 0x9e, 0x82, 0x22, 0x12, 0xaf,
	0x5a, 0xae, 0xf0, 0x20, 0x95, 0x1d, 0x84, 0xc5, 0xe9, 0xa4, 0x1b, 0xbf, 0x54, 0x3e, 0xb1, 0xa8,
	0x13, 0xea, 0xa4, 0x83, 0xae, 0x18, 0x21, 0x0d, 0xcc, 0x41, 0x3b, 0x5f, 0x4d, 0xd6, 0x82, 0x90,
	0x15, 0x88, 0xff, 0x75, 0xd5, 0x02, 0x53, 0xbf, 0x8e, 0xa2, 0xbe, 0x9e, 0xed, 0xdf, 0x9a, 0x5c,
	0x0c, 0xf1, 0x21, 0x20, 0xc5, 0x79, 0x74, 0x09, 0xed, 0xe7, 0xe2, 0x36, 0x3e, 0x48, 0xb9, 0x2e,
	0xd8, 0x44, 0xaa, 0x77, 0xd1, 0xd9, 0x6b, 0xa9, 0x3a, 0x46, 0x7b, 0xf0, 0x54, 0x49, 0x8c, 0x83,
	0xf2, 0x1d, 0x55, 0x49, 0xed, 0x4e, 0x51, 0x54, 0xd7, 0xe6, 0x09, 0x93, 0x13, 0xaf, 0x70, 0x4d,
	0xa1, 0x5c, 0xbf, 0xe1, 0xfd, 0xe9, 0xed, 0x8b, 0xe2, 0x6a, 0xee, 0x9d, 0xce, 0x11, 0x31, 0x4e,
	0x65, 0x15, 0x82, 0x9f, 0xc5, 0xa0, 0xce, 0x0b, 0x23, 0xac, 0x0d, 0xff, 0xeb, 0xc8, 0x6a, 0x04,
	0xe9, 0x21, 0xf1, 0xfd, 0x58, 0x13, 0xb2, 0x81, 0x72, 0xf8, 0x31, 0x13, 0x62, 0xcd, 0x41, 0xb7,
	0xaf, 0x0d, 0x8a, 0x88, 0x41, 0x7c, 0x60, 0xc9, 0x22, 0xd2, 0x4b, 0xea, 0x97, 0x9f, 0x79, 0x17,
	0xd0, 0x9d, 0x0b, 0x81, 0x26, 0x35, 0x94, 0x7f, 0x73, 0x22, 0xe0, 0x70, 0x05, 0x66, 0xfb, 0x07,
	0xb2, 0x78, 0xab, 0xa2, 0xa6, 0xb0, 0xeb, 0x90, 0x4d, 0xa9, 0xa2, 0x08, 0x0c, 0x93, 0x52, 0xbf,
	0xd8, 0x89, 0xd6, 0xa9, 0x94, 0x9b, 0x43, 0x4e, 0x67, 0x32, 0x83, 0xb7, 0x01, 0x2f, 0x4b, 0x3a,
	0xa3, 0x2d, 0x71, 0x7b, 0x7d, 0x82, 0x77, 0x01, 0x01, 0x19, 0xf9, 0x62, 0xa7, 0x21, 0x56, 0x07,
	0x01, 0x13, 0x2d, 0x8b, 0x82, 0xcf, 0xa8, 0x24, 0x5d, 0x8f, 0x16, 0x46, 0x36, 0xa5, 0xbf, 0x56
};

/**
 * Length of the testing PCD with no ports, no power controller, and no components.
 */
const uint32_t PCD_NO_PORTS_POWER_CONTROLLER_COMPONENTS_DATA_LEN =
	sizeof (PCD_NO_PORTS_POWER_CONTROLLER_COMPONENTS_DATA);

/**
 * PCD_NO_PORTS_POWER_CONTROLLER_COMPONENTS_DATA hash for testing.
 *
 * head -c -256 <file> | openssl dgst -sha256 -binary | to_array.sh -
 */
const uint8_t PCD_NO_PORTS_POWER_CONTROLLER_COMPONENTS_HASH[] = {
	0x70, 0x30, 0x74, 0xe1, 0xc1, 0xae, 0xb2, 0xc0, 0x47, 0x80, 0xa3, 0x59, 0x4d, 0x2e, 0x5c, 0x4a,
	0xeb, 0x0a, 0x15, 0x50, 0x13, 0x50, 0x77, 0xfa, 0x7b, 0x2d, 0xf5, 0x8d, 0x6f, 0xf8, 0xa2, 0x14
};

/**
 * The platform ID for the PCD with no ports, no power controller, and no components.
 */
const char PCD_NO_PORTS_POWER_CONTROLLER_COMPONENTS_PLATFORM_ID[] = "SKU1";

/**
 * Components of the no ports, no power controller, and no components PCD.
 */
static struct pcd_testing_data PCD_NO_PORTS_POWER_CONTROLLER_COMPONENTS_TESTING = {
	.manifest = {
		.raw = PCD_NO_PORTS_POWER_CONTROLLER_COMPONENTS_DATA,
		.length = sizeof (PCD_NO_PORTS_POWER_CONTROLLER_COMPONENTS_DATA),
		.hash = PCD_NO_PORTS_POWER_CONTROLLER_COMPONENTS_HASH,
		.hash_len = sizeof (PCD_NO_PORTS_POWER_CONTROLLER_COMPONENTS_HASH),
		.id = 0x1a,
		.signature = PCD_NO_PORTS_POWER_CONTROLLER_COMPONENTS_DATA +
			(sizeof (PCD_NO_PORTS_POWER_CONTROLLER_COMPONENTS_DATA) - 256),
		.sig_len = 256,
		.sig_offset = (sizeof (PCD_NO_PORTS_POWER_CONTROLLER_COMPONENTS_DATA) - 256),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = PCD_NO_PORTS_POWER_CONTROLLER_COMPONENTS_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x0074,
		.toc_hash = PCD_NO_PORTS_POWER_CONTROLLER_COMPONENTS_DATA + 0x0060,
		.toc_hash_len = 32,
		.toc_hash_offset = 0x0060,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 2,
		.toc_hashes = 2,
		.plat_id = PCD_NO_PORTS_POWER_CONTROLLER_COMPONENTS_DATA + 0x0080,
		.plat_id_len = 0x0008,
		.plat_id_str = PCD_NO_PORTS_POWER_CONTROLLER_COMPONENTS_PLATFORM_ID,
		.plat_id_str_len = sizeof (PCD_NO_PORTS_POWER_CONTROLLER_COMPONENTS_PLATFORM_ID) - 1,
		.plat_id_str_pad = 0,
		.plat_id_offset = 0x0080,
		.plat_id_entry = 0,
		.plat_id_hash = 0
	},
	.rot_len = 0x0028,
	.rot_offset = 0x0088,
	.rot_entry = 1,
	.rot_hash = 1,
	.power_ctrl_len = 0,
	.power_ctrl_offset = 0,
	.power_ctrl_entry = -1,
	.power_ctrl_hash = -1,
	.bridge_component_len = 0,
	.bridge_component_offset = 0,
	.bridge_component_entry = -1,
	.bridge_component_hash = -1,
	.direct_component_len = 0,
	.direct_component_offset = 0,
	.direct_component_entry = -1,
	.direct_component_hash = -1,
	.port_len = 0,
	.port_offset = 0,
	.port_entry = -1,
	.port_hash = -1,
	.num_optional_elements = 0,
};

/**
 * PCD with two direct components and no bridge components for testing.
 *
 * PCD file: pcd_only_direct_components.xml
 *
 * python3 pcd_generator.py pcd_generator.config
 * to_array.sh <output pcd bin>
 */
const uint8_t PCD_ONLY_DIRECT_COMPONENTS_DATA[] = {
	0xb4, 0x02, 0x29, 0x10, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x07, 0x07, 0x00, 0x00,
	0x00, 0xff, 0x01, 0x00, 0x48, 0x01, 0x08, 0x00, 0x42, 0xff, 0x01, 0x01, 0x50, 0x01, 0x0c, 0x00,
	0x43, 0xff, 0x01, 0x02, 0x5c, 0x01, 0x10, 0x00, 0x43, 0xff, 0x01, 0x03, 0x6c, 0x01, 0x10, 0x00,
	0x40, 0xff, 0x01, 0x04, 0x7c, 0x01, 0x28, 0x00, 0x41, 0x40, 0x01, 0x05, 0xa4, 0x01, 0x08, 0x00,
	0x41, 0x40, 0x01, 0x06, 0xac, 0x01, 0x08, 0x00, 0x13, 0xe9, 0x1c, 0x16, 0x0e, 0xcf, 0xd2, 0xbb,
	0x3a, 0x86, 0x83, 0xb6, 0x01, 0xc4, 0xba, 0xcb, 0x04, 0xf0, 0xa5, 0x18, 0x9b, 0x97, 0xd9, 0x2d,
	0x67, 0xf4, 0x6d, 0x69, 0xea, 0x1e, 0x25, 0x36, 0x4d, 0x9a, 0x65, 0x85, 0x38, 0xe7, 0x61, 0xba,
	0xbb, 0xb3, 0xdc, 0x6a, 0x01, 0x3f, 0xb4, 0x11, 0x77, 0x16, 0x30, 0x68, 0x93, 0x9c, 0xc5, 0x89,
	0xf1, 0xd1, 0x9a, 0x66, 0xab, 0xc9, 0x09, 0x7f, 0x18, 0x72, 0x54, 0x75, 0xd8, 0xc5, 0x2b, 0xa3,
	0xa3, 0x39, 0x56, 0x0c, 0xb8, 0x74, 0x5e, 0x0f, 0xfc, 0x5a, 0x81, 0xa7, 0x4e, 0x0e, 0x12, 0x6b,
	0x16, 0x5a, 0x34, 0xcf, 0xd8, 0x55, 0x76, 0xcb, 0x1b, 0xcb, 0x20, 0x97, 0x0b, 0x1f, 0xb0, 0x28,
	0xb1, 0x98, 0x84, 0x28, 0x94, 0x9d, 0x48, 0xbc, 0x10, 0x53, 0x3b, 0x38, 0x3a, 0xe4, 0x56, 0x9e,
	0x7f, 0x0e, 0xbc, 0xb6, 0x17, 0xc5, 0x17, 0xc6, 0xe0, 0x44, 0x1c, 0xdf, 0x92, 0x99, 0x8f, 0xf9,
	0x93, 0x1c, 0x0f, 0x81, 0x4f, 0xee, 0x7a, 0x50, 0xdf, 0x9e, 0xba, 0x20, 0x59, 0x40, 0x2c, 0xa4,
	0xcf, 0x53, 0x04, 0x23, 0x9b, 0xd7, 0x1d, 0x13, 0xd8, 0xa8, 0xa9, 0xa2, 0x83, 0xe3, 0x96, 0x44,
	0x4f, 0xe0, 0x88, 0x64, 0x32, 0x82, 0xd2, 0x36, 0xd9, 0xac, 0x81, 0x15, 0x30, 0x9d, 0x10, 0x51,
	0xc9, 0x73, 0x14, 0xa7, 0xc1, 0x85, 0xeb, 0x2b, 0x1a, 0x12, 0xc0, 0x2d, 0x58, 0x70, 0x5e, 0x4c,
	0xc1, 0x0a, 0x6f, 0xff, 0x25, 0x23, 0x1b, 0x60, 0x26, 0x11, 0x30, 0xc1, 0x83, 0xf3, 0x08, 0x24,
	0xdb, 0x1b, 0x97, 0x6a, 0xcd, 0xc5, 0xde, 0xa5, 0xb2, 0x8f, 0x51, 0x25, 0x4c, 0xce, 0x98, 0xb9,
	0xc0, 0x4d, 0x47, 0x92, 0x4c, 0x68, 0x31, 0x3e, 0x5e, 0xa4, 0x57, 0x59, 0xad, 0x06, 0xe4, 0xb7,
	0xb9, 0xad, 0xe2, 0xb3, 0xa7, 0x7b, 0x43, 0xc2, 0x04, 0x00, 0x00, 0x00, 0x53, 0x4b, 0x55, 0x31,
	0x02, 0x02, 0x22, 0x14, 0x66, 0x07, 0x00, 0x00, 0x45, 0x04, 0x00, 0x00, 0x00, 0x50, 0xe0, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x75, 0x77, 0x55, 0x03, 0x00, 0x00, 0x00, 0x56, 0xe6, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x11, 0x05, 0x81, 0x88, 0x11, 0x04, 0x00, 0x00, 0x00, 0x02, 0x02, 0x41,
	0x0b, 0x10, 0x0a, 0x00, 0x00, 0x5c, 0x26, 0x05, 0x10, 0x27, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xd0, 0x07, 0x00, 0x00, 0xb8, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe8, 0x03, 0x00, 0x00,
	0x04, 0x00, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 0x48, 0xe8, 0x01, 0x01, 0x04, 0x01, 0x0a,
	0x00, 0x90, 0xd0, 0x03, 0x72, 0xab, 0x75, 0x7e, 0xeb, 0x49, 0x4a, 0x99, 0xf2, 0x2a, 0x78, 0x1f,
	0x6c, 0xec, 0x3c, 0xcd, 0x57, 0x25, 0x22, 0xb6, 0x46, 0xfe, 0xbb, 0x79, 0x0a, 0xc6, 0x96, 0xb5,
	0x06, 0xd3, 0x5a, 0xe8, 0xfe, 0x76, 0x61, 0x7c, 0xea, 0xfc, 0x20, 0xaf, 0x25, 0x12, 0xef, 0x4e,
	0xbe, 0x94, 0xab, 0xa0, 0x92, 0xfc, 0x4e, 0x76, 0x0f, 0xe0, 0x6c, 0xdb, 0xf7, 0x0b, 0x7c, 0x7f,
	0x41, 0xa6, 0xc9, 0xd3, 0x10, 0x91, 0xa9, 0xe3, 0xb3, 0xbf, 0xad, 0x93, 0x5b, 0x0b, 0x2f, 0x75,
	0xfe, 0xad, 0x6e, 0x75, 0x55, 0xa8, 0x56, 0xa5, 0x0e, 0x1a, 0xf4, 0x57, 0x2e, 0x35, 0xf7, 0x75,
	0x17, 0x07, 0xc1, 0x62, 0xb4, 0xd9, 0x88, 0xf9, 0x54, 0xb1, 0xf2, 0xb5, 0xf3, 0x5a, 0x6f, 0xf6,
	0x08, 0x2e, 0x27, 0x50, 0x1e, 0x3f, 0x16, 0xd0, 0xb3, 0x32, 0x84, 0x1f, 0x8b, 0x02, 0xdf, 0xfb,
	0x73, 0x1e, 0xca, 0x43, 0xf3, 0xda, 0xb5, 0x11, 0x79, 0xcd, 0x5f, 0x9a, 0x3d, 0x73, 0x4a, 0xe0,
	0xe0, 0x9f, 0x4d, 0x07, 0xfa, 0x22, 0xbf, 0xa3, 0x8d, 0xc5, 0x39, 0x07, 0x84, 0x48, 0xd3, 0x81,
	0x66, 0x1b, 0x85, 0x97, 0xd6, 0xde, 0xc3, 0x0e, 0x45, 0xd1, 0xd2, 0xd5, 0x07, 0xcf, 0x39, 0x6f,
	0x7d, 0x9e, 0x24, 0x43, 0xd5, 0x1b, 0xb9, 0x06, 0x29, 0x62, 0x7e, 0xd4, 0x32, 0x69, 0xa4, 0xda,
	0x14, 0xdb, 0xf7, 0x47, 0xeb, 0xc2, 0x66, 0x36, 0x7c, 0x40, 0x61, 0x68, 0x7a, 0x22, 0xa5, 0xde,
	0xbb, 0x2c, 0x3a, 0x7f, 0xc3, 0x9c, 0x1f, 0xa6, 0xcc, 0xc4, 0xc3, 0x60, 0x8d, 0xc1, 0x4c, 0xf3,
	0x7d, 0x82, 0x6f, 0x36, 0x38, 0x8e, 0xa4, 0xa1, 0xbc, 0x07, 0x12, 0x01, 0xde, 0x45, 0x2f, 0xb8,
	0x1a, 0xc4, 0x0c, 0xee, 0x3b, 0x13, 0x52, 0x5f, 0x2f, 0x48, 0x04, 0xec, 0x40, 0xe2, 0xa6, 0xfe,
	0x10, 0x71, 0x02, 0x3b
};

/**
 * Length of the testing PCD with two direct components and no bridge components.
 */
const uint32_t PCD_ONLY_DIRECT_COMPONENTS_DATA_LEN = sizeof (PCD_ONLY_DIRECT_COMPONENTS_DATA);

/**
 * PCD_ONLY_DIRECT_COMPONENTS_DATA hash for testing.
 *
 * head -c -256 <file> | openssl dgst -sha256 -binary | to_array.sh -
 */
const uint8_t PCD_ONLY_DIRECT_COMPONENTS_HASH[] = {
	0xfe, 0x53, 0xb3, 0x45, 0x71, 0x81, 0x3a, 0x60, 0x36, 0x8b, 0x14, 0x4e, 0xba, 0xa5, 0xff, 0x63,
	0x26, 0x66, 0xd6, 0x90, 0x7b, 0x8e, 0x79, 0x63, 0x9e, 0xf1, 0x04, 0x37, 0x49, 0xd8, 0xf4, 0xf0
};

/**
 * The platform ID for the PCD with two direct components and no bridge components.
 */
const char PCD_ONLY_DIRECT_COMPONENTS_PLATFORM_ID[] = "SKU1";

/**
 * Components of the test PCD with two direct components and no bridge components.
 */
const struct pcd_testing_data PCD_ONLY_DIRECT_COMPONENTS_TESTING = {
	.manifest = {
		.raw = PCD_ONLY_DIRECT_COMPONENTS_DATA,
		.length = sizeof (PCD_ONLY_DIRECT_COMPONENTS_DATA),
		.hash = PCD_ONLY_DIRECT_COMPONENTS_HASH,
		.hash_len = sizeof (PCD_ONLY_DIRECT_COMPONENTS_HASH),
		.id = 0x1a,
		.signature = PCD_ONLY_DIRECT_COMPONENTS_DATA +
			(sizeof (PCD_ONLY_DIRECT_COMPONENTS_DATA) - 256),
		.sig_len = 256,
		.sig_offset = (sizeof (PCD_ONLY_DIRECT_COMPONENTS_DATA) - 256),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = PCD_ONLY_DIRECT_COMPONENTS_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x013c,
		.toc_hash = PCD_ONLY_DIRECT_COMPONENTS_DATA + 0x0128,
		.toc_hash_len = 32,
		.toc_hash_offset = 0x0128,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 7,
		.toc_hashes = 7,
		.plat_id = PCD_ONLY_DIRECT_COMPONENTS_DATA + 0x0148,
		.plat_id_len = 0x0008,
		.plat_id_str = PCD_ONLY_DIRECT_COMPONENTS_PLATFORM_ID,
		.plat_id_str_len = sizeof (PCD_ONLY_DIRECT_COMPONENTS_PLATFORM_ID) - 1,
		.plat_id_str_pad = 0,
		.plat_id_offset = 0x0148,
		.plat_id_entry = 0,
		.plat_id_hash = 0
	},
	.rot_len = 0x0028,
	.rot_offset = 0x017c,
	.rot_entry = 4,
	.rot_hash = 4,
	.power_ctrl_len = 0x000c,
	.power_ctrl_offset = 0x0150,
	.power_ctrl_entry = 1,
	.power_ctrl_hash = 1,
	.bridge_component_len = 0,
	.bridge_component_offset = 0,
	.bridge_component_entry = -1,
	.bridge_component_hash = -1,
	.direct_component_len = 0x0010,
	.direct_component_offset = 0x015c,
	.direct_component_entry = 2,
	.direct_component_hash = 2,
	.port_len = 0x0008,
	.port_offset = 0x01a4,
	.port_entry = 5,
	.port_hash = 5,
	.num_optional_elements = 5,
};

/**
 * PCD with two direct components and one bridge component for testing.
 *
 * PCD file: pcd_multiple_direct_components.xml
 *
 * python3 pcd_generator.py pcd_generator.config
 * to_array.sh <output pcd bin>
 */
const uint8_t PCD_MULTIPLE_DIRECT_COMPONENTS_DATA[] = {
	0xf0, 0x02, 0x29, 0x10, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x08, 0x08, 0x00, 0x00,
	0x00, 0xff, 0x01, 0x00, 0x70, 0x01, 0x08, 0x00, 0x42, 0xff, 0x01, 0x01, 0x78, 0x01, 0x0c, 0x00,
	0x43, 0xff, 0x01, 0x02, 0x84, 0x01, 0x10, 0x00, 0x43, 0xff, 0x01, 0x03, 0x94, 0x01, 0x10, 0x00,
	0x44, 0xff, 0x01, 0x04, 0xa4, 0x01, 0x14, 0x00, 0x40, 0xff, 0x01, 0x05, 0xb8, 0x01, 0x28, 0x00,
	0x41, 0x40, 0x01, 0x06, 0xe0, 0x01, 0x08, 0x00, 0x41, 0x40, 0x01, 0x07, 0xe8, 0x01, 0x08, 0x00,
	0x13, 0xe9, 0x1c, 0x16, 0x0e, 0xcf, 0xd2, 0xbb, 0x3a, 0x86, 0x83, 0xb6, 0x01, 0xc4, 0xba, 0xcb,
	0x04, 0xf0, 0xa5, 0x18, 0x9b, 0x97, 0xd9, 0x2d, 0x67, 0xf4, 0x6d, 0x69, 0xea, 0x1e, 0x25, 0x36,
	0x4d, 0x9a, 0x65, 0x85, 0x38, 0xe7, 0x61, 0xba, 0xbb, 0xb3, 0xdc, 0x6a, 0x01, 0x3f, 0xb4, 0x11,
	0x77, 0x16, 0x30, 0x68, 0x93, 0x9c, 0xc5, 0x89, 0xf1, 0xd1, 0x9a, 0x66, 0xab, 0xc9, 0x09, 0x7f,
	0x18, 0x72, 0x54, 0x75, 0xd8, 0xc5, 0x2b, 0xa3, 0xa3, 0x39, 0x56, 0x0c, 0xb8, 0x74, 0x5e, 0x0f,
	0xfc, 0x5a, 0x81, 0xa7, 0x4e, 0x0e, 0x12, 0x6b, 0x16, 0x5a, 0x34, 0xcf, 0xd8, 0x55, 0x76, 0xcb,
	0x33, 0x5e, 0x70, 0xfe, 0xd7, 0x81, 0x41, 0xca, 0x47, 0x86, 0x15, 0x07, 0xb4, 0xa5, 0xa4, 0x07,
	0x83, 0x3a, 0xf0, 0x9d, 0x12, 0x68, 0x9f, 0x4d, 0x39, 0x4a, 0x5d, 0x33, 0xe9, 0x9a, 0xd7, 0x7d,
	0x2f, 0x93, 0x32, 0xcb, 0xf8, 0x59, 0xaa, 0xe2, 0xce, 0xc4, 0x66, 0x1b, 0xf7, 0x2b, 0x10, 0xd4,
	0xe7, 0x3f, 0xf4, 0x4f, 0x97, 0x2a, 0x1c, 0xc0, 0x4d, 0x5b, 0xe2, 0x2f, 0x07, 0xb5, 0xdd, 0x76,
	0xcf, 0x28, 0x69, 0xb5, 0x68, 0xdd, 0x45, 0xdd, 0x8d, 0x5c, 0x72, 0x5e, 0xbd, 0xee, 0xa1, 0x44,
	0xd6, 0xd5, 0xef, 0xc4, 0xc4, 0x16, 0x82, 0xcd, 0xb3, 0x0c, 0x66, 0xde, 0x4c, 0xb1, 0x1e, 0xf4,
	0xd8, 0xa8, 0xa9, 0xa2, 0x83, 0xe3, 0x96, 0x44, 0x4f, 0xe0, 0x88, 0x64, 0x32, 0x82, 0xd2, 0x36,
	0xd9, 0xac, 0x81, 0x15, 0x30, 0x9d, 0x10, 0x51, 0xc9, 0x73, 0x14, 0xa7, 0xc1, 0x85, 0xeb, 0x2b,
	0x1a, 0x12, 0xc0, 0x2d, 0x58, 0x70, 0x5e, 0x4c, 0xc1, 0x0a, 0x6f, 0xff, 0x25, 0x23, 0x1b, 0x60,
	0x26, 0x11, 0x30, 0xc1, 0x83, 0xf3, 0x08, 0x24, 0xdb, 0x1b, 0x97, 0x6a, 0xcd, 0xc5, 0xde, 0xa5,
	0x3c, 0xc6, 0x68, 0x0c, 0x99, 0xf7, 0xb5, 0xec, 0xfa, 0x77, 0xac, 0xcf, 0xb6, 0x1e, 0xcd, 0xba,
	0x6d, 0xc8, 0x3e, 0x7a, 0xe1, 0x26, 0x59, 0x4a, 0x75, 0xc8, 0x51, 0x3c, 0x9a, 0xec, 0x84, 0xfc,
	0x04, 0x00, 0x00, 0x00, 0x53, 0x4b, 0x55, 0x31, 0x02, 0x02, 0x22, 0x14, 0x66, 0x07, 0x00, 0x00,
	0x45, 0x04, 0x00, 0x00, 0x00, 0x50, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x75, 0x77,
	0x55, 0x03, 0x00, 0x00, 0x00, 0x56, 0xe6, 0x00, 0x02, 0x00, 0x00, 0x00, 0x11, 0x05, 0x81, 0x88,
	0x11, 0x04, 0x00, 0x00, 0x00, 0x70, 0xf0, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x0b, 0x00,
	0x0c, 0x00, 0x0d, 0x00, 0x02, 0x30, 0x00, 0x00, 0x00, 0x02, 0x03, 0x41, 0x0b, 0x10, 0x0a, 0x00,
	0x00, 0x5c, 0x26, 0x05, 0x10, 0x27, 0x00, 0x00, 0x28, 0x23, 0x00, 0x00, 0xd0, 0x07, 0x00, 0x00,
	0xb8, 0x0b, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x00, 0xdc, 0x05, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
	0x00, 0x31, 0x00, 0x00, 0x00, 0x48, 0xe8, 0x01, 0x01, 0x04, 0x01, 0x0a, 0x00, 0x90, 0xd0, 0x03,
	0x94, 0x78, 0xed, 0x55, 0x14, 0xed, 0xe0, 0xf5, 0x0a, 0xd9, 0x01, 0x39, 0x91, 0x68, 0x11, 0x37,
	0xf5, 0x9c, 0x33, 0x46, 0x9d, 0x98, 0xf2, 0xa6, 0xc4, 0xb3, 0xcc, 0x17, 0x35, 0x92, 0xfa, 0x6e,
	0xd0, 0xea, 0xaf, 0x82, 0x2e, 0x93, 0xa4, 0x79, 0xfe, 0xba, 0x50, 0x68, 0x30, 0xf7, 0xaf, 0xc9,
	0xef, 0xf2, 0xee, 0x38, 0xbd, 0x7a, 0x77, 0xa5, 0x0b, 0x67, 0x15, 0x90, 0x04, 0xd3, 0xe2, 0x06,
	0x3b, 0x26, 0x64, 0xe3, 0xdc, 0xef, 0x12, 0xac, 0xb8, 0xd4, 0xac, 0x82, 0x70, 0x2c, 0xd7, 0x91,
	0x88, 0x74, 0xb0, 0x6d, 0xb1, 0x14, 0xee, 0xf9, 0x41, 0xa4, 0xee, 0xa6, 0x35, 0x42, 0x6e, 0x52,
	0x3a, 0x8c, 0x56, 0xc9, 0xbd, 0x97, 0x40, 0xed, 0x6d, 0xdb, 0xac, 0x0c, 0xfa, 0x98, 0xb1, 0xc7,
	0xe1, 0x0c, 0x93, 0x84, 0x04, 0xdf, 0x04, 0x03, 0x4d, 0xfc, 0x63, 0xad, 0xc0, 0xfd, 0xde, 0xd1,
	0x8b, 0x0f, 0x50, 0x2d, 0x3e, 0x85, 0x58, 0x13, 0x88, 0x6c, 0x5c, 0xef, 0x71, 0xec, 0x88, 0x6d,
	0x78, 0xd3, 0xe6, 0x19, 0x40, 0x80, 0x29, 0xfd, 0xdb, 0x95, 0xf7, 0x19, 0x77, 0xb7, 0xd4, 0x60,
	0x63, 0xe9, 0x13, 0x2e, 0xdb, 0x44, 0xc6, 0x0d, 0x0f, 0x2b, 0x1b, 0x88, 0x95, 0xc9, 0x8e, 0x4f,
	0xcd, 0xc1, 0xea, 0xd6, 0x83, 0x1f, 0x50, 0xa1, 0x62, 0xe6, 0x6c, 0xa7, 0xd1, 0xe3, 0x69, 0x9a,
	0xb7, 0x14, 0xfd, 0x2e, 0x1c, 0x29, 0x99, 0x93, 0x51, 0xab, 0x5c, 0x77, 0xc0, 0x54, 0x06, 0x7b,
	0x73, 0xab, 0xc6, 0xe7, 0x84, 0x33, 0xe4, 0xe0, 0x19, 0x98, 0xf9, 0x40, 0xe2, 0x91, 0xb1, 0x46,
	0xe2, 0x74, 0x9f, 0x16, 0xd1, 0xcf, 0x16, 0xd3, 0xad, 0x24, 0xdc, 0x5e, 0xa6, 0x1f, 0xba, 0x65,
	0x8c, 0xa1, 0x11, 0x43, 0x97, 0x56, 0x58, 0x2d, 0x03, 0x97, 0xca, 0xf3, 0xec, 0x2f, 0xe6, 0x96
};

/**
 * Length of the testing PCD with two direct components and one bridge component for testing.
 */
const uint32_t PCD_MULTIPLE_DIRECT_COMPONENTS_DATA_LEN =
	sizeof (PCD_MULTIPLE_DIRECT_COMPONENTS_DATA);

/**
 * PCD_MULTIPLE_DIRECT_COMPONENTS_DATA hash for testing.
 *
 * head -c -256 <file> | openssl dgst -sha256 -binary | to_array.sh -
 */
const uint8_t PCD_MULTIPLE_DIRECT_COMPONENTS_HASH[] = {
	0x37, 0xd4, 0xdf, 0x51, 0xc7, 0x2c, 0x55, 0xda, 0x41, 0x65, 0xde, 0x13, 0xd6, 0xe5, 0x19, 0x27,
	0x85, 0x4c, 0x2d, 0x19, 0xcd, 0x28, 0xa9, 0x0c, 0x8c, 0x4c, 0x5e, 0xf8, 0xad, 0x46, 0x10, 0xfe
};

/**
 * The platform ID for the PCD with two direct components and one bridge component for testing.
 */
const char PCD_MULTIPLE_DIRECT_COMPONENTS_PLATFORM_ID[] = "SKU1";

/**
 * Components of the test PCD with two direct components and one bridge component for testing.
 */
const struct pcd_testing_data PCD_MULTIPLE_DIRECT_COMPONENTS_TESTING = {
	.manifest = {
		.raw = PCD_MULTIPLE_DIRECT_COMPONENTS_DATA,
		.length = sizeof (PCD_MULTIPLE_DIRECT_COMPONENTS_DATA),
		.hash = PCD_MULTIPLE_DIRECT_COMPONENTS_HASH,
		.hash_len = sizeof (PCD_MULTIPLE_DIRECT_COMPONENTS_HASH),
		.id = 0x1a,
		.signature = PCD_MULTIPLE_DIRECT_COMPONENTS_DATA +
			(sizeof (PCD_MULTIPLE_DIRECT_COMPONENTS_DATA) - 256),
		.sig_len = 256,
		.sig_offset = (sizeof (PCD_MULTIPLE_DIRECT_COMPONENTS_DATA) - 256),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = PCD_MULTIPLE_DIRECT_COMPONENTS_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x0164,
		.toc_hash = PCD_MULTIPLE_DIRECT_COMPONENTS_DATA + 0x0150,
		.toc_hash_len = 32,
		.toc_hash_offset = 0x0150,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 8,
		.toc_hashes = 8,
		.plat_id = PCD_MULTIPLE_DIRECT_COMPONENTS_DATA + 0x0170,
		.plat_id_len = 0x0008,
		.plat_id_str = PCD_MULTIPLE_DIRECT_COMPONENTS_PLATFORM_ID,
		.plat_id_str_len = sizeof (PCD_MULTIPLE_DIRECT_COMPONENTS_PLATFORM_ID) - 1,
		.plat_id_str_pad = 0,
		.plat_id_offset = 0x0170,
		.plat_id_entry = 0,
		.plat_id_hash = 0
	},
	.rot_len = 0x0028,
	.rot_offset = 0x01b8,
	.rot_entry = 5,
	.rot_hash = 5,
	.power_ctrl_len = 0x000c,
	.power_ctrl_offset = 0x0178,
	.power_ctrl_entry = 1,
	.power_ctrl_hash = 1,
	.bridge_component_len = 0x0014,
	.bridge_component_offset = 0x01a4,
	.bridge_component_entry = 4,
	.bridge_component_hash = 4,
	.direct_component_len = 0x0010,
	.direct_component_offset = 0x0184,
	.direct_component_entry = 2,
	.direct_component_hash = 2,
	.port_len = 0x0008,
	.port_offset = 0x01e0,
	.port_entry = 6,
	.port_hash = 6,
	.num_optional_elements = 6,
};

/**
 * PCD with no direct components and two bridge components for testing for testing.
 *
 * PCD file: pcd_only_bridge_components.xml
 *
 * python3 pcd_generator.py pcd_generator.config
 * to_array.sh <output pcd bin>
 */
const uint8_t PCD_ONLY_BRIDGE_COMPONENTS_DATA[] = {
	0xbc, 0x02, 0x29, 0x10, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x07, 0x07, 0x00, 0x00,
	0x00, 0xff, 0x01, 0x00, 0x48, 0x01, 0x08, 0x00, 0x42, 0xff, 0x01, 0x01, 0x50, 0x01, 0x0c, 0x00,
	0x44, 0xff, 0x02, 0x02, 0x5c, 0x01, 0x14, 0x00, 0x44, 0xff, 0x02, 0x03, 0x70, 0x01, 0x14, 0x00,
	0x40, 0xff, 0x02, 0x04, 0x84, 0x01, 0x28, 0x00, 0x41, 0x40, 0x01, 0x05, 0xac, 0x01, 0x08, 0x00,
	0x41, 0x40, 0x01, 0x06, 0xb4, 0x01, 0x08, 0x00, 0x13, 0xe9, 0x1c, 0x16, 0x0e, 0xcf, 0xd2, 0xbb,
	0x3a, 0x86, 0x83, 0xb6, 0x01, 0xc4, 0xba, 0xcb, 0x04, 0xf0, 0xa5, 0x18, 0x9b, 0x97, 0xd9, 0x2d,
	0x67, 0xf4, 0x6d, 0x69, 0xea, 0x1e, 0x25, 0x36, 0x4d, 0x9a, 0x65, 0x85, 0x38, 0xe7, 0x61, 0xba,
	0xbb, 0xb3, 0xdc, 0x6a, 0x01, 0x3f, 0xb4, 0x11, 0x77, 0x16, 0x30, 0x68, 0x93, 0x9c, 0xc5, 0x89,
	0xf1, 0xd1, 0x9a, 0x66, 0xab, 0xc9, 0x09, 0x7f, 0x2f, 0x93, 0x32, 0xcb, 0xf8, 0x59, 0xaa, 0xe2,
	0xce, 0xc4, 0x66, 0x1b, 0xf7, 0x2b, 0x10, 0xd4, 0xe7, 0x3f, 0xf4, 0x4f, 0x97, 0x2a, 0x1c, 0xc0,
	0x4d, 0x5b, 0xe2, 0x2f, 0x07, 0xb5, 0xdd, 0x76, 0xa9, 0x1a, 0x38, 0x44, 0xe9, 0x1f, 0x3a, 0xe7,
	0x72, 0x89, 0x42, 0xe2, 0x24, 0x79, 0x4b, 0x72, 0xd7, 0xb9, 0x4e, 0xf1, 0x3f, 0x5d, 0x38, 0x72,
	0x98, 0xdb, 0x8e, 0x18, 0xab, 0x81, 0x74, 0xcc, 0x25, 0x9f, 0xb0, 0x45, 0xb2, 0xe2, 0x16, 0x05,
	0xa5, 0x02, 0x35, 0x91, 0x00, 0xe9, 0x9e, 0xab, 0x2a, 0x3e, 0xe9, 0x28, 0xef, 0x55, 0xc4, 0x4a,
	0x59, 0x7b, 0x57, 0x44, 0x11, 0x89, 0xb4, 0x52, 0xaa, 0xfd, 0xea, 0x5c, 0x58, 0xa3, 0x0e, 0x3d,
	0x84, 0x2c, 0x6d, 0xde, 0x2a, 0x44, 0x9b, 0xd4, 0x9c, 0xbf, 0x8c, 0x8a, 0x7e, 0xeb, 0x99, 0x6e,
	0x0f, 0xdd, 0x3f, 0x34, 0xf5, 0x14, 0xce, 0xbc, 0x7b, 0xbe, 0xda, 0xd8, 0x73, 0x6b, 0x03, 0xb8,
	0x24, 0xc9, 0x8d, 0xd2, 0xa6, 0x5d, 0x7c, 0x0f, 0xb2, 0xc6, 0x19, 0x73, 0xcf, 0x10, 0x70, 0x06,
	0x18, 0xad, 0xce, 0xcc, 0x09, 0xcb, 0xd3, 0x92, 0xd7, 0xb5, 0xac, 0x9c, 0x17, 0x9d, 0x34, 0x07,
	0x63, 0xcf, 0xaf, 0x3f, 0x3a, 0x99, 0xfc, 0x4e, 0x9b, 0xc9, 0xa0, 0xc1, 0x3f, 0xce, 0xad, 0x89,
	0xa2, 0x40, 0x26, 0x3f, 0x18, 0xa3, 0xed, 0xf0, 0x04, 0x00, 0x00, 0x00, 0x53, 0x4b, 0x55, 0x31,
	0x02, 0x02, 0x22, 0x14, 0x66, 0x07, 0x00, 0x00, 0x45, 0x04, 0x00, 0x00, 0x00, 0x70, 0xf0, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x0b, 0x00, 0x0c, 0x00, 0x0d, 0x00, 0x02, 0x30, 0x00, 0x00,
	0x01, 0x71, 0xf1, 0x00, 0x02, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x0e, 0x00, 0x0f, 0x00, 0x0a, 0x00,
	0x01, 0x35, 0x00, 0x00, 0x00, 0x02, 0x02, 0x41, 0x0b, 0x10, 0x0a, 0x00, 0x00, 0x5c, 0x26, 0x05,
	0x10, 0x27, 0x00, 0x00, 0x10, 0x27, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x32, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xe8, 0x03, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x7a, 0x00, 0x00,
	0x00, 0x48, 0xe8, 0x01, 0x01, 0x0c, 0x01, 0x0a, 0x00, 0x90, 0xd0, 0x03, 0xb0, 0xdb, 0x80, 0x3c,
	0x86, 0x8f, 0x45, 0x12, 0xba, 0x50, 0xd7, 0x06, 0xcf, 0x08, 0x42, 0xa6, 0x2d, 0x3c, 0x59, 0x8b,
	0x8a, 0xb7, 0x35, 0x56, 0xe4, 0x11, 0xa5, 0xe4, 0xda, 0xad, 0x4c, 0xd8, 0x43, 0xb8, 0xe3, 0xb9,
	0xc9, 0xd5, 0xb6, 0x41, 0xd0, 0x6a, 0xb4, 0x57, 0xe1, 0x24, 0x55, 0xcd, 0xf6, 0xba, 0x0b, 0x68,
	0x57, 0x95, 0x8b, 0x2f, 0x3f, 0x22, 0x44, 0x4f, 0xef, 0xe8, 0x2b, 0x75, 0xda, 0x80, 0xee, 0x90,
	0x8c, 0x27, 0x83, 0x69, 0x73, 0x72, 0xc6, 0xee, 0x15, 0x89, 0x49, 0x8e, 0x4f, 0x5f, 0xa5, 0x48,
	0xda, 0x84, 0x1d, 0x17, 0x11, 0x96, 0x7d, 0xc8, 0x06, 0xac, 0x51, 0x23, 0x98, 0x47, 0x04, 0xa8,
	0xf5, 0x00, 0x18, 0xbf, 0xd6, 0x93, 0xb8, 0xe1, 0x06, 0x11, 0xc0, 0x1d, 0x0c, 0x18, 0x79, 0xb5,
	0xa6, 0xb1, 0xdb, 0xdc, 0x34, 0xe7, 0xa5, 0x95, 0x6a, 0x35, 0xd1, 0x65, 0x93, 0x19, 0xa0, 0x90,
	0xd5, 0x41, 0x31, 0x57, 0xbb, 0x40, 0x42, 0xc2, 0xe6, 0xd1, 0x26, 0xb4, 0x61, 0x9c, 0x99, 0x25,
	0x32, 0x3b, 0x4f, 0xfc, 0x86, 0x51, 0xfa, 0x16, 0xae, 0xbe, 0x85, 0xa6, 0x3d, 0x37, 0xe5, 0x2b,
	0x99, 0x9e, 0xc9, 0xfb, 0x87, 0xab, 0x81, 0xfa, 0x5f, 0x57, 0xab, 0xeb, 0xe6, 0x3b, 0x49, 0x83,
	0xd7, 0xac, 0x2b, 0x05, 0x19, 0xcd, 0x76, 0x61, 0x70, 0xcf, 0x0e, 0xf3, 0x45, 0x23, 0xbb, 0x66,
	0xf8, 0x74, 0x61, 0x20, 0xdf, 0xe2, 0x6e, 0x5e, 0xdd, 0x39, 0x3c, 0x59, 0x01, 0x0e, 0xad, 0xea,
	0x76, 0xa7, 0x7c, 0xdb, 0x50, 0x77, 0x66, 0x9a, 0x3d, 0xd4, 0x10, 0x0a, 0xe7, 0xb1, 0x1c, 0xc6,
	0xc2, 0x54, 0x9c, 0xab, 0x45, 0x07, 0xfa, 0x3f, 0x01, 0x05, 0xdc, 0xf4, 0x71, 0xc7, 0xe0, 0x10,
	0x12, 0x22, 0xd0, 0x27, 0x9c, 0xa9, 0xf2, 0xa0, 0x2c, 0x79, 0xcd, 0xf0
};

/**
 * Length of the testing PCD with no direct components and two bridge components.
 */
const uint32_t PCD_ONLY_BRIDGE_COMPONENTS_DATA_LEN = sizeof (PCD_ONLY_BRIDGE_COMPONENTS_DATA);

/**
 * PCD_ONLY_BRIDGE_COMPONENTS_DATA hash for testing.
 *
 * head -c -256 <file> | openssl dgst -sha256 -binary | to_array.sh -
 */
const uint8_t PCD_ONLY_BRIDGE_COMPONENTS_HASH[] = {
	0x14, 0xbf, 0xa9, 0x7d, 0xde, 0xdf, 0xf5, 0x7c, 0xa9, 0x58, 0x27, 0x6a, 0x21, 0x11, 0x66, 0x53,
	0x2f, 0x43, 0x2b, 0x71, 0xdf, 0x73, 0xfd, 0x0f, 0x72, 0xd0, 0x38, 0x9e, 0xca, 0x14, 0x1c, 0xe8
};

/**
 * The platform ID for the PCD with no direct components and two bridge components.
 */
const char PCD_ONLY_BRIDGE_COMPONENTS_PLATFORM_ID[] = "SKU1";

/**
 * Components of the test PCD with no direct components and two bridge components.
 */
const struct pcd_testing_data PCD_ONLY_BRIDGE_COMPONENTS_TESTING = {
	.manifest = {
		.raw = PCD_ONLY_BRIDGE_COMPONENTS_DATA,
		.length = sizeof (PCD_ONLY_BRIDGE_COMPONENTS_DATA),
		.hash = PCD_ONLY_BRIDGE_COMPONENTS_HASH,
		.hash_len = sizeof (PCD_ONLY_BRIDGE_COMPONENTS_HASH),
		.id = 0x1a,
		.signature = PCD_ONLY_BRIDGE_COMPONENTS_DATA +
			(sizeof (PCD_ONLY_BRIDGE_COMPONENTS_DATA) - 256),
		.sig_len = 256,
		.sig_offset = (sizeof (PCD_ONLY_BRIDGE_COMPONENTS_DATA) - 256),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = PCD_ONLY_BRIDGE_COMPONENTS_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x013c,
		.toc_hash = PCD_ONLY_BRIDGE_COMPONENTS_DATA + 0x0128,
		.toc_hash_len = 32,
		.toc_hash_offset = 0x0128,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 7,
		.toc_hashes = 7,
		.plat_id = PCD_ONLY_BRIDGE_COMPONENTS_DATA + 0x0148,
		.plat_id_len = 0x0008,
		.plat_id_str = PCD_ONLY_BRIDGE_COMPONENTS_PLATFORM_ID,
		.plat_id_str_len = sizeof (PCD_ONLY_BRIDGE_COMPONENTS_PLATFORM_ID) - 1,
		.plat_id_str_pad = 0,
		.plat_id_offset = 0x0148,
		.plat_id_entry = 0,
		.plat_id_hash = 0
	},
	.rot_len = 0x0028,
	.rot_offset = 0x0184,
	.rot_entry = 4,
	.rot_hash = 4,
	.power_ctrl_len = 0x000c,
	.power_ctrl_offset = 0x0150,
	.power_ctrl_entry = 1,
	.power_ctrl_hash = 1,
	.bridge_component_len = 0x0014,
	.bridge_component_offset = 0x015c,
	.bridge_component_entry = 2,
	.bridge_component_hash = 2,
	.direct_component_len = 0,
	.direct_component_offset = 0,
	.direct_component_entry = -1,
	.direct_component_hash = -1,
	.port_len = 0x0008,
	.port_offset = 0x01a8,
	.port_entry = 5,
	.port_hash = 5,
	.num_optional_elements = 5,
};

/**
 * PCD with one direct component and two bridge components for testing.
 *
 * PCD file: pcd_multiple_bridge_components.xml
 *
 * python3 pcd_generator.py pcd_generator.config
 * to_array.sh <output pcd bin>
 */
const uint8_t PCD_MULTIPLE_BRIDGE_COMPONENTS_DATA[] = {
	0xf4, 0x02, 0x29, 0x10, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x08, 0x08, 0x00, 0x00,
	0x00, 0xff, 0x01, 0x00, 0x70, 0x01, 0x08, 0x00, 0x42, 0xff, 0x01, 0x01, 0x78, 0x01, 0x0c, 0x00,
	0x43, 0xff, 0x01, 0x02, 0x84, 0x01, 0x10, 0x00, 0x44, 0xff, 0x01, 0x03, 0x94, 0x01, 0x14, 0x00,
	0x44, 0xff, 0x01, 0x04, 0xa8, 0x01, 0x14, 0x00, 0x40, 0xff, 0x01, 0x05, 0xbc, 0x01, 0x28, 0x00,
	0x41, 0x40, 0x01, 0x06, 0xe4, 0x01, 0x08, 0x00, 0x41, 0x40, 0x01, 0x07, 0xec, 0x01, 0x08, 0x00,
	0x13, 0xe9, 0x1c, 0x16, 0x0e, 0xcf, 0xd2, 0xbb, 0x3a, 0x86, 0x83, 0xb6, 0x01, 0xc4, 0xba, 0xcb,
	0x04, 0xf0, 0xa5, 0x18, 0x9b, 0x97, 0xd9, 0x2d, 0x67, 0xf4, 0x6d, 0x69, 0xea, 0x1e, 0x25, 0x36,
	0x4d, 0x9a, 0x65, 0x85, 0x38, 0xe7, 0x61, 0xba, 0xbb, 0xb3, 0xdc, 0x6a, 0x01, 0x3f, 0xb4, 0x11,
	0x77, 0x16, 0x30, 0x68, 0x93, 0x9c, 0xc5, 0x89, 0xf1, 0xd1, 0x9a, 0x66, 0xab, 0xc9, 0x09, 0x7f,
	0x18, 0x72, 0x54, 0x75, 0xd8, 0xc5, 0x2b, 0xa3, 0xa3, 0x39, 0x56, 0x0c, 0xb8, 0x74, 0x5e, 0x0f,
	0xfc, 0x5a, 0x81, 0xa7, 0x4e, 0x0e, 0x12, 0x6b, 0x16, 0x5a, 0x34, 0xcf, 0xd8, 0x55, 0x76, 0xcb,
	0x2f, 0x93, 0x32, 0xcb, 0xf8, 0x59, 0xaa, 0xe2, 0xce, 0xc4, 0x66, 0x1b, 0xf7, 0x2b, 0x10, 0xd4,
	0xe7, 0x3f, 0xf4, 0x4f, 0x97, 0x2a, 0x1c, 0xc0, 0x4d, 0x5b, 0xe2, 0x2f, 0x07, 0xb5, 0xdd, 0x76,
	0xa9, 0x1a, 0x38, 0x44, 0xe9, 0x1f, 0x3a, 0xe7, 0x72, 0x89, 0x42, 0xe2, 0x24, 0x79, 0x4b, 0x72,
	0xd7, 0xb9, 0x4e, 0xf1, 0x3f, 0x5d, 0x38, 0x72, 0x98, 0xdb, 0x8e, 0x18, 0xab, 0x81, 0x74, 0xcc,
	0x57, 0x87, 0x49, 0xa8, 0xdf, 0xea, 0xe7, 0xa0, 0xbf, 0x2a, 0x92, 0x4b, 0x20, 0xcb, 0x1f, 0x34,
	0xd5, 0xd5, 0x40, 0x5f, 0xc4, 0x5d, 0x57, 0x4e, 0x39, 0x75, 0x67, 0x86, 0x78, 0x17, 0x55, 0x9a,
	0xd8, 0xa8, 0xa9, 0xa2, 0x83, 0xe3, 0x96, 0x44, 0x4f, 0xe0, 0x88, 0x64, 0x32, 0x82, 0xd2, 0x36,
	0xd9, 0xac, 0x81, 0x15, 0x30, 0x9d, 0x10, 0x51, 0xc9, 0x73, 0x14, 0xa7, 0xc1, 0x85, 0xeb, 0x2b,
	0x1a, 0x12, 0xc0, 0x2d, 0x58, 0x70, 0x5e, 0x4c, 0xc1, 0x0a, 0x6f, 0xff, 0x25, 0x23, 0x1b, 0x60,
	0x26, 0x11, 0x30, 0xc1, 0x83, 0xf3, 0x08, 0x24, 0xdb, 0x1b, 0x97, 0x6a, 0xcd, 0xc5, 0xde, 0xa5,
	0xcc, 0xdc, 0xa0, 0x39, 0x87, 0xcb, 0x65, 0x46, 0x49, 0xa1, 0xbc, 0xa2, 0x4a, 0x25, 0xfc, 0xa0,
	0x95, 0xab, 0x7f, 0xaa, 0x50, 0x2e, 0xd5, 0xa7, 0x9f, 0xe8, 0x60, 0x4c, 0xe6, 0xd0, 0x29, 0x9d,
	0x04, 0x00, 0x00, 0x00, 0x53, 0x4b, 0x55, 0x31, 0x02, 0x02, 0x22, 0x14, 0x66, 0x07, 0x00, 0x00,
	0x45, 0x04, 0x00, 0x00, 0x00, 0x50, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x75, 0x77,
	0x55, 0x03, 0x00, 0x00, 0x00, 0x70, 0xf0, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x0b, 0x00,
	0x0c, 0x00, 0x0d, 0x00, 0x02, 0x30, 0x00, 0x00, 0x01, 0x71, 0xf1, 0x00, 0x02, 0x00, 0x00, 0x00,
	0x0d, 0x00, 0x0e, 0x00, 0x0f, 0x00, 0x0a, 0x00, 0x01, 0x35, 0x00, 0x00, 0x00, 0x02, 0x03, 0x41,
	0x0b, 0x10, 0x0a, 0x00, 0x00, 0x5c, 0x26, 0x05, 0x10, 0x27, 0x00, 0x00, 0x10, 0x27, 0x00, 0x00,
	0xd0, 0x07, 0x00, 0x00, 0xb8, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe8, 0x03, 0x00, 0x00,
	0x03, 0x00, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 0x48, 0xe8, 0x01, 0x01, 0x04, 0x01, 0x0a,
	0x00, 0x90, 0xd0, 0x03, 0xa6, 0xd6, 0xb5, 0xa3, 0x0f, 0x60, 0x8b, 0x99, 0xcc, 0xc7, 0x3e, 0x2b,
	0x31, 0xf1, 0xf4, 0xb1, 0x00, 0x2e, 0xf3, 0x0a, 0x9d, 0x18, 0x2c, 0xcc, 0x6b, 0x45, 0xba, 0x98,
	0x6e, 0xc7, 0x2a, 0x4e, 0xea, 0xee, 0x88, 0xfe, 0xa7, 0x46, 0x4c, 0x0c, 0xa2, 0x8c, 0xb3, 0xf5,
	0xb0, 0x23, 0x78, 0x2e, 0xd4, 0x31, 0xb1, 0x33, 0x60, 0xea, 0x33, 0x3c, 0x50, 0x9d, 0x7b, 0xf5,
	0x11, 0x26, 0xaf, 0xfe, 0x95, 0x07, 0x36, 0x4d, 0x49, 0xa7, 0x80, 0x68, 0x3b, 0xfd, 0x25, 0x5c,
	0xb7, 0x61, 0x3a, 0x11, 0xd1, 0x13, 0x71, 0x88, 0x64, 0xc5, 0xa8, 0x20, 0xbd, 0x47, 0x8f, 0x3e,
	0xaf, 0x4f, 0x23, 0x9a, 0xdd, 0x56, 0x6e, 0xcd, 0x3c, 0x37, 0x85, 0xa7, 0x0e, 0xbb, 0x24, 0x6c,
	0x39, 0xcc, 0xe9, 0x58, 0x54, 0xc1, 0xfd, 0x37, 0xa9, 0x35, 0x18, 0x2f, 0x1b, 0x9c, 0x5d, 0xd3,
	0xb5, 0xcc, 0x38, 0x17, 0x77, 0xcf, 0xa6, 0x97, 0xcb, 0x99, 0x6c, 0x0e, 0x4a, 0xe2, 0x54, 0x79,
	0x2f, 0x6b, 0x28, 0x3d, 0xdb, 0x53, 0xb0, 0x2b, 0xfb, 0xab, 0x42, 0x8b, 0xc2, 0x6c, 0x42, 0x06,
	0x78, 0x67, 0xa0, 0x5d, 0x96, 0xd4, 0x1c, 0xf3, 0x7f, 0xe8, 0x67, 0xa3, 0xf1, 0xf6, 0xd2, 0xf0,
	0xa1, 0xd6, 0x5d, 0x8b, 0x9f, 0xae, 0xa4, 0xf5, 0x7c, 0x1a, 0xb5, 0x69, 0x84, 0xfe, 0xef, 0x5e,
	0x98, 0x84, 0xea, 0x0f, 0x07, 0xee, 0xff, 0xe7, 0x5f, 0x8d, 0xbb, 0xfd, 0x22, 0x8b, 0xb3, 0x39,
	0xed, 0x29, 0x73, 0x5a, 0x41, 0x56, 0xe5, 0x43, 0x5a, 0x62, 0x99, 0xa4, 0x34, 0xb2, 0xdf, 0x4e,
	0x0f, 0x86, 0x42, 0xed, 0x40, 0x41, 0x1a, 0xd1, 0x26, 0xe8, 0x5c, 0xc0, 0x68, 0x01, 0x8d, 0xd9,
	0x7f, 0x46, 0xea, 0x25, 0xf8, 0x6b, 0xed, 0x6f, 0x19, 0xb7, 0x4c, 0xe9, 0xb4, 0x42, 0x8b, 0xc3,
	0x48, 0xcd, 0x3d, 0xd9
};

/**
 * Length of the testing PCD with one direct component and two bridge components.
 */
const uint32_t PCD_MULTIPLE_BRIDGE_COMPONENTS_DATA_LEN =
	sizeof (PCD_MULTIPLE_BRIDGE_COMPONENTS_DATA);

/**
 * PCD_MULTIPLE_BRIDGE_COMPONENTS_DATA hash for testing.
 *
 * head -c -256 <file> | openssl dgst -sha256 -binary | to_array.sh -
 */
const uint8_t PCD_MULTIPLE_BRIDGE_COMPONENTS_HASH[] = {
	0x69, 0x1f, 0x5e, 0xfe, 0x0b, 0xba, 0xe9, 0x03, 0xf0, 0xba, 0xab, 0x43, 0xa1, 0x31, 0x4c, 0x3d,
	0x1c, 0xb4, 0xd4, 0xc0, 0x18, 0x9a, 0xb1, 0x74, 0x87, 0xd5, 0x2c, 0x35, 0xe1, 0xd1, 0x48, 0xcf
};

/**
 * The platform ID for the PCD with one direct component and two bridge components.
 */
const char PCD_MULTIPLE_BRIDGE_COMPONENTS_PLATFORM_ID[] = "SKU1";

/**
 * Components of the test PCD with one direct component and two bridge components.
 */
const struct pcd_testing_data PCD_MULTIPLE_BRIDGE_COMPONENTS_TESTING = {
	.manifest = {
		.raw = PCD_MULTIPLE_BRIDGE_COMPONENTS_DATA,
		.length = sizeof (PCD_MULTIPLE_BRIDGE_COMPONENTS_DATA),
		.hash = PCD_MULTIPLE_BRIDGE_COMPONENTS_HASH,
		.hash_len = sizeof (PCD_MULTIPLE_BRIDGE_COMPONENTS_HASH),
		.id = 0x1a,
		.signature = PCD_MULTIPLE_BRIDGE_COMPONENTS_DATA +
			(sizeof (PCD_MULTIPLE_BRIDGE_COMPONENTS_DATA) - 256),
		.sig_len = 256,
		.sig_offset = (sizeof (PCD_MULTIPLE_BRIDGE_COMPONENTS_DATA) - 256),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = PCD_MULTIPLE_BRIDGE_COMPONENTS_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x0164,
		.toc_hash = PCD_MULTIPLE_BRIDGE_COMPONENTS_DATA + 0x0150,
		.toc_hash_len = 32,
		.toc_hash_offset = 0x0150,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 8,
		.toc_hashes = 8,
		.plat_id = PCD_MULTIPLE_BRIDGE_COMPONENTS_DATA + 0x0170,
		.plat_id_len = 0x0008,
		.plat_id_str = PCD_MULTIPLE_BRIDGE_COMPONENTS_PLATFORM_ID,
		.plat_id_str_len = sizeof (PCD_MULTIPLE_BRIDGE_COMPONENTS_PLATFORM_ID) - 1,
		.plat_id_str_pad = 0,
		.plat_id_offset = 0x0170,
		.plat_id_entry = 0,
		.plat_id_hash = 0
	},
	.rot_len = 0x0028,
	.rot_offset = 0x01bc,
	.rot_entry = 5,
	.rot_hash = 5,
	.power_ctrl_len = 0x000c,
	.power_ctrl_offset = 0x0178,
	.power_ctrl_entry = 1,
	.power_ctrl_hash = 1,
	.bridge_component_len = 0x0014,
	.bridge_component_offset = 0x0194,
	.bridge_component_entry = 3,
	.bridge_component_hash = 3,
	.direct_component_len = 0x0010,
	.direct_component_offset = 0x0184,
	.direct_component_entry = 2,
	.direct_component_hash = 2,
	.port_len = 0x0008,
	.port_offset = 0x01e4,
	.port_entry = 6,
	.port_hash = 6,
	.num_optional_elements = 6,
};

/**
 * PCD with ports with filtered bypass flash modes and pulse reset control for testing.
 *
 * PCD file: pcd_filtered_bypass_pulse_reset.xml
 *
 * python3 pcd_generator.py pcd_generator.config
 * to_array.sh <output pcd bin>
 */
const uint8_t PCD_FILTERED_BYPASS_PULSE_RESET_DATA[] = {
	0xb8, 0x02, 0x29, 0x10, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x07, 0x07, 0x00, 0x00,
	0x00, 0xff, 0x01, 0x00, 0x48, 0x01, 0x08, 0x00, 0x42, 0xff, 0x01, 0x01, 0x50, 0x01, 0x0c, 0x00,
	0x43, 0xff, 0x01, 0x02, 0x5c, 0x01, 0x10, 0x00, 0x44, 0xff, 0x01, 0x03, 0x6c, 0x01, 0x14, 0x00,
	0x40, 0xff, 0x01, 0x04, 0x80, 0x01, 0x28, 0x00, 0x41, 0x40, 0x01, 0x05, 0xa8, 0x01, 0x08, 0x00,
	0x41, 0x40, 0x01, 0x06, 0xb0, 0x01, 0x08, 0x00, 0x13, 0xe9, 0x1c, 0x16, 0x0e, 0xcf, 0xd2, 0xbb,
	0x3a, 0x86, 0x83, 0xb6, 0x01, 0xc4, 0xba, 0xcb, 0x04, 0xf0, 0xa5, 0x18, 0x9b, 0x97, 0xd9, 0x2d,
	0x67, 0xf4, 0x6d, 0x69, 0xea, 0x1e, 0x25, 0x36, 0x4d, 0x9a, 0x65, 0x85, 0x38, 0xe7, 0x61, 0xba,
	0xbb, 0xb3, 0xdc, 0x6a, 0x01, 0x3f, 0xb4, 0x11, 0x77, 0x16, 0x30, 0x68, 0x93, 0x9c, 0xc5, 0x89,
	0xf1, 0xd1, 0x9a, 0x66, 0xab, 0xc9, 0x09, 0x7f, 0x18, 0x72, 0x54, 0x75, 0xd8, 0xc5, 0x2b, 0xa3,
	0xa3, 0x39, 0x56, 0x0c, 0xb8, 0x74, 0x5e, 0x0f, 0xfc, 0x5a, 0x81, 0xa7, 0x4e, 0x0e, 0x12, 0x6b,
	0x16, 0x5a, 0x34, 0xcf, 0xd8, 0x55, 0x76, 0xcb, 0x2f, 0x93, 0x32, 0xcb, 0xf8, 0x59, 0xaa, 0xe2,
	0xce, 0xc4, 0x66, 0x1b, 0xf7, 0x2b, 0x10, 0xd4, 0xe7, 0x3f, 0xf4, 0x4f, 0x97, 0x2a, 0x1c, 0xc0,
	0x4d, 0x5b, 0xe2, 0x2f, 0x07, 0xb5, 0xdd, 0x76, 0xd2, 0xfd, 0x90, 0x9a, 0x37, 0x65, 0x98, 0xa2,
	0x5e, 0x96, 0x8f, 0x3f, 0x0d, 0x35, 0x45, 0x64, 0x5a, 0x9e, 0x1b, 0xee, 0x79, 0xf0, 0xd1, 0x44,
	0xd3, 0x39, 0x78, 0xe0, 0x6b, 0xb3, 0x06, 0x91, 0xaa, 0xfd, 0xea, 0x5c, 0x58, 0xa3, 0x0e, 0x3d,
	0x84, 0x2c, 0x6d, 0xde, 0x2a, 0x44, 0x9b, 0xd4, 0x9c, 0xbf, 0x8c, 0x8a, 0x7e, 0xeb, 0x99, 0x6e,
	0x0f, 0xdd, 0x3f, 0x34, 0xf5, 0x14, 0xce, 0xbc, 0x7b, 0xbe, 0xda, 0xd8, 0x73, 0x6b, 0x03, 0xb8,
	0x24, 0xc9, 0x8d, 0xd2, 0xa6, 0x5d, 0x7c, 0x0f, 0xb2, 0xc6, 0x19, 0x73, 0xcf, 0x10, 0x70, 0x06,
	0x18, 0xad, 0xce, 0xcc, 0x09, 0xcb, 0xd3, 0x92, 0x14, 0xae, 0xd4, 0x8a, 0x7e, 0x01, 0xbe, 0xc9,
	0x95, 0xe9, 0x84, 0x10, 0x18, 0xd8, 0x29, 0xde, 0x78, 0x2e, 0x8f, 0xe0, 0x36, 0xb5, 0x17, 0x0c,
	0xea, 0xaf, 0x3b, 0xa8, 0x69, 0xc6, 0x11, 0xda, 0x04, 0x00, 0x00, 0x00, 0x53, 0x4b, 0x55, 0x31,
	0x02, 0x02, 0x22, 0x14, 0x66, 0x07, 0x00, 0x00, 0x45, 0x04, 0x00, 0x00, 0x00, 0x50, 0xe0, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x75, 0x77, 0x55, 0x03, 0x00, 0x00, 0x00, 0x70, 0xf0, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x0b, 0x00, 0x0c, 0x00, 0x0d, 0x00, 0x02, 0x30, 0x00, 0x00,
	0x00, 0x02, 0x02, 0x41, 0x0b, 0x10, 0x0a, 0x00, 0x00, 0x5c, 0x26, 0x05, 0x10, 0x27, 0x00, 0x00,
	0x10, 0x27, 0x00, 0x00, 0xd0, 0x07, 0x00, 0x00, 0xb8, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xe8, 0x03, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x7a, 0x00, 0x00, 0x00, 0x48, 0xe8, 0x01,
	0x01, 0x0c, 0x01, 0x0a, 0x00, 0x90, 0xd0, 0x03, 0x4a, 0x70, 0xf1, 0x05, 0x60, 0x5d, 0xaa, 0xe1,
	0x2b, 0x59, 0x1c, 0x46, 0xef, 0x4e, 0xcf, 0xde, 0x36, 0x43, 0x35, 0x8a, 0x7a, 0xe5, 0xa1, 0x99,
	0x3c, 0x81, 0x38, 0xc7, 0x1e, 0x97, 0xae, 0x78, 0x8d, 0xad, 0xed, 0xad, 0xe1, 0x8e, 0xae, 0x09,
	0xbf, 0x08, 0xd3, 0x51, 0xa2, 0x82, 0x4d, 0x57, 0xc6, 0xf0, 0x65, 0xd6, 0x0d, 0xef, 0x3b, 0x5c,
	0xd3, 0x21, 0xf3, 0xef, 0x26, 0x4d, 0xd7, 0x4d, 0xd9, 0x89, 0x18, 0x40, 0x83, 0x47, 0x8d, 0x7a,
	0x67, 0x85, 0xd1, 0x3b, 0x75, 0xc7, 0x46, 0x6f, 0x28, 0x79, 0xdb, 0xed, 0x05, 0x65, 0xcb, 0xd9,
	0x15, 0x85, 0x77, 0x68, 0xef, 0xa4, 0x4b, 0xf7, 0x5a, 0xe9, 0x09, 0xd0, 0x40, 0x88, 0xb1, 0xe9,
	0x64, 0xd0, 0xe0, 0x5a, 0x42, 0xc3, 0x06, 0xb2, 0xdc, 0xb2, 0x3c, 0x62, 0xe0, 0x27, 0xe4, 0x23,
	0x8d, 0xb7, 0xd5, 0x79, 0x88, 0xde, 0xf0, 0xab, 0x31, 0xf0, 0x2a, 0xe0, 0xf7, 0x04, 0xf1, 0x1c,
	0x4f, 0xd1, 0x88, 0xe2, 0x7f, 0x4d, 0x20, 0xf9, 0xa2, 0xe7, 0x94, 0x5f, 0x71, 0x99, 0x2d, 0xda,
	0x58, 0x57, 0xe1, 0x74, 0x74, 0x8e, 0x48, 0x5b, 0x5b, 0xfa, 0x65, 0xa4, 0xf6, 0x5f, 0x2e, 0x31,
	0x22, 0x32, 0xbc, 0xa8, 0xdf, 0x5c, 0x0a, 0xc8, 0x24, 0x82, 0x58, 0x18, 0xec, 0x5c, 0x14, 0x89,
	0x8b, 0xd3, 0xa2, 0x0b, 0xaf, 0xfa, 0x7d, 0x54, 0xe0, 0x63, 0xdf, 0x01, 0x81, 0x85, 0xaa, 0xba,
	0xcd, 0x36, 0xdc, 0x6f, 0x87, 0x27, 0x30, 0xa0, 0x6c, 0x28, 0x47, 0x97, 0x89, 0x9e, 0xd2, 0x2c,
	0x19, 0x22, 0x1e, 0x8b, 0x5c, 0x95, 0x6a, 0x42, 0x42, 0x3c, 0xec, 0x48, 0x16, 0x57, 0x54, 0x2a,
	0x4f, 0xea, 0xfa, 0x25, 0x1d, 0x8c, 0x30, 0x4f, 0x43, 0x98, 0x52, 0x5c, 0x36, 0x2a, 0x16, 0x5e,
	0xce, 0xa3, 0x13, 0x64, 0xcb, 0xea, 0xb7, 0xef
};

/**
 * Length of the testing PCD with ports with filtered bypass flash modes and pulse reset control.
 */
const uint32_t PCD_FILTERED_BYPASS_PULSE_RESET_DATA_LEN =
	sizeof (PCD_FILTERED_BYPASS_PULSE_RESET_DATA);

/**
 * PCD_FILTERED_BYPASS_PULSE_RESET_DATA hash for testing.
 *
 * head -c -256 <file> | openssl dgst -sha256 -binary | to_array.sh -
 */
const uint8_t PCD_FILTERED_BYPASS_PULSE_RESET_HASH[] = {
	0x30, 0x9c, 0x36, 0x5f, 0x99, 0xc7, 0x56, 0x86, 0x5d, 0x70, 0xdb, 0x57, 0x5d, 0xf0, 0x53, 0xda,
	0x5a, 0x42, 0x08, 0x6f, 0x24, 0x36, 0x0c, 0xd9, 0x1c, 0x50, 0x42, 0x60, 0x57, 0x62, 0xca, 0x6d
};

/**
 * The platform ID for the PCD with ports with filtered bypass flash modes and pulse reset control.
 */
const char PCD_FILTERED_BYPASS_PULSE_RESET_PLATFORM_ID[] = "SKU1";

/**
 * Components of the test PCD with ports with filtered bypass flash modes and pulse reset control.
 */
const struct pcd_testing_data PCD_FILTERED_BYPASS_PULSE_RESET_TESTING = {
	.manifest = {
		.raw = PCD_FILTERED_BYPASS_PULSE_RESET_DATA,
		.length = sizeof (PCD_FILTERED_BYPASS_PULSE_RESET_DATA),
		.hash = PCD_FILTERED_BYPASS_PULSE_RESET_HASH,
		.hash_len = sizeof (PCD_FILTERED_BYPASS_PULSE_RESET_HASH),
		.id = 0x1a,
		.signature = PCD_FILTERED_BYPASS_PULSE_RESET_DATA +
			(sizeof (PCD_FILTERED_BYPASS_PULSE_RESET_DATA) - 256),
		.sig_len = 256,
		.sig_offset = (sizeof (PCD_FILTERED_BYPASS_PULSE_RESET_DATA) - 256),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = PCD_FILTERED_BYPASS_PULSE_RESET_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x013c,
		.toc_hash = PCD_FILTERED_BYPASS_PULSE_RESET_DATA + 0x0128,
		.toc_hash_len = 32,
		.toc_hash_offset = 0x0128,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 7,
		.toc_hashes = 7,
		.plat_id = PCD_FILTERED_BYPASS_PULSE_RESET_DATA + 0x0148,
		.plat_id_len = 0x0008,
		.plat_id_str = PCD_FILTERED_BYPASS_PULSE_RESET_PLATFORM_ID,
		.plat_id_str_len = sizeof (PCD_FILTERED_BYPASS_PULSE_RESET_PLATFORM_ID) - 1,
		.plat_id_str_pad = 0,
		.plat_id_offset = 0x0148,
		.plat_id_entry = 0,
		.plat_id_hash = 0
	},
	.rot_len = 0x0028,
	.rot_offset = 0x0180,
	.rot_entry = 4,
	.rot_hash = 4,
	.power_ctrl_len = 0x000c,
	.power_ctrl_offset = 0x0150,
	.power_ctrl_entry = 1,
	.power_ctrl_hash = 1,
	.bridge_component_len = 0x0014,
	.bridge_component_offset = 0x016c,
	.bridge_component_entry = 3,
	.bridge_component_hash = 3,
	.direct_component_len = 0x0010,
	.direct_component_offset = 0x015c,
	.direct_component_entry = 2,
	.direct_component_hash = 2,
	.port_len = 0x0008,
	.port_offset = 0x01a8,
	.port_entry = 5,
	.port_hash = 5,
	.num_optional_elements = 5,
};

/**
 * Empty PCD for testing.
 *
 * PCD file: pcd_empty.xml
 *
 * python3 pcd_generator.py pcd_generator.config
 * to_array.sh <output pcd bin>
 */
const uint8_t PCD_EMPTY_DATA[] = {
	0x60, 0x01, 0x29, 0x10, 0x20, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
	0x00, 0xff, 0x01, 0x00, 0x58, 0x00, 0x08, 0x00, 0x13, 0xe9, 0x1c, 0x16, 0x0e, 0xcf, 0xd2, 0xbb,
	0x3a, 0x86, 0x83, 0xb6, 0x01, 0xc4, 0xba, 0xcb, 0x04, 0xf0, 0xa5, 0x18, 0x9b, 0x97, 0xd9, 0x2d,
	0x67, 0xf4, 0x6d, 0x69, 0xea, 0x1e, 0x25, 0x36, 0xdc, 0x10, 0x83, 0x7f, 0x37, 0xb5, 0x77, 0xd9,
	0x7e, 0x1b, 0xb5, 0xf2, 0xbf, 0x58, 0xf4, 0xd7, 0xa2, 0x05, 0xf2, 0xc9, 0x76, 0xcb, 0x32, 0x0e,
	0xa2, 0xd3, 0xbe, 0x32, 0xbe, 0x76, 0x0c, 0x0b, 0x04, 0x00, 0x00, 0x00, 0x53, 0x4b, 0x55, 0x31,
	0xa8, 0x6c, 0x1b, 0xf8, 0x53, 0xff, 0xec, 0x09, 0x32, 0x93, 0xb6, 0xd0, 0x70, 0x22, 0x15, 0x41,
	0x5b, 0x80, 0xbb, 0x27, 0xe3, 0x6c, 0x13, 0xeb, 0xc6, 0xc9, 0x9d, 0x90, 0x80, 0x48, 0x06, 0x5c,
	0x39, 0xcc, 0x96, 0x5a, 0xfc, 0x9f, 0x73, 0x45, 0x28, 0xfa, 0x52, 0xcd, 0xf5, 0x94, 0x8e, 0x54,
	0x62, 0x8f, 0xf2, 0xce, 0x76, 0x8e, 0x1e, 0xf4, 0x44, 0x77, 0x03, 0x42, 0x29, 0xca, 0xc2, 0xd2,
	0xf2, 0x2a, 0xe8, 0x06, 0x1c, 0x05, 0xda, 0xee, 0xe3, 0x62, 0x89, 0xb2, 0xf1, 0x37, 0x52, 0x4c,
	0x05, 0x01, 0xcd, 0x18, 0x22, 0x83, 0xa7, 0xd7, 0xd6, 0xef, 0xfc, 0x4c, 0xc9, 0x04, 0x90, 0x55,
	0x36, 0xb9, 0x77, 0x89, 0xe3, 0x77, 0x42, 0x32, 0x93, 0x09, 0x01, 0x65, 0x09, 0xf3, 0xe2, 0x2c,
	0x08, 0xf0, 0x6e, 0x38, 0xec, 0x47, 0x09, 0xc2, 0x43, 0x45, 0xd9, 0xf1, 0x54, 0xa0, 0x85, 0x93,
	0x1e, 0x28, 0xbb, 0xe9, 0xf0, 0x64, 0x69, 0x80, 0x77, 0x94, 0xc7, 0xc9, 0x30, 0xd8, 0xbe, 0x49,
	0xd1, 0x4e, 0xad, 0x22, 0x21, 0x06, 0x12, 0x8b, 0xf7, 0xd7, 0xcb, 0xb7, 0x65, 0x8e, 0x87, 0x05,
	0x33, 0x52, 0x4e, 0xdb, 0xbe, 0x5f, 0xcb, 0x74, 0xb9, 0x19, 0x98, 0xb5, 0xa8, 0x0c, 0xfa, 0x83,
	0xb3, 0xa6, 0x6a, 0xcc, 0xe8, 0x4f, 0xc5, 0xac, 0x71, 0x47, 0xd8, 0x62, 0xd5, 0x37, 0x96, 0x5e,
	0x64, 0x30, 0x20, 0xc4, 0xcf, 0x7f, 0x5c, 0x50, 0x5d, 0x16, 0xd7, 0x4e, 0xbf, 0x46, 0x58, 0x18,
	0xc3, 0xef, 0xbb, 0xa1, 0x41, 0xa1, 0xad, 0xb1, 0x59, 0xe4, 0x6c, 0x9e, 0xa6, 0x83, 0x0d, 0x93,
	0xfa, 0xb7, 0xc6, 0x94, 0xed, 0x43, 0x43, 0x4c, 0x82, 0x56, 0xd9, 0x93, 0x89, 0x76, 0x14, 0x8f,
	0xec, 0xb7, 0x7a, 0x1e, 0x63, 0x17, 0xc5, 0x9a, 0x49, 0xc1, 0x79, 0x2b, 0x42, 0x41, 0x70, 0x60
};

/**
 * Length of the testing empty PCD.
 */
const uint32_t PCD_EMPTY_DATA_LEN = sizeof (PCD_EMPTY_DATA);

/**
 * PCD_DATA_EMPTY hash for testing.
 *
 * head -c -256 <file> | openssl dgst -sha256 -binary | to_array.sh -
 */
const uint8_t PCD_EMPTY_HASH[] = {
	0xf1, 0xc7, 0xcb, 0xf1, 0x74, 0xa8, 0x85, 0x3e, 0xbc, 0x13, 0xb7, 0x73, 0xd1, 0xeb, 0x7a, 0x52,
	0x69, 0x8e, 0x0a, 0x94, 0x45, 0x36, 0x06, 0xe3, 0x00, 0x7b, 0xa6, 0xf4, 0x68, 0xcf, 0x95, 0xe1
};

/**
 * The platform ID for the empty PCD.
 */
const char PCD_EMPTY_PLATFORM_ID[] = "SKU1";

/**
 * Components of the test empty PCD.
 */
const struct pcd_testing_data PCD_EMPTY_TESTING = {
	.manifest = {
		.raw = PCD_EMPTY_DATA,
		.length = sizeof (PCD_EMPTY_DATA),
		.hash = PCD_EMPTY_HASH,
		.hash_len = sizeof (PCD_EMPTY_HASH),
		.id = 0x20,
		.signature = PCD_EMPTY_DATA + (sizeof (PCD_EMPTY_DATA) - 256),
		.sig_len = 256,
		.sig_offset = (sizeof (PCD_EMPTY_DATA) - 256),
		.sig_hash_type = HASH_TYPE_SHA256,
		.toc = PCD_EMPTY_DATA + MANIFEST_V2_TOC_HDR_OFFSET,
		.toc_len = 0x0044,
		.toc_hash = PCD_EMPTY_DATA + 0x0038,
		.toc_hash_len = 32,
		.toc_hash_offset = 0x0038,
		.toc_hash_type = HASH_TYPE_SHA256,
		.toc_entries = 1,
		.toc_hashes = 1,
		.plat_id = PCD_EMPTY_DATA + 0x0058,
		.plat_id_len = 0x008,
		.plat_id_str = PCD_EMPTY_PLATFORM_ID,
		.plat_id_str_len = sizeof (PCD_EMPTY_PLATFORM_ID) - 1,
		.plat_id_str_pad = 0,
		.plat_id_offset = 0x0058,
		.plat_id_entry = 0,
		.plat_id_hash = 0
	},
	.rot_len = 0,
	.rot_offset = 0,
	.rot_entry = -1,
	.rot_hash = -1,
	.power_ctrl_len = 0,
	.power_ctrl_offset = 0,
	.power_ctrl_entry = -1,
	.power_ctrl_hash = -1,
	.bridge_component_len = 0,
	.bridge_component_offset = 0,
	.bridge_component_entry = -1,
	.bridge_component_hash = -1,
	.direct_component_len = 0,
	.direct_component_offset = 0,
	.direct_component_entry = -1,
	.direct_component_hash = -1,
	.port_len = 0,
	.port_offset = 0,
	.port_entry = -1,
	.port_hash = -1,
	.num_optional_elements = 0,
};

/**
 * Dependencies for testing PCDs.
 */
struct pcd_flash_testing {
	struct manifest_flash_v2_testing manifest;	/**< Common dependencies for manifest testing. */
	struct pcd_flash_state state;				/**< Context for the PCD test instance. */
	struct pcd_flash test;						/**< PCD instance under test. */
};


/**
 * Initialize common PCD testing dependencies.
 *
 * @param test The testing framework.
 * @param pcd The testing components to initialize.
 * @param address The base address for the PCD data.
 */
static void pcd_flash_testing_init_dependencies (CuTest *test, struct pcd_flash_testing *pcd,
	uint32_t address)
{
	manifest_flash_v2_testing_init_dependencies (test, &pcd->manifest, address);
}

/**
 * Release test dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param pcd The testing components to release.
 */
static void pcd_flash_testing_validate_and_release_dependencies (CuTest *test,
	struct pcd_flash_testing *pcd)
{
	manifest_flash_v2_testing_validate_and_release_dependencies (test, &pcd->manifest);
}

/**
 * Initialize a PCD for testing.
 *
 * @param test The testing framework.
 * @param pcd The testing components to initialize.
 * @param address The base address for the PCD data.
 */
static void pcd_flash_testing_init (CuTest *test, struct pcd_flash_testing *pcd, uint32_t address)
{
	int status;

	pcd_flash_testing_init_dependencies (test, pcd, address);
	manifest_flash_v2_testing_init_common (test, &pcd->manifest, 0x1000);

	status = pcd_flash_init (&pcd->test, &pcd->state, &pcd->manifest.flash.base,
		&pcd->manifest.hash.base, address, pcd->manifest.signature,
		sizeof (pcd->manifest.signature), pcd->manifest.platform_id,
		sizeof (pcd->manifest.platform_id));
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&pcd->manifest.flash.mock);
	status |= mock_validate (&pcd->manifest.verification.mock);
	status |= mock_validate (&pcd->manifest.hash_mock.mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a static PCD for testing.
 *
 * @param test The testing framework.
 * @param pcd The testing components to initialize.
 * @param address The base address for the PCD data.
 */
static void pcd_flash_testing_init_static (CuTest *test, struct pcd_flash_testing *pcd,
	uint32_t address)
{
	int status;

	pcd_flash_testing_init_dependencies (test, pcd, address);
	manifest_flash_v2_testing_init_common (test, &pcd->manifest, 0x1000);

	status = pcd_flash_init_state (&pcd->test);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&pcd->manifest.flash.mock);
	status |= mock_validate (&pcd->manifest.verification.mock);
	status |= mock_validate (&pcd->manifest.hash_mock.mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a PCD for testing with mocked hash engine.
 *
 * @param test The testing framework.
 * @param pcd The testing components to initialize.
 * @param address The base address for the PCD data.
 */
static void pcd_flash_testing_init_mocked_hash (CuTest *test, struct pcd_flash_testing *pcd,
	uint32_t address)
{
	int status;

	pcd_flash_testing_init_dependencies (test, pcd, address);
	manifest_flash_v2_testing_init_common (test, &pcd->manifest, 0x1000);

	status = pcd_flash_init (&pcd->test, &pcd->state, &pcd->manifest.flash.base,
		&pcd->manifest.hash_mock.base, address, pcd->manifest.signature,
		sizeof (pcd->manifest.signature), pcd->manifest.platform_id,
		sizeof (pcd->manifest.platform_id));
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&pcd->manifest.flash.mock);
	status |= mock_validate (&pcd->manifest.verification.mock);
	status |= mock_validate (&pcd->manifest.hash_mock.mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param pcd The testing components to release.
 */
static void pcd_flash_testing_validate_and_release (CuTest *test, struct pcd_flash_testing *pcd)
{
	pcd_flash_release (&pcd->test);

	pcd_flash_testing_validate_and_release_dependencies (test, pcd);
}

/**
 * Set up expectations for verifying a PCD on flash.
 *
 * @param test The testing framework.
 * @param pcd The testing components.
 * @param testing_data Container with testing data.
 * @param sig_result Result of the signature verification call.
 */
static void pcd_flash_testing_verify_pcd (CuTest *test, struct pcd_flash_testing *pcd,
	const struct pcd_testing_data *testing_data, int sig_result)
{
	manifest_flash_v2_testing_verify_manifest (test, &pcd->manifest, &testing_data->manifest,
		sig_result);
}

/**
 * Set up expectations for verifying a PCD on flash with mocked hash engine.
 *
 * @param test The testing framework.
 * @param pcd The testing components.
 * @param testing_data Container with testing data.
 * @param sig_result Result of the signature verification call.
 * @param hash_result Result of the call to finalize the manifest hash.
 */
static void pcd_flash_testing_verify_pcd_mocked_hash (CuTest *test, struct pcd_flash_testing *pcd,
	const struct pcd_testing_data *testing_data, int sig_result, int hash_result)
{
	manifest_flash_v2_testing_verify_manifest_mocked_hash (test, &pcd->manifest,
		&testing_data->manifest, sig_result, hash_result);
}


/**
 * Initialize a PCD for testing.  Run verification to load the PCD information.
 *
 * @param test The testing framework.
 * @param pcd The testing components to initialize.
 * @param address The base address for the PCD data.
 * @param testing_data Container with testing data.
 * @param sig_result Result of the signature verification call.
 * @param use_mock true to use the mock hash engine.
 * @param hash_result Result of the final hash call when using the mock hash engine.
 */
static void pcd_flash_testing_init_and_verify (CuTest *test, struct pcd_flash_testing *pcd,
	uint32_t address, const struct pcd_testing_data *testing_data, int sig_result, bool use_mock,
	int hash_result)
{
	struct hash_engine *hash =
		(!use_mock) ? &pcd->manifest.hash.base : &pcd->manifest.hash_mock.base;
	int status;

	if (!use_mock) {
		pcd_flash_testing_init (test, pcd, address);
		pcd_flash_testing_verify_pcd (test, pcd, testing_data, sig_result);
	}
	else {
		pcd_flash_testing_init_mocked_hash (test, pcd, address);
		pcd_flash_testing_verify_pcd_mocked_hash (test, pcd, testing_data, sig_result, hash_result);
	}

	status = pcd->test.base.base.verify (&pcd->test.base.base, hash,
		&pcd->manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, sig_result, status);

	status = mock_validate (&pcd->manifest.flash.mock);
	status |= mock_validate (&pcd->manifest.verification.mock);
	status |= mock_validate (&pcd->manifest.hash_mock.mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a static PCD for testing.  Run verification to load the PCD information.
 *
 * @param test The testing framework.
 * @param pcd The testing components to initialize.
 * @param address The base address for the PCD data.
 * @param testing_data Container with testing data.
 * @param sig_result Result of the signature verification call.
 * @param use_mock true to use the mock hash engine.
 * @param hash_result Result of the final hash call when using the mock hash engine.
 */
static void pcd_flash_testing_init_static_and_verify (CuTest *test, struct pcd_flash_testing *pcd,
	uint32_t address, const struct pcd_testing_data *testing_data, int sig_result, bool use_mock,
	int hash_result)
{
	struct hash_engine *hash =
		(!use_mock) ? &pcd->manifest.hash.base : &pcd->manifest.hash_mock.base;
	int status;

	pcd_flash_testing_init_static (test, pcd, address);

	if (!use_mock) {
		pcd_flash_testing_verify_pcd (test, pcd, testing_data, sig_result);
	}
	else {
		pcd_flash_testing_verify_pcd_mocked_hash (test, pcd, testing_data, sig_result, hash_result);
	}

	status = pcd->test.base.base.verify (&pcd->test.base.base, hash,
		&pcd->manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, sig_result, status);

	status = mock_validate (&pcd->manifest.flash.mock);
	status |= mock_validate (&pcd->manifest.verification.mock);
	status |= mock_validate (&pcd->manifest.hash_mock.mock);
	CuAssertIntEquals (test, 0, status);
}

/*******************
 * Test cases
 *******************/

static void pcd_flash_test_init (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;

	TEST_START;

	pcd_flash_testing_init_dependencies (test, &pcd, 0x10000);
	manifest_flash_v2_testing_init_common (test, &pcd.manifest, 0x1000);

	status = pcd_flash_init (&pcd.test, &pcd.state, &pcd.manifest.flash.base,
		&pcd.manifest.hash.base, 0x10000, pcd.manifest.signature, sizeof (pcd.manifest.signature),
		pcd.manifest.platform_id, sizeof (pcd.manifest.platform_id));
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, pcd.test.base.base.verify);
	CuAssertPtrNotNull (test, pcd.test.base.base.get_id);
	CuAssertPtrNotNull (test, pcd.test.base.base.get_platform_id);
	CuAssertPtrNotNull (test, pcd.test.base.base.free_platform_id);
	CuAssertPtrNotNull (test, pcd.test.base.base.get_hash);
	CuAssertPtrNotNull (test, pcd.test.base.base.get_signature);
	CuAssertPtrNotNull (test, pcd.test.base.base.is_empty);

	CuAssertPtrNotNull (test, pcd.test.base.buffer_supported_components);
	CuAssertPtrNotNull (test, pcd.test.base.get_next_mctp_bridge_component);
	CuAssertPtrNotNull (test, pcd.test.base.get_rot_info);
	CuAssertPtrNotNull (test, pcd.test.base.get_port_info);
	CuAssertPtrNotNull (test, pcd.test.base.get_power_controller_info);

	CuAssertIntEquals (test, 0x10000, manifest_flash_get_addr (&pcd.test.base_flash));
	CuAssertPtrEquals (test, &pcd.manifest.flash,
		(void*) manifest_flash_get_flash (&pcd.test.base_flash));

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_init_null (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;

	TEST_START;

	pcd_flash_testing_init_dependencies (test, &pcd, 0x10000);

	status = pcd_flash_init (NULL, &pcd.state, &pcd.manifest.flash.base, &pcd.manifest.hash.base,
		0x10000, pcd.manifest.signature, sizeof (pcd.manifest.signature), pcd.manifest.platform_id,
		sizeof (pcd.manifest.platform_id));
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = pcd_flash_init (&pcd.test, NULL, &pcd.manifest.flash.base, &pcd.manifest.hash.base,
		0x10000, pcd.manifest.signature, sizeof (pcd.manifest.signature), pcd.manifest.platform_id,
		sizeof (pcd.manifest.platform_id));
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = pcd_flash_init (&pcd.test, &pcd.state, NULL, &pcd.manifest.hash.base, 0x10000,
		pcd.manifest.signature, sizeof (pcd.manifest.signature), pcd.manifest.platform_id,
		sizeof (pcd.manifest.platform_id));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = pcd_flash_init (&pcd.test, &pcd.state, &pcd.manifest.flash.base, NULL, 0x10000,
		pcd.manifest.signature, sizeof (pcd.manifest.signature), pcd.manifest.platform_id,
		sizeof (pcd.manifest.platform_id));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = pcd_flash_init (&pcd.test, &pcd.state, &pcd.manifest.flash.base,
		&pcd.manifest.hash.base, 0x10000, NULL, sizeof (pcd.manifest.signature),
		pcd.manifest.platform_id, sizeof (pcd.manifest.platform_id));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = pcd_flash_init (&pcd.test, &pcd.state, NULL, &pcd.manifest.hash.base, 0x10000,
		pcd.manifest.signature, sizeof (pcd.manifest.signature), NULL,
		sizeof (pcd.manifest.platform_id));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	pcd_flash_testing_validate_and_release_dependencies (test, &pcd);
}

static void pcd_flash_test_init_manifest_flash_init_fail (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;

	TEST_START;

	pcd_flash_testing_init_dependencies (test, &pcd, 0x10001);
	manifest_flash_v2_testing_init_common (test, &pcd.manifest, 0x1000);

	status = pcd_flash_init (&pcd.test, &pcd.state, &pcd.manifest.flash.base,
		&pcd.manifest.hash.base, 0x10001, pcd.manifest.signature, sizeof (pcd.manifest.signature),
		pcd.manifest.platform_id, sizeof (pcd.manifest.platform_id));
	CuAssertIntEquals (test, MANIFEST_STORAGE_NOT_ALIGNED, status);

	pcd_flash_testing_validate_and_release_dependencies (test, &pcd);
}

static void pcd_flash_test_static_init (CuTest *test)
{
	struct pcd_flash_testing pcd = {
		.test = pcd_flash_static_init (&pcd.state, &pcd.manifest.flash.base,
			&pcd.manifest.hash.base, 0x10000, pcd.manifest.signature,
			sizeof (pcd.manifest.signature), pcd.manifest.platform_id,
			sizeof (pcd.manifest.platform_id))
	};
	int status;

	TEST_START;

	CuAssertPtrNotNull (test, pcd.test.base.base.verify);
	CuAssertPtrNotNull (test, pcd.test.base.base.get_id);
	CuAssertPtrNotNull (test, pcd.test.base.base.get_platform_id);
	CuAssertPtrNotNull (test, pcd.test.base.base.free_platform_id);
	CuAssertPtrNotNull (test, pcd.test.base.base.get_hash);
	CuAssertPtrNotNull (test, pcd.test.base.base.get_signature);
	CuAssertPtrNotNull (test, pcd.test.base.base.is_empty);

	CuAssertPtrNotNull (test, pcd.test.base.buffer_supported_components);
	CuAssertPtrNotNull (test, pcd.test.base.get_next_mctp_bridge_component);
	CuAssertPtrNotNull (test, pcd.test.base.get_rot_info);
	CuAssertPtrNotNull (test, pcd.test.base.get_port_info);
	CuAssertPtrNotNull (test, pcd.test.base.get_power_controller_info);

	pcd_flash_testing_init_dependencies (test, &pcd, 0x10000);
	manifest_flash_v2_testing_init_common (test, &pcd.manifest, 0x1000);

	status = pcd_flash_init_state (&pcd.test);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 0x10000, manifest_flash_get_addr (&pcd.test.base_flash));
	CuAssertPtrEquals (test, &pcd.manifest.flash,
		(void*) manifest_flash_get_flash (&pcd.test.base_flash));

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_static_init_null (CuTest *test)
{
	struct pcd_flash_testing pcd = {
		.test = pcd_flash_static_init (&pcd.state, &pcd.manifest.flash.base,
			&pcd.manifest.hash.base, 0x10000, pcd.manifest.signature,
			sizeof (pcd.manifest.signature), pcd.manifest.platform_id,
			sizeof (pcd.manifest.platform_id))
	};

	struct pcd_flash null_state = pcd_flash_static_init ((struct pcd_flash_state*) NULL,
		&pcd.manifest.flash.base, &pcd.manifest.hash.base, 0x10000, pcd.manifest.signature,
		sizeof (pcd.manifest.signature), pcd.manifest.platform_id,
		sizeof (pcd.manifest.platform_id));

	struct pcd_flash null_flash = pcd_flash_static_init (&pcd.state, NULL, &pcd.manifest.hash.base,
		0x10000, pcd.manifest.signature, sizeof (pcd.manifest.signature), pcd.manifest.platform_id,
		sizeof (pcd.manifest.platform_id));

	struct pcd_flash null_hash = pcd_flash_static_init (&pcd.state, &pcd.manifest.flash.base, NULL,
		0x10000, pcd.manifest.signature, sizeof (pcd.manifest.signature), pcd.manifest.platform_id,
		sizeof (pcd.manifest.platform_id));

	struct pcd_flash null_sig = pcd_flash_static_init (&pcd.state, &pcd.manifest.flash.base,
		&pcd.manifest.hash.base, 0x10000, NULL, sizeof (pcd.manifest.signature),
		pcd.manifest.platform_id, sizeof (pcd.manifest.platform_id));

	struct pcd_flash null_plat_id = pcd_flash_static_init (&pcd.state, &pcd.manifest.flash.base,
		&pcd.manifest.hash.base, 0x10000, pcd.manifest.signature, sizeof (pcd.manifest.signature),
		NULL, sizeof (pcd.manifest.platform_id));
	int status;

	TEST_START;

	pcd_flash_testing_init_dependencies (test, &pcd, 0x10000);

	status = pcd_flash_init_state (NULL);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = pcd_flash_init_state (&null_state);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = pcd_flash_init_state (&null_flash);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = pcd_flash_init_state (&null_hash);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = pcd_flash_init_state (&null_sig);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = pcd_flash_init_state (&null_plat_id);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	pcd_flash_testing_validate_and_release_dependencies (test, &pcd);
}

static void pcd_flash_test_static_init_manifest_flash_init_fail (CuTest *test)
{
	struct pcd_flash_testing pcd = {
		.test = pcd_flash_static_init (&pcd.state, &pcd.manifest.flash.base,
			&pcd.manifest.hash.base, 0x10001, pcd.manifest.signature,
			sizeof (pcd.manifest.signature), pcd.manifest.platform_id,
			sizeof (pcd.manifest.platform_id))
	};
	int status;

	TEST_START;

	pcd_flash_testing_init_dependencies (test, &pcd, 0x10001);
	manifest_flash_v2_testing_init_common (test, &pcd.manifest, 0x1000);

	status = pcd_flash_init_state (&pcd.test);
	CuAssertIntEquals (test, MANIFEST_STORAGE_NOT_ALIGNED, status);

	pcd_flash_testing_validate_and_release_dependencies (test, &pcd);
}

static void pcd_flash_test_release_null (CuTest *test)
{
	TEST_START;

	pcd_flash_release (NULL);
}

static void pcd_flash_test_verify (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	pcd_flash_testing_verify_pcd (test, &pcd, &PCD_TESTING, 0);

	status = pcd.test.base.base.verify (&pcd.test.base.base, &pcd.manifest.hash.base,
		&pcd.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_verify_no_power_controller (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	pcd_flash_testing_verify_pcd (test, &pcd, &PCD_NO_POWER_CONTROLLER_TESTING, 0);

	status = pcd.test.base.base.verify (&pcd.test.base.base, &pcd.manifest.hash.base,
		&pcd.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_verify_no_components (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	pcd_flash_testing_verify_pcd (test, &pcd, &PCD_NO_COMPONENTS_TESTING, 0);

	status = pcd.test.base.base.verify (&pcd.test.base.base, &pcd.manifest.hash.base,
		&pcd.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_verify_no_ports (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	pcd_flash_testing_verify_pcd (test, &pcd, &PCD_NO_PORTS_TESTING, 0);

	status = pcd.test.base.base.verify (&pcd.test.base.base, &pcd.manifest.hash.base,
		&pcd.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_verify_no_ports_power_controller_components (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	pcd_flash_testing_verify_pcd (test, &pcd, &PCD_NO_PORTS_POWER_CONTROLLER_COMPONENTS_TESTING, 0);

	status = pcd.test.base.base.verify (&pcd.test.base.base, &pcd.manifest.hash.base,
		&pcd.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_verify_only_direct_components (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	pcd_flash_testing_verify_pcd (test, &pcd, &PCD_ONLY_DIRECT_COMPONENTS_TESTING, 0);

	status = pcd.test.base.base.verify (&pcd.test.base.base, &pcd.manifest.hash.base,
		&pcd.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_verify_multiple_direct_components (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	pcd_flash_testing_verify_pcd (test, &pcd, &PCD_MULTIPLE_DIRECT_COMPONENTS_TESTING, 0);

	status = pcd.test.base.base.verify (&pcd.test.base.base, &pcd.manifest.hash.base,
		&pcd.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_verify_only_bridge_components (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	pcd_flash_testing_verify_pcd (test, &pcd, &PCD_ONLY_BRIDGE_COMPONENTS_TESTING, 0);

	status = pcd.test.base.base.verify (&pcd.test.base.base, &pcd.manifest.hash.base,
		&pcd.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_verify_multiple_bridge_components (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	pcd_flash_testing_verify_pcd (test, &pcd, &PCD_MULTIPLE_BRIDGE_COMPONENTS_TESTING, 0);

	status = pcd.test.base.base.verify (&pcd.test.base.base, &pcd.manifest.hash.base,
		&pcd.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_verify_filtered_bypass_pulse_reset (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	pcd_flash_testing_verify_pcd (test, &pcd, &PCD_FILTERED_BYPASS_PULSE_RESET_TESTING, 0);

	status = pcd.test.base.base.verify (&pcd.test.base.base, &pcd.manifest.hash.base,
		&pcd.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_verify_empty_manifest (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	pcd_flash_testing_verify_pcd (test, &pcd, &PCD_EMPTY_TESTING, 0);

	status = pcd.test.base.base.verify (&pcd.test.base.base, &pcd.manifest.hash.base,
		&pcd.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_verify_static_init (CuTest *test)
{
	struct pcd_flash_testing pcd = {
		.test = pcd_flash_static_init (&pcd.state, &pcd.manifest.flash.base,
			&pcd.manifest.hash.base, 0x10000, pcd.manifest.signature,
			sizeof (pcd.manifest.signature), pcd.manifest.platform_id,
			sizeof (pcd.manifest.platform_id))
	};
	int status;

	TEST_START;

	pcd_flash_testing_init_static (test, &pcd, 0x10000);

	pcd_flash_testing_verify_pcd (test, &pcd, &PCD_TESTING, 0);

	status = pcd.test.base.base.verify (&pcd.test.base.base, &pcd.manifest.hash.base,
		&pcd.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_verify_null (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = pcd.test.base.base.verify (NULL, &pcd.manifest.hash.base,
		&pcd.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = pcd.test.base.base.verify (&pcd.test.base.base, NULL, &pcd.manifest.verification.base,
		NULL, 0);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = pcd.test.base.base.verify (&pcd.test.base.base, &pcd.manifest.hash.base, NULL, NULL,
		0);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_verify_read_header_fail (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = mock_expect (&pcd.manifest.flash.mock, pcd.manifest.flash.base.read,
		&pcd.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (pcd.manifest.addr), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.base.verify (&pcd.test.base.base, &pcd.manifest.hash.base,
		&pcd.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_verify_bad_magic_number (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;
	uint8_t pcd_bad_data[MANIFEST_V2_HEADER_SIZE];

	TEST_START;

	memcpy (pcd_bad_data, PCD_TESTING.manifest.raw, sizeof (pcd_bad_data));
	pcd_bad_data[2] ^= 0x55;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = mock_expect (&pcd.manifest.flash.mock, pcd.manifest.flash.base.read,
		&pcd.manifest.flash, 0, MOCK_ARG (pcd.manifest.addr), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&pcd.manifest.flash.mock, 1, pcd_bad_data,
		MANIFEST_V2_HEADER_SIZE, 2);
	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.base.verify (&pcd.test.base.base, &pcd.manifest.hash.base,
		&pcd.manifest.verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_id (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;
	uint32_t id;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_TESTING, 0, false, 0);

	status = pcd.test.base.base.get_id (&pcd.test.base.base, &id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x1A, id);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_id_static_init (CuTest *test)
{
	struct pcd_flash_testing pcd = {
		.test = pcd_flash_static_init (&pcd.state, &pcd.manifest.flash.base,
			&pcd.manifest.hash.base, 0x10000, pcd.manifest.signature,
			sizeof (pcd.manifest.signature), pcd.manifest.platform_id,
			sizeof (pcd.manifest.platform_id))
	};
	int status;
	uint32_t id;

	TEST_START;

	pcd_flash_testing_init_static_and_verify (test, &pcd, 0x10000, &PCD_TESTING, 0, false, 0);

	status = pcd.test.base.base.get_id (&pcd.test.base.base, &id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x1A, id);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_id_null (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;
	uint32_t id;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_TESTING, 0, false, 0);

	status = pcd.test.base.base.get_id (NULL, &id);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = pcd.test.base.base.get_id (&pcd.test.base.base, NULL);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_id_verify_never_run (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;
	uint32_t id;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = pcd.test.base.base.get_id (&pcd.test.base.base, &id);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_hash (CuTest *test)
{
	struct pcd_flash_testing pcd;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	/* Read manifest header. */
	status = mock_expect (&pcd.manifest.flash.mock, pcd.manifest.flash.base.read,
		&pcd.manifest.flash, 0, MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&pcd.manifest.flash.mock, 1, PCD_TESTING.manifest.raw,
		MANIFEST_V2_HEADER_SIZE, 2);

	status |= flash_mock_expect_verify_flash (&pcd.manifest.flash, 0x10000,
		PCD_TESTING.manifest.raw, PCD_DATA_LEN - PCD_TESTING.manifest.sig_len);

	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.base.get_hash (&pcd.test.base.base, &pcd.manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCD_TESTING.manifest.hash, hash_out,
		PCD_TESTING.manifest.hash_len);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_hash_after_verify (CuTest *test)
{
	struct pcd_flash_testing pcd;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_TESTING, 0, false, 0);

	status = pcd.test.base.base.get_hash (&pcd.test.base.base, &pcd.manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCD_TESTING.manifest.hash, hash_out,
		PCD_TESTING.manifest.hash_len);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_hash_static_init (CuTest *test)
{
	struct pcd_flash_testing pcd = {
		.test = pcd_flash_static_init (&pcd.state, &pcd.manifest.flash.base,
			&pcd.manifest.hash.base, 0x10000, pcd.manifest.signature,
			sizeof (pcd.manifest.signature), pcd.manifest.platform_id,
			sizeof (pcd.manifest.platform_id))
	};
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	pcd_flash_testing_init_static (test, &pcd, 0x10000);

	/* Read manifest header. */
	status = mock_expect (&pcd.manifest.flash.mock, pcd.manifest.flash.base.read,
		&pcd.manifest.flash, 0, MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&pcd.manifest.flash.mock, 1, PCD_TESTING.manifest.raw,
		MANIFEST_V2_HEADER_SIZE, 2);

	status |= flash_mock_expect_verify_flash (&pcd.manifest.flash, 0x10000,
		PCD_TESTING.manifest.raw, PCD_DATA_LEN - PCD_TESTING.manifest.sig_len);

	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.base.get_hash (&pcd.test.base.base, &pcd.manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, SHA256_HASH_LENGTH, status);

	status = testing_validate_array (PCD_TESTING.manifest.hash, hash_out,
		PCD_TESTING.manifest.hash_len);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_hash_null (CuTest *test)
{
	struct pcd_flash_testing pcd;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_TESTING, 0, false, 0);

	status = pcd.test.base.base.get_hash (NULL, &pcd.manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = pcd.test.base.base.get_hash (&pcd.test.base.base, NULL, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = pcd.test.base.base.get_hash (&pcd.test.base.base, &pcd.manifest.hash.base, NULL,
		sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_hash_bad_magic_num (CuTest *test)
{
	struct pcd_flash_testing pcd;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;
	uint8_t pcd_bad_data[PCD_TESTING.manifest.sig_offset];

	TEST_START;

	memcpy (pcd_bad_data, PCD_TESTING.manifest.raw, sizeof (pcd_bad_data));
	pcd_bad_data[2] ^= 0x55;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = mock_expect (&pcd.manifest.flash.mock, pcd.manifest.flash.base.read,
		&pcd.manifest.flash, 0, MOCK_ARG (pcd.manifest.addr), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&pcd.manifest.flash.mock, 1, pcd_bad_data,
		MANIFEST_V2_HEADER_SIZE, 2);
	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.base.get_hash (&pcd.test.base.base, &pcd.manifest.hash.base, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_signature (CuTest *test)
{
	struct pcd_flash_testing pcd;
	uint8_t sig_out[PCD_TESTING.manifest.sig_len];
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = mock_expect (&pcd.manifest.flash.mock, pcd.manifest.flash.base.read,
		&pcd.manifest.flash, 0, MOCK_ARG (pcd.manifest.addr), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&pcd.manifest.flash.mock, 1, PCD_TESTING.manifest.raw,
		MANIFEST_V2_HEADER_SIZE, 2);

	status |= mock_expect (&pcd.manifest.flash.mock, pcd.manifest.flash.base.read,
		&pcd.manifest.flash, 0, MOCK_ARG (pcd.manifest.addr + PCD_TESTING.manifest.sig_offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCD_TESTING.manifest.sig_len));
	status |= mock_expect_output (&pcd.manifest.flash.mock, 1, PCD_TESTING.manifest.signature,
		PCD_TESTING.manifest.sig_len, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.base.get_signature (&pcd.test.base.base, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, PCD_TESTING.manifest.sig_len, status);

	status = testing_validate_array (PCD_TESTING.manifest.signature, sig_out,
		PCD_TESTING.manifest.sig_len);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_signature_after_verify (CuTest *test)
{
	struct pcd_flash_testing pcd;
	uint8_t sig_out[PCD_TESTING.manifest.sig_len];
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_TESTING, 0, false, 0);

	status = pcd.test.base.base.get_signature (&pcd.test.base.base, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, PCD_TESTING.manifest.sig_len, status);

	status = testing_validate_array (PCD_TESTING.manifest.signature, sig_out,
		PCD_TESTING.manifest.sig_len);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_signature_static_init (CuTest *test)
{
	struct pcd_flash_testing pcd = {
		.test = pcd_flash_static_init (&pcd.state, &pcd.manifest.flash.base,
			&pcd.manifest.hash.base, 0x10000, pcd.manifest.signature,
			sizeof (pcd.manifest.signature), pcd.manifest.platform_id,
			sizeof (pcd.manifest.platform_id))
	};
	uint8_t sig_out[PCD_TESTING.manifest.sig_len];
	int status;

	TEST_START;

	pcd_flash_testing_init_static (test, &pcd, 0x10000);

	status = mock_expect (&pcd.manifest.flash.mock, pcd.manifest.flash.base.read,
		&pcd.manifest.flash, 0, MOCK_ARG (pcd.manifest.addr), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&pcd.manifest.flash.mock, 1, PCD_TESTING.manifest.raw,
		MANIFEST_V2_HEADER_SIZE, 2);

	status |= mock_expect (&pcd.manifest.flash.mock, pcd.manifest.flash.base.read,
		&pcd.manifest.flash, 0, MOCK_ARG (pcd.manifest.addr + PCD_TESTING.manifest.sig_offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCD_TESTING.manifest.sig_len));
	status |= mock_expect_output (&pcd.manifest.flash.mock, 1, PCD_TESTING.manifest.signature,
		PCD_TESTING.manifest.sig_len, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.base.get_signature (&pcd.test.base.base, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, PCD_TESTING.manifest.sig_len, status);

	status = testing_validate_array (PCD_TESTING.manifest.signature, sig_out,
		PCD_TESTING.manifest.sig_len);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_signature_null (CuTest *test)
{
	struct pcd_flash_testing pcd;
	uint8_t sig_out[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_TESTING, 0, false, 0);

	status = pcd.test.base.base.get_signature (NULL, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = pcd.test.base.base.get_signature (&pcd.test.base.base, NULL, sizeof (sig_out));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_signature_bad_magic_number (CuTest *test)
{
	struct pcd_flash_testing pcd;
	uint8_t sig_out[SHA256_HASH_LENGTH];
	int status;
	uint8_t pcd_bad_data[MANIFEST_V2_HEADER_SIZE];

	TEST_START;

	memcpy (pcd_bad_data, PCD_TESTING.manifest.raw, sizeof (pcd_bad_data));
	pcd_bad_data[2] ^= 0x55;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = mock_expect (&pcd.manifest.flash.mock, pcd.manifest.flash.base.read,
		&pcd.manifest.flash, 0, MOCK_ARG (pcd.manifest.addr), MOCK_ARG_NOT_NULL,
		MOCK_ARG (MANIFEST_V2_HEADER_SIZE));
	status |= mock_expect_output (&pcd.manifest.flash.mock, 1, pcd_bad_data,
		MANIFEST_V2_HEADER_SIZE, 2);

	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.base.get_signature (&pcd.test.base.base, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_platform_id (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;
	char buffer[32];
	char *id = buffer;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_TESTING, 0, false, 0);

	status = pcd.test.base.base.get_platform_id (&pcd.test.base.base, &id, sizeof (buffer));
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, buffer, id);
	CuAssertStrEquals (test, PCD_TESTING.manifest.plat_id_str, id);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_platform_id_manifest_allocation (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;
	char *id = NULL;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_TESTING, 0, false, 0);

	status = pcd.test.base.base.get_platform_id (&pcd.test.base.base, &id, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, id);
	CuAssertStrEquals (test, PCD_TESTING.manifest.plat_id_str, id);

	pcd.test.base.base.free_platform_id (&pcd.test.base.base, id);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_platform_id_static_init (CuTest *test)
{
	struct pcd_flash_testing pcd = {
		.test = pcd_flash_static_init (&pcd.state, &pcd.manifest.flash.base,
			&pcd.manifest.hash.base, 0x10000, pcd.manifest.signature,
			sizeof (pcd.manifest.signature), pcd.manifest.platform_id,
			sizeof (pcd.manifest.platform_id))
	};
	int status;
	char buffer[32];
	char *id = buffer;

	TEST_START;

	pcd_flash_testing_init_static_and_verify (test, &pcd, 0x10000, &PCD_TESTING, 0, false, 0);

	status = pcd.test.base.base.get_platform_id (&pcd.test.base.base, &id, sizeof (buffer));
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, buffer, id);
	CuAssertStrEquals (test, PCD_TESTING.manifest.plat_id_str, id);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_platform_id_null (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;
	char *id = NULL;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_TESTING, 0, false, 0);

	status = pcd.test.base.base.get_platform_id (NULL, &id, 0);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = pcd.test.base.base.get_platform_id (&pcd.test.base.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_platform_id_verify_never_run (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;
	char buffer[32];
	char *id = buffer;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = pcd.test.base.base.get_platform_id (&pcd.test.base.base, &id, sizeof (buffer));
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_next_mctp_bridge_component (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_mctp_bridge_components_info info;
	uint32_t component_id1 = 1;
	uint32_t component_id2 = 2;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_ONLY_BRIDGE_COMPONENTS_TESTING, 0,
		false, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest,
		&PCD_ONLY_BRIDGE_COMPONENTS_TESTING.manifest,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_entry, 0,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_hash,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_offset,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_len,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_len, 0);

	status = pcd.test.base.get_next_mctp_bridge_component (&pcd.test.base, &info, true);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x0B, info.pci_vid);
	CuAssertIntEquals (test, 0x0A, info.pci_device_id);
	CuAssertIntEquals (test, 0x0D, info.pci_subsystem_vid);
	CuAssertIntEquals (test, 0x0C, info.pci_subsystem_id);
	CuAssertIntEquals (test, 0x02, info.components_count);
	CuAssertIntEquals (test, component_id1, info.component_id);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest,
		&PCD_ONLY_BRIDGE_COMPONENTS_TESTING.manifest,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_entry + 1,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_entry + 1,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_hash + 1,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_offset +
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_len,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_len,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_len, 0);

	status = pcd.test.base.get_next_mctp_bridge_component (&pcd.test.base, &info, false);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x0E, info.pci_vid);
	CuAssertIntEquals (test, 0x0D, info.pci_device_id);
	CuAssertIntEquals (test, 0x0A, info.pci_subsystem_vid);
	CuAssertIntEquals (test, 0x0F, info.pci_subsystem_id);
	CuAssertIntEquals (test, 0x01, info.components_count);
	CuAssertIntEquals (test, component_id2, info.component_id);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest,
		&PCD_ONLY_BRIDGE_COMPONENTS_TESTING.manifest, 0,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_entry + 2, 0, 0, 0, 0, 0);

	status = pcd.test.base.get_next_mctp_bridge_component (&pcd.test.base, &info, false);
	CuAssertIntEquals (test, MANIFEST_ELEMENT_NOT_FOUND, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_next_mctp_bridge_component_static_init (CuTest *test)
{
	struct pcd_flash_testing pcd = {
		.test = pcd_flash_static_init (&pcd.state, &pcd.manifest.flash.base,
			&pcd.manifest.hash.base, 0x10000, pcd.manifest.signature,
			sizeof (pcd.manifest.signature), pcd.manifest.platform_id,
			sizeof (pcd.manifest.platform_id))
	};
	struct pcd_mctp_bridge_components_info info;
	uint32_t component_id1 = 1;
	uint32_t component_id2 = 2;
	int status;

	TEST_START;

	pcd_flash_testing_init_static_and_verify (test, &pcd, 0x10000,
		&PCD_ONLY_BRIDGE_COMPONENTS_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest,
		&PCD_ONLY_BRIDGE_COMPONENTS_TESTING.manifest,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_entry, 0,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_hash,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_offset,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_len,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_len, 0);

	status = pcd.test.base.get_next_mctp_bridge_component (&pcd.test.base, &info, true);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x0B, info.pci_vid);
	CuAssertIntEquals (test, 0x0A, info.pci_device_id);
	CuAssertIntEquals (test, 0x0D, info.pci_subsystem_vid);
	CuAssertIntEquals (test, 0x0C, info.pci_subsystem_id);
	CuAssertIntEquals (test, 0x02, info.components_count);
	CuAssertIntEquals (test, component_id1, info.component_id);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest,
		&PCD_ONLY_BRIDGE_COMPONENTS_TESTING.manifest,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_entry + 1,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_entry + 1,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_hash + 1,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_offset +
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_len,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_len,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_len, 0);

	status = pcd.test.base.get_next_mctp_bridge_component (&pcd.test.base, &info, false);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x0E, info.pci_vid);
	CuAssertIntEquals (test, 0x0D, info.pci_device_id);
	CuAssertIntEquals (test, 0x0A, info.pci_subsystem_vid);
	CuAssertIntEquals (test, 0x0F, info.pci_subsystem_id);
	CuAssertIntEquals (test, 0x01, info.components_count);
	CuAssertIntEquals (test, component_id2, info.component_id);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest,
		&PCD_ONLY_BRIDGE_COMPONENTS_TESTING.manifest, 0,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_entry + 2, 0, 0, 0, 0, 0);

	status = pcd.test.base.get_next_mctp_bridge_component (&pcd.test.base, &info, false);
	CuAssertIntEquals (test, MANIFEST_ELEMENT_NOT_FOUND, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_next_mctp_bridge_component_null (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_mctp_bridge_components_info info;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_TESTING, 0, false, 0);

	status = pcd.test.base.get_next_mctp_bridge_component (NULL, &info, true);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = pcd.test.base.get_next_mctp_bridge_component (&pcd.test.base, NULL, true);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_next_mctp_bridge_component_verify_never_run (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_mctp_bridge_components_info info;
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = pcd.test.base.get_next_mctp_bridge_component (&pcd.test.base, &info, true);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_next_mctp_bridge_component_component_read_error (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_mctp_bridge_components_info info;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_TESTING, 0, false, 0);

	status = mock_expect (&pcd.manifest.flash.mock, pcd.manifest.flash.base.read,
		&pcd.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x08));
	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.get_next_mctp_bridge_component (&pcd.test.base, &info, true);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_next_mctp_bridge_component_no_components (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_mctp_bridge_components_info info;
	int status = 0;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_NO_COMPONENTS_TESTING, 0, false,
		0);

	for (int i = 0; i < PCD_NO_COMPONENTS_TESTING.manifest.toc_entries; ++i) {
		status |= mock_expect (&pcd.manifest.flash.mock, pcd.manifest.flash.base.read,
			&pcd.manifest.flash, 0, MOCK_ARG (pcd.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET +
			i * MANIFEST_V2_TOC_ENTRY_SIZE), MOCK_ARG_NOT_NULL,
			MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
		status |= mock_expect_output (&pcd.manifest.flash.mock, 1,
			(struct manifest_toc_entry*) (PCD_NO_COMPONENTS_TESTING.manifest.raw +
				MANIFEST_V2_TOC_ENTRY_OFFSET + MANIFEST_V2_TOC_ENTRY_SIZE * i),
			MANIFEST_V2_TOC_ENTRY_SIZE, 2);
	}
	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.get_next_mctp_bridge_component (&pcd.test.base, &info, true);
	CuAssertIntEquals (test, MANIFEST_ELEMENT_NOT_FOUND, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_next_mctp_bridge_component_malformed_component (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_mctp_bridge_components_info info;
	int status = 0;
	struct manifest_toc_entry bad_entry;
	uint8_t bad_data[3];

	TEST_START;

	bad_entry.type_id = PCD_COMPONENT_MCTP_BRIDGE;
	bad_entry.parent = 0xff;
	bad_entry.format = 2;
	bad_entry.hash_id = PCD_TESTING.bridge_component_hash;
	bad_entry.offset = PCD_TESTING.bridge_component_offset;
	bad_entry.length = sizeof (bad_data);

	memset (bad_data, 0x55, sizeof (bad_data));

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_TESTING, 0, true, 0);

	manifest_flash_v2_testing_read_element_mocked_hash_bad_entry (test, &pcd.manifest,
		&PCD_TESTING.manifest, PCD_TESTING.bridge_component_entry, 0,
		PCD_TESTING.bridge_component_hash, PCD_TESTING.bridge_component_offset, bad_entry.length,
		bad_entry.length, 0, &bad_entry, NULL);

	status = pcd.test.base.get_next_mctp_bridge_component (&pcd.test.base, &info, true);
	CuAssertIntEquals (test, PCD_MALFORMED_BRIDGE_COMPONENT_ELEMENT, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_rot_info (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_rot_info info;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest, &PCD_TESTING.manifest,
		PCD_TESTING.rot_entry, 0, PCD_TESTING.rot_hash, PCD_TESTING.rot_offset, PCD_TESTING.rot_len,
		PCD_TESTING.rot_len, 0);

	status = pcd.test.base.get_rot_info (&pcd.test.base, &info);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, info.is_pa_rot);
	CuAssertIntEquals (test, 2, info.port_count);
	CuAssertIntEquals (test, 2, info.components_count);
	CuAssertIntEquals (test, 0x41, info.i2c_slave_addr);
	CuAssertIntEquals (test, 0x0B, info.eid);
	CuAssertIntEquals (test, 0x10, info.bridge_i2c_addr);
	CuAssertIntEquals (test, 0x0A, info.bridge_eid);
	CuAssertIntEquals (test, 86400000, info.attestation_success_retry);
	CuAssertIntEquals (test, 10000, info.attestation_fail_retry);
	CuAssertIntEquals (test, 10000, info.discovery_fail_retry);
	CuAssertIntEquals (test, 2000, info.mctp_ctrl_timeout);
	CuAssertIntEquals (test, 3000, info.mctp_bridge_get_table_wait);
	CuAssertIntEquals (test, 0, info.mctp_bridge_additional_timeout);
	CuAssertIntEquals (test, 1000, info.attestation_rsp_not_ready_max_duration);
	CuAssertIntEquals (test, 3, info.attestation_rsp_not_ready_max_retry);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_rot_info_v1 (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_rot_info info;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_V1_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest, &PCD_V1_TESTING.manifest,
		PCD_V1_TESTING.rot_entry, 0, PCD_V1_TESTING.rot_hash, PCD_V1_TESTING.rot_offset,
		PCD_V1_TESTING.rot_len, PCD_V1_TESTING.rot_len, 0);

	status = pcd.test.base.get_rot_info (&pcd.test.base, &info);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, info.is_pa_rot);
	CuAssertIntEquals (test, 2, info.port_count);
	CuAssertIntEquals (test, 2, info.components_count);
	CuAssertIntEquals (test, 0x41, info.i2c_slave_addr);
	CuAssertIntEquals (test, 0x0B, info.eid);
	CuAssertIntEquals (test, 0x10, info.bridge_i2c_addr);
	CuAssertIntEquals (test, 0x0A, info.bridge_eid);
	CuAssertIntEquals (test, PCD_FLASH_ATTESTATION_SUCCESS_RETRY_DEFAULT,
		info.attestation_success_retry);
	CuAssertIntEquals (test, PCD_FLASH_ATTESTATION_FAIL_RETRY_DEFAULT, info.attestation_fail_retry);
	CuAssertIntEquals (test, PCD_FLASH_DISCOVERY_FAIL_RETRY_DEFAULT, info.discovery_fail_retry);
	CuAssertIntEquals (test, PCD_FLASH_MCTP_CTRL_TIMEOUT_DEFAULT, info.mctp_ctrl_timeout);
	CuAssertIntEquals (test, PCD_FLASH_MCTP_BRIDGE_GET_TABLE_WAIT_DEFAULT,
		info.mctp_bridge_get_table_wait);
	CuAssertIntEquals (test, PCD_FLASH_MCTP_BRIDGE_ADDITIONAL_TIMEOUT_DEFAULT,
		info.mctp_bridge_additional_timeout);
	CuAssertIntEquals (test, PCD_FLASH_ATTESTATION_RSP_NOT_READY_MAX_DURATION_DEFAULT,
		info.attestation_rsp_not_ready_max_duration);
	CuAssertIntEquals (test, PCD_FLASH_ATTESTATION_RSP_NOT_READY_MAX_RETRY_DEFAULT,
		info.attestation_rsp_not_ready_max_retry);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_rot_info_static_init (CuTest *test)
{
	struct pcd_flash_testing pcd = {
		.test = pcd_flash_static_init (&pcd.state, &pcd.manifest.flash.base,
			&pcd.manifest.hash.base, 0x10000, pcd.manifest.signature,
			sizeof (pcd.manifest.signature), pcd.manifest.platform_id,
			sizeof (pcd.manifest.platform_id))
	};
	struct pcd_rot_info info;
	int status;

	TEST_START;

	pcd_flash_testing_init_static_and_verify (test, &pcd, 0x10000, &PCD_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest, &PCD_TESTING.manifest,
		PCD_TESTING.rot_entry, 0, PCD_TESTING.rot_hash, PCD_TESTING.rot_offset, PCD_TESTING.rot_len,
		PCD_TESTING.rot_len, 0);

	status = pcd.test.base.get_rot_info (&pcd.test.base, &info);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, info.is_pa_rot);
	CuAssertIntEquals (test, 2, info.port_count);
	CuAssertIntEquals (test, 2, info.components_count);
	CuAssertIntEquals (test, 0x41, info.i2c_slave_addr);
	CuAssertIntEquals (test, 0x0B, info.eid);
	CuAssertIntEquals (test, 0x10, info.bridge_i2c_addr);
	CuAssertIntEquals (test, 0x0A, info.bridge_eid);
	CuAssertIntEquals (test, 86400000, info.attestation_success_retry);
	CuAssertIntEquals (test, 10000, info.attestation_fail_retry);
	CuAssertIntEquals (test, 10000, info.discovery_fail_retry);
	CuAssertIntEquals (test, 2000, info.mctp_ctrl_timeout);
	CuAssertIntEquals (test, 3000, info.mctp_bridge_get_table_wait);
	CuAssertIntEquals (test, 0, info.mctp_bridge_additional_timeout);
	CuAssertIntEquals (test, 1000, info.attestation_rsp_not_ready_max_duration);
	CuAssertIntEquals (test, 3, info.attestation_rsp_not_ready_max_retry);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_rot_info_null (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_rot_info info;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_TESTING, 0, false, 0);

	status = pcd.test.base.get_rot_info (NULL, &info);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = pcd.test.base.get_rot_info (&pcd.test.base, NULL);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_rot_info_verify_never_run (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_rot_info info;
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = pcd.test.base.get_rot_info (&pcd.test.base, &info);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_rot_info_rot_read_error (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_rot_info info;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_TESTING, 0, false, 0);

	status = mock_expect (&pcd.manifest.flash.mock, pcd.manifest.flash.base.read,
		&pcd.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x08));
	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.get_rot_info (&pcd.test.base, &info);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_rot_info_malformed_rot (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_rot_info info;
	int status = 0;
	struct manifest_toc_entry bad_entry;
	uint8_t bad_data[3];

	TEST_START;

	bad_entry.type_id = PCD_ROT;
	bad_entry.parent = 0xff;
	bad_entry.format = 2;
	bad_entry.hash_id = PCD_TESTING.rot_hash;
	bad_entry.offset = PCD_TESTING.rot_offset;
	bad_entry.length = sizeof (bad_data);

	memset (bad_data, 0x66, sizeof (bad_data));

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_TESTING, 0, true, 0);

	manifest_flash_v2_testing_read_element_mocked_hash_bad_entry (test, &pcd.manifest,
		&PCD_TESTING.manifest, PCD_TESTING.rot_entry, 0, PCD_TESTING.rot_hash,
		PCD_TESTING.rot_offset, bad_entry.length, bad_entry.length, 0, &bad_entry, NULL);

	status = pcd.test.base.get_rot_info (&pcd.test.base, &info);
	CuAssertIntEquals (test, PCD_MALFORMED_ROT_ELEMENT, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_rot_info_malformed_rot_v1 (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_rot_info info;
	int status = 0;
	struct manifest_toc_entry bad_entry;
	uint8_t bad_data[3];

	TEST_START;

	bad_entry.type_id = PCD_ROT;
	bad_entry.parent = 0xff;
	bad_entry.format = 1;
	bad_entry.hash_id = PCD_V1_TESTING.rot_hash;
	bad_entry.offset = PCD_V1_TESTING.rot_offset;
	bad_entry.length = sizeof (bad_data);

	memset (bad_data, 0x66, sizeof (bad_data));

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_V1_TESTING, 0, true, 0);

	manifest_flash_v2_testing_read_element_mocked_hash_bad_entry (test, &pcd.manifest,
		&PCD_V1_TESTING.manifest, PCD_V1_TESTING.rot_entry, 0, PCD_V1_TESTING.rot_hash,
		PCD_V1_TESTING.rot_offset, bad_entry.length, bad_entry.length, 0, &bad_entry, NULL);

	status = pcd.test.base.get_rot_info (&pcd.test.base, &info);
	CuAssertIntEquals (test, PCD_MALFORMED_ROT_ELEMENT, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_port_info (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_port_info info;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest, &PCD_TESTING.manifest,
		PCD_TESTING.rot_entry, 0, PCD_TESTING.rot_hash, PCD_TESTING.rot_offset, PCD_TESTING.rot_len,
		PCD_TESTING.rot_len, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest, &PCD_TESTING.manifest,
		PCD_TESTING.port_entry, PCD_TESTING.port_entry, PCD_TESTING.port_hash,
		PCD_TESTING.port_offset, PCD_TESTING.port_len, PCD_TESTING.port_len, 0);

	status = pcd.test.base.get_port_info (&pcd.test.base, 0, &info);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 32000000, info.spi_freq);
	CuAssertIntEquals (test, 0, info.flash_mode);
	CuAssertIntEquals (test, 1, info.reset_ctrl);
	CuAssertIntEquals (test, 0, info.policy);
	CuAssertIntEquals (test, 1, info.runtime_verification);
	CuAssertIntEquals (test, 1, info.watchdog_monitoring);
	CuAssertIntEquals (test, 1, info.host_reset_action);
	CuAssertIntEquals (test, 0, info.pulse_interval);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest, &PCD_TESTING.manifest,
		PCD_TESTING.rot_entry, 0, PCD_TESTING.rot_hash, PCD_TESTING.rot_offset, PCD_TESTING.rot_len,
		PCD_TESTING.rot_len, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest, &PCD_TESTING.manifest,
		PCD_TESTING.port_entry, PCD_TESTING.port_entry, PCD_TESTING.port_hash,
		PCD_TESTING.port_offset, PCD_TESTING.port_len, PCD_TESTING.port_len, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest, &PCD_TESTING.manifest,
		PCD_TESTING.port_entry + 1, PCD_TESTING.port_entry + 1, PCD_TESTING.port_hash + 1,
		PCD_TESTING.port_offset + PCD_TESTING.port_len, PCD_TESTING.port_len, PCD_TESTING.port_len,
		0);

	status = pcd.test.base.get_port_info (&pcd.test.base, 1, &info);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 64000000, info.spi_freq);
	CuAssertIntEquals (test, 1, info.flash_mode);
	CuAssertIntEquals (test, 0, info.reset_ctrl);
	CuAssertIntEquals (test, 1, info.policy);
	CuAssertIntEquals (test, 0, info.runtime_verification);
	CuAssertIntEquals (test, 0, info.watchdog_monitoring);
	CuAssertIntEquals (test, 0, info.host_reset_action);
	CuAssertIntEquals (test, 10, info.pulse_interval);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_port_info_filtered_bypass_flash_modes_and_pulse_reset_control (
	CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_port_info info;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000,
		&PCD_FILTERED_BYPASS_PULSE_RESET_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest,
		&PCD_FILTERED_BYPASS_PULSE_RESET_TESTING.manifest,
		PCD_FILTERED_BYPASS_PULSE_RESET_TESTING.rot_entry, 0,
		PCD_FILTERED_BYPASS_PULSE_RESET_TESTING.rot_hash,
		PCD_FILTERED_BYPASS_PULSE_RESET_TESTING.rot_offset,
		PCD_FILTERED_BYPASS_PULSE_RESET_TESTING.rot_len,
		PCD_FILTERED_BYPASS_PULSE_RESET_TESTING.rot_len, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest,
		&PCD_FILTERED_BYPASS_PULSE_RESET_TESTING.manifest,
		PCD_FILTERED_BYPASS_PULSE_RESET_TESTING.port_entry,
		PCD_FILTERED_BYPASS_PULSE_RESET_TESTING.port_entry,
		PCD_FILTERED_BYPASS_PULSE_RESET_TESTING.port_hash,
		PCD_FILTERED_BYPASS_PULSE_RESET_TESTING.port_offset,
		PCD_FILTERED_BYPASS_PULSE_RESET_TESTING.port_len,
		PCD_FILTERED_BYPASS_PULSE_RESET_TESTING.port_len, 0);

	status = pcd.test.base.get_port_info (&pcd.test.base, 0, &info);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 32000000, info.spi_freq);
	CuAssertIntEquals (test, 2, info.flash_mode);
	CuAssertIntEquals (test, 2, info.reset_ctrl);
	CuAssertIntEquals (test, 0, info.policy);
	CuAssertIntEquals (test, 1, info.runtime_verification);
	CuAssertIntEquals (test, 1, info.watchdog_monitoring);
	CuAssertIntEquals (test, 1, info.host_reset_action);
	CuAssertIntEquals (test, 0, info.pulse_interval);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest,
		&PCD_FILTERED_BYPASS_PULSE_RESET_TESTING.manifest,
		PCD_FILTERED_BYPASS_PULSE_RESET_TESTING.rot_entry, 0,
		PCD_FILTERED_BYPASS_PULSE_RESET_TESTING.rot_hash,
		PCD_FILTERED_BYPASS_PULSE_RESET_TESTING.rot_offset,
		PCD_FILTERED_BYPASS_PULSE_RESET_TESTING.rot_len,
		PCD_FILTERED_BYPASS_PULSE_RESET_TESTING.rot_len, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest,
		&PCD_FILTERED_BYPASS_PULSE_RESET_TESTING.manifest,
		PCD_FILTERED_BYPASS_PULSE_RESET_TESTING.port_entry,
		PCD_FILTERED_BYPASS_PULSE_RESET_TESTING.port_entry,
		PCD_FILTERED_BYPASS_PULSE_RESET_TESTING.port_hash,
		PCD_FILTERED_BYPASS_PULSE_RESET_TESTING.port_offset,
		PCD_FILTERED_BYPASS_PULSE_RESET_TESTING.port_len,
		PCD_FILTERED_BYPASS_PULSE_RESET_TESTING.port_len, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest,
		&PCD_FILTERED_BYPASS_PULSE_RESET_TESTING.manifest,
		PCD_FILTERED_BYPASS_PULSE_RESET_TESTING.port_entry + 1,
		PCD_FILTERED_BYPASS_PULSE_RESET_TESTING.port_entry + 1,
		PCD_FILTERED_BYPASS_PULSE_RESET_TESTING.port_hash + 1,
		PCD_FILTERED_BYPASS_PULSE_RESET_TESTING.port_offset +
		PCD_FILTERED_BYPASS_PULSE_RESET_TESTING.port_len,
		PCD_FILTERED_BYPASS_PULSE_RESET_TESTING.port_len,
		PCD_FILTERED_BYPASS_PULSE_RESET_TESTING.port_len, 0);

	status = pcd.test.base.get_port_info (&pcd.test.base, 1, &info);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 64000000, info.spi_freq);
	CuAssertIntEquals (test, 3, info.flash_mode);
	CuAssertIntEquals (test, 0, info.reset_ctrl);
	CuAssertIntEquals (test, 1, info.policy);
	CuAssertIntEquals (test, 0, info.runtime_verification);
	CuAssertIntEquals (test, 0, info.watchdog_monitoring);
	CuAssertIntEquals (test, 0, info.host_reset_action);
	CuAssertIntEquals (test, 10, info.pulse_interval);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_port_info_static_init (CuTest *test)
{
	struct pcd_flash_testing pcd = {
		.test = pcd_flash_static_init (&pcd.state, &pcd.manifest.flash.base,
			&pcd.manifest.hash.base, 0x10000, pcd.manifest.signature,
			sizeof (pcd.manifest.signature), pcd.manifest.platform_id,
			sizeof (pcd.manifest.platform_id))
	};
	struct pcd_port_info info;
	int status;

	TEST_START;

	pcd_flash_testing_init_static_and_verify (test, &pcd, 0x10000, &PCD_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest, &PCD_TESTING.manifest,
		PCD_TESTING.rot_entry, 0, PCD_TESTING.rot_hash, PCD_TESTING.rot_offset, PCD_TESTING.rot_len,
		PCD_TESTING.rot_len, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest, &PCD_TESTING.manifest,
		PCD_TESTING.port_entry, PCD_TESTING.port_entry, PCD_TESTING.port_hash,
		PCD_TESTING.port_offset, PCD_TESTING.port_len, PCD_TESTING.port_len, 0);

	status = pcd.test.base.get_port_info (&pcd.test.base, 0, &info);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 32000000, info.spi_freq);
	CuAssertIntEquals (test, 0, info.flash_mode);
	CuAssertIntEquals (test, 1, info.reset_ctrl);
	CuAssertIntEquals (test, 0, info.policy);
	CuAssertIntEquals (test, 1, info.runtime_verification);
	CuAssertIntEquals (test, 1, info.watchdog_monitoring);
	CuAssertIntEquals (test, 1, info.host_reset_action);
	CuAssertIntEquals (test, 0, info.pulse_interval);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest, &PCD_TESTING.manifest,
		PCD_TESTING.rot_entry, 0, PCD_TESTING.rot_hash, PCD_TESTING.rot_offset, PCD_TESTING.rot_len,
		PCD_TESTING.rot_len, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest, &PCD_TESTING.manifest,
		PCD_TESTING.port_entry, PCD_TESTING.port_entry, PCD_TESTING.port_hash,
		PCD_TESTING.port_offset, PCD_TESTING.port_len, PCD_TESTING.port_len, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest, &PCD_TESTING.manifest,
		PCD_TESTING.port_entry + 1, PCD_TESTING.port_entry + 1, PCD_TESTING.port_hash + 1,
		PCD_TESTING.port_offset + PCD_TESTING.port_len, PCD_TESTING.port_len, PCD_TESTING.port_len,
		0);

	status = pcd.test.base.get_port_info (&pcd.test.base, 1, &info);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 64000000, info.spi_freq);
	CuAssertIntEquals (test, 1, info.flash_mode);
	CuAssertIntEquals (test, 0, info.reset_ctrl);
	CuAssertIntEquals (test, 1, info.policy);
	CuAssertIntEquals (test, 0, info.runtime_verification);
	CuAssertIntEquals (test, 0, info.watchdog_monitoring);
	CuAssertIntEquals (test, 0, info.host_reset_action);
	CuAssertIntEquals (test, 10, info.pulse_interval);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_port_info_null (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_port_info info;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_TESTING, 0, false, 0);

	status = pcd.test.base.get_port_info (NULL, 0, &info);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = pcd.test.base.get_port_info (&pcd.test.base, 0, NULL);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_port_info_verify_never_run (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_port_info info;
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = pcd.test.base.get_port_info (&pcd.test.base, 0, &info);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_port_info_no_ports (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_port_info info;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_NO_PORTS_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest, &PCD_NO_PORTS_TESTING.manifest,
		PCD_NO_PORTS_TESTING.rot_entry, 0, PCD_NO_PORTS_TESTING.rot_hash,
		PCD_NO_PORTS_TESTING.rot_offset, PCD_NO_PORTS_TESTING.rot_len, PCD_NO_PORTS_TESTING.rot_len,
		0);

	status = pcd.test.base.get_port_info (&pcd.test.base, 0, &info);
	CuAssertIntEquals (test, PCD_INVALID_PORT, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_port_info_port_id_invalid (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_port_info info;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest, &PCD_TESTING.manifest,
		PCD_TESTING.rot_entry, 0, PCD_TESTING.rot_hash, PCD_TESTING.rot_offset, PCD_TESTING.rot_len,
		PCD_TESTING.rot_len, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest, &PCD_TESTING.manifest,
		PCD_TESTING.port_entry, PCD_TESTING.port_entry, PCD_TESTING.port_hash,
		PCD_TESTING.port_offset, PCD_TESTING.port_len, PCD_TESTING.port_len, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest, &PCD_TESTING.manifest,
		PCD_TESTING.port_entry + 1, PCD_TESTING.port_entry + 1, PCD_TESTING.port_hash + 1,
		PCD_TESTING.port_offset + PCD_TESTING.port_len, PCD_TESTING.port_len, PCD_TESTING.port_len,
		0);

	status = pcd.test.base.get_port_info (&pcd.test.base, 2, &info);
	CuAssertIntEquals (test, PCD_INVALID_PORT, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_port_info_rot_read_error (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_port_info info;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_TESTING, 0, false, 0);

	status = mock_expect (&pcd.manifest.flash.mock, pcd.manifest.flash.base.read,
		&pcd.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x08));
	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.get_port_info (&pcd.test.base, 0, &info);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_port_info_no_parent (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_port_info info;
	int status;
	struct manifest_toc_entry bad_entry;

	TEST_START;

	bad_entry.type_id = PCD_SPI_FLASH_PORT;
	bad_entry.parent = 0xff;
	bad_entry.format = 1;
	bad_entry.hash_id = PCD_TESTING.port_hash;
	bad_entry.offset = PCD_TESTING.port_offset;
	bad_entry.length = PCD_TESTING.port_len;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest, &PCD_TESTING.manifest,
		PCD_TESTING.rot_entry, 0, PCD_TESTING.rot_hash, PCD_TESTING.rot_offset, PCD_TESTING.rot_len,
		PCD_TESTING.rot_len, 0);

	/* Read TOC data with bad TOC entry. */
	status = flash_mock_expect_verify_flash (&pcd.manifest.flash,
		pcd.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET,
		PCD_TESTING.manifest.raw + MANIFEST_V2_TOC_ENTRY_OFFSET,
		PCD_TESTING.port_entry * MANIFEST_V2_TOC_ENTRY_SIZE);
	// *INDENT-OFF*
	status |= mock_expect (&pcd.manifest.flash.mock, pcd.manifest.flash.base.read,
		&pcd.manifest.flash, 0, MOCK_ARG (pcd.manifest.addr + MANIFEST_V2_TOC_ENTRY_OFFSET +\
		(PCD_TESTING.port_entry * MANIFEST_V2_TOC_ENTRY_SIZE)),
		MOCK_ARG_NOT_NULL, MOCK_ARG (MANIFEST_V2_TOC_ENTRY_SIZE));
	// *INDENT-ON*
	status |= mock_expect_output (&pcd.manifest.flash.mock, 1, &bad_entry,
		MANIFEST_V2_TOC_ENTRY_SIZE, 2);
	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.get_port_info (&pcd.test.base, 0, &info);
	CuAssertIntEquals (test, PCD_INVALID_PORT, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_port_info_hash_error (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_port_info info;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_TESTING, 0, true, 0);

	manifest_flash_v2_testing_read_element_mocked_hash (test, &pcd.manifest, &PCD_TESTING.manifest,
		PCD_TESTING.rot_entry, 0, PCD_TESTING.rot_hash, PCD_TESTING.rot_offset, PCD_TESTING.rot_len,
		PCD_TESTING.rot_len, 0);

	status = mock_expect (&pcd.manifest.hash_mock.mock, pcd.manifest.hash_mock.base.start_sha256,
		&pcd.manifest.hash_mock, HASH_ENGINE_NO_MEMORY);
	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.get_port_info (&pcd.test.base, 0, &info);
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_port_info_malformed_port (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_port_info info;
	int status;
	struct manifest_toc_entry bad_entry;
	uint8_t bad_data[3];

	TEST_START;

	bad_entry.type_id = PCD_SPI_FLASH_PORT;
	bad_entry.parent = PCD_ROT;
	bad_entry.format = 1;
	bad_entry.hash_id = PCD_TESTING.port_hash;
	bad_entry.offset = PCD_TESTING.port_offset;
	bad_entry.length = sizeof (bad_data);

	memset (bad_data, 0x66, sizeof (bad_data));

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_TESTING, 0, true, 0);

	manifest_flash_v2_testing_read_element_mocked_hash (test, &pcd.manifest, &PCD_TESTING.manifest,
		PCD_TESTING.rot_entry, 0, PCD_TESTING.rot_hash, PCD_TESTING.rot_offset, PCD_TESTING.rot_len,
		PCD_TESTING.rot_len, 0);

	manifest_flash_v2_testing_read_element_mocked_hash_bad_entry (test, &pcd.manifest,
		&PCD_TESTING.manifest, PCD_TESTING.port_entry, PCD_TESTING.port_entry,
		PCD_TESTING.port_hash, PCD_TESTING.port_offset, bad_entry.length, bad_entry.length, 0,
		&bad_entry, NULL);

	status = pcd.test.base.get_port_info (&pcd.test.base, 0, &info);
	CuAssertIntEquals (test, PCD_MALFORMED_PORT_ELEMENT, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_power_controller_info (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_power_controller_info info;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest, &PCD_TESTING.manifest,
		PCD_TESTING.power_ctrl_entry, 0, PCD_TESTING.power_ctrl_hash, PCD_TESTING.power_ctrl_offset,
		PCD_TESTING.power_ctrl_len, sizeof (struct pcd_power_controller_element), 0);

	status = pcd.test.base.get_power_controller_info (&pcd.test.base, &info);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, info.mux_count);
	CuAssertIntEquals (test, PCD_I2C_MODE_MULTIMASTER, info.i2c_mode);
	CuAssertIntEquals (test, 2, info.bus);
	CuAssertIntEquals (test, 0x22, info.address);
	CuAssertIntEquals (test, 0x14, info.eid);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_power_controller_info_static_init (CuTest *test)
{
	struct pcd_flash_testing pcd = {
		.test = pcd_flash_static_init (&pcd.state, &pcd.manifest.flash.base,
			&pcd.manifest.hash.base, 0x10000, pcd.manifest.signature,
			sizeof (pcd.manifest.signature), pcd.manifest.platform_id,
			sizeof (pcd.manifest.platform_id))
	};
	struct pcd_power_controller_info info;
	int status;

	TEST_START;

	pcd_flash_testing_init_static_and_verify (test, &pcd, 0x10000, &PCD_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest, &PCD_TESTING.manifest,
		PCD_TESTING.power_ctrl_entry, 0, PCD_TESTING.power_ctrl_hash, PCD_TESTING.power_ctrl_offset,
		PCD_TESTING.power_ctrl_len, sizeof (struct pcd_power_controller_element), 0);

	status = pcd.test.base.get_power_controller_info (&pcd.test.base, &info);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, info.mux_count);
	CuAssertIntEquals (test, PCD_I2C_MODE_MULTIMASTER, info.i2c_mode);
	CuAssertIntEquals (test, 2, info.bus);
	CuAssertIntEquals (test, 0x22, info.address);
	CuAssertIntEquals (test, 0x14, info.eid);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_power_controller_info_null (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_power_controller_info info;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_TESTING, 0, false, 0);

	status = pcd.test.base.get_power_controller_info (NULL, &info);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = pcd.test.base.get_power_controller_info (&pcd.test.base, NULL);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_power_controller_info_verify_never_run (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_power_controller_info info;
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = pcd.test.base.get_power_controller_info (&pcd.test.base, &info);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_power_controller_info_no_power_controller (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_power_controller_info info;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_NO_POWER_CONTROLLER_TESTING, 0,
		false, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest,
		&PCD_NO_POWER_CONTROLLER_TESTING.manifest, PCD_NO_POWER_CONTROLLER_TESTING.power_ctrl_entry,
		0, PCD_NO_POWER_CONTROLLER_TESTING.power_ctrl_hash,
		PCD_NO_POWER_CONTROLLER_TESTING.power_ctrl_offset,
		PCD_NO_POWER_CONTROLLER_TESTING.power_ctrl_len, 0, 0);

	status = pcd.test.base.get_power_controller_info (&pcd.test.base, &info);
	CuAssertIntEquals (test, MANIFEST_ELEMENT_NOT_FOUND, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_get_power_controller_info_power_controller_read_error (CuTest *test)
{
	struct pcd_flash_testing pcd;
	struct pcd_power_controller_info info;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_TESTING, 0, false, 0);

	status = mock_expect (&pcd.manifest.flash.mock, pcd.manifest.flash.base.read,
		&pcd.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x08));
	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.get_power_controller_info (&pcd.test.base, &info);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_buffer_supported_components (CuTest *test)
{
	struct pcd_flash_testing pcd;
	uint8_t components[4096];
	size_t components_len = sizeof (components);
	struct pcd_supported_component supported_component[2] = {{1, 2}, {2, 1}};
	size_t component_len = sizeof (supported_component[0]);
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_ONLY_BRIDGE_COMPONENTS_TESTING, 0,
		false, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest,
		&PCD_ONLY_BRIDGE_COMPONENTS_TESTING.manifest, PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_entry,
		0, PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_hash,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_offset, PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_len,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_len, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest,
		&PCD_ONLY_BRIDGE_COMPONENTS_TESTING.manifest,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_entry, 0,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_hash,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_offset,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_len,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_len, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest,
		&PCD_ONLY_BRIDGE_COMPONENTS_TESTING.manifest,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_entry + 1,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_entry + 1,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_hash + 1,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_offset +
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_len,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_len,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_len, 0);

	status = pcd.test.base.buffer_supported_components (&pcd.test.base, 0, components_len,
		(uint8_t*) components);

	CuAssertIntEquals (test, sizeof (supported_component), status);
	CuAssertIntEquals (test, supported_component[0].component_id, *(uint32_t*) components);
	CuAssertIntEquals (test, supported_component[1].component_id,
		*(uint32_t*) (components + component_len));

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_buffer_supported_components_offset_nonzero (CuTest *test)
{
	struct pcd_flash_testing pcd;
	uint8_t components[4096];
	struct pcd_supported_component supported_component[2] = {{1, 2}, {2, 1}};
	size_t component_len = sizeof (supported_component[0]);
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_ONLY_BRIDGE_COMPONENTS_TESTING, 0,
		false, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest,
		&PCD_ONLY_BRIDGE_COMPONENTS_TESTING.manifest, PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_entry,
		0, PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_hash,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_offset, PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_len,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_len, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest,
		&PCD_ONLY_BRIDGE_COMPONENTS_TESTING.manifest,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_entry, 0,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_hash,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_offset,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_len,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_len, 0);

	status = pcd.test.base.buffer_supported_components (&pcd.test.base, 0, component_len,
		(uint8_t*) components);

	CuAssertIntEquals (test, component_len, status);
	CuAssertIntEquals (test, supported_component[0].component_id, *(uint32_t*) components);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest,
		&PCD_ONLY_BRIDGE_COMPONENTS_TESTING.manifest, PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_entry,
		0, PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_hash,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_offset, PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_len,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_len, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest,
		&PCD_ONLY_BRIDGE_COMPONENTS_TESTING.manifest,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_entry, 0,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_hash,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_offset,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_len,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_len, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest,
		&PCD_ONLY_BRIDGE_COMPONENTS_TESTING.manifest,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_entry + 1,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_entry + 1,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_hash + 1,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_offset +
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_len,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_len,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_len, 0);

	status = pcd.test.base.buffer_supported_components (&pcd.test.base, component_len,
		component_len, (uint8_t*) components);

	CuAssertIntEquals (test, component_len, status);
	CuAssertIntEquals (test, supported_component[1].component_id, *(uint32_t*) components);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_buffer_supported_components_offset_too_large (CuTest *test)
{
	struct pcd_flash_testing pcd;
	uint8_t components[4096];
	size_t components_len = sizeof (components);
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_ONLY_BRIDGE_COMPONENTS_TESTING, 0,
		false, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest,
		&PCD_ONLY_BRIDGE_COMPONENTS_TESTING.manifest, PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_entry,
		0, PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_hash,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_offset, PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_len,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_len, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest,
		&PCD_ONLY_BRIDGE_COMPONENTS_TESTING.manifest,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_entry, 0,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_hash,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_offset,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_len,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_len, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest,
		&PCD_ONLY_BRIDGE_COMPONENTS_TESTING.manifest,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_entry + 1,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_entry + 1,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_hash + 1,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_offset +
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_len,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_len,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_len, 0);

	status = pcd.test.base.buffer_supported_components (&pcd.test.base,
		sizeof (struct pcd_supported_component) * 2, components_len, (uint8_t*) components);

	CuAssertIntEquals (test, 0, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_buffer_supported_components_offset_not_word_aligned (CuTest *test)
{
	struct pcd_flash_testing pcd;
	uint8_t components[4096];
	struct pcd_supported_component supported_component[2] = {{1, 2}, {2, 1}};
	size_t component_len = sizeof (supported_component[0]);
	size_t offset = component_len - 2;	// offset inside of the component
	int status;

	TEST_START;

	components[0] = 1;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_ONLY_BRIDGE_COMPONENTS_TESTING, 0,
		false, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest,
		&PCD_ONLY_BRIDGE_COMPONENTS_TESTING.manifest, PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_entry,
		0, PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_hash,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_offset, PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_len,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_len, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest,
		&PCD_ONLY_BRIDGE_COMPONENTS_TESTING.manifest,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_entry, 0,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_hash,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_offset,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_len,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_len, 0);

	status = pcd.test.base.buffer_supported_components (&pcd.test.base, offset,
		component_len - offset, (uint8_t*) &components[offset]);

	CuAssertIntEquals (test, component_len - offset, status);
	CuAssertIntEquals (test, supported_component[0].component_id, components[0]);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_buffer_supported_components_smaller_length (CuTest *test)
{
	struct pcd_flash_testing pcd;
	uint8_t components[4096];
	struct pcd_supported_component supported_component[4] = {{1, 2}, {2, 1}, {3, 2}, {4, 1}};
	size_t component_len = sizeof (supported_component[0]);
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_ONLY_BRIDGE_COMPONENTS_TESTING, 0,
		false, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest,
		&PCD_ONLY_BRIDGE_COMPONENTS_TESTING.manifest, PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_entry,
		0, PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_hash,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_offset, PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_len,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_len, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest,
		&PCD_ONLY_BRIDGE_COMPONENTS_TESTING.manifest,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_entry, 0,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_hash,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_offset,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_len,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_len, 0);

	status = pcd.test.base.buffer_supported_components (&pcd.test.base, 0, component_len,
		(uint8_t*) components);

	CuAssertIntEquals (test, sizeof (supported_component[0]), status);
	CuAssertIntEquals (test, supported_component[0].component_id, *(uint32_t*) components);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_buffer_supported_components_static_init (CuTest *test)
{
	struct pcd_flash_testing pcd = {
		.test = pcd_flash_static_init (&pcd.state, &pcd.manifest.flash.base,
			&pcd.manifest.hash.base, 0x10000, pcd.manifest.signature,
			sizeof (pcd.manifest.signature), pcd.manifest.platform_id,
			sizeof (pcd.manifest.platform_id))
	};
	uint8_t components[4096];
	size_t components_len = sizeof (components);
	struct pcd_supported_component supported_component[2] = {{1, 2}, {2, 1}};
	size_t component_len = sizeof (supported_component[0]);
	int status;

	TEST_START;

	pcd_flash_testing_init_static_and_verify (test, &pcd, 0x10000,
		&PCD_ONLY_BRIDGE_COMPONENTS_TESTING, 0, false, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest,
		&PCD_ONLY_BRIDGE_COMPONENTS_TESTING.manifest, PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_entry,
		0, PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_hash,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_offset, PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_len,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_len, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest,
		&PCD_ONLY_BRIDGE_COMPONENTS_TESTING.manifest,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_entry, 0,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_hash,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_offset,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_len,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_len, 0);

	manifest_flash_v2_testing_read_element (test, &pcd.manifest,
		&PCD_ONLY_BRIDGE_COMPONENTS_TESTING.manifest,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_entry + 1,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_entry + 1,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_hash + 1,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_offset +
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_len,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_len,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_len, 0);

	status = pcd.test.base.buffer_supported_components (&pcd.test.base, 0, components_len,
		(uint8_t*) components);

	CuAssertIntEquals (test, sizeof (supported_component), status);
	CuAssertIntEquals (test, supported_component[0].component_id, *(uint32_t*) components);
	CuAssertIntEquals (test, supported_component[1].component_id,
		*(uint32_t*) (components + component_len));

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_buffer_supported_components_null (CuTest *test)
{
	struct pcd_flash_testing pcd;
	uint32_t components[2];
	size_t components_len = sizeof (components);
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_TESTING, 0, false, 0);

	status = pcd.test.base.buffer_supported_components (NULL, 0, components_len,
		(uint8_t*) components);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = pcd.test.base.buffer_supported_components (&pcd.test.base, 0, components_len, NULL);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = pcd.test.base.buffer_supported_components (&pcd.test.base, 0, 0,
		(uint8_t*) components);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_buffer_supported_components_verify_never_run (CuTest *test)
{
	struct pcd_flash_testing pcd;
	uint32_t components[2];
	size_t components_len = sizeof (components);
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = pcd.test.base.buffer_supported_components (&pcd.test.base, 0, components_len,
		(uint8_t*) components);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_buffer_supported_components_rot_element_read_fail (CuTest *test)
{
	struct pcd_flash_testing pcd;
	uint32_t components[2];
	size_t components_len = sizeof (components);
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_TESTING, 0, false, 0);

	status = mock_expect (&pcd.manifest.flash.mock, pcd.manifest.flash.base.read,
		&pcd.manifest.flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000 + MANIFEST_V2_TOC_ENTRY_OFFSET),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x08));
	CuAssertIntEquals (test, 0, status);

	status = pcd.test.base.buffer_supported_components (&pcd.test.base, 0, components_len,
		(uint8_t*) components);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_buffer_supported_components_malformed_component_device (CuTest *test)
{
	struct pcd_flash_testing pcd;
	uint8_t components[4096];
	size_t component_len = sizeof (struct pcd_supported_component);
	int status;
	struct manifest_toc_entry bad_entry;
	uint8_t bad_data[3];

	TEST_START;

	bad_entry.type_id = PCD_COMPONENT_MCTP_BRIDGE;
	bad_entry.parent = 0xff;
	bad_entry.format = 2;
	bad_entry.hash_id = PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_hash;
	bad_entry.offset = PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_offset;
	bad_entry.length = sizeof (bad_data);

	memset (bad_data, 0x55, sizeof (bad_data));

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_ONLY_BRIDGE_COMPONENTS_TESTING, 0,
		true, 0);

	manifest_flash_v2_testing_read_element_mocked_hash (test, &pcd.manifest,
		&PCD_ONLY_BRIDGE_COMPONENTS_TESTING.manifest, PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_entry,
		0, PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_hash,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_offset, PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_len,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.rot_len, 0);

	manifest_flash_v2_testing_read_element_mocked_hash_bad_entry (test, &pcd.manifest,
		&PCD_ONLY_BRIDGE_COMPONENTS_TESTING.manifest,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_entry, 0,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_hash,
		PCD_ONLY_BRIDGE_COMPONENTS_TESTING.bridge_component_offset, bad_entry.length,
		bad_entry.length, 0, &bad_entry, NULL);

	status = pcd.test.base.buffer_supported_components (&pcd.test.base, 0, component_len,
		(uint8_t*) components);
	CuAssertIntEquals (test, PCD_MALFORMED_BRIDGE_COMPONENT_ELEMENT, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_is_empty (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_TESTING, 0, false, 0);

	status = pcd.test.base.base.is_empty (&pcd.test.base.base);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_is_empty_empty_manifest (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_EMPTY_TESTING, 0, false, 0);

	status = pcd.test.base.base.is_empty (&pcd.test.base.base);
	CuAssertIntEquals (test, 1, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_is_empty_static_init (CuTest *test)
{
	struct pcd_flash_testing pcd = {
		.test = pcd_flash_static_init (&pcd.state, &pcd.manifest.flash.base,
			&pcd.manifest.hash.base, 0x10000, pcd.manifest.signature,
			sizeof (pcd.manifest.signature), pcd.manifest.platform_id,
			sizeof (pcd.manifest.platform_id))
	};
	int status;

	TEST_START;

	pcd_flash_testing_init_static_and_verify (test, &pcd, 0x10000, &PCD_TESTING, 0, false, 0);

	status = pcd.test.base.base.is_empty (&pcd.test.base.base);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_is_empty_null (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;

	TEST_START;

	pcd_flash_testing_init_and_verify (test, &pcd, 0x10000, &PCD_TESTING, 0, false, 0);

	status = pcd.test.base.base.is_empty (NULL);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}

static void pcd_flash_test_is_empty_verify_never_run (CuTest *test)
{
	struct pcd_flash_testing pcd;
	int status;

	TEST_START;

	pcd_flash_testing_init (test, &pcd, 0x10000);

	status = pcd.test.base.base.is_empty (&pcd.test.base.base);
	CuAssertIntEquals (test, MANIFEST_NO_MANIFEST, status);

	pcd_flash_testing_validate_and_release (test, &pcd);
}


// *INDENT-OFF*
TEST_SUITE_START (pcd_flash);

TEST (pcd_flash_test_init);
TEST (pcd_flash_test_init_null);
TEST (pcd_flash_test_init_manifest_flash_init_fail);
TEST (pcd_flash_test_static_init);
TEST (pcd_flash_test_static_init_null);
TEST (pcd_flash_test_static_init_manifest_flash_init_fail);
TEST (pcd_flash_test_release_null);
TEST (pcd_flash_test_verify);
TEST (pcd_flash_test_verify_no_power_controller);
TEST (pcd_flash_test_verify_no_components);
TEST (pcd_flash_test_verify_no_ports);
TEST (pcd_flash_test_verify_no_ports_power_controller_components);
TEST (pcd_flash_test_verify_only_direct_components);
TEST (pcd_flash_test_verify_multiple_direct_components);
TEST (pcd_flash_test_verify_only_bridge_components);
TEST (pcd_flash_test_verify_multiple_bridge_components);
TEST (pcd_flash_test_verify_filtered_bypass_pulse_reset);
TEST (pcd_flash_test_verify_empty_manifest);
TEST (pcd_flash_test_verify_static_init);
TEST (pcd_flash_test_verify_null);
TEST (pcd_flash_test_verify_read_header_fail);
TEST (pcd_flash_test_verify_bad_magic_number);
TEST (pcd_flash_test_get_id);
TEST (pcd_flash_test_get_id_static_init);
TEST (pcd_flash_test_get_id_null);
TEST (pcd_flash_test_get_id_verify_never_run);
TEST (pcd_flash_test_get_hash);
TEST (pcd_flash_test_get_hash_after_verify);
TEST (pcd_flash_test_get_hash_static_init);
TEST (pcd_flash_test_get_hash_null);
TEST (pcd_flash_test_get_hash_bad_magic_num);
TEST (pcd_flash_test_get_signature);
TEST (pcd_flash_test_get_signature_after_verify);
TEST (pcd_flash_test_get_signature_static_init);
TEST (pcd_flash_test_get_signature_null);
TEST (pcd_flash_test_get_signature_bad_magic_number);
TEST (pcd_flash_test_get_platform_id);
TEST (pcd_flash_test_get_platform_id_manifest_allocation);
TEST (pcd_flash_test_get_platform_id_static_init);
TEST (pcd_flash_test_get_platform_id_null);
TEST (pcd_flash_test_get_platform_id_verify_never_run);
TEST (pcd_flash_test_get_next_mctp_bridge_component);
TEST (pcd_flash_test_get_next_mctp_bridge_component_static_init);
TEST (pcd_flash_test_get_next_mctp_bridge_component_null);
TEST (pcd_flash_test_get_next_mctp_bridge_component_verify_never_run);
TEST (pcd_flash_test_get_next_mctp_bridge_component_component_read_error);
TEST (pcd_flash_test_get_next_mctp_bridge_component_no_components);
TEST (pcd_flash_test_get_next_mctp_bridge_component_malformed_component);
TEST (pcd_flash_test_get_rot_info);
TEST (pcd_flash_test_get_rot_info_v1);
TEST (pcd_flash_test_get_rot_info_static_init);
TEST (pcd_flash_test_get_rot_info_null);
TEST (pcd_flash_test_get_rot_info_verify_never_run);
TEST (pcd_flash_test_get_rot_info_rot_read_error);
TEST (pcd_flash_test_get_rot_info_malformed_rot);
TEST (pcd_flash_test_get_rot_info_malformed_rot_v1);
TEST (pcd_flash_test_get_port_info);
TEST (pcd_flash_test_get_port_info_filtered_bypass_flash_modes_and_pulse_reset_control);
TEST (pcd_flash_test_get_port_info_static_init);
TEST (pcd_flash_test_get_port_info_null);
TEST (pcd_flash_test_get_port_info_verify_never_run);
TEST (pcd_flash_test_get_port_info_no_ports);
TEST (pcd_flash_test_get_port_info_port_id_invalid);
TEST (pcd_flash_test_get_port_info_rot_read_error);
TEST (pcd_flash_test_get_port_info_no_parent);
TEST (pcd_flash_test_get_port_info_hash_error);
TEST (pcd_flash_test_get_port_info_malformed_port);
TEST (pcd_flash_test_get_power_controller_info);
TEST (pcd_flash_test_get_power_controller_info_static_init);
TEST (pcd_flash_test_get_power_controller_info_null);
TEST (pcd_flash_test_get_power_controller_info_verify_never_run);
TEST (pcd_flash_test_get_power_controller_info_no_power_controller);
TEST (pcd_flash_test_get_power_controller_info_power_controller_read_error);
TEST (pcd_flash_test_buffer_supported_components);
TEST (pcd_flash_test_buffer_supported_components_offset_nonzero);
TEST (pcd_flash_test_buffer_supported_components_offset_too_large);
TEST (pcd_flash_test_buffer_supported_components_offset_not_word_aligned);
TEST (pcd_flash_test_buffer_supported_components_smaller_length);
TEST (pcd_flash_test_buffer_supported_components_static_init);
TEST (pcd_flash_test_buffer_supported_components_null);
TEST (pcd_flash_test_buffer_supported_components_verify_never_run);
TEST (pcd_flash_test_buffer_supported_components_rot_element_read_fail);
TEST (pcd_flash_test_buffer_supported_components_malformed_component_device);
TEST (pcd_flash_test_is_empty);
TEST (pcd_flash_test_is_empty_empty_manifest);
TEST (pcd_flash_test_is_empty_static_init);
TEST (pcd_flash_test_is_empty_null);
TEST (pcd_flash_test_is_empty_verify_never_run);

TEST_SUITE_END;
// *INDENT-ON*
