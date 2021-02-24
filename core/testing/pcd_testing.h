// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PCD_TESTING_H_
#define PCD_TESTING_H_

#include <stdint.h>
#include "manifest_v2_testing.h"


/**
 * Describe a test PFM structure.
 */
struct pcd_testing_data {
	struct manifest_v2_testing_data manifest;			/**< Common manifest components. */
	size_t rot_len;										/**< RoT element data length. */
	uint32_t rot_offset;								/**< Offset of the RoT element. */
	int rot_entry;										/**< TOC entry for the RoT element. */
	int rot_hash;										/**< TOC hash for the RoT element. */
	size_t power_ctrl_len;								/**< Power controller element data length. */
	uint32_t power_ctrl_offset;							/**< Offset of a power controller element. */
	int power_ctrl_entry;								/**< TOC entry for a power controller element. */
	int power_ctrl_hash;								/**< TOC hash for a power controller element. */
	size_t bridge_component_len;						/**< Bridge component element data length. */
	uint32_t bridge_component_offset;					/**< Offset of a bridge component element. */
	int bridge_component_entry;							/**< TOC entry for a bridge component element. */
	int bridge_component_hash;							/**< TOC hash for a bridge component element. */
	size_t direct_component_len;						/**< Direct component element data length. */
	uint32_t direct_component_offset;					/**< Offset of a direct component element. */
	int direct_component_entry;							/**< TOC entry for a direct component element. */
	int direct_component_hash;							/**< TOC hash for a direct component element. */
};


extern const uint8_t PCD_DATA[];
extern const uint32_t PCD_DATA_LEN;

extern const uint8_t *PCD_SIGNATURE;
extern const uint8_t *PCD2_SIGNATURE;
extern const size_t PCD_SIGNATURE_LEN;
extern const uint32_t PCD_SIGNATURE_OFFSET;

extern const uint8_t PCD2_DATA[];
extern const uint32_t PCD2_DATA_LEN;

extern const uint8_t PCD_HASH[];
extern const uint8_t PCD_HASH_DIGEST[];
extern const uint8_t PCD2_HASH[];
extern const uint32_t PCD_HASH_LEN;

extern const uint32_t PCD_HEADER_OFFSET;
extern const uint32_t PCD_ROT_OFFSET;
extern const uint32_t PCD_COMPONENTS_OFFSET;
extern const uint32_t PCD_PLATFORM_ID_HDR_OFFSET;
extern const uint32_t PCD_PLATFORM_ID_OFFSET;

extern const char PCD_PLATFORM_ID[];
extern const size_t PCD_PLATFORM_ID_LEN;

extern const uint8_t PCD_TOC_HASH[];

extern const struct pcd_testing_data PCD_TESTING;


#endif /* PCD_TESTING_H_ */
