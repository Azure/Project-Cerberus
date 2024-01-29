// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CFM_TESTING_H_
#define CFM_TESTING_H_

#include <stdint.h>
#include "testing/manifest/manifest_v2_testing.h"


/**
 * Describe a test CFM structure.
 */
struct cfm_testing_data {
	struct manifest_v2_testing_data manifest;			/**< Common manifest components. */
	size_t component_device1_len;						/**< First component device element data length. */
	uint32_t component_device1_offset;					/**< Offset of the first component device element. */
	int component_device1_entry;						/**< TOC entry for the first component device element. */
	int component_device1_hash;							/**< TOC hash for the first component device element. */
	size_t component_device2_len;						/**< Second component device element data length. */
	uint32_t component_device2_offset;					/**< Offset of the second component device element. */
	int component_device2_entry;						/**< TOC entry for the second component device element. */
	int component_device2_hash;							/**< TOC hash for the second component device element. */
};

extern const struct cfm_testing_data CFM_TESTING;
extern const struct cfm_testing_data CFM_ONLY_PMR_DIGEST_TESTING;
extern const struct cfm_testing_data CFM_EMPTY_TESTING;


#endif /* CFM_TESTING_H_ */
