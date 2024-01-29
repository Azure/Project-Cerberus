// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PFM_FLASH_V2_TESTING_H_
#define PFM_FLASH_V2_TESTING_H_

#include <stdint.h>
#include "pfm_v2_testing.h"
#include "manifest/pfm/pfm_flash.h"


extern const struct pfm_v2_testing_data PFM_V2;
extern const struct pfm_v2_testing_data PFM_V2_PLAT_FIRST;
extern const struct pfm_v2_testing_data PFM_V2_TWO_FW;
extern const struct pfm_v2_testing_data PFM_V2_SHA384;
extern const struct pfm_v2_testing_data PFM_V2_SHA512;
extern const struct pfm_v2_testing_data PFM_V2_DIFF_HASH_TYPE;
extern const struct pfm_v2_testing_data PFM_V2_NO_TOC_HASHES;
extern const struct pfm_v2_testing_data PFM_V2_NO_FW_HASHES;
extern const struct pfm_v2_testing_data PFM_V2_NO_FLASH_DEV;
extern const struct pfm_v2_testing_data PFM_V2_EMPTY;
extern const struct pfm_v2_testing_data PFM_V2_NO_FW;
extern const struct pfm_v2_testing_data PFM_V2_THREE_FW_NO_VER;
extern const struct pfm_v2_testing_data PFM_V2_MULTIPLE;
extern const struct pfm_v2_testing_data PFM_V2_MAX_VERSION;
extern const struct pfm_v2_testing_data PFM_V2_RW_TEST;
extern const struct pfm_v2_testing_data PFM_V2_THREE_FW;
extern const struct pfm_v2_testing_data PFM_V2_IMG_TEST;
extern const struct pfm_v2_testing_data PFM_V2_BAD_REGIONS;


/**
 * Dependencies for testing v2 PFMs.
 */
struct pfm_flash_v2_testing {
	struct manifest_flash_v2_testing manifest;	/**< Common dependencies for manifest testing. */
	struct pfm_flash test;						/**< PFM instance under test. */
};


void pfm_flash_v2_testing_init (CuTest *test, struct pfm_flash_v2_testing *pfm,
	uint32_t address);

void pfm_flash_v2_testing_validate_and_release (CuTest *test, struct pfm_flash_v2_testing *pfm);


#endif /* PFM_FLASH_V2_TESTING_H_ */
