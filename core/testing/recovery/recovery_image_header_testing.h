// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RECOVERY_IMAGE_HEADER_TESTING_H_
#define RECOVERY_IMAGE_HEADER_TESTING_H_

#include "testing/common/image_header_testing.h"


/* Recovery image header */
extern const uint8_t RECOVERY_IMAGE_HEADER_FORMAT_0[];
extern const size_t RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN;

extern const char *RECOVERY_IMAGE_HEADER_PLATFORM_ID;

extern const char *RECOVERY_IMAGE_HEADER_VERSION_ID;

#define RECOVERY_IMAGE_HEADER_VERSION_ID_LEN		(strlen (RECOVERY_IMAGE_HEADER_VERSION_ID))

#define RECOVERY_IMAGE_HEADER_PLATFORM_ID_LEN		(strlen (RECOVERY_IMAGE_HEADER_PLATFORM_ID))

/**
 * The size in bytes of the information in the recovery image header format 0 example.
 */
#define	RECOVERY_IMAGE_HEADER_FORMAT_0_LEN		(RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN - \
	IMAGE_HEADER_BASE_LEN)

#define RECOVERY_IMAGE_HEADER_SIGNATURE_LEN     256


#endif /* RECOVERY_IMAGE_HEADER_TESTING_H_ */
