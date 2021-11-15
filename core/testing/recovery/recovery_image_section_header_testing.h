// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RECOVERY_IMAGE_SECTION_HEADER_TESTING_H_
#define RECOVERY_IMAGE_SECTION_HEADER_TESTING_H_


extern const uint8_t RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0[];
extern const size_t RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN;

/**
 * The size of the information added for example section header format 0.
 */
#define	RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN	\
	(RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN - IMAGE_HEADER_BASE_LEN)


#endif /* RECOVERY_IMAGE_SECTION_HEADER_TESTING_H_ */
