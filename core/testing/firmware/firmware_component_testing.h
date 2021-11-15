// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FIRMWARE_COMPONENT_TESTING_H_
#define FIRMWARE_COMPONENT_TESTING_H_

#include <stdint.h>
#include <stddef.h>


/**
 * Length of the component header.
 */
#define	FW_COMPONENT_HDR_LENGTH			(14 - IMAGE_HEADER_BASE_LEN)

/**
 * Length of the component signature.
 */
#define	FW_COMPONENT_SIG_LENGTH			256

/**
 * Component marker for the test image.
 */
#define	FW_COMPONENT_MARKER				0x12345678


extern const uint8_t FW_COMPONENT_DATA[];
extern const size_t FW_COMPONENT_DATA_LEN;


#endif /* FIRMWARE_COMPONENT_TESTING_H_ */
