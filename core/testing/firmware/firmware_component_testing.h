// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FIRMWARE_COMPONENT_TESTING_H_
#define FIRMWARE_COMPONENT_TESTING_H_

#include <stdint.h>
#include <stddef.h>


/**
 * Length of the format 0 component header.
 */
#define	FW_COMPONENT_HDR_LENGTH			(14 - IMAGE_HEADER_BASE_LEN)

/**
 * Length of the format 1 component header.
 */
#define	FW_COMPONENT_HDR_V1_LENGTH		(31 - IMAGE_HEADER_BASE_LEN)

/**
 * Length of the component signature.
 */
#define	FW_COMPONENT_SIG_LENGTH			256

/**
 * Length of the component signature using ECC384.
 */
#define	FW_COMPONENT_SIG_LENGTH_ECC384	105

/**
 * Length of the component signature using ECC521.
 */
#define	FW_COMPONENT_SIG_LENGTH_ECC521	141

/**
 * Component marker for the test image.
 */
#define	FW_COMPONENT_MARKER				0x12345678

/**
 * Component marker for the test image using format 1 header.
 */
#define	FW_COMPONENT_MARKER_V1			0x87654321


extern const uint8_t FW_COMPONENT_DATA[];
extern const size_t FW_COMPONENT_DATA_LEN;

extern const uint8_t FW_COMPONENT_V1_DATA[];
extern const size_t FW_COMPONENT_V1_DATA_LEN;

extern const uint8_t FW_COMPONENT_SHA384_DATA[];
extern const size_t FW_COMPONENT_SHA384_DATA_LEN;

extern const uint8_t FW_COMPONENT_SHA512_DATA[];
extern const size_t FW_COMPONENT_SHA512_DATA_LEN;


#endif /* FIRMWARE_COMPONENT_TESTING_H_ */
