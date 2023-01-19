// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef IMAGE_HEADER_TESTING_H_
#define IMAGE_HEADER_TESTING_H_


/**
 * The size of the minimum information in an image header.
 */
#define	IMAGE_HEADER_BASE_LEN			8


extern const uint8_t IMAGE_HEADER_TEST[];
extern const size_t IMAGE_HEADER_TEST_LEN;

extern const uint8_t IMAGE_HEADER_TEST_SHA1[];
extern const uint8_t IMAGE_HEADER_TEST_SHA256[];
extern const uint8_t IMAGE_HEADER_TEST_SHA384[];
extern const uint8_t IMAGE_HEADER_TEST_SHA512[];

/**
 * Marker for the test image header.
 */
#define	IMAGE_HEADER_TEST_MARKER		0x43494d47

/**
 * Format identifier of the test image header.
 */
#define	IMAGE_HEADER_TEST_FORMAT		2

/**
 * Length of the variable data contained in the header.
 */
#define	IMAGE_HEADER_TEST_DATA_LENGTH		(IMAGE_HEADER_TEST_LEN - IMAGE_HEADER_BASE_LEN)


#endif /* IMAGE_HEADER_TESTING_H_ */
