// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FIRMWARE_HEADER_TESTING_H_
#define FIRMWARE_HEADER_TESTING_H_

#include <stdint.h>
#include <stddef.h>


/**
 * The size of the information added for header format 0.
 */
#define	FIRMWARE_HEADER_FORMAT_0_LEN		2

/**
 * The size of the information added for header format 1.
 */
#define	FIRMWARE_HEADER_FORMAT_1_LEN		3

/**
 * The size of the information added for header format 2.
 */
#define	FIRMWARE_HEADER_FORMAT_2_LEN		5

/**
 * The size of the information added for header format 3.
 */
#define	FIRMWARE_HEADER_FORMAT_3_LEN		11


extern const uint8_t FIRMWARE_HEADER_FORMAT_0[];
extern const size_t FIRMWARE_HEADER_FORMAT_0_TOTAL_LEN;

extern const uint8_t FIRMWARE_HEADER_FORMAT_1[];
extern const size_t FIRMWARE_HEADER_FORMAT_1_TOTAL_LEN;

extern const uint8_t FIRMWARE_HEADER_FORMAT_2[];
extern const size_t FIRMWARE_HEADER_FORMAT_2_TOTAL_LEN;

extern const uint8_t FIRMWARE_HEADER_FORMAT_3[];
extern const size_t FIRMWARE_HEADER_FORMAT_3_TOTAL_LEN;


#endif /* FIRMWARE_HEADER_TESTING_H_ */
