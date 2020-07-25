// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PCD_TESTING_H_
#define PCD_TESTING_H_

#include <stdint.h>


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

extern const char *PCD_PLATFORM_ID;
extern const size_t PCD_PLATFORM_ID_LEN;

/*
 * Constant PCD sizes.
 */
#define	PCD_HEADER_SIZE				12


#endif /* PCD_TESTING_H_ */
