// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PFM_TESTING_H_
#define PFM_TESTING_H_

#include <stdint.h>
#include <stddef.h>


extern const uint8_t PFM_DATA[];
extern const uint32_t PFM_DATA_LEN;

extern const size_t PFM_SIGNATURE_LEN;
extern const uint32_t PFM_SIGNATURE_OFFSET;
extern const uint8_t *PFM_SIGNATURE;

extern const uint8_t PFM2_DATA[];
extern const uint32_t PFM2_DATA_LEN;

extern const uint8_t *PFM2_SIGNATURE;

extern const uint8_t PFM_PLATFORM2_DATA[];
extern const uint32_t PFM_PLATFORM2_DATA_LEN;

extern const uint8_t *PFM_PLATFORM2_SIGNATURE;

extern const size_t PFM_ALLOWED_HDR_OFFSET;
extern const size_t PFM_FW_HEADER_OFFSET;
extern const size_t PFM_VERSION_OFFSET;
extern const size_t PFM_MANIFEST_OFFSET;
extern const size_t PFM_PLATFORM_HEADER_OFFSET;
extern const size_t PFM_PLATFORM_ID_OFFSET;
extern const char *PFM_VERSION_ID;
extern const char PFM_PLATFORM_ID[];
extern const size_t PFM_PLATFORM_ID_LEN;

extern const uint8_t PFM_HASH[];
extern const uint8_t PFM_HASH_DIGEST[];
extern const uint8_t PFM2_HASH[];
extern const uint8_t PFM_PLATFORM2_HASH[];
extern const uint32_t PFM_HASH_LEN;


/**
 * The length of image key.
 */
#define	PFM_IMG_KEY_SIZE		256


/*
 * Constant PFM sizes.
 */
#define	PFM_HEADER_SIZE				12
#define	PFM_ALLOWED_HEADER_SIZE		4
#define	PFM_FW_HEADER_SIZE			12
#define	PFM_IMG_HEADER_SIZE			8
#define	PFM_REGION_SIZE				8
#define	PFM_MANIFEST_HEADER_SIZE	4
#define	PFM_KEY_HEADER_SIZE			12
#define	PFM_PLATFORM_HEADER_SIZE	4


#endif /* PFM_TESTING_H_ */
