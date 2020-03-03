// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CFM_TESTING_H_
#define CFM_TESTING_H_

#include <stdint.h>


extern const uint8_t CFM_DATA[];
extern const uint32_t CFM_DATA_LEN;

extern const size_t CFM_SIGNATURE_LEN;
extern const uint32_t CFM_SIGNATURE_OFFSET;
extern const uint8_t *CFM_SIGNATURE;

extern const uint8_t CFM2_DATA[];
extern const uint32_t CFM2_DATA_LEN;

extern const uint8_t *CFM2_SIGNATURE;

extern const uint8_t CFM_HASH[];
extern const uint8_t CFM2_HASH[];
extern const uint32_t CFM_HASH_LEN;

/*
 * Constant CFM sizes.
 */
#define	CFM_HEADER_SIZE				12
#define	CFM_COMPONENTS_HDR_SIZE		4
#define	CFM_COMPONENT_HDR_SIZE		8
#define	CFM_FW_HEADER_SIZE			8
#define	CFM_IMG_HEADER_SIZE			8


#endif /* CFM_TESTING_H_ */
