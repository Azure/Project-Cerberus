// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HASH_KAT_VECTORS_H_
#define HASH_KAT_VECTORS_H_

#include <stddef.h>
#include <stdint.h>


/* SHA calculate digest */
extern const uint8_t SHA_KAT_VECTORS_CALCULATE_DATA[];
extern const size_t SHA_KAT_VECTORS_CALCULATE_DATA_LEN;
extern const uint8_t SHA_KAT_VECTORS_CALCULATE_SHA1_DIGEST[];
extern const uint8_t SHA_KAT_VECTORS_CALCULATE_SHA256_DIGEST[];
extern const uint8_t SHA_KAT_VECTORS_CALCULATE_SHA384_DIGEST[];
extern const uint8_t SHA_KAT_VECTORS_CALCULATE_SHA512_DIGEST[];

/* SHA start/update/finish digest */
extern const uint8_t SHA_KAT_VECTORS_UPDATE_DATA_1[];
extern const size_t SHA_KAT_VECTORS_UPDATE_DATA_1_LEN;
extern const uint8_t SHA_KAT_VECTORS_UPDATE_DATA_2[];
extern const size_t SHA_KAT_VECTORS_UPDATE_DATA_2_LEN;
extern const uint8_t SHA_KAT_VECTORS_UPDATE_SHA1_DIGEST[];
extern const uint8_t SHA_KAT_VECTORS_UPDATE_SHA256_DIGEST[];
extern const uint8_t SHA_KAT_VECTORS_UPDATE_SHA384_DIGEST[];
extern const uint8_t SHA_KAT_VECTORS_UPDATE_SHA512_DIGEST[];


#endif /* HASH_KAT_VECTORS_H_ */
