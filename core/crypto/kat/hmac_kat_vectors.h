// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HMAC_KAT_VECTORS_H_
#define HMAC_KAT_VECTORS_H_

#include <stddef.h>
#include <stdint.h>
#include "hash_kat_vectors.h"


/* Direct HMAC generation of input data. */
extern const uint8_t HMAC_KAT_VECTORS_CALCULATE_KEY[];
extern const size_t HMAC_KAT_VECTORS_CALCULATE_KEY_LEN;

/**
 * Input data for HMAC self tests using direct HMAC calculation.
 */
#define	HMAC_KAT_VECTORS_CALCULATE_DATA			SHA_KAT_VECTORS_CALCULATE_DATA
#define	HMAC_KAT_VECTORS_CALCULATE_DATA_LEN		SHA_KAT_VECTORS_CALCULATE_DATA_LEN

extern const uint8_t HMAC_KAT_VECTORS_CALCULATE_SHA1_MAC[];
extern const uint8_t HMAC_KAT_VECTORS_CALCULATE_SHA256_MAC[];
extern const uint8_t HMAC_KAT_VECTORS_CALCULATE_SHA384_MAC[];
extern const uint8_t HMAC_KAT_VECTORS_CALCULATE_SHA512_MAC[];


/* HMAC generation using the init/update/finish sequence. */
extern const uint8_t HMAC_KAT_VECTORS_UPDATE_KEY[];
extern const size_t HMAC_KAT_VECTORS_UPDATE_KEY_LEN;

/**
 * First block of input data for HMAC self tests using the init/update/finish sequence.
 */
#define	HMAC_KAT_VECTORS_UPDATE_DATA_1			SHA_KAT_VECTORS_UPDATE_DATA_1
#define	HMAC_KAT_VECTORS_UPDATE_DATA_1_LEN		SHA_KAT_VECTORS_UPDATE_DATA_1_LEN

/**
 * Second block of input data for HMAC self tests using the init/update/finish sequence.
 */
#define	HMAC_KAT_VECTORS_UPDATE_DATA_2			SHA_KAT_VECTORS_UPDATE_DATA_2
#define	HMAC_KAT_VECTORS_UPDATE_DATA_2_LEN		SHA_KAT_VECTORS_UPDATE_DATA_2_LEN

extern const uint8_t HMAC_KAT_VECTORS_UPDATE_SHA1_MAC[];
extern const uint8_t HMAC_KAT_VECTORS_UPDATE_SHA256_MAC[];
extern const uint8_t HMAC_KAT_VECTORS_UPDATE_SHA384_MAC[];
extern const uint8_t HMAC_KAT_VECTORS_UPDATE_SHA512_MAC[];


#endif	/* HMAC_KAT_VECTORS_H_ */
