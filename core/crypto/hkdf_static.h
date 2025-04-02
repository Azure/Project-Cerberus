// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HKDF_STATIC_H_
#define HKDF_STATIC_H_

#include "crypto/hkdf.h"


/* Internal functions declared to allow for static initialization. */
int hkdf_extract (const struct hkdf_interface *hkdf, enum hash_type hash_algo, const uint8_t *ikm,
	size_t length, const uint8_t *salt, size_t salt_length);
int hkdf_expand (const struct hkdf_interface *hkdf, const uint8_t *info, size_t info_length,
	uint8_t *key_out, size_t key_length);
int hkdf_clear_prk (const struct hkdf_interface *hkdf);


/**
 * Constant initializer for the HKDF API.
 */
#define	HKDF_API_INIT { \
		.extract = hkdf_extract, \
		.expand = hkdf_expand, \
		.clear_prk = hkdf_clear_prk ,\
	}


/**
 * Initialize a static instance for deriving keys using HKDF.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for HKDF execution.
 * @param hash_ptr Hash engine to use for HMAC operations.
 */
#define	hkdf_static_init(state_ptr, hash_ptr) { \
		.base = HKDF_API_INIT, \
		.state = state_ptr, \
		.hash = hash_ptr, \
	}


#endif	/* HKDF_STATIC_H_ */
