// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SIGNATURE_VERIFICATION_NULL_STATIC_H_
#define SIGNATURE_VERIFICATION_NULL_STATIC_H_

#include "crypto/signature_verification_null.h"


/* Internal functions declared to allow for static initialization. */
int signature_verification_null_verify_signature (
	const struct signature_verification *verification, const uint8_t *digest, size_t length,
	const uint8_t *signature, size_t sig_length);
int signature_verification_null_get_max_signature_length (
	const struct signature_verification *verification, size_t *max_length);
int signature_verification_null_set_verification_key (
	const struct signature_verification *verification, const uint8_t *key, size_t length);
int signature_verification_null_is_key_valid (const struct signature_verification *verification,
	const uint8_t *key, size_t length);


/**
 * Constant initializer for the null signature verification API.
 */
#define	SIGNATURE_VERIFICATION_NULL_API_INIT  { \
		.verify_signature = signature_verification_null_verify_signature, \
		.get_max_signature_length = signature_verification_null_get_max_signature_length, \
		.set_verification_key = signature_verification_null_set_verification_key, \
		.is_key_valid = signature_verification_null_is_key_valid \
	}


/**
 * Initialize a static instance for null signature verification.  This can be a constant instance.
 *
 * There is no validation done on the arguments.
 */
#define	signature_verification_null_static_init()	{ \
		.base = SIGNATURE_VERIFICATION_NULL_API_INIT, \
	}


#endif	/* signature_verification_null_STATIC_H_ */
