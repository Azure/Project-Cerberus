// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SIGNATURE_VERIFICATION_RSA_STATIC_H_
#define SIGNATURE_VERIFICATION_RSA_STATIC_H_

#include "crypto/signature_verification_rsa.h"


/* Internal functions declared to allow for static initialization. */
int signature_verification_rsa_verify_signature (const struct signature_verification *verification,
	const uint8_t *digest, size_t length, const uint8_t *signature, size_t sig_length);
int signature_verification_rsa_set_verification_key (
	const struct signature_verification *verification, const uint8_t *key, size_t length);
int signature_verification_rsa_is_key_valid (const struct signature_verification *verification,
	const uint8_t *key, size_t length);


/**
 * Constant initializer for the signature verification API.
 */
#define	SIGNATURE_VERIFICATION_RSA_API_INIT  { \
		.verify_signature = signature_verification_rsa_verify_signature, \
		.set_verification_key = signature_verification_rsa_set_verification_key, \
		.is_key_valid = signature_verification_rsa_is_key_valid \
	}


/**
 * Initialize a static instance for RSA signature verification.  This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the verification.
 * @param rsa_ptr The RSA engine to use for signature verification.
 */
#define	signature_verification_rsa_static_init(state_ptr, rsa_ptr)	{ \
		.base = SIGNATURE_VERIFICATION_RSA_API_INIT, \
		.state = state_ptr, \
		.rsa = rsa_ptr \
	}


#endif /* SIGNATURE_VERIFICATION_RSA_STATIC_H_ */
