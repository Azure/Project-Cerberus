// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SIGNATURE_VERIFICATION_NULL_H_
#define SIGNATURE_VERIFICATION_NULL_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "crypto/signature_verification.h"

/**
 * Verification implementation to bypass signature verification.
 */
struct signature_verification_null {
	struct signature_verification base;	/**< Base verification instance. */
};


int signature_verification_null_init (struct signature_verification_null *verification);
void signature_verification_null_release (const struct signature_verification_null *verification);


#endif	/* SIGNATURE_VERIFICATION_NULL_H_ */
