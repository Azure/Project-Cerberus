// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "rsa.h"


/**
 * Compare RSA public keys to determine if they are the same key.
 *
 * @param key1 The first RSA public key.
 * @param key2 The second RSA public key.
 *
 * @return true if the keys are the same or false if they are different.
 */
bool rsa_same_public_key (const struct rsa_public_key *key1, const struct rsa_public_key *key2)
{
	if ((key1 == NULL) || (key2 == NULL)) {
		if ((key1 == NULL) && (key2 == NULL)) {
			return true;
		}

		return false;
	}

	if ((key1->exponent != key2->exponent) || (key1->mod_length != key2->mod_length)) {
		return false;
	}

	if (memcmp (key1->modulus, key2->modulus, key1->mod_length) != 0) {
		return false;
	}

	return true;
}
