// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HKDF_H_
#define HKDF_H_

#include "hkdf_interface.h"
#include "crypto/hash.h"


/**
 * Variable context for HKDF execution.
 */
struct hkdf_state {
	uint8_t prk[HASH_MAX_HASH_LEN];	/**< Current PRK used for key derivations. */
	enum hmac_hash hmac_type;		/**< Hash algorithm used for the HMAC. */
};

/**
 * General implementation of HKDF that is compatible with any instance of the common hash interface.
 */
struct hkdf {
	struct hkdf_interface base;		/**< Base HKDF API. */
	struct hkdf_state *state;		/**< Variable context for the HKDF execution. */
	const struct hash_engine *hash;	/**< Hash engine to use for HMAC operations. */
};


int hkdf_init (struct hkdf *hkdf, struct hkdf_state *state, const struct hash_engine *hash);
int hkdf_init_state (const struct hkdf *hkdf);
void hkdf_release (const struct hkdf *hkdf);


#endif	/* HKDF_H_ */
