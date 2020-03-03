// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ECC_OPENSSL_H_
#define ECC_OPENSSL_H_

#include "crypto/ecc.h"


/**
 * An OpenSSL context for ECC operations.
 */
struct ecc_engine_openssl {
	struct ecc_engine base;		/**< The base ECC engine. */
};


int ecc_openssl_init (struct ecc_engine_openssl *engine);
void ecc_openssl_release (struct ecc_engine_openssl *engine);


#endif /* ECC_OPENSSL_H_ */
