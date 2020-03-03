// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_MBEDTLS_H_
#define AES_MBEDTLS_H_

#include "aes.h"
#include "mbedtls/gcm.h"


/**
 * An mbedTLS context for AES operations.
 */
struct aes_engine_mbedtls {
	struct aes_engine base;			/**< The base AES engine. */
	mbedtls_gcm_context context;	/**< Context for AES-GCM operations. */
};


int aes_mbedtls_init (struct aes_engine_mbedtls *engine);
void aes_mbedtls_release (struct aes_engine_mbedtls *engine);


#endif /* AES_MBEDTLS_H_ */
