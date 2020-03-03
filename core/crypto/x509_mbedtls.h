// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef X509_MBEDTLS_H_
#define X509_MBEDTLS_H_

#include "x509.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/x509_crt.h"


/**
 * The maximum size for a DER certificate.
 */
#define	X509_MAX_SIZE		1024


/**
 * An mbedTLS context for X.509 operations.
 */
struct x509_engine_mbedtls {
	struct x509_engine base;			/**< The base X.509 engine. */
	mbedtls_ctr_drbg_context ctr_drbg;	/**< A random number generator for the engine. */
	mbedtls_entropy_context entropy;	/**< Entropy source for the random number generator. */
	uint8_t der_buf[X509_MAX_SIZE];		/**< Temp buffer for building certificate DER data. */
};


int x509_mbedtls_init (struct x509_engine_mbedtls *engine);
void x509_mbedtls_release (struct x509_engine_mbedtls *engine);


#endif /* X509_MBEDTLS_H_ */
