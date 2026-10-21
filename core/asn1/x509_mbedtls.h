// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef X509_MBEDTLS_H_
#define X509_MBEDTLS_H_

#include "asn1/x509.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/x509_crt.h"


/**
 * The maximum size for a DER certificate.
 */
#define	X509_MAX_SIZE		1024


/**
 * Variable context for mbedTLS X.509 operations.
 */
struct x509_engine_mbedtls_state {
#ifdef X509_ENABLE_CREATE_CERTIFICATES
	mbedtls_ctr_drbg_context ctr_drbg;	/**< A random number generator for the engine. */
	mbedtls_entropy_context entropy;	/**< Entropy source for the random number generator. */
#endif
	uint8_t der_buf[X509_MAX_SIZE];		/**< Temp buffer for building certificate DER data. */
};

/**
 * An mbedTLS context for X.509 operations.
 */
struct x509_engine_mbedtls {
	struct x509_engine base;					/**< The base X.509 engine. */
	struct x509_engine_mbedtls_state *state;	/**< Variable context for the X.509 engine. */
};


int x509_mbedtls_init (struct x509_engine_mbedtls *engine, struct x509_engine_mbedtls_state *state);
int x509_mbedtls_init_state (const struct x509_engine_mbedtls *engine);
void x509_mbedtls_release (const struct x509_engine_mbedtls *engine);

/* ASN.1 encoding helper functions. */
int x509_mbedtls_close_asn1_object (uint8_t **pos, uint8_t *start, uint8_t tag, int *length);


#endif	/* X509_MBEDTLS_H_ */
