// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef X509_RIOT_H_
#define X509_RIOT_H_

#include "crypto/x509.h"
#include "crypto/ecc.h"
#include "crypto/hash.h"


/**
 * The maximum size for a DER certificate.
 */
#define	X509_MAX_SIZE		1024


/**
 * An X.509 handler for generating DICE certificates.
 *
 * This implementation only provides ASN.1/DER encoding for certificate and CSR building.  All
 * crypto functionality is leveraged through the defined crypto APIs.
 *
 * This implementation does not provide any functionality for certificate parsing and authentication
 * and must not be used in any contexts that have X509_ENABLE_AUTHENTICATION defined.
 *
 * There is only limited support for RSA keys with this implementation.
 *   - Input RSA keys are required to be public keys.
 *   - RSA CSRs or self-signed certificates cannot be created.
 *   - Certificate signing using an RSA CA is not supported.
 */
struct x509_engine_riot {
	struct x509_engine base;	/**< The base X.509 engine. */
	struct ecc_engine *ecc;		/**< An ECC engine for the riot X.509 engine. */
	struct hash_engine *hash;	/**< A hash engine for the riot X.509 engine. */
};


int x509_riot_init (struct x509_engine_riot *engine, struct ecc_engine *ecc,
	struct hash_engine *hash);
void x509_riot_release (struct x509_engine_riot *engine);


#endif /* X509_RIOT_H_ */
