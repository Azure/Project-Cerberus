// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef X509_CERT_BUILD_H_
#define X509_CERT_BUILD_H_

#include "asn1/x509.h"
#include "crypto/ecc.h"
#include "crypto/hash.h"


/**
 * The maximum size allowed for a DER encoded certificate.
 */
#define	X509_CERT_BUILD_MAX_SIZE		1024


/**
 * An X.509 handler that only supports building certificates.  This support is provided without
 * requiring any external ASN.1 encoders.  The primary use-case for this would be for DICE layer 0
 * code to build the DICE identity certificate chain.
 *
 * This implementation does not provide any functionality for certificate parsing and authentication
 * and must not be used in any contexts that have X509_ENABLE_AUTHENTICATION defined.
 *
 * This implementation only provides ASN.1/DER encoding for certificate and CSR building.  All
 * crypto functionality is leveraged through the common crypto APIs.  This allows any hardware or
 * software crypto implementation to be used for certificate signing.
 *
 * There is only limited support for RSA keys with this implementation to allow signing certificates
 * containing an RSA public key.
 *   - Input RSA keys are required to be public keys.
 *   - RSA CSRs or self-signed certificates cannot be created.
 *   - Certificate signing using an RSA CA is not supported.
 */
struct x509_engine_cert_build {
	struct x509_engine base;	/**< The base X.509 engine. */
	struct ecc_engine *ecc;		/**< The ECC engine to use for certificate signing. */
	struct hash_engine *hash;	/**< The hash engine to use digest calculation. */
};


int x509_cert_build_init (struct x509_engine_cert_build *engine, struct ecc_engine *ecc,
	struct hash_engine *hash);
void x509_cert_build_release (struct x509_engine_cert_build *engine);


#endif /* X509_CERT_BUILD_H_ */
