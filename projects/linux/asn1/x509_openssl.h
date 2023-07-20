// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef X509_OPENSSL_H_
#define X509_OPENSSL_H_

#include <openssl/x509_vfy.h>
#include "asn1/x509.h"


/**
 * An OpenSSL context for X.509 operations.
 */
struct x509_engine_openssl {
	struct x509_engine base;		/**< The base X.509 engine. */
};


int x509_openssl_init (struct x509_engine_openssl *engine);
void x509_openssl_release (struct x509_engine_openssl *engine);

/* ASN.1 encoding helper functions. */
int x509_openssl_parse_encoded_oid (const uint8_t *encoded_oid, size_t length, ASN1_OBJECT **oid);
int x509_openssl_set_bit_string (const uint8_t *data, size_t length, ASN1_BIT_STRING *bits);


#endif /* X509_OPENSSL_H_ */
