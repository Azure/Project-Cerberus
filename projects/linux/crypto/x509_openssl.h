// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef X509_OPENSSL_H_
#define X509_OPENSSL_H_

#include <openssl/x509_vfy.h>
#include "crypto/x509.h"


/**
 * An OpenSSL context for X.509 operations.
 */
struct x509_engine_openssl {
	struct x509_engine base;		/**< The base X.509 engine. */
};


int x509_openssl_init (struct x509_engine_openssl *engine);
void x509_openssl_release (struct x509_engine_openssl *engine);


#endif /* X509_OPENSSL_H_ */
