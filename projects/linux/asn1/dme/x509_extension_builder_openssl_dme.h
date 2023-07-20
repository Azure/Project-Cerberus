// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef X509_EXTENSION_BUILDER_OPENSSL_DME_H_
#define X509_EXTENSION_BUILDER_OPENSSL_DME_H_

#include "asn1/x509_extension_builder.h"
#include "asn1/dme/dme_structure.h"


/**
 * X.509 extension handler for building a DME extension endorsing a DICE identity key.  The
 * extension builder uses OpenSSL ASN.1/DER encoding functions.
 */
struct x509_extension_builder_openssl_dme {
	struct x509_extension_builder base;		/**< Base extension builder API. */
	const struct dme_structure *dme;		/**< The DME structure being encoded in the extension. */
};


int x509_extension_builder_openssl_dme_init (struct x509_extension_builder_openssl_dme *builder,
	const struct dme_structure *dme);
void x509_extension_builder_openssl_dme_release (
	const struct x509_extension_builder_openssl_dme *builder);


#endif /* X509_EXTENSION_BUILDER_OPENSSL_DME_H_ */
