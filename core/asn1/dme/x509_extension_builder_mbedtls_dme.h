// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef X509_EXTENSION_BUILDER_MBEDTLS_DME_H_
#define X509_EXTENSION_BUILDER_MBEDTLS_DME_H_

#include "dme_structure.h"
#include "asn1/x509_extension_builder.h"


/**
 * X.509 extension handler for building a DME extension endorsing a DICE identity key.  The
 * extension builder uses mbedTLS ASN.1/DER encoding functions.
 */
struct x509_extension_builder_mbedtls_dme {
	struct x509_extension_builder base;		/**< Base extension builder API. */
	const struct dme_structure *dme;		/**< The DME structure being encoded in the extension. */
	uint8_t *ext_buffer;					/**< Buffer to use for building the extension data. */
	size_t ext_length;						/**< Length of the extension data duffer. */
};


int x509_extension_builder_mbedtls_dme_init (struct x509_extension_builder_mbedtls_dme *builder,
	const struct dme_structure *dme);
int x509_extension_builder_mbedtls_dme_init_with_buffer (
	struct x509_extension_builder_mbedtls_dme *builder, const struct dme_structure *dme,
	uint8_t *ext_buffer, size_t buffer_length);
void x509_extension_builder_mbedtls_dme_release (
	const struct x509_extension_builder_mbedtls_dme *builder);


#endif /* X509_EXTENSION_BUILDER_MBEDTLS_DME_H_ */
