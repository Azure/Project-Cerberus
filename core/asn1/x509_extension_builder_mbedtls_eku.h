// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef X509_EXTENSION_BUILDER_MBEDTLS_EKU_H_
#define X509_EXTENSION_BUILDER_MBEDTLS_EKU_H_

#include "x509_extension_builder.h"
#include "x509_extension_builder_eku.h"


/**
 * Builder for the Extended Key Usage extension.  The extension builder uses mbedTLS ASN.1/DER
 * encoding functions.
 */
struct x509_extension_builder_mbedtls_eku {
	struct x509_extension_builder base;					/**< Base extension builder API. */
	const struct x509_extension_builder_eku_oid *eku;	/**< List of EKU OIDs to include. */
	size_t eku_count;									/**< Number of EKU OIDs in the list. */
	bool critical;										/**< Flag indicating if the extension is critical. */
	uint8_t *ext_buffer;								/**< Buffer to use for building the extension data. */
	size_t ext_length;									/**< Length of the extension data duffer. */
};


int x509_extension_builder_mbedtls_eku_init (struct x509_extension_builder_mbedtls_eku *builder,
	const struct x509_extension_builder_eku_oid *eku, size_t eku_count, bool critical);
int x509_extension_builder_mbedtls_eku_init_with_buffer (
	struct x509_extension_builder_mbedtls_eku *builder,
	const struct x509_extension_builder_eku_oid *eku, size_t eku_count, bool critical,
	uint8_t *ext_buffer, size_t buffer_length);
void x509_extension_builder_mbedtls_eku_release (
	const struct x509_extension_builder_mbedtls_eku *builder);


#endif	/* X509_EXTENSION_BUILDER_MBEDTLS_EKU_H_ */
