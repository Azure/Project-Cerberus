// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef X509_EXTENSION_BUILDER_OPENSSL_DICE_UEID_H_
#define X509_EXTENSION_BUILDER_OPENSSL_DICE_UEID_H_

#include "asn1/x509_extension_builder.h"


/**
 * Builder for the TCG DICE Ueid extension.  The extension builder uses OpenSSL ASN.1/DER encoding
 * functions.
 */
struct x509_extension_builder_openssl_dice_ueid {
	struct x509_extension_builder base;			/**< Base extension builder API. */
	const uint8_t *ueid;						/**< The UEID to encode in the extension. */
	size_t ueid_length;							/**< Length of the UEID. */
};


int x509_extension_builder_openssl_dice_ueid_init (
	struct x509_extension_builder_openssl_dice_ueid *builder, const uint8_t *ueid, size_t length);
void x509_extension_builder_openssl_dice_ueid_release (
	const struct x509_extension_builder_openssl_dice_ueid *builder);


#endif /* X509_EXTENSION_BUILDER_OPENSSL_DICE_UEID_H_ */
