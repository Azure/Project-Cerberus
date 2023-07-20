// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef X509_EXTENSION_BUILDER_MBEDTLS_DICE_TCBINFO_H_
#define X509_EXTENSION_BUILDER_MBEDTLS_DICE_TCBINFO_H_

#include "asn1/x509_extension_builder.h"
#include "riot/tcg_dice.h"


/**
 * Builder for the TCG DICE TcbInfo extension.  The extension builder uses mbedTLS ASN.1/DER
 * encoding functions.
 */
struct x509_extension_builder_mbedtls_dice_tcbinfo {
	struct x509_extension_builder base;		/**< Base extension builder API. */
	const struct tcg_dice_tcbinfo *tcb;		/**< The TCB information to encode in the extension. */
	uint8_t *ext_buffer;					/**< Buffer to use for building the extension data. */
	size_t ext_length;						/**< Length of the extension data duffer. */
};


int x509_extension_builder_mbedtls_dice_tcbinfo_init (
	struct x509_extension_builder_mbedtls_dice_tcbinfo *builder,
	const struct tcg_dice_tcbinfo *tcb);
int x509_extension_builder_mbedtls_dice_tcbinfo_init_with_buffer (
	struct x509_extension_builder_mbedtls_dice_tcbinfo *builder, const struct tcg_dice_tcbinfo *tcb,
	uint8_t *ext_buffer, size_t buffer_length);
void x509_extension_builder_mbedtls_dice_tcbinfo_release (
	const struct x509_extension_builder_mbedtls_dice_tcbinfo *builder);


#endif /* X509_EXTENSION_BUILDER_MBEDTLS_DICE_TCBINFO_H_ */
