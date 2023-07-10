// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef X509_EXTENSION_BUILDER_OPENSSL_DICE_TCBINFO_STATIC_H_
#define X509_EXTENSION_BUILDER_OPENSSL_DICE_TCBINFO_STATIC_H_

#include "x509_extension_builder_openssl_dice_tcbinfo.h"


/* Internal functions declared to allow for static initialization. */
int x509_extension_builder_openssl_dice_tcbinfo_build (const struct x509_extension_builder *builder,
	struct x509_extension *extension);
void x509_extension_builder_openssl_dice_tcbinfo_free (const struct x509_extension_builder *builder,
	struct x509_extension *extension);


/**
 * Constant initializer for extension builder API.
 */
#define	X509_EXTENSION_BUILDER_MBEDTLS_DICE_TCBINFO_API_INIT  { \
		.build = x509_extension_builder_openssl_dice_tcbinfo_build, \
		.free = x509_extension_builder_openssl_dice_tcbinfo_free \
	}


/**
 * Initialize a static instance for creating a TCG DICE TcbInfo extension.   This can be a constant
 * instance.
 *
 * There is no validation done on the arguments.
 *
 * @param tcb_ptr The device unique identifier that should be encoded in the extension.  This
 * does not need to be constant.  The contents can be updated at run-time to affect what will be
 * encoded in the extension.
 */
#define	x509_extension_builder_openssl_dice_tcbinfo_static_init(tcb_ptr)	{ \
		.base = X509_EXTENSION_BUILDER_MBEDTLS_DICE_TCBINFO_API_INIT, \
		.tcb = tcb_ptr, \
	}


#endif /* X509_EXTENSION_BUILDER_OPENSSL_DICE_TCBINFO_STATIC_H_ */
