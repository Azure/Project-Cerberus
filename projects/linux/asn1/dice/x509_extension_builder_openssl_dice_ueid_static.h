// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef X509_EXTENSION_BUILDER_OPENSSL_DICE_UEID_STATIC_H_
#define X509_EXTENSION_BUILDER_OPENSSL_DICE_UEID_STATIC_H_

#include "x509_extension_builder_openssl_dice_ueid.h"


/* Internal functions declared to allow for static initialization. */
int x509_extension_builder_openssl_dice_ueid_build (const struct x509_extension_builder *builder,
	struct x509_extension *extension);
void x509_extension_builder_openssl_dice_ueid_free (const struct x509_extension_builder *builder,
	struct x509_extension *extension);


/**
 * Constant initializer for extension builder API.
 */
#define	X509_EXTENSION_BUILDER_OPENSSL_DICE_UEID_API_INIT  { \
		.build = x509_extension_builder_openssl_dice_ueid_build, \
		.free = x509_extension_builder_openssl_dice_ueid_free \
	}


/**
 * Initialize a static instance for creating a TCG DICE Ueid extension.  This can be a constant
 * instance.
 *
 * There is no validation done on the arguments.
 *
 * @param ueid_ptr The device unique identifier that should be encoded in the extension.  This does
 * not need to be a constant value.  The contents can be updated at run-time to affect the value
 * that gets encoded in the extension.
 * @param length Length of the device UEID.
 */
#define	x509_extension_builder_openssl_dice_ueid_static_init(ueid_ptr, length)	{ \
		.base = X509_EXTENSION_BUILDER_OPENSSL_DICE_UEID_API_INIT, \
		.ueid = ueid_ptr, \
		.ueid_length = length, \
	}


#endif /* X509_EXTENSION_BUILDER_OPENSSL_DICE_UEID_STATIC_H_ */
