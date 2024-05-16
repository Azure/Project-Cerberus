// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef X509_EXTENSION_BUILDER_MBEDTLS_DICE_TCBINFO_STATIC_H_
#define X509_EXTENSION_BUILDER_MBEDTLS_DICE_TCBINFO_STATIC_H_

#include "x509_extension_builder_mbedtls_dice_tcbinfo.h"


/* Internal functions declared to allow for static initialization. */
int x509_extension_builder_mbedtls_dice_tcbinfo_build_dynamic (
	const struct x509_extension_builder *builder, struct x509_extension *extension);
void x509_extension_builder_mbedtls_dice_tcbinfo_free_dynamic (
	const struct x509_extension_builder *builder, struct x509_extension *extension);

int x509_extension_builder_mbedtls_dice_tcbinfo_build_static (
	const struct x509_extension_builder *builder, struct x509_extension *extension);
void x509_extension_builder_mbedtls_dice_tcbinfo_free_static (
	const struct x509_extension_builder *builder, struct x509_extension *extension);


/**
 * Constant initializer for extension builder API using dynamic buffers.
 */
#define	X509_EXTENSION_BUILDER_MBEDTLS_DICE_TCBINFO_DYNAMIC_API_INIT  { \
		.build = x509_extension_builder_mbedtls_dice_tcbinfo_build_dynamic, \
		.free = x509_extension_builder_mbedtls_dice_tcbinfo_free_dynamic \
	}

/**
 * Constant initializer for extension builder API using static buffers.
 */
#define	X509_EXTENSION_BUILDER_MBEDTLS_DICE_TCBINFO_STATIC_API_INIT  { \
		.build = x509_extension_builder_mbedtls_dice_tcbinfo_build_static, \
		.free = x509_extension_builder_mbedtls_dice_tcbinfo_free_static \
	}


/**
 * Initialize a static instance for creating a TCG DICE TcbInfo extension.  The buffer that will be
 * used for the extension data will be dynamically allocated.  This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param tcb_ptr The firmware TCB to encode in the extension.  This does not need to be constant.
 * The contents can be updated at run-time to affect what will be encoded in the extension.
 */
#define	x509_extension_builder_mbedtls_dice_tcbinfo_static_init(tcb_ptr)	{ \
		.base = X509_EXTENSION_BUILDER_MBEDTLS_DICE_TCBINFO_DYNAMIC_API_INIT, \
		.tcb = tcb_ptr, \
		.ext_buffer = NULL, \
		.ext_length = 0, \
	}

/**
 * Initialize a static instance for creating a TCG DICE TcbInfo extension. The buffer used for the
 * extension data is statically provided during initialization.  This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param tcb_ptr The firmware TCB to encode in the extension.  This does not need to be constant.
 * The contents can be updated at run-time to affect what will be encoded in the extension.
 * @param ext_buffer_ptr Buffer for the encoded TcbInfo extension data.
 * @param buffer_length Length of the extension data buffer.
 */
#define	x509_extension_builder_mbedtls_dice_tcbinfo_static_init_with_buffer(tcb_ptr, \
	ext_buffer_ptr, buffer_length)	{ \
		.base = X509_EXTENSION_BUILDER_MBEDTLS_DICE_TCBINFO_STATIC_API_INIT, \
		.tcb = tcb_ptr, \
		.ext_buffer = ext_buffer_ptr, \
		.ext_length = buffer_length, \
	}


#endif	/* X509_EXTENSION_BUILDER_MBEDTLS_DICE_TCBINFO_STATIC_H_ */
