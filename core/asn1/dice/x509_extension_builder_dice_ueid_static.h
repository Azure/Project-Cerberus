// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef X509_EXTENSION_BUILDER_DICE_UEID_STATIC_H_
#define X509_EXTENSION_BUILDER_DICE_UEID_STATIC_H_

#include "x509_extension_builder_dice_ueid.h"


/* Internal functions declared to allow for static initialization. */
int x509_extension_builder_dice_ueid_build_dynamic (const struct x509_extension_builder *builder,
	struct x509_extension *extension);
void x509_extension_builder_dice_ueid_free_dynamic (const struct x509_extension_builder *builder,
	struct x509_extension *extension);

int x509_extension_builder_dice_ueid_build_static (const struct x509_extension_builder *builder,
	struct x509_extension *extension);
void x509_extension_builder_dice_ueid_free_static (const struct x509_extension_builder *builder,
	struct x509_extension *extension);


/**
 * Constant initializer for extension builder API using dynamic buffers.
 */
#define	X509_EXTENSION_BUILDER_DICE_UEID_DYNAMIC_API_INIT  { \
		.build = x509_extension_builder_dice_ueid_build_dynamic, \
		.free = x509_extension_builder_dice_ueid_free_dynamic \
	}

/**
 * Constant initializer for extension builder API using static buffers.
 */
#define	X509_EXTENSION_BUILDER_DICE_UEID_STATIC_API_INIT  { \
		.build = x509_extension_builder_dice_ueid_build_static, \
		.free = x509_extension_builder_dice_ueid_free_static \
	}


/**
 * Initialize a static instance for creating a TCG DICE Ueid extension.  The buffer that will be
 * used for the extension data will be dynamically allocated.  This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param ueid_ptr The device unique identifier that should be encoded in the extension.  This does
 * not need to be a constant value.  The contents can be updated at run-time to affect the value
 * that gets encoded in the extension.
 * @param length Length of the device UEID.
 */
#define	x509_extension_builder_dice_ueid_static_init(ueid_ptr, length)	{ \
		.base = X509_EXTENSION_BUILDER_DICE_UEID_DYNAMIC_API_INIT, \
		.ueid = ueid_ptr, \
		.ueid_length = length, \
		.ext_buffer = NULL, \
		.ext_length = 0, \
	}

/**
 * Initialize a static instance for creating a TCG DICE Ueid extension. The buffer used for the
 * extension data is statically provided during initialization.  This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param ueid_ptr The device unique identifier that should be encoded in the extension.  This
 * does not need to be a constant value.  The contents can be updated at run-time to affect the
 * value that gets encoded in the extension.
 * @param length Length of the device UEID.
 * @param ext_buffer_ptr Buffer for the encoded Ueid extension data.
 * @param buffer_length Length of the extension data buffer.
 */
#define	x509_extension_builder_dice_ueid_static_init_with_buffer(ueid_ptr, length, \
	ext_buffer_ptr, buffer_length)	{ \
		.base = X509_EXTENSION_BUILDER_DICE_UEID_STATIC_API_INIT, \
		.ueid = ueid_ptr, \
		.ueid_length = length, \
		.ext_buffer = ext_buffer_ptr, \
		.ext_length = buffer_length, \
	}


#endif	/* X509_EXTENSION_BUILDER_DICE_UEID_STATIC_H_ */
