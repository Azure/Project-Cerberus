// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef X509_EXTENSION_BUILDER_MBEDTLS_EKU_STATIC_H_
#define X509_EXTENSION_BUILDER_MBEDTLS_EKU_STATIC_H_

#include "x509_extension_builder_mbedtls_eku.h"


/* Internal functions declared to allow for static initialization. */
int x509_extension_builder_mbedtls_eku_build_dynamic (const struct x509_extension_builder *builder,
	struct x509_extension *extension);
void x509_extension_builder_mbedtls_eku_free_dynamic (const struct x509_extension_builder *builder,
	struct x509_extension *extension);

int x509_extension_builder_mbedtls_eku_build_static (const struct x509_extension_builder *builder,
	struct x509_extension *extension);
void x509_extension_builder_mbedtls_eku_free_static (const struct x509_extension_builder *builder,
	struct x509_extension *extension);


/**
 * Constant initializer for the extension builder API using dynamic buffers.
 */
#define	X509_EXTENSION_BUILDER_MBEDTLS_EKU_DYNAMIC_API_INIT  { \
		.build = x509_extension_builder_mbedtls_eku_build_dynamic, \
		.free = x509_extension_builder_mbedtls_eku_free_dynamic \
	}

/**
 * Constant initializer for the extension builder API using static buffers.
 */
#define	X509_EXTENSION_BUILDER_MBEDTLS_EKU_STATIC_API_INIT  { \
		.build = x509_extension_builder_mbedtls_eku_build_static, \
		.free = x509_extension_builder_mbedtls_eku_free_static \
	}


/**
 * Initialize a static instance for creating an Extended Key Usage extension.  The buffer that will
 * be used for the extension data will be dynamically allocated.  This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param eku_ptr The list of EKU OIDs that will be included in the extension data.  While the list
 * location and size must be pre-determined, the contents of the OID descriptors in the list can be
 * externally modified after initialization to change the values that will be encoded in the
 * extension.
 * @param eku_count_arg The number of EKU OIDs to add to the extension.
 * @param critical_arg Flag to indicate if the extension should be marked critical.
 */
#define	x509_extension_builder_mbedtls_eku_static_init(eku_ptr, eku_count_arg, critical_arg)	{ \
		.base = X509_EXTENSION_BUILDER_MBEDTLS_EKU_DYNAMIC_API_INIT, \
		.eku = eku_ptr, \
		.eku_count = eku_count_arg, \
		.critical = critical_arg, \
		.ext_buffer = NULL, \
		.ext_length = 0, \
	}

/**
 * Initialize a static instance for creating an Extended Key Usage extension. The buffer used for
 * the extension data is statically provided during initialization.  This can be a constant
 * instance.
 *
 * There is no validation done on the arguments.
 *
 * @param eku_ptr The list of EKU OIDs that will be included in the extension data.  While the list
 * location and size must be pre-determined, the contents of the OID descriptors in the list can be
 * externally modified after initialization to change the values that will be encoded in the
 * extension.
 * @param eku_count_arg The number of EKU OIDs to add to the extension.
 * @param critical_arg Flag to indicate if the extension should be marked critical.
 * @param ext_buffer_ptr Buffer for the encoded EKU extension data.
 * @param buffer_length Length of the extension data buffer.
 */
#define	x509_extension_builder_mbedtls_eku_static_init_with_buffer(eku_ptr, eku_count_arg, \
	critical_arg, ext_buffer_ptr, buffer_length)	{ \
		.base = X509_EXTENSION_BUILDER_MBEDTLS_EKU_STATIC_API_INIT, \
		.eku = eku_ptr, \
		.eku_count = eku_count_arg, \
		.critical = critical_arg, \
		.ext_buffer = ext_buffer_ptr, \
		.ext_length = buffer_length, \
	}


#endif	/* X509_EXTENSION_BUILDER_MBEDTLS_EKU_STATIC_H_ */
