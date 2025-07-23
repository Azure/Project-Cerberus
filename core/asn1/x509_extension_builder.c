// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "platform_api.h"
#include "x509_extension_builder.h"


/**
 * Initialize an extension descriptor with the extension information.
 *
 * @param extension The extension descriptor to initialize.
 * @param critical Value to assign to the descriptor 'critical' flag.
 * @param oid Buffer containing the encoded OID for the extension.
 * @param oid_length Length of the extension OID.
 * @param data Buffer containing the encoded extension data.
 * @param data_length Length of the extension data.
 */
void x509_extension_builder_init_extension_descriptor (struct x509_extension *extension,
	bool critical, const uint8_t *oid, size_t oid_length, const uint8_t *data, size_t data_length)
{
	const uint8_t **oid_tmp;
	const uint8_t **data_tmp;

	if (extension != NULL) {
		extension->critical = critical;

		/* Temp pointers are used to avoid compile errors with modifying const pointers. */
		oid_tmp = (const uint8_t**) &extension->oid;
		*oid_tmp = oid;
		extension->oid_length = oid_length;

		data_tmp = (const uint8_t**) &extension->data;
		*data_tmp = data;
		extension->data_length = data_length;
	}
}

/**
 * Free the extension data referenced by an extension descriptor.
 *
 * This must only be called for extensions that used dynamically allocated buffers.
 *
 * @param extension The extension descriptor to free.
 */
void x509_extension_builder_free_extension_descriptor (struct x509_extension *extension)
{
	/* A temp pointer is needed to get around the const pointer in the descriptor */
	void **data_tmp;

	if ((extension != NULL) && (extension->data != NULL)) {
		data_tmp = (void**) &extension->data;
		platform_free (*data_tmp);
		*data_tmp = NULL;
		extension->data_length = 0;
	}
}
