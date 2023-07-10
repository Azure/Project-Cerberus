// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

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
