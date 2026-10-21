// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "platform_api.h"
#include "x509_extension_builder_mbedtls_eku.h"
#include "x509_mbedtls.h"
#include "x509_oid.h"
#include "common/unused.h"
#include "mbedtls/asn1write.h"


/**
 * Create the Extended Key Usage extension.
 *
 * @param x509 The extension builder.
 * @param buffer The buffer to use for the extension data.
 * @param length Length of the extension data buffer.
 * @param extension Output for extension information.
 *
 * @return 0 if the extension was created successfully or an error code.
 */
static int x509_extension_builder_mbedtls_eku_create_extension (
	const struct x509_extension_builder_mbedtls_eku *x509, uint8_t *buffer, size_t length,
	struct x509_extension *extension)
{
	uint8_t *pos;
	int enc_length = 0;
	size_t i;
	int ret;

	if ((x509->eku == NULL) || (x509->eku_count == 0)) {
		return EKU_EXTENSION_INVALID_ARGUMENT;
	}

	pos = buffer + length;

	/* mbedTLS builds ASN.1 in reverse, so read the OIDs from the end of the list. */
	for (i = x509->eku_count; i > 0; i--) {
		MBEDTLS_ASN1_CHK_ADD (enc_length,
			mbedtls_asn1_write_oid (&pos, buffer, (char*) x509->eku[i - 1].oid,
			x509->eku[i - 1].length));
	}

	ret = x509_mbedtls_close_asn1_object (&pos, buffer,
		(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE), &enc_length);
	if (ret != 0) {
		return ret;
	}

	if (pos != buffer) {
		memmove (buffer, pos, enc_length);
	}

	x509_extension_builder_init_extension_descriptor (extension, x509->critical,
		X509_OID_EKU_EXTENSION, X509_OID_EKU_EXTENSION_LENGTH, buffer, enc_length);

	return 0;
}

int x509_extension_builder_mbedtls_eku_build_dynamic (const struct x509_extension_builder *builder,
	struct x509_extension *extension)
{
	const struct x509_extension_builder_mbedtls_eku *x509 =
		(const struct x509_extension_builder_mbedtls_eku*) builder;
	uint8_t *buffer;
	size_t length;
	int status;

	if ((builder == NULL) || (extension == NULL)) {
		return EKU_EXTENSION_INVALID_ARGUMENT;
	}

	length = x509_extension_builder_eku_get_ext_buffer_length (x509->eku, x509->eku_count);
	buffer = platform_malloc (length);
	if (buffer == NULL) {
		return EKU_EXTENSION_NO_MEMORY;
	}

	status = x509_extension_builder_mbedtls_eku_create_extension (x509, buffer, length, extension);
	if (status != 0) {
		platform_free (buffer);
	}

	return status;
}

int x509_extension_builder_mbedtls_eku_build_static (const struct x509_extension_builder *builder,
	struct x509_extension *extension)
{
	const struct x509_extension_builder_mbedtls_eku *x509 =
		(const struct x509_extension_builder_mbedtls_eku*) builder;
	int status;

	if ((x509 == NULL) || (extension == NULL) || (x509->ext_buffer == NULL)) {
		return EKU_EXTENSION_INVALID_ARGUMENT;
	}

	status = x509_extension_builder_mbedtls_eku_create_extension (x509, x509->ext_buffer,
		x509->ext_length, extension);
	if (status == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL) {
		status = EKU_EXTENSION_SMALL_EXT_BUFFER;
	}

	return status;
}

void x509_extension_builder_mbedtls_eku_free_dynamic (const struct x509_extension_builder *builder,
	struct x509_extension *extension)
{
	UNUSED (builder);

	x509_extension_builder_free_extension_descriptor (extension);
}

void x509_extension_builder_mbedtls_eku_free_static (const struct x509_extension_builder *builder,
	struct x509_extension *extension)
{
	UNUSED (builder);
	UNUSED (extension);
}

/**
 * Initialize an extension builder for an Extended Key Usage extension.  The buffer that will be
 * used for the extension data will be dynamically allocated.
 *
 * @param builder The extension builder to initialize.
 * @param eku The list of EKU OIDs that will be included in the extension data.  While the list
 * location and size must be pre-determined, the contents of the OID descriptors in the list can be
 * externally modified after initialization to change the values that will be encoded in the
 * extension.
 * @param eku_count The number of EKU OIDs to add to the extension.
 * @param critical Flag to indicate if the extension should be marked critical.
 *
 * @return 0 if the extension builder was initialized successfully or an error code.
 */
int x509_extension_builder_mbedtls_eku_init (struct x509_extension_builder_mbedtls_eku *builder,
	const struct x509_extension_builder_eku_oid *eku, size_t eku_count, bool critical)
{
	if ((builder == NULL) || (eku == NULL) || (eku_count == 0)) {
		return EKU_EXTENSION_INVALID_ARGUMENT;
	}

	memset (builder, 0, sizeof (struct x509_extension_builder_mbedtls_eku));

	builder->base.build = x509_extension_builder_mbedtls_eku_build_dynamic;
	builder->base.free = x509_extension_builder_mbedtls_eku_free_dynamic;

	builder->eku = eku;
	builder->eku_count = eku_count;
	builder->critical = critical;

	return 0;
}

/**
 * Initialize an extension builder for an Extended Key Usage extension.  The buffer used for the
 * extension data is statically provided during initialization.
 *
 * @param builder The extension builder to initialize.
 * @param eku The list of EKU OIDs that will be included in the extension data.  While the list
 * location and size must be pre-determined, the contents of the OID descriptors in the list can be
 * externally modified after initialization to change the values that will be encoded in the
 * extension.
 * @param eku_count The number of EKU OIDs to add to the extension.
 * @param critical Flag to indicate if the extension should be marked critical.
 * @param ext_buffer Buffer for the encoded EKU extension data.
 * @param buffer_length Length of the extension data buffer.
 *
 * @return 0 if the extension builder was initialized successfully or an error code.
 */
int x509_extension_builder_mbedtls_eku_init_with_buffer (
	struct x509_extension_builder_mbedtls_eku *builder,
	const struct x509_extension_builder_eku_oid *eku, size_t eku_count, bool critical,
	uint8_t *ext_buffer, size_t buffer_length)
{
	if ((builder == NULL) || (eku == NULL) || (eku_count == 0) || (ext_buffer == NULL)) {
		return EKU_EXTENSION_INVALID_ARGUMENT;
	}

	memset (builder, 0, sizeof (struct x509_extension_builder_mbedtls_eku));

	builder->base.build = x509_extension_builder_mbedtls_eku_build_static;
	builder->base.free = x509_extension_builder_mbedtls_eku_free_static;

	builder->eku = eku;
	builder->eku_count = eku_count;
	builder->critical = critical;
	builder->ext_buffer = ext_buffer;
	builder->ext_length = buffer_length;

	return 0;
}

/**
 * Release the resources used by an Extended Key Usage extension builder.
 *
 * @param builder The extension builder to release.
 */
void x509_extension_builder_mbedtls_eku_release (
	const struct x509_extension_builder_mbedtls_eku *builder)
{
	UNUSED (builder);
}
