// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "platform_api.h"
#include "x509_extension_builder_dice_ueid.h"
#include "x509_extension_builder_mbedtls_dice_ueid.h"
#include "common/unused.h"
#include "mbedtls/asn1write.h"


/**
 * Create the TCG DICE Ueid extension.
 *
 * @param dice The extension builder.
 * @param buffer The buffer to use for the extension data.
 * @param length Length of the extension data buffer.
 * @param extension Output for extension information.
 *
 * @return 0 if the extension was created successfully or an error code.
 */
int x509_extension_builder_mbedtls_dice_ueid_create_extension (
	const struct x509_extension_builder_mbedtls_dice_ueid *dice, uint8_t *buffer, size_t length,
	struct x509_extension *extension)
{
	uint8_t *pos;
	size_t enc_length = 0;
	int ret;

	pos = buffer + length;

	/* ueid			OCTET STRING */
	MBEDTLS_ASN1_CHK_ADD (enc_length,
		mbedtls_asn1_write_octet_string (&pos, buffer, dice->ueid, dice->ueid_length));

	/* TcgUeid ::= SEQUENCE */
	MBEDTLS_ASN1_CHK_ADD (enc_length, mbedtls_asn1_write_len (&pos, buffer, enc_length));
	MBEDTLS_ASN1_CHK_ADD (enc_length,
		mbedtls_asn1_write_tag (&pos, buffer, (MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)));

	if (pos != buffer) {
		memmove (buffer, pos, enc_length);
	}

	x509_extension_builder_init_extension_descriptor (extension, false,
		X509_EXTENSION_BUILDER_DICE_UEID_OID, X509_EXTENSION_BUILDER_DICE_UEID_OID_LENGTH, buffer,
		enc_length);

	return 0;
}

int x509_extension_builder_mbedtls_dice_ueid_build_dynamic (
	const struct x509_extension_builder *builder, struct x509_extension *extension)
{
	const struct x509_extension_builder_mbedtls_dice_ueid *dice =
		(const struct x509_extension_builder_mbedtls_dice_ueid*) builder;
	uint8_t *buffer;
	size_t length;
	int status;

	if ((dice == NULL) || (extension == NULL)) {
		return DICE_UEID_EXTENSION_INVALID_ARGUMENT;
	}

	length = X509_EXTENSION_BUILDER_MBEDTLS_DICE_UEID_DATA_LENGTH (dice->ueid_length);
	buffer = platform_malloc (length);
	if (buffer == NULL) {
		return DICE_UEID_EXTENSION_NO_MEMORY;
	}

	status = x509_extension_builder_mbedtls_dice_ueid_create_extension (dice, buffer, length,
		extension);
	if (status != 0) {
		platform_free (buffer);
	}

	return 0;
}

int x509_extension_builder_mbedtls_dice_ueid_build_static (
	const struct x509_extension_builder *builder, struct x509_extension *extension)
{
	const struct x509_extension_builder_mbedtls_dice_ueid *dice =
		(const struct x509_extension_builder_mbedtls_dice_ueid*) builder;
	int status;

	if ((dice == NULL) || (extension == NULL) || (dice->ext_buffer == NULL)) {
		return DICE_UEID_EXTENSION_INVALID_ARGUMENT;
	}

	status = x509_extension_builder_mbedtls_dice_ueid_create_extension (dice, dice->ext_buffer,
		dice->ext_length, extension);
	if (status == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL) {
		status = DICE_UEID_EXTENSION_SMALL_EXT_BUFFER;
	}

	return status;
}

void x509_extension_builder_mbedtls_dice_ueid_free_dynamic (
	const struct x509_extension_builder *builder, struct x509_extension *extension)
{
	UNUSED (builder);

	platform_free ((void*) extension->data);
}

void x509_extension_builder_mbedtls_dice_ueid_free_static (
	const struct x509_extension_builder *builder, struct x509_extension *extension)
{
	UNUSED (builder);
	UNUSED (extension);
}

/**
 * Initialize an extension builder for a TCG DICE Ueid extension.  The buffer that will be used for
 * the extension data will be dynamically allocated.
 *
 * @param builder The extension builder to initialize.
 * @param ueid The device unique identifier that should be encoded in the extension.  This does
 * not need to be a constant value.  The contents can be externally modified after initialization to
 * change the value that will be encoded in the extension.
 * @param length Length of the device UEID.
 *
 * @return 0 if the extension builder was initialized successfully or an error code.
 */
int x509_extension_builder_mbedtls_dice_ueid_init (
	struct x509_extension_builder_mbedtls_dice_ueid *builder, const uint8_t *ueid, size_t length)
{
	if ((builder == NULL) || (ueid == NULL) || (length == 0)) {
		return DICE_UEID_EXTENSION_INVALID_ARGUMENT;
	}

	memset (builder, 0, sizeof (struct x509_extension_builder_mbedtls_dice_ueid));

	builder->base.build = x509_extension_builder_mbedtls_dice_ueid_build_dynamic;
	builder->base.free = x509_extension_builder_mbedtls_dice_ueid_free_dynamic;

	builder->ueid = ueid;
	builder->ueid_length = length;

	return 0;
}

/**
 * Initialize an extension builder for a TCG DICE Ueid extension.  The buffer used for the extension
 * data is statically provided during initialization.
 *
 * @param builder The extension builder to initialize.
 * @param ueid The device unique identifier that should be encoded in the extension.  This does
 * not need to be a constant value.  The contents can be externally modified after initialization to
 * change the value that will be encoded in the extension.
 * @param length Length of the device UEID.
 * @param ext_buffer Buffer for the encoded Ueid extension data.
 * @param buffer_length Length of the extension data buffer.
 *
 * @return 0 if the extension builder was initialized successfully or an error code.
 */
int x509_extension_builder_mbedtls_dice_ueid_init_with_buffer (
	struct x509_extension_builder_mbedtls_dice_ueid *builder, const uint8_t *ueid, size_t length,
	uint8_t *ext_buffer, size_t buffer_length)
{
	if ((builder == NULL) || (ueid == NULL) || (length == 0) || (ext_buffer == NULL)) {
		return DICE_UEID_EXTENSION_INVALID_ARGUMENT;
	}

	/* This check will need to be updated if UEIDs greater than 125 bytes need to be supported. */
	if (buffer_length < X509_EXTENSION_BUILDER_MBEDTLS_DICE_UEID_DATA_LENGTH (length)) {
		return DICE_UEID_EXTENSION_SMALL_EXT_BUFFER;
	}

	memset (builder, 0, sizeof (struct x509_extension_builder_mbedtls_dice_ueid));

	builder->base.build = x509_extension_builder_mbedtls_dice_ueid_build_static;
	builder->base.free = x509_extension_builder_mbedtls_dice_ueid_free_static;

	builder->ueid = ueid;
	builder->ueid_length = length;
	builder->ext_buffer = ext_buffer;
	builder->ext_length = buffer_length;

	return 0;
}

/**
 * Release the resources used by a TCG DICE Ueid extension builder.
 *
 * @param builder The extension builder to release.
 */
void x509_extension_builder_mbedtls_dice_ueid_release (
	const struct x509_extension_builder_mbedtls_dice_ueid *builder)
{
	UNUSED (builder);
}
