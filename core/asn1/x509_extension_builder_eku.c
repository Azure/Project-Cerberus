// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "platform_api.h"
#include "x509_extension_builder_eku.h"
#include "x509_oid.h"
#include "common/unused.h"
#include "riot/reference/include/RiotDerEnc.h"


/**
 * Update the DER encoding and fail if the result is non-zero.
 *
 * TODO:  Put this in a common location.
 */
#define	DER_CHK_ENCODE(func)	if ((status = (func)) != 0) {goto error;}

/**
 * Extra buffer space to add to keep the DER encoder happy.
 *
 * TODO:  Remove the need for the extra padding with updates to the DER encoder.
 */
#define	X509_EXTENSION_BUILDER_EKU_BUFFER_PADDING				32


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
static int x509_extension_builder_eku_create_extension (
	const struct x509_extension_builder_eku *x509, uint8_t *buffer, size_t length,
	struct x509_extension *extension)
{
	DERBuilderContext der;
	size_t i;
	int status;

	if ((x509->eku == NULL) || (x509->eku_count == 0)) {
		return EKU_EXTENSION_INVALID_ARGUMENT;
	}

	DERInitContext (&der, buffer, length);

	// *INDENT-OFF*
	/* TODO:  Each of these error checks is not tested.  Add tests when refactoring DER encoding. */
	DER_CHK_ENCODE (DERStartSequenceOrSet (&der, true));
		for (i = 0; i < x509->eku_count; i++) {
			DER_CHK_ENCODE (DERAddEncodedOID (&der, x509->eku[i].oid, x509->eku[i].length));
		}
	DER_CHK_ENCODE (DERPopNesting (&der));
	// *INDENT-ON*

	x509_extension_builder_init_extension_descriptor (extension, x509->critical,
		X509_OID_EKU_EXTENSION, X509_OID_EKU_EXTENSION_LENGTH, buffer, DERGetEncodedLength (&der));

	return 0;

error:

	return EKU_EXTENSION_SMALL_EXT_BUFFER;
}

int x509_extension_builder_eku_build_dynamic (const struct x509_extension_builder *builder,
	struct x509_extension *extension)
{
	const struct x509_extension_builder_eku *x509 =
		(const struct x509_extension_builder_eku*) builder;
	uint8_t *buffer;
	size_t length;
	int status;

	if ((builder == NULL) || (extension == NULL)) {
		return EKU_EXTENSION_INVALID_ARGUMENT;
	}

	length = x509_extension_builder_eku_get_ext_buffer_length (x509->eku, x509->eku_count) +
		X509_EXTENSION_BUILDER_EKU_BUFFER_PADDING;
	buffer = platform_malloc (length);
	if (buffer == NULL) {
		return EKU_EXTENSION_NO_MEMORY;
	}

	status = x509_extension_builder_eku_create_extension (x509, buffer, length, extension);
	if (status != 0) {
		platform_free (buffer);
	}

	return status;
}

int x509_extension_builder_eku_build_static (const struct x509_extension_builder *builder,
	struct x509_extension *extension)
{
	const struct x509_extension_builder_eku *x509 =
		(const struct x509_extension_builder_eku*) builder;

	if ((x509 == NULL) || (extension == NULL) || (x509->ext_buffer == NULL)) {
		return EKU_EXTENSION_INVALID_ARGUMENT;
	}

	return x509_extension_builder_eku_create_extension (x509, x509->ext_buffer, x509->ext_length,
		extension);
}

void x509_extension_builder_eku_free_dynamic (const struct x509_extension_builder *builder,
	struct x509_extension *extension)
{
	UNUSED (builder);

	x509_extension_builder_free_extension_descriptor (extension);
}

void x509_extension_builder_eku_free_static (const struct x509_extension_builder *builder,
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
int x509_extension_builder_eku_init (struct x509_extension_builder_eku *builder,
	const struct x509_extension_builder_eku_oid *eku, size_t eku_count, bool critical)
{
	if ((builder == NULL) || (eku == NULL) || (eku_count == 0)) {
		return EKU_EXTENSION_INVALID_ARGUMENT;
	}

	memset (builder, 0, sizeof (struct x509_extension_builder_eku));

	builder->base.build = x509_extension_builder_eku_build_dynamic;
	builder->base.free = x509_extension_builder_eku_free_dynamic;

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
int x509_extension_builder_eku_init_with_buffer (
	struct x509_extension_builder_eku *builder, const struct x509_extension_builder_eku_oid *eku,
	size_t eku_count, bool critical, uint8_t *ext_buffer, size_t buffer_length)
{
	if ((builder == NULL) || (eku == NULL) || (eku_count == 0) || (ext_buffer == NULL)) {
		return EKU_EXTENSION_INVALID_ARGUMENT;
	}

	memset (builder, 0, sizeof (struct x509_extension_builder_eku));

	builder->base.build = x509_extension_builder_eku_build_static;
	builder->base.free = x509_extension_builder_eku_free_static;

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
void x509_extension_builder_eku_release (
	const struct x509_extension_builder_eku *builder)
{
	UNUSED (builder);
}

/**
 * Determine an appropriately sized buffer to use for Extended Key Usage extension building based on
 * the list of EKU OIDs to include.  This will be valid so long as no OID is longer than 127 bytes.
 *
 * @param eku The list of EKU OIDs that will be included in the extension data.
 * @param eku_count The number of EKU OIDs in the list.
 *
 * @return The buffer length needed for the Extended Key Usage extension.
 */
size_t x509_extension_builder_eku_get_ext_buffer_length (
	const struct x509_extension_builder_eku_oid *const eku, size_t eku_count)
{
	size_t length = 3;	// The sequence header.  Add an extra byte to account for long OID lists.
	size_t i;

	if (eku != NULL) {
		for (i = 0; i < eku_count; i++) {
			length += (2 + eku[i].length);	// OID data plus ASN.1 header.
		}
	}

	return length;
}
