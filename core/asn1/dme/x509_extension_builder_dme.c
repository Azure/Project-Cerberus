// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "platform_api.h"
#include "x509_extension_builder_dme.h"
#include "common/unused.h"
#include "riot/reference/include/RiotDerEnc.h"
#include "riot/reference/include/RiotX509Bldr.h"


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
#define	X509_EXTENSION_BUILDER_DME_BUFFER_PADDING		32


/**
 * The encoded OID for the DME extension:  1.3.6.1.4.1.311.102.3.1
 */
const uint8_t X509_EXTENSION_BUILDER_DME_OID[] = {
	0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x66, 0x03, 0x01
};

/**
 * Length of the encoded DME extension OID.
 */
const size_t X509_EXTENSION_BUILDER_DME_OID_LENGTH = sizeof (X509_EXTENSION_BUILDER_DME_OID);


/**
 * Create the DME extension.
 *
 * @param dme The DME information to encode in the extension.
 * @param buffer The buffer to use for the extension data.
 * @param length Length of the extension data buffer.
 * @param extension Output for extension information.
 *
 * @return 0 if the extension was created successfully or an error code.
 */
int x509_extension_builder_dme_create_extension (const struct dme_structure *dme, uint8_t *buffer,
	size_t length, struct x509_extension *extension)
{
	DERBuilderContext der;
	size_t tag_pos;
	int status;

	if (dme == NULL) {
		return DME_EXTENSION_INVALID_ARGUMENT;
	}

	if (dme->data_oid == NULL) {
		return DME_EXTENSION_NO_TYPE_OID;
	}

	if (dme->data == NULL) {
		return DME_EXTENSION_NO_DATA;
	}

	if (dme->sig_oid == NULL) {
		return DME_EXTENSION_NO_SIG_TYPE_OID;
	}

	if (dme->signature == NULL) {
		return DME_EXTENSION_NO_SIGNATURE;
	}

	if (dme->dme_pub_key == NULL) {
		return DME_EXTENSION_NO_DME_KEY;
	}

	DERInitContext (&der, buffer, length);

	/* TODO:  Not each of these error checks is tested.  Add tests when refactoring DER encoding. */
	DER_CHK_ENCODE (DERStartSequenceOrSet (&der, true));
	DER_CHK_ENCODE (DERAddPublicKey (&der, dme->dme_pub_key, dme->key_length));
	DER_CHK_ENCODE (DERAddEncodedOID (&der, dme->data_oid, dme->data_oid_length));
	DER_CHK_ENCODE (DERAddOctetString (&der, dme->data, dme->data_length));
	DER_CHK_ENCODE (DERStartSequenceOrSet (&der, true));
	DER_CHK_ENCODE (DERAddEncodedOID (&der, dme->sig_oid, dme->sig_oid_length));
	DER_CHK_ENCODE (DERPopNesting (&der));
	DER_CHK_ENCODE (DERAddBitString (&der, dme->signature, dme->signature_length));

	/* Optional fields need different tags. */
	if (dme->device_oid) {
		tag_pos = der.Position;
		DER_CHK_ENCODE (DERAddEncodedOID (&der, dme->device_oid, dme->dev_oid_length));
		der.Buffer[tag_pos] = 0x80;
	}

	if (dme->renewal_counter) {
		tag_pos = der.Position;
		DER_CHK_ENCODE (DERAddBitString (&der, dme->renewal_counter, dme->counter_length));
		der.Buffer[tag_pos] = 0x81;
	}
	DER_CHK_ENCODE (DERPopNesting (&der));

	x509_extension_builder_init_extension_descriptor (extension, false,
		X509_EXTENSION_BUILDER_DME_OID, X509_EXTENSION_BUILDER_DME_OID_LENGTH, buffer,
		DERGetEncodedLength (&der));

	return 0;

error:

	return DME_EXTENSION_SMALL_EXT_BUFFER;
}

int x509_extension_builder_dme_build_dynamic (const struct x509_extension_builder *builder,
	struct x509_extension *extension)
{
	const struct x509_extension_builder_dme *dme_build =
		(const struct x509_extension_builder_dme*) builder;
	uint8_t *buffer;
	size_t length;
	int status;

	if ((dme_build == NULL) || (extension == NULL)) {
		return DME_EXTENSION_INVALID_ARGUMENT;
	}

	length = x509_extension_builder_dme_get_ext_buffer_length (dme_build->dme) +
		X509_EXTENSION_BUILDER_DME_BUFFER_PADDING;
	buffer = platform_malloc (length);
	if (buffer == NULL) {
		return DME_EXTENSION_NO_MEMORY;
	}

	status = x509_extension_builder_dme_create_extension (dme_build->dme, buffer, length,
		extension);
	if (status != 0) {
		platform_free (buffer);
	}

	return status;
}

int x509_extension_builder_dme_build_static (const struct x509_extension_builder *builder,
	struct x509_extension *extension)
{
	const struct x509_extension_builder_dme *dme_build =
		(const struct x509_extension_builder_dme*) builder;

	if ((dme_build == NULL) || (extension == NULL) || (dme_build->ext_buffer == NULL)) {
		return DME_EXTENSION_INVALID_ARGUMENT;
	}

	return x509_extension_builder_dme_create_extension (dme_build->dme, dme_build->ext_buffer,
		dme_build->ext_length, extension);
}

void x509_extension_builder_dme_free_dynamic (const struct x509_extension_builder *builder,
	struct x509_extension *extension)
{
	UNUSED (builder);

	platform_free ((void*) extension->data);
}

void x509_extension_builder_dme_free_static (const struct x509_extension_builder *builder,
	struct x509_extension *extension)
{
	UNUSED (builder);
	UNUSED (extension);
}

/**
 * Initialize an extension builder for a DME extension.  The buffer that will be used for the
 * extension data will be dynamically allocated.
 *
 * @param builder The extension builder to initialize.
 * @param dme The DME structure to encode in the extension.  This does not need to be constant.  The
 * contents can be externally modified after initialization to change what will be encoded in the
 * extension.
 *
 * @return 0 if the extension builder was initialized successfully or an error code.
 */
int x509_extension_builder_dme_init (struct x509_extension_builder_dme *builder,
	const struct dme_structure *dme)
{
	if ((builder == NULL) || (dme == NULL)) {
		return DME_EXTENSION_INVALID_ARGUMENT;
	}

	memset (builder, 0, sizeof (struct x509_extension_builder_dme));

	builder->base.build = x509_extension_builder_dme_build_dynamic;
	builder->base.free = x509_extension_builder_dme_free_dynamic;

	builder->dme = dme;

	return 0;
}

/**
 * Initialize an extension builder for a DME extension.  The buffer used for the extension data is
 * statically provided during initialization.
 *
 * @param builder The extension builder to initialize.
 * @param dme The DME structure to encode in the extension.  This does not need to be constant.  The
 * contents can be externally modified after initialization to change what will be encoded in the
 * extension.
 * @param ext_buffer Buffer for the encoded DME extension data.
 * @param buffer_length Length of the extension data buffer.
 *
 * @return 0 if the extension builder was initialized successfully or an error code.
 */
int x509_extension_builder_dme_init_with_buffer (struct x509_extension_builder_dme *builder,
	const struct dme_structure *dme, uint8_t *ext_buffer, size_t buffer_length)
{
	if ((builder == NULL) || (dme == NULL) || (ext_buffer == NULL)) {
		return DME_EXTENSION_INVALID_ARGUMENT;
	}

	memset (builder, 0, sizeof (struct x509_extension_builder_dme));

	builder->base.build = x509_extension_builder_dme_build_static;
	builder->base.free = x509_extension_builder_dme_free_static;

	builder->dme = dme;
	builder->ext_buffer = ext_buffer;
	builder->ext_length = buffer_length;

	return 0;
}

/**
 * Release the resources used by a DME extension builder.
 *
 * @param builder The extension builder to release.
 */
void x509_extension_builder_dme_release (const struct x509_extension_builder_dme *builder)
{
	UNUSED (builder);
}

/**
 * Determine an appropriately sized buffer to use for DME extension building based on the DME
 * structure values.  This is not an exact extension length, but will provide sufficient space to
 * fit the encoded extension.
 *
 * @param dme The DME structure that will be encoded into an extension.
 *
 * @return The buffer length needed for the DME extension.
 */
size_t x509_extension_builder_dme_get_ext_buffer_length (const struct dme_structure *dme)
{
	size_t length = 4;	/* Space for the top-level sequence header. */

	if (dme != NULL) {
		length += dme->data_oid_length;
		length += dme->data_length;
		length += dme->sig_oid_length;
		length += dme->signature_length;
		length += dme->key_length;
		length += dme->dev_oid_length;
		length += dme->counter_length;

		/* Give everything else space for 4 header bytes, which should be more then enough, plus two
		 * extra bytes for BIT STRING fields. */
		length += (4 * 7) + 2;
	}

	return length;
}
