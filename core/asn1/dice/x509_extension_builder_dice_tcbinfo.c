// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "platform_api.h"
#include "x509_extension_builder_dice_tcbinfo.h"
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
#define	X509_EXTENSION_BUILDER_DICE_TCBINFO_BUFFER_PADDING		32


/**
 * The encoded OID for the TCG DICE TcbInfo extension:  2.23.133.5.4.1
 */
const uint8_t X509_EXTENSION_BUILDER_DICE_TCBINFO_OID[] = {
	0x67, 0x81, 0x05, 0x05, 0x04, 0x01
};

/**
 * Length of the encoded TCG DICE TcbInfo extension OID.
 */
const size_t X509_EXTENSION_BUILDER_DICE_TCBINFO_OID_LENGTH =
	sizeof (X509_EXTENSION_BUILDER_DICE_TCBINFO_OID);


/**
 * Create the TCG DICE TcbInfo extension.
 *
 * @param dice The extension builder.
 * @param buffer The buffer to use for the extension data.
 * @param length Length of the extension data buffer.
 * @param extension Output for extension information.
 *
 * @return 0 if the extension was created successfully or an error code.
 */
int x509_extension_builder_dice_tcbinfo_create_extension (
	const struct x509_extension_builder_dice_tcbinfo *dice, uint8_t *buffer, size_t length,
	struct x509_extension *extension)
{
	DERBuilderContext der;
	size_t fwid_length;
	const int *fwid_oid;
	int status;

	if (dice->tcb == NULL) {
		return DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT;
	}

	if (dice->tcb->version == NULL) {
		return DICE_TCBINFO_EXTENSION_NO_VERSION;
	}

	if ((dice->tcb->svn == NULL) || (dice->tcb->svn_length == 0)) {
		return DICE_TCBINFO_EXTENSION_NO_SVN;
	}

	if (dice->tcb->fwid == NULL) {
		return DICE_TCBINFO_EXTENSION_NO_FWID;
	}

	switch (dice->tcb->fwid_hash) {
		case HASH_TYPE_SHA1:
			fwid_length = SHA1_HASH_LENGTH;
			fwid_oid = sha1OID;
			break;

		case HASH_TYPE_SHA256:
			fwid_length = SHA256_HASH_LENGTH;
			fwid_oid = sha256OID;
			break;

		case HASH_TYPE_SHA384:
			fwid_length = SHA384_HASH_LENGTH;
			fwid_oid = sha384OID;
			break;

		case HASH_TYPE_SHA512:
			fwid_length = SHA512_HASH_LENGTH;
			fwid_oid = sha512OID;
			break;

		default:
			return DICE_TCBINFO_EXTENSION_UNKNOWN_FWID;
	}

	DERInitContext (&der, buffer, length);

	/* TODO:  Not each of these error checks is tested.  Add tests when refactoring DER encoding. */
	DER_CHK_ENCODE (DERStartSequenceOrSet (&der, true));
	DER_CHK_ENCODE (DERAddString (&der, dice->tcb->version, 0x82));
	DER_CHK_ENCODE (DERAddTaggedIntegerFromArray (&der, dice->tcb->svn, dice->tcb->svn_length,
		0x83));
	DER_CHK_ENCODE (DERStartConstructed (&der, 0xa6));
	DER_CHK_ENCODE (DERStartSequenceOrSet (&der, true));
	DER_CHK_ENCODE (DERAddOID (&der, fwid_oid));
	DER_CHK_ENCODE (DERAddOctetString (&der, dice->tcb->fwid, fwid_length));
	DER_CHK_ENCODE (DERPopNesting (&der));
	DER_CHK_ENCODE (DERPopNesting (&der));
	DER_CHK_ENCODE (DERPopNesting (&der));

	x509_extension_builder_init_extension_descriptor (extension, false,
		X509_EXTENSION_BUILDER_DICE_TCBINFO_OID, X509_EXTENSION_BUILDER_DICE_TCBINFO_OID_LENGTH,
		buffer, DERGetEncodedLength (&der));

	return 0;

error:

	return DICE_TCBINFO_EXTENSION_SMALL_EXT_BUFFER;
}

int x509_extension_builder_dice_tcbinfo_build_dynamic (const struct x509_extension_builder *builder,
	struct x509_extension *extension)
{
	const struct x509_extension_builder_dice_tcbinfo *dice =
		(const struct x509_extension_builder_dice_tcbinfo*) builder;
	uint8_t *buffer;
	size_t length;
	int status;

	if ((dice == NULL) || (extension == NULL)) {
		return DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT;
	}

	length = x509_extension_builder_dice_tcbinfo_get_ext_buffer_length (dice->tcb) +
		X509_EXTENSION_BUILDER_DICE_TCBINFO_BUFFER_PADDING;
	buffer = platform_malloc (length);
	if (buffer == NULL) {
		return DICE_TCBINFO_EXTENSION_NO_MEMORY;
	}

	status = x509_extension_builder_dice_tcbinfo_create_extension (dice, buffer, length, extension);
	if (status != 0) {
		platform_free (buffer);
	}

	return status;
}

int x509_extension_builder_dice_tcbinfo_build_static (const struct x509_extension_builder *builder,
	struct x509_extension *extension)
{
	const struct x509_extension_builder_dice_tcbinfo *dice =
		(const struct x509_extension_builder_dice_tcbinfo*) builder;

	if ((dice == NULL) || (extension == NULL) || (dice->ext_buffer == NULL)) {
		return DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT;
	}

	return x509_extension_builder_dice_tcbinfo_create_extension (dice, dice->ext_buffer,
		dice->ext_length, extension);
}

void x509_extension_builder_dice_tcbinfo_free_dynamic (const struct x509_extension_builder *builder,
	struct x509_extension *extension)
{
	UNUSED (builder);

	platform_free ((void*) extension->data);
}

void x509_extension_builder_dice_tcbinfo_free_static (const struct x509_extension_builder *builder,
	struct x509_extension *extension)
{
	UNUSED (builder);
	UNUSED (extension);
}

/**
 * Initialize an extension builder for a TCG DICE TcbInfo extension.  The buffer that will be used
 * for the extension data will be dynamically allocated.
 *
 * @param builder The extension builder to initialize.
 * @param tcb The firmware TCB to encode in the extension.  This does not need to be constant.  The
 * contents can be externally modified after initialization to change what will be encoded in the
 * extension.
 *
 * @return 0 if the extension builder was initialized successfully or an error code.
 */
int x509_extension_builder_dice_tcbinfo_init (struct x509_extension_builder_dice_tcbinfo *builder,
	const struct tcg_dice_tcbinfo *tcb)
{
	if ((builder == NULL) || (tcb == NULL)) {
		return DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT;
	}

	memset (builder, 0, sizeof (struct x509_extension_builder_dice_tcbinfo));

	builder->base.build = x509_extension_builder_dice_tcbinfo_build_dynamic;
	builder->base.free = x509_extension_builder_dice_tcbinfo_free_dynamic;

	builder->tcb = tcb;

	return 0;
}

/**
 * Initialize an extension builder for a TCG DICE TcbInfo extension.  The buffer used for the
 * extension data is statically provided during initialization.
 *
 * @param builder The extension builder to initialize.
 * @param tcb The firmware TCB to encode in the extension.  This does not need to be constant.  The
 * contents can be externally modified after initialization to change what will be encoded in the
 * extension.
 * @param ext_buffer Buffer for the encoded TcbInfo extension data.
 * @param buffer_length Length of the extension data buffer.
 *
 * @return 0 if the extension builder was initialized successfully or an error code.
 */
int x509_extension_builder_dice_tcbinfo_init_with_buffer (
	struct x509_extension_builder_dice_tcbinfo *builder, const struct tcg_dice_tcbinfo *tcb,
	uint8_t *ext_buffer, size_t buffer_length)
{
	if ((builder == NULL) || (tcb == NULL) || (ext_buffer == NULL)) {
		return DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT;
	}

	memset (builder, 0, sizeof (struct x509_extension_builder_dice_tcbinfo));

	builder->base.build = x509_extension_builder_dice_tcbinfo_build_static;
	builder->base.free = x509_extension_builder_dice_tcbinfo_free_static;

	builder->tcb = tcb;
	builder->ext_buffer = ext_buffer;
	builder->ext_length = buffer_length;

	return 0;
}

/**
 * Release the resources used by a TCG DICE TcbInfo extension builder.
 *
 * @param builder The extension builder to release.
 */
void x509_extension_builder_dice_tcbinfo_release (
	const struct x509_extension_builder_dice_tcbinfo *builder)
{
	UNUSED (builder);
}

/**
 * Determine an appropriately sized buffer to use for TCG DICE TcbInfo extension building based on
 * the TCB information.  This is not an exact extension length, but will provide sufficient space to
 * fit the encoded extension.
 *
 * @param tcb The TCG DICE TCB information that will be encoded into an extension.
 *
 * @return The buffer length needed for the TCG DICE TcbInfo extension.
 */
size_t x509_extension_builder_dice_tcbinfo_get_ext_buffer_length (
	const struct tcg_dice_tcbinfo *tcb)
{
	size_t length = 4;	/* Space for the top-level sequence header. */

	if (tcb != NULL) {
		if (tcb->version != NULL) {
			length += strlen (tcb->version);
		}

		length += tcb->svn_length + 1;	/* Worst-case SVN length, including a leading zero. */
		length += 9;					/* Worst-case FWID OID length. */
		length += SHA512_HASH_LENGTH;	/* Worst-case FWID length. */

		/* Extra space for headers and sequence tags. */
		length += (4 * 4) + (4 * 2);
	}

	return length;
}
