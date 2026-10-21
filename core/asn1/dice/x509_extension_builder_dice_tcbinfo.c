// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "platform_api.h"
#include "tcg_dice_oid.h"
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
 * Add a list of FWID digests to the extension.
 *
 * @param der Context being used to construct the extension.
 * @param fwid_list List of digests to add.
 * @param fwid_count Number of digests in the list.
 *
 * @return 0 if the extension was updated successfully or an error code.
 */
static int x509_extension_builder_dice_tcbinfo_add_fwid_list (DERBuilderContext *der,
	const struct tcg_dice_fwid *const fwid_list, size_t fwid_count)
{
	size_t fwid_length;
	const int *fwid_oid;
	size_t i;
	int status;

	/* Encode each digest in the list as a FWID sequence.  Each digest can be a different algorithm,
	 * so each has to be checked. */
	for (i = 0; i < fwid_count; i++) {
		if (fwid_list[i].digest == NULL) {
			return DICE_TCBINFO_EXTENSION_NO_FWID;
		}

		switch (fwid_list[i].hash_alg) {
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

		// *INDENT-OFF*
		DER_CHK_ENCODE (DERStartSequenceOrSet (der, true));
			DER_CHK_ENCODE (DERAddOID (der, fwid_oid));
			DER_CHK_ENCODE (DERAddOctetString (der, fwid_list[i].digest, fwid_length));
		DER_CHK_ENCODE (DERPopNesting (der));
		// *INDENT-ON*
	}

	return 0;

error:

	return DICE_TCBINFO_EXTENSION_SMALL_EXT_BUFFER;
}

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
static int x509_extension_builder_dice_tcbinfo_create_extension (
	const struct x509_extension_builder_dice_tcbinfo *dice, uint8_t *buffer, size_t length,
	struct x509_extension *extension)
{
	DERBuilderContext der;
	size_t i;
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

	if ((dice->tcb->fwid_list == NULL) || (dice->tcb->fwid_count == 0)) {
		return DICE_TCBINFO_EXTENSION_NO_FWID_LIST;
	}

	DERInitContext (&der, buffer, length);

	// *INDENT-OFF*
	/* TODO:  Each of these error checks is not tested.  Add tests when refactoring DER encoding. */
	DER_CHK_ENCODE (DERStartSequenceOrSet (&der, true));
		if (dice->tcb->vendor != NULL) {
			DER_CHK_ENCODE (DERAddString (&der, dice->tcb->vendor, 0x80));
		}

		if (dice->tcb->model != NULL) {
			DER_CHK_ENCODE (DERAddString (&der, dice->tcb->model, 0x81));
		}

		DER_CHK_ENCODE (DERAddString (&der, dice->tcb->version, 0x82));
		DER_CHK_ENCODE (DERAddTaggedIntegerFromArray (&der, dice->tcb->svn, dice->tcb->svn_length,
			0x83));
		DER_CHK_ENCODE (DERAddTaggedInteger (&der, dice->tcb->layer, 0x84));
		DER_CHK_ENCODE (DERStartConstructed (&der, 0xa6));
			status = x509_extension_builder_dice_tcbinfo_add_fwid_list (&der, dice->tcb->fwid_list,
				dice->tcb->fwid_count);
			if (status != 0) {
				return status;
			}
		DER_CHK_ENCODE (DERPopNesting (&der));

		if ((dice->tcb->ir_list != NULL) && (dice->tcb->ir_count > 0)) {
			DER_CHK_ENCODE (DERStartConstructed (&der, 0xaa));
				for (i = 0; i < dice->tcb->ir_count; i++) {
					if ((dice->tcb->ir_list[i].name == NULL) &&
						(dice->tcb->ir_list[i].number < 0)) {
						return DICE_TCBINFO_EXTENSION_NO_IR_ID;
					}

					if ((dice->tcb->ir_list[i].digests == NULL) ||
						(dice->tcb->ir_list[i].digest_count == 0)) {
						return DICE_TCBINFO_EXTENSION_NO_IR_DIGEST_LIST;
					}

					DER_CHK_ENCODE (DERStartSequenceOrSet (&der, true));
						if (dice->tcb->ir_list[i].name != NULL) {
							DER_CHK_ENCODE (DERAddString (&der, dice->tcb->ir_list[i].name, 0x80));
						}

						if (dice->tcb->ir_list[i].number >= 0) {
							DER_CHK_ENCODE (
								DERAddTaggedInteger (&der, dice->tcb->ir_list[i].number, 0x81));
						}

						DER_CHK_ENCODE (DERStartConstructed (&der, 0xa2));
							status = x509_extension_builder_dice_tcbinfo_add_fwid_list (&der,
								dice->tcb->ir_list[i].digests, dice->tcb->ir_list[i].digest_count);
							if (status != 0) {
								switch (status) {
									case DICE_TCBINFO_EXTENSION_NO_FWID:
										status = DICE_TCBINFO_EXTENSION_NO_IR_DIGEST;
										break;

									case DICE_TCBINFO_EXTENSION_UNKNOWN_FWID:
										status = DICE_TCBINFO_EXTENSION_UNKNOWN_IR_DIGEST;
										break;
								}

								return status;
							}
						DER_CHK_ENCODE (DERPopNesting (&der));
					DER_CHK_ENCODE (DERPopNesting (&der));
				}
			DER_CHK_ENCODE (DERPopNesting (&der));
		}
	DER_CHK_ENCODE (DERPopNesting (&der));
	// *INDENT-ON*

	x509_extension_builder_init_extension_descriptor (extension, false,
		TCG_DICE_OID_TCBINFO_EXTENSION, TCG_DICE_OID_TCBINFO_EXTENSION_LENGTH, buffer,
		DERGetEncodedLength (&der));

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

	x509_extension_builder_free_extension_descriptor (extension);
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
 * Get a worst-case buffer length needed to encode a FWID sequence with a specified number of
 * digests.
 *
 * @param fwid_count The number of digests to include in the sequence.
 *
 * @return The FWID sequence length.
 */
static size_t x509_extension_builder_dice_tcbinfo_get_fwid_buffer_length (size_t fwid_count)
{
	size_t length = 0;
	size_t i;

	for (i = 0; i < fwid_count; i++) {
		length += 9;					/* Worst-case FWID OID length. */
		length += SHA512_HASH_LENGTH;	/* Worst-case FWID length. */
		length += 3 + (2 * 2);			/* Sequence and other ASN.1 headers */
	}

	length += 4;						/* FWID list sequence header. */

	return length;
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
	size_t i;

	if (tcb != NULL) {
		if (tcb->vendor != NULL) {
			length += strlen (tcb->vendor);
			length += 3;
		}

		if (tcb->model != NULL) {
			length += strlen (tcb->model);
			length += 3;
		}

		if (tcb->version != NULL) {
			length += strlen (tcb->version);
			length += 3;
		}

		length += tcb->svn_length + 1;	/* Worst-case SVN length, including a leading zero. */
		length += 4 + 1;				/* Worst-case layer length, including a leading zero. */
		length += (2 * 3);				/* ASN.1 headers. */

		length += x509_extension_builder_dice_tcbinfo_get_fwid_buffer_length (tcb->fwid_count);

		if ((tcb->ir_list != NULL) && (tcb->ir_count > 0)) {
			for (i = 0; i < tcb->ir_count; i++) {
				if (tcb->ir_list[i].name != NULL) {
					length += strlen (tcb->ir_list[i].name);
					length += 3;
				}

				if (tcb->ir_list[i].number >= 0) {
					length += 9;	/* Worst-case integer length, including a leading zero. */
					length += 2;	/* ASN.1 headers. */
				}

				length +=
					x509_extension_builder_dice_tcbinfo_get_fwid_buffer_length (
					tcb->ir_list[i].digest_count);
			}
		}
	}

	return length;
}
