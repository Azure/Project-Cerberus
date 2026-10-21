// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "platform_api.h"
#include "tcg_dice_oid.h"
#include "x509_extension_builder_dice_tcbinfo.h"
#include "x509_extension_builder_mbedtls_dice_tcbinfo.h"
#include "asn1/x509_mbedtls.h"
#include "common/unused.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/bignum.h"
#include "mbedtls/oid.h"


/**
 * Add a list of FWID digests to the extension.
 *
 * @param pos The position in the buffer to add the FWID list.  This will be updated upon return to
 * point to the next position to add data.
 * @param buffer The start of the extension buffer.
 * @param fwid_list List of FWID digests to add to the extension.
 * @param fwid_count Number of FWIDs in the list.
 * @param enc_length Output to be updated with the total encoded length of the FWID list.
 *
 * @return 0 if the extension was updated successfully or an error code.
 */
static int x509_extension_builder_mbedtls_dice_tcbinfo_add_fwid_list (uint8_t **pos,
	uint8_t *buffer, const struct tcg_dice_fwid *const fwid_list, size_t fwid_count,
	int *enc_length)
{
	int fwid_length;
	char *fwid_oid;
	size_t fwid_oid_length;
	int i;
	int ret;

	for (i = fwid_count - 1; i >= 0; i--) {
		/* Generate a list of FWID SEQUENCEs.  ASN.1 is built in reverse, so the FWID list needs to
		 * be processed from the end.  Each FWID digest can use a different hash algorithm, so each
		 * must be individually checked. */
		int fwid_enc_length = 0;

		if (fwid_list[i].digest == NULL) {
			return DICE_TCBINFO_EXTENSION_NO_FWID;
		}

		switch (fwid_list[i].hash_alg) {
			case HASH_TYPE_SHA1:
				fwid_length = SHA1_HASH_LENGTH;
				fwid_oid = MBEDTLS_OID_DIGEST_ALG_SHA1;
				fwid_oid_length = MBEDTLS_OID_SIZE (MBEDTLS_OID_DIGEST_ALG_SHA1);
				break;

			case HASH_TYPE_SHA256:
				fwid_length = SHA256_HASH_LENGTH;
				fwid_oid = MBEDTLS_OID_DIGEST_ALG_SHA256;
				fwid_oid_length = MBEDTLS_OID_SIZE (MBEDTLS_OID_DIGEST_ALG_SHA256);
				break;

			case HASH_TYPE_SHA384:
				fwid_length = SHA384_HASH_LENGTH;
				fwid_oid = MBEDTLS_OID_DIGEST_ALG_SHA384;
				fwid_oid_length = MBEDTLS_OID_SIZE (MBEDTLS_OID_DIGEST_ALG_SHA384);
				break;

			case HASH_TYPE_SHA512:
				fwid_length = SHA512_HASH_LENGTH;
				fwid_oid = MBEDTLS_OID_DIGEST_ALG_SHA512;
				fwid_oid_length = MBEDTLS_OID_SIZE (MBEDTLS_OID_DIGEST_ALG_SHA512);
				break;

			default:
				return DICE_TCBINFO_EXTENSION_UNKNOWN_FWID;
		}

		/* digest			OCTET_STRING */
		MBEDTLS_ASN1_CHK_ADD (fwid_enc_length,
			mbedtls_asn1_write_raw_buffer (pos, buffer, fwid_list[i].digest, fwid_length));
		ret = x509_mbedtls_close_asn1_object (pos, buffer, MBEDTLS_ASN1_OCTET_STRING,
			&fwid_enc_length);
		if (ret != 0) {
			return ret;
		}

		/* hashAlg			OBJECT IDENTIFIER */
		MBEDTLS_ASN1_CHK_ADD (fwid_enc_length,
			mbedtls_asn1_write_oid (pos, buffer, fwid_oid, fwid_oid_length));

		/* fwid SEQUENCE */
		ret = x509_mbedtls_close_asn1_object (pos, buffer,
			(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE), &fwid_enc_length);
		if (ret != 0) {
			return ret;
		}

		*enc_length += fwid_enc_length;
	}

	return 0;
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
static int x509_extension_builder_mbedtls_dice_tcbinfo_create_extension (
	const struct x509_extension_builder_mbedtls_dice_tcbinfo *dice, uint8_t *buffer, size_t length,
	struct x509_extension *extension)
{
	uint8_t *pos;
	int enc_length = 0;
	int fwid_enc_length = 0;
	mbedtls_mpi svn;
	int i;
	int ret;

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

	pos = buffer + length;

	/* integrityRegisters		IrList		OPTIONAL */
	if ((dice->tcb->ir_list != NULL) && (dice->tcb->ir_count > 0)) {
		/* Generate a list of name digests.  ASN.1 is built in reverse, so the digest list needs to
		 * be processed from the end. */
		for (i = dice->tcb->ir_count - 1; i >= 0; i--) {
			int ir_enc_length = 0;

			if ((dice->tcb->ir_list[i].name == NULL) && (dice->tcb->ir_list[i].number < 0)) {
				return DICE_TCBINFO_EXTENSION_NO_IR_ID;
			}

			if ((dice->tcb->ir_list[i].digests == NULL) ||
				(dice->tcb->ir_list[i].digest_count == 0)) {
				return DICE_TCBINFO_EXTENSION_NO_IR_DIGEST_LIST;
			}

			/* registerDigests		FWIDLIST */
			ret = x509_extension_builder_mbedtls_dice_tcbinfo_add_fwid_list (&pos, buffer,
				dice->tcb->ir_list[i].digests, dice->tcb->ir_list[i].digest_count, &ir_enc_length);
			if (ret != 0) {
				switch (ret) {
					case DICE_TCBINFO_EXTENSION_NO_FWID:
						ret = DICE_TCBINFO_EXTENSION_NO_IR_DIGEST;
						break;

					case DICE_TCBINFO_EXTENSION_UNKNOWN_FWID:
						ret = DICE_TCBINFO_EXTENSION_UNKNOWN_IR_DIGEST;
						break;
				}

				return ret;
			}

			/* registerDigests SEQUENCE */
			ret = x509_mbedtls_close_asn1_object (&pos, buffer,
				(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | 2), &ir_enc_length);
			if (ret != 0) {
				return ret;
			}

			/* registerNum		INTEGER		OPTIONAL */
			if (dice->tcb->ir_list[i].number >= 0) {
				ret = mbedtls_asn1_write_int (&pos, buffer, dice->tcb->ir_list[i].number);
				if (ret < 0) {
					return ret;
				}

				ir_enc_length += ret;
				*pos = (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 1);
			}

			/* registerName		IA5String		OPTIONAL */
			if (dice->tcb->ir_list[i].name != NULL) {
				MBEDTLS_ASN1_CHK_ADD (ir_enc_length,
					mbedtls_asn1_write_ia5_string (&pos, buffer, dice->tcb->ir_list[i].name,
					strlen (dice->tcb->ir_list[i].name)));
				*pos = (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0);
			}

			/* IntegrityRegister SEQUENCE */
			ret = x509_mbedtls_close_asn1_object (&pos, buffer,
				(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE), &ir_enc_length);
			if (ret != 0) {
				return ret;
			}

			enc_length += ir_enc_length;
		}

		/* integrityRegisters SEQUENCE */
		ret = x509_mbedtls_close_asn1_object (&pos, buffer,
			(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | 10), &enc_length);
		if (ret != 0) {
			return ret;
		}
	}

	/* fwids		FWIDLIST		OPTIONAL */
	ret = x509_extension_builder_mbedtls_dice_tcbinfo_add_fwid_list (&pos, buffer,
		dice->tcb->fwid_list, dice->tcb->fwid_count, &fwid_enc_length);
	if (ret != 0) {
		return ret;
	}

	/* fwids SEQUENCE */
	ret = x509_mbedtls_close_asn1_object (&pos, buffer,
		(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | 6), &fwid_enc_length);
	if (ret != 0) {
		return ret;
	}

	enc_length += fwid_enc_length;

	/* layer		INTEGER		OPTIONAL */
	ret = mbedtls_asn1_write_int (&pos, buffer, dice->tcb->layer);
	if (ret < 0) {
		return ret;
	}

	enc_length += ret;
	*pos = (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 4);

	/* svn			INTEGER		OPTIONAL */
	mbedtls_mpi_init (&svn);
	ret = mbedtls_mpi_read_binary (&svn, dice->tcb->svn, dice->tcb->svn_length);
	if (ret != 0) {
		if (ret == MBEDTLS_ERR_MPI_ALLOC_FAILED) {
			ret = DICE_TCBINFO_EXTENSION_NO_MEMORY;
		}

		return ret;
	}

	ret = mbedtls_asn1_write_mpi (&pos, buffer, &svn);
	mbedtls_mpi_free (&svn);
	if (ret < 0) {
		return ret;
	}

	enc_length += ret;
	*pos = (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 3);

	/* version		UTF8String	OPTIONAL */
	MBEDTLS_ASN1_CHK_ADD (enc_length,
		mbedtls_asn1_write_utf8_string (&pos, buffer, dice->tcb->version,
		strlen (dice->tcb->version)));
	*pos = (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 2);

	/* model		UTF8String	OPTIONAL */
	if (dice->tcb->model != NULL) {
		MBEDTLS_ASN1_CHK_ADD (enc_length,
			mbedtls_asn1_write_utf8_string (&pos, buffer, dice->tcb->model,
			strlen (dice->tcb->model)));
		*pos = (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 1);
	}

	/* vendor		UTF8String	OPTIONAL */
	if (dice->tcb->vendor != NULL) {
		MBEDTLS_ASN1_CHK_ADD (enc_length,
			mbedtls_asn1_write_utf8_string (&pos, buffer, dice->tcb->vendor,
			strlen (dice->tcb->vendor)));
		*pos = (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0);
	}

	/* DiceTcbInfo ::= SEQUENCE */
	ret = x509_mbedtls_close_asn1_object (&pos, buffer,
		(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE), &enc_length);
	if (ret != 0) {
		return ret;
	}

	if (pos != buffer) {
		memmove (buffer, pos, enc_length);
	}

	x509_extension_builder_init_extension_descriptor (extension, false,
		TCG_DICE_OID_TCBINFO_EXTENSION, TCG_DICE_OID_TCBINFO_EXTENSION_LENGTH, buffer, enc_length);

	return 0;
}

int x509_extension_builder_mbedtls_dice_tcbinfo_build_dynamic (
	const struct x509_extension_builder *builder, struct x509_extension *extension)
{
	const struct x509_extension_builder_mbedtls_dice_tcbinfo *dice =
		(const struct x509_extension_builder_mbedtls_dice_tcbinfo*) builder;
	uint8_t *buffer;
	size_t length;
	int status;

	if ((dice == NULL) || (extension == NULL)) {
		return DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT;
	}

	length = x509_extension_builder_dice_tcbinfo_get_ext_buffer_length (dice->tcb);
	buffer = platform_malloc (length);
	if (buffer == NULL) {
		return DICE_TCBINFO_EXTENSION_NO_MEMORY;
	}

	status = x509_extension_builder_mbedtls_dice_tcbinfo_create_extension (dice, buffer, length,
		extension);
	if (status != 0) {
		platform_free (buffer);
	}

	return status;
}

int x509_extension_builder_mbedtls_dice_tcbinfo_build_static (
	const struct x509_extension_builder *builder, struct x509_extension *extension)
{
	const struct x509_extension_builder_mbedtls_dice_tcbinfo *dice =
		(const struct x509_extension_builder_mbedtls_dice_tcbinfo*) builder;
	int status;

	if ((dice == NULL) || (extension == NULL) || (dice->ext_buffer == NULL)) {
		return DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT;
	}

	status = x509_extension_builder_mbedtls_dice_tcbinfo_create_extension (dice, dice->ext_buffer,
		dice->ext_length, extension);
	if (status == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL) {
		status = DICE_TCBINFO_EXTENSION_SMALL_EXT_BUFFER;
	}

	return status;
}

void x509_extension_builder_mbedtls_dice_tcbinfo_free_dynamic (
	const struct x509_extension_builder *builder, struct x509_extension *extension)
{
	UNUSED (builder);

	x509_extension_builder_free_extension_descriptor (extension);
}

void x509_extension_builder_mbedtls_dice_tcbinfo_free_static (
	const struct x509_extension_builder *builder, struct x509_extension *extension)
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
int x509_extension_builder_mbedtls_dice_tcbinfo_init (
	struct x509_extension_builder_mbedtls_dice_tcbinfo *builder, const struct tcg_dice_tcbinfo *tcb)
{
	if ((builder == NULL) || (tcb == NULL)) {
		return DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT;
	}

	memset (builder, 0, sizeof (struct x509_extension_builder_mbedtls_dice_tcbinfo));

	builder->base.build = x509_extension_builder_mbedtls_dice_tcbinfo_build_dynamic;
	builder->base.free = x509_extension_builder_mbedtls_dice_tcbinfo_free_dynamic;

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
int x509_extension_builder_mbedtls_dice_tcbinfo_init_with_buffer (
	struct x509_extension_builder_mbedtls_dice_tcbinfo *builder, const struct tcg_dice_tcbinfo *tcb,
	uint8_t *ext_buffer, size_t buffer_length)
{
	if ((builder == NULL) || (tcb == NULL) || (ext_buffer == NULL)) {
		return DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT;
	}

	memset (builder, 0, sizeof (struct x509_extension_builder_mbedtls_dice_tcbinfo));

	builder->base.build = x509_extension_builder_mbedtls_dice_tcbinfo_build_static;
	builder->base.free = x509_extension_builder_mbedtls_dice_tcbinfo_free_static;

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
void x509_extension_builder_mbedtls_dice_tcbinfo_release (
	const struct x509_extension_builder_mbedtls_dice_tcbinfo *builder)
{
	UNUSED (builder);
}
