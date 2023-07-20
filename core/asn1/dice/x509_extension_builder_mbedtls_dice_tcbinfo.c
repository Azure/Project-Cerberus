// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform_api.h"
#include "x509_extension_builder_dice_tcbinfo.h"
#include "x509_extension_builder_mbedtls_dice_tcbinfo.h"
#include "asn1/x509_mbedtls.h"
#include "common/unused.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/bignum.h"
#include "mbedtls/oid.h"


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
int x509_extension_builder_mbedtls_dice_tcbinfo_create_extension (
	const struct x509_extension_builder_mbedtls_dice_tcbinfo *dice, uint8_t *buffer, size_t length,
	struct x509_extension *extension)
{
	uint8_t *pos;
	int enc_length = 0;
	mbedtls_mpi svn;
	uint32_t be_svn;
	int fwid_length;
	char *fwid_oid;
	size_t fwid_oid_length;
	int ret;

	if (dice->tcb == NULL) {
		return DICE_TCBINFO_EXTENSION_INVALID_ARGUMENT;
	}

	if (dice->tcb->version == NULL) {
		return DICE_TCBINFO_EXTENSION_NO_VERSION;
	}

	if (dice->tcb->fwid == NULL) {
		return DICE_TCBINFO_EXTENSION_NO_FWID;
	}

	switch (dice->tcb->fwid_hash) {
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

	pos = buffer + length;

	/* fwids		Fwids		OPTIONAL */

	/* fwid				OCTET_STRING */
	MBEDTLS_ASN1_CHK_ADD (enc_length,
		mbedtls_asn1_write_raw_buffer (&pos, buffer, dice->tcb->fwid, fwid_length));
	ret = x509_mbedtls_close_asn1_object (&pos, buffer, MBEDTLS_ASN1_OCTET_STRING, &enc_length);
	if (ret != 0) {
		return ret;
	}

	/* hashAlg			OBJECT IDENTIFIER */
	MBEDTLS_ASN1_CHK_ADD (enc_length,
		mbedtls_asn1_write_oid (&pos, buffer, fwid_oid, fwid_oid_length));

	/* fwid SEQUENCE */
	ret = x509_mbedtls_close_asn1_object (&pos, buffer,
		(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE), &enc_length);
	if (ret != 0) {
		return ret;
	}

	ret = x509_mbedtls_close_asn1_object (&pos, buffer,
		(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC | 6), &enc_length);
	if (ret != 0) {
		return ret;
	}

	/* svn			INTEGER		OPTIONAL */
	/* mbedtls_asn1_write_int only writes 1 byte integers.  MPI is needed for larger ones. */
	mbedtls_mpi_init (&svn);
	be_svn = platform_htonl (dice->tcb->svn);
	ret = mbedtls_mpi_read_binary (&svn, (uint8_t*) &be_svn, sizeof (uint32_t));
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

	/* version		IA5String	OPTIONAL */
	MBEDTLS_ASN1_CHK_ADD (enc_length,
		mbedtls_asn1_write_ia5_string (&pos, buffer, dice->tcb->version,
			strlen (dice->tcb->version)));
	*pos = (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 2);

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
		X509_EXTENSION_BUILDER_DICE_TCBINFO_OID, X509_EXTENSION_BUILDER_DICE_TCBINFO_OID_LENGTH,
		buffer, enc_length);

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

	platform_free ((void*) extension->data);
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
