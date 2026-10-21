// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "platform_api.h"
#include "x509_extension_builder_dme.h"
#include "x509_extension_builder_mbedtls_dme.h"
#include "asn1/x509_mbedtls.h"
#include "common/unused.h"
#include "mbedtls/asn1write.h"


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
static int x509_extension_builder_mbedtls_dme_create_extension (const struct dme_structure *dme,
	uint8_t *buffer, size_t length, struct x509_extension *extension)
{
	uint8_t *pos;
	int enc_length = 0;
	int sig_alg_length = 0;
	int ret;

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

	pos = buffer + length;

	/* renewalCounter 	[1] IMPLICIT BIT STRING 	OPTIONAL */
	if (dme->renewal_counter != NULL) {
		MBEDTLS_ASN1_CHK_ADD (enc_length,
			mbedtls_asn1_write_bitstring (&pos, buffer, dme->renewal_counter,
			dme->counter_length * 8));

		*pos = (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 1);
	}

	/* deviceType 	[0] IMPLICIT OBJECT IDENTIFIER 	OPTIONAL */
	if (dme->device_oid != NULL) {
		MBEDTLS_ASN1_CHK_ADD (enc_length,
			mbedtls_asn1_write_oid (&pos, buffer, (char*) dme->device_oid, dme->dev_oid_length));

		*pos = (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0);
	}

	/* signatureValue 	 	BIT STRING */
	MBEDTLS_ASN1_CHK_ADD (enc_length,
		mbedtls_asn1_write_bitstring (&pos, buffer, dme->signature, dme->signature_length * 8));

	/* signatureAlgorithm 	 	AlgorithmIdentifier */
	MBEDTLS_ASN1_CHK_ADD (sig_alg_length,
		mbedtls_asn1_write_oid (&pos, buffer, (char*) dme->sig_oid, dme->sig_oid_length));

	ret = x509_mbedtls_close_asn1_object (&pos, buffer,
		(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE), &sig_alg_length);
	if (ret != 0) {
		return ret;
	}

	enc_length += sig_alg_length;

	/* dmeStructure 	 	OCTET STRING */
	MBEDTLS_ASN1_CHK_ADD (enc_length,
		mbedtls_asn1_write_octet_string (&pos, buffer, dme->data, dme->data_length));

	/* dmeStructureFormat 	 	OBJECT IDENTIFIER */
	MBEDTLS_ASN1_CHK_ADD (enc_length,
		mbedtls_asn1_write_oid (&pos, buffer, (char*) dme->data_oid, dme->data_oid_length));

	/* dmePublicKey 	 	SubjectPublicKeyInfo */
	MBEDTLS_ASN1_CHK_ADD (enc_length,
		mbedtls_asn1_write_raw_buffer (&pos, buffer, dme->dme_pub_key, dme->key_length));

	ret = x509_mbedtls_close_asn1_object (&pos, buffer,
		(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE), &enc_length);
	if (ret != 0) {
		return ret;
	}

	if (pos != buffer) {
		memmove (buffer, pos, enc_length);
	}

	x509_extension_builder_init_extension_descriptor (extension, false,
		X509_EXTENSION_BUILDER_DME_OID, X509_EXTENSION_BUILDER_DME_OID_LENGTH, buffer, enc_length);

	return 0;
}

int x509_extension_builder_mbedtls_dme_build_dynamic (const struct x509_extension_builder *builder,
	struct x509_extension *extension)
{
	const struct x509_extension_builder_mbedtls_dme *dme_build =
		(const struct x509_extension_builder_mbedtls_dme*) builder;
	uint8_t *buffer;
	size_t length;
	int status;

	if ((dme_build == NULL) || (extension == NULL)) {
		return DME_EXTENSION_INVALID_ARGUMENT;
	}

	length = x509_extension_builder_dme_get_ext_buffer_length (dme_build->dme);
	buffer = platform_malloc (length);
	if (buffer == NULL) {
		return DME_EXTENSION_NO_MEMORY;
	}

	status = x509_extension_builder_mbedtls_dme_create_extension (dme_build->dme, buffer, length,
		extension);
	if (status != 0) {
		platform_free (buffer);
	}

	return status;
}

int x509_extension_builder_mbedtls_dme_build_static (const struct x509_extension_builder *builder,
	struct x509_extension *extension)
{
	const struct x509_extension_builder_mbedtls_dme *dme_build =
		(const struct x509_extension_builder_mbedtls_dme*) builder;
	int status;

	if ((dme_build == NULL) || (extension == NULL) || (dme_build->ext_buffer == NULL)) {
		return DME_EXTENSION_INVALID_ARGUMENT;
	}

	status = x509_extension_builder_mbedtls_dme_create_extension (dme_build->dme,
		dme_build->ext_buffer, dme_build->ext_length, extension);
	if (status == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL) {
		status = DME_EXTENSION_SMALL_EXT_BUFFER;
	}

	return status;
}

void x509_extension_builder_mbedtls_dme_free_dynamic (const struct x509_extension_builder *builder,
	struct x509_extension *extension)
{
	UNUSED (builder);

	x509_extension_builder_free_extension_descriptor (extension);
}

void x509_extension_builder_mbedtls_dme_free_static (const struct x509_extension_builder *builder,
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
int x509_extension_builder_mbedtls_dme_init (struct x509_extension_builder_mbedtls_dme *builder,
	const struct dme_structure *dme)
{
	if ((builder == NULL) || (dme == NULL)) {
		return DME_EXTENSION_INVALID_ARGUMENT;
	}

	memset (builder, 0, sizeof (struct x509_extension_builder_mbedtls_dme));

	builder->base.build = x509_extension_builder_mbedtls_dme_build_dynamic;
	builder->base.free = x509_extension_builder_mbedtls_dme_free_dynamic;

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
int x509_extension_builder_mbedtls_dme_init_with_buffer (
	struct x509_extension_builder_mbedtls_dme *builder, const struct dme_structure *dme,
	uint8_t *ext_buffer, size_t buffer_length)
{
	if ((builder == NULL) || (dme == NULL) || (ext_buffer == NULL)) {
		return DME_EXTENSION_INVALID_ARGUMENT;
	}

	memset (builder, 0, sizeof (struct x509_extension_builder_mbedtls_dme));

	builder->base.build = x509_extension_builder_mbedtls_dme_build_static;
	builder->base.free = x509_extension_builder_mbedtls_dme_free_static;

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
void x509_extension_builder_mbedtls_dme_release (
	const struct x509_extension_builder_mbedtls_dme *builder)
{
	UNUSED (builder);
}
