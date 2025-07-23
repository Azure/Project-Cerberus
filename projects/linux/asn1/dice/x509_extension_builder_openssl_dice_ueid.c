// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "platform_api.h"
#include "x509_extension_builder_openssl_dice_ueid.h"
#include "asn1/dice/tcg_dice_oid.h"
#include "asn1/dice/x509_extension_builder_dice_ueid.h"
#include "common/unused.h"


/**
 * Defines the structure of the Ueid extension for use with the OpenSSL ASN.1 encoding framework.
 */
typedef struct dice_ueid_st {
	ASN1_OCTET_STRING *ueid;	/**< The UEID string. */
	ASN1_ENCODING enc;			/**< ASN1 encoding. */
} DICE_UEID;

ASN1_SEQUENCE_enc (DICE_UEID, enc, 0) = {
	ASN1_SIMPLE (DICE_UEID, ueid, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END_enc (DICE_UEID, DICE_UEID)

IMPLEMENT_ASN1_FUNCTIONS (DICE_UEID)


int x509_extension_builder_openssl_dice_ueid_build (const struct x509_extension_builder *builder,
	struct x509_extension *extension)
{
	const struct x509_extension_builder_openssl_dice_ueid *dice =
		(const struct x509_extension_builder_openssl_dice_ueid*) builder;
	DICE_UEID *ueid_ext;
	int status;
	uint8_t *ueid_der = NULL;
	int ueid_len;

	if ((dice == NULL) || (extension == NULL) || (dice->ueid == NULL) || (dice->ueid_length == 0)) {
		return DICE_UEID_EXTENSION_INVALID_ARGUMENT;
	}

	ueid_ext = DICE_UEID_new ();
	if (ueid_ext == NULL) {
		return -ERR_get_error ();
	}

	status = ASN1_OCTET_STRING_set (ueid_ext->ueid, dice->ueid, dice->ueid_length);
	if (status == 0) {
		status = -ERR_get_error ();
		goto exit;
	}

	ueid_len = i2d_DICE_UEID (ueid_ext, &ueid_der);
	if (ueid_len < 0) {
		status = -ERR_get_error ();
		goto exit;
	}

	x509_extension_builder_init_extension_descriptor (extension, false, TCG_DICE_OID_UEID_EXTENSION,
		TCG_DICE_OID_UEID_EXTENSION_LENGTH, ueid_der, ueid_len);

	status = 0;

exit:
	DICE_UEID_free (ueid_ext);

	return status;
}

void x509_extension_builder_openssl_dice_ueid_free (const struct x509_extension_builder *builder,
	struct x509_extension *extension)
{
	UNUSED (builder);

	x509_extension_builder_free_extension_descriptor (extension);
}

/**
 * Initialize an extension builder for a TCG DICE Ueid extension.
 *
 * @param builder The extension builder to initialize.
 * @param ueid The device unique identifier that should be encoded in the extension.  This does
 * not need to be a constant value.  The contents can be externally modified after initialization to
 * change the value that will be encoded in the extension.
 * @param length Length of the device UEID.
 *
 * @return 0 if the extension builder was initialized successfully or an error code.
 */
int x509_extension_builder_openssl_dice_ueid_init (
	struct x509_extension_builder_openssl_dice_ueid *builder, const uint8_t *ueid, size_t length)
{
	if ((builder == NULL) || (ueid == NULL) || (length == 0)) {
		return DICE_UEID_EXTENSION_INVALID_ARGUMENT;
	}

	memset (builder, 0, sizeof (struct x509_extension_builder_openssl_dice_ueid));

	builder->base.build = x509_extension_builder_openssl_dice_ueid_build;
	builder->base.free = x509_extension_builder_openssl_dice_ueid_free;

	builder->ueid = ueid;
	builder->ueid_length = length;

	return 0;
}

/**
 * Release the resources used by a TCG DICE Ueid extension builder.
 *
 * @param builder The extension builder to release.
 */
void x509_extension_builder_openssl_dice_ueid_release (
	const struct x509_extension_builder_openssl_dice_ueid *builder)
{
	UNUSED (builder);
}
