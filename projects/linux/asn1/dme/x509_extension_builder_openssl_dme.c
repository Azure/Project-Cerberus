// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include "platform_api.h"
#include "x509_extension_builder_openssl_dme.h"
#include "asn1/x509_openssl.h"
#include "asn1/dme/x509_extension_builder_dme.h"
#include "common/unused.h"


/**
 * Structure of the DME extension.
 */
typedef struct dme_extension_st {
	X509_PUBKEY *dme_key;				/**< The DME public key for the device. */
	ASN1_OBJECT *struct_format;			/**< Format of the DME structure. */
	ASN1_OCTET_STRING *dme_struct;		/**< The DME structure data used for key endorsement. */
	X509_ALGOR *sig_alg;				/**< Algorithm used to generate signature for the DME structure. */
	ASN1_BIT_STRING *signature;			/**< Signature of the DME structure. */
	ASN1_OBJECT *device_type;			/**< Identifier for the type of device that generated the DME structure. */
	ASN1_BIT_STRING *renewal_counter;	/**< Current value of the renewal counter for the DME key. */
	ASN1_ENCODING enc;					/**< ASN1 encoding. */
} DME_EXTENSION;

ASN1_SEQUENCE_enc (DME_EXTENSION, enc, 0) = {
	ASN1_SIMPLE (DME_EXTENSION, dme_key, X509_PUBKEY),
	ASN1_SIMPLE (DME_EXTENSION, struct_format, ASN1_OBJECT),
	ASN1_SIMPLE (DME_EXTENSION, dme_struct, ASN1_OCTET_STRING),
	ASN1_SIMPLE (DME_EXTENSION, sig_alg, X509_ALGOR),
	ASN1_SIMPLE (DME_EXTENSION, signature, ASN1_BIT_STRING),
	ASN1_IMP_OPT (DME_EXTENSION, device_type, ASN1_OBJECT, 0),
	ASN1_IMP_OPT (DME_EXTENSION, renewal_counter, ASN1_BIT_STRING, 1)
} ASN1_SEQUENCE_END_enc (DME_EXTENSION, DME_EXTENSION)

IMPLEMENT_ASN1_FUNCTIONS (DME_EXTENSION)


int x509_extension_builder_openssl_dme_build (const struct x509_extension_builder *builder,
	struct x509_extension *extension)
{
	const struct x509_extension_builder_openssl_dme *dme_build =
		(const struct x509_extension_builder_openssl_dme*) builder;
	DME_EXTENSION *dme_ext;
	EVP_PKEY *pubkey;
	ASN1_OBJECT *oid;
	int status;
	uint8_t *ext_der = NULL;
	int ext_der_len;

	if ((dme_build == NULL) || (extension == NULL)) {
		return DME_EXTENSION_INVALID_ARGUMENT;
	}

	if (dme_build->dme == NULL) {
		return DME_EXTENSION_INVALID_ARGUMENT;
	}

	if (dme_build->dme->data_oid == NULL) {
		return DME_EXTENSION_NO_TYPE_OID;
	}

	if (dme_build->dme->data == NULL) {
		return DME_EXTENSION_NO_DATA;
	}

	if (dme_build->dme->sig_oid == NULL) {
		return DME_EXTENSION_NO_SIG_TYPE_OID;
	}

	if (dme_build->dme->signature == NULL) {
		return DME_EXTENSION_NO_SIGNATURE;
	}

	if (dme_build->dme->dme_pub_key == NULL) {
		return DME_EXTENSION_NO_DME_KEY;
	}

	dme_ext = DME_EXTENSION_new ();
	if (dme_ext == NULL) {
		status = -ERR_get_error ();
		goto err_ext;
	}

	pubkey = d2i_PUBKEY (NULL, (const uint8_t**) &dme_build->dme->dme_pub_key,
		dme_build->dme->key_length);
	if (pubkey == NULL) {
		status = -ERR_get_error ();
		goto err_build;
	}

	status = X509_PUBKEY_set (&dme_ext->dme_key, pubkey);
	EVP_PKEY_free (pubkey);
	if (status == 0) {
		status = -ERR_get_error ();
		goto err_build;
	}

	status = x509_openssl_parse_encoded_oid (dme_build->dme->data_oid,
		dme_build->dme->data_oid_length, &oid);
	if (status != 0) {
		goto err_build;
	}

	ASN1_OBJECT_free (dme_ext->struct_format);
	dme_ext->struct_format = oid;

	status = ASN1_OCTET_STRING_set (dme_ext->dme_struct, dme_build->dme->data,
		dme_build->dme->data_length);
	if (status == 0) {
		status = -ERR_get_error ();
		goto err_build;
	}

	status = x509_openssl_parse_encoded_oid (dme_build->dme->sig_oid,
		dme_build->dme->sig_oid_length, &oid);
	if (status != 0) {
		goto err_build;
	}

	status = X509_ALGOR_set0 (dme_ext->sig_alg, oid, V_ASN1_UNDEF, NULL);
	if (status == 0) {
		status = -ERR_get_error ();
		ASN1_OBJECT_free (oid);
		goto err_build;
	}

	status = x509_openssl_set_bit_string (dme_build->dme->signature,
		dme_build->dme->signature_length, dme_ext->signature);
	if (status != 0) {
		goto err_build;
	}

	if (dme_build->dme->device_oid != NULL) {
		status = x509_openssl_parse_encoded_oid (dme_build->dme->device_oid,
			dme_build->dme->dev_oid_length, &dme_ext->device_type);
		if (status != 0) {
			goto err_build;
		}
	}

	if (dme_build->dme->renewal_counter != NULL) {
		dme_ext->renewal_counter = ASN1_BIT_STRING_new ();
		if (dme_ext->renewal_counter == NULL) {
			status = DME_EXTENSION_NO_MEMORY;
			goto err_build;
		}

		status = x509_openssl_set_bit_string (dme_build->dme->renewal_counter,
			dme_build->dme->counter_length, dme_ext->renewal_counter);
		if (status != 0) {
			goto err_build;
		}
	}

	ext_der_len = i2d_DME_EXTENSION (dme_ext, &ext_der);
	if (ext_der_len < 0) {
		status = -ERR_get_error ();
		goto err_build;
	}

	x509_extension_builder_init_extension_descriptor (extension, false,
		X509_EXTENSION_BUILDER_DME_OID, X509_EXTENSION_BUILDER_DME_OID_LENGTH, ext_der,
		ext_der_len);

	status = 0;

err_build:
	DME_EXTENSION_free (dme_ext);
err_ext:
	return status;
}

void x509_extension_builder_openssl_dme_free (const struct x509_extension_builder *builder,
	struct x509_extension *extension)
{
	UNUSED (builder);

	x509_extension_builder_free_extension_descriptor (extension);
}

/**
 * Initialize an extension builder for a DME extension.
 *
 * @param builder The extension builder to initialize.
 * @param dme The DME structure to encode in the extension.  This does not need to be constant.  The
 * contents can be externally modified after initialization to change what will be encoded in the
 * extension.
 *
 * @return 0 if the extension builder was initialized successfully or an error code.
 */
int x509_extension_builder_openssl_dme_init (struct x509_extension_builder_openssl_dme *builder,
	const struct dme_structure *dme)
{
	if ((builder == NULL) || (dme == NULL)) {
		return DME_EXTENSION_INVALID_ARGUMENT;
	}

	memset (builder, 0, sizeof (struct x509_extension_builder_openssl_dme));

	builder->base.build = x509_extension_builder_openssl_dme_build;
	builder->base.free = x509_extension_builder_openssl_dme_free;

	builder->dme = dme;

	return 0;
}

/**
 * Release the resources used by a DME extension builder.
 *
 * @param builder The extension builder to release.
 */
void x509_extension_builder_openssl_dme_release (
	const struct x509_extension_builder_openssl_dme *builder)
{
	UNUSED (builder);
}
