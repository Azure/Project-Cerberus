// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "platform_api.h"
#include "x509_mbedtls.h"
#include "common/unused.h"
#include "crypto/crypto_logging.h"
#include "crypto/mbedtls_compat.h"
#include "logging/debug_log.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/bignum.h"
#include "mbedtls/oid.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"


/**
 * Get the context to pass when adding extensions to certificates or CSR.
 *
 * @param x The X.509 certificate or CSR builder context.
 */
#if MBEDTLS_IS_VERSION_3
#define	X509_MBEDTLS_EXT_CONTEXT(x)		x
#else
#define	X509_MBEDTLS_EXT_CONTEXT(x)		x.extensions
#endif


/**
 * mbedTLS data for managing CA certificates.
 */
struct x509_mbedtls_ca_store_context {
	mbedtls_x509_crt *root_ca;		/**< The chain of trusted root certificates. */
	mbedtls_x509_crt *intermediate;	/**< The chain of intermediate CAs. */
};


/**
 * Create a new mbedTLS certificate instance.
 *
 * @return The allocated certificate or null.
 */
static mbedtls_x509_crt* x509_mbedtls_new_cert ()
{
	mbedtls_x509_crt *x509 = platform_malloc (sizeof (mbedtls_x509_crt));

	if (x509 != NULL) {
		mbedtls_x509_crt_init (x509);
	}

	return x509;
}

/**
 * Free an mbedTLS certificate instance.
 *
 * @param cert The certificate to free.
 */
static void x509_mbedtls_free_cert (void *cert)
{
	mbedtls_x509_crt *x509 = (mbedtls_x509_crt*) cert;

	if (x509) {
		mbedtls_x509_crt_free (x509);
		platform_free (x509);
	}
}

#ifdef X509_ENABLE_CREATE_CERTIFICATES
/**
 * Initialize a key context from a DER formatted key.
 *
 * @param mbedtls X.509 engine context being used.
 * @param key The key instance that will be initialized.
 * @param der The DER formatted key to load.
 * @param length The length of the DER key.
 * @param require_priv Flag indicating if the key must be a private a key.
 *
 * @return 0 if the key was successfully loaded or an error code.
 */
static int x509_mbedtls_load_key (const struct x509_engine_mbedtls *mbedtls,
	mbedtls_pk_context *key, const uint8_t *der, size_t length, bool require_priv)
{
	int status;

	mbedtls_pk_init (key);

#if MBEDTLS_IS_VERSION_3
	status = mbedtls_pk_parse_key (key, der, length, NULL, 0, mbedtls_ctr_drbg_random,
		&mbedtls->state->ctr_drbg);
#else
	UNUSED (mbedtls);
	status = mbedtls_pk_parse_key (key, der, length, NULL, 0);
#endif
	if (status != 0) {
		if (require_priv) {
			goto exit;
		}

		status = mbedtls_pk_parse_public_key (key, der, length);
	}

exit:
	if (status != 0) {
		mbedtls_pk_free (key);
	}

	return status;
}

/**
 * Write the ASN.1 header to an object.
 *
 * @param pos The current buffer position.
 * @param start The start of the buffer.
 * @param tag The object tag to write.
 * @param length The length of the object, updated with the header length.
 *
 * @return 0 if the object header was written or an error code.
 */
int x509_mbedtls_close_asn1_object (uint8_t **pos, uint8_t *start, uint8_t tag, int *length)
{
	int ret;

	MBEDTLS_ASN1_CHK_ADD (*length, mbedtls_asn1_write_len (pos, start, *length));
	MBEDTLS_ASN1_CHK_ADD (*length, mbedtls_asn1_write_tag (pos, start, tag));

	return 0;
}

/**
 * Construct the key usage data that can be added as an extension to a certificate or CSR.
 *
 * @param usage The key usage to advertise in the extension.
 * @param ext_data Output buffer for the extension data.  This will be updated on output to
 * reference the start of the extension data.
 * @param ext_length Maximum length of the extension data.  This will be updated on outut to
 * indicate the length of the extension data.
 *
 * @return 0 if the extension was successfully added or an error code.
 */
static int x509_mbedtls_build_key_usage_extension_data (int usage, uint8_t **ext_data,
	size_t *ext_length)
{
	uint8_t *pos;
	int length;

	pos = *ext_data + *ext_length;
	length = mbedtls_asn1_write_bitstring (&pos, *ext_data, (uint8_t*) &usage,
		(usage & 0x04) ? 6 : 5);
	if (length < 0) {
		return length;
	}

	*ext_data = pos;
	*ext_length = length;

	return 0;
}

/**
 * Construct the extended key usage sequence that can be added as an extension to a certificate or
 * CSR.
 *
 * @param oid The encoded OID string to add.
 * @param oid_length Length of the OID string.
 * @param ext_data Output buffer for the extension data.  This will be updated on output to
 * reference the start of the extension data.
 * @param ext_length Maximum length of the extension data.  This will be updated on outut to
 * indicate the length of the extension data.
 *
 * @return 0 if the extension data was successfully created or an error code.
 */
static int x509_mbedtls_build_extended_key_usage_extension_data (const char *oid, int oid_length,
	uint8_t **ext_data, size_t *ext_length)
{
	uint8_t *pos;
	int status;
	int length;

	pos = *ext_data + *ext_length;
	length = mbedtls_asn1_write_oid (&pos, *ext_data, oid, oid_length);
	if (length < 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_ASN1_WRITE_OID_EC, length, 0);

		return length;
	}

	status = x509_mbedtls_close_asn1_object (&pos, *ext_data,
		(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE), &length);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_ASN1_CLOSE_EC, length, 0);

		return status;
	}

	*ext_data = pos;
	*ext_length = length;

	return 0;
}

/**
 * Construct the basic constraints data that can be added as an extension to a certificate or CSR.
 *
 * @param ca Flag indicating if the cA flag should be set.
 * @param pathlen The value of the pathLengthConstraint.  Greater that the max path length will omit
 * the constraint.
 * @param ext_data Output buffer for the extension data.  This will be updated on output to
 * reference the start of the extension data.
 * @param ext_length Maximum length of the extension data.  This will be updated on outut to
 * indicate the length of the extension data.
 *
 * @return 0 if the extension data was successfully created or an error code.
 */
static int x509_mbedtls_build_basic_constraints_extension_data (bool ca, int pathlen,
	uint8_t **ext_data, size_t *ext_length)
{
	uint8_t *pos;
	int length = 0;
	int ret;

	pos = *ext_data + *ext_length;

	if (ca) {
		if (pathlen <= X509_CERT_MAX_PATHLEN) {
			MBEDTLS_ASN1_CHK_ADD (length, mbedtls_asn1_write_int (&pos, *ext_data, pathlen));
		}

		MBEDTLS_ASN1_CHK_ADD (length, mbedtls_asn1_write_bool (&pos, *ext_data, 1));
	}

	ret = x509_mbedtls_close_asn1_object (&pos, *ext_data,
		(MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE), &length);
	if (ret != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_ASN1_CLOSE_EC, ret, 0);

		return ret;
	}

	*ext_data = pos;
	*ext_length = length;

	return 0;
}

#if MBEDTLS_IS_VERSION_3
/**
 * Create and add the key usage extension to a CSR.
 *
 * @param extensions The list of extensions to update.
 * @param usage The key usage to advertise in the extension.
 *
 * @return 0 if the extension was successfully added or an error code.
 */
static int x509_mbedtls_add_key_usage_extension (mbedtls_x509write_csr *x509, int usage)
{
	uint8_t ext[4];
	uint8_t *pos = ext;
	size_t length = sizeof (ext);
	int status;

	status = x509_mbedtls_build_key_usage_extension_data (usage, &pos, &length);
	if (status != 0) {
		return status;
	}

	return mbedtls_x509write_csr_set_extension (x509, MBEDTLS_OID_KEY_USAGE,
		MBEDTLS_OID_SIZE (MBEDTLS_OID_KEY_USAGE), 1, pos, length);
}

/**
 * Create and add the extended key usage extension to a CSR.
 *
 * @param x509 The CSR to update with the extendend key usage.
 * @param oid The encoded OID string to add.
 * @param oid_length Length of the OID string.
 * @param critical Critical flag for the extension.
 *
 * @return 0 if the extension was successfully added or an error code.
 */
static int x509_mbedtls_add_extended_key_usage_extension (mbedtls_x509write_csr *x509,
	const char *oid, int oid_length, bool critical)
{
	uint8_t ext[20];
	uint8_t *pos = ext;
	size_t length = sizeof (ext);
	int status;

	status = x509_mbedtls_build_extended_key_usage_extension_data (oid, oid_length, &pos, &length);
	if (status != 0) {
		return status;
	}

	return mbedtls_x509write_csr_set_extension (x509, MBEDTLS_OID_EXTENDED_KEY_USAGE,
		MBEDTLS_OID_SIZE (MBEDTLS_OID_EXTENDED_KEY_USAGE), critical, pos, length);
}

/**
 * Create and add the basic constraints extension to a CSR.
 *
 * @param x509 The CSR to update with the extendend key usage.
 * @param ca Flag indicating if the cA flag should be set.
 * @param pathlen The value of the pathLengthConstraint.  Greater that the max path length will omit
 * the constraint.
 *
 * @return 0 if the extension was successfully added or an error code.
 */
static int x509_mbedtls_add_basic_constraints_extension (mbedtls_x509write_csr *x509, bool ca,
	int pathlen)
{
	uint8_t ext[9];
	uint8_t *pos = ext;
	size_t length = sizeof (ext);
	int status;

	status = x509_mbedtls_build_basic_constraints_extension_data (ca, pathlen, &pos, &length);
	if (status != 0) {
		return status;
	}

	return mbedtls_x509write_csr_set_extension (x509, MBEDTLS_OID_BASIC_CONSTRAINTS,
		MBEDTLS_OID_SIZE (MBEDTLS_OID_BASIC_CONSTRAINTS), 1, pos, length);
}

/**
 * Add a custom extensions to a certificate or CSR.
 *
 * @param builder The extension to add.
 * @param is_cert Flag to indicate if the X.509 context is a certificate rather than a CSR.
 * @param x509 The X.509 context to update with the new extension.
 *
 * @return 0 if the extension was add successfully or an error code.
 */
static int x509_mbedtls_add_custom_extension (const struct x509_extension_builder *builder,
	bool is_cert, void *x509)
{
	struct x509_extension extension = {0};
	int status;

	if (builder == NULL) {
		/* Silently skip null extension builders. */
		return 0;
	}

	status = builder->build (builder, &extension);
	if (status != 0) {
		return status;
	}

	if (is_cert) {
		status = mbedtls_x509write_crt_set_extension ((struct mbedtls_x509write_cert*) x509,
			(char*) extension.oid, extension.oid_length, extension.critical, extension.data,
			extension.data_length);
	}
	else {
		status = mbedtls_x509write_csr_set_extension ((struct mbedtls_x509write_csr*) x509,
			(char*) extension.oid, extension.oid_length, extension.critical, extension.data,
			extension.data_length);
	}

	builder->free (builder, &extension);

	return status;
}
#else	// MBEDTLS_IS_VERSION_3
/**
 * Create and add the key usage extension to a certificate or CSR.
 *
 * @param extensions The list of extensions to update.
 * @param usage The key usage to advertise in the extension.
 *
 * @return 0 if the extension was successfully added or an error code.
 */
static int x509_mbedtls_add_key_usage_extension (mbedtls_asn1_named_data **extensions, int usage)
{
	uint8_t ext[4];
	uint8_t *pos = ext;
	size_t length = sizeof (ext);
	int status;

	status = x509_mbedtls_build_key_usage_extension_data (usage, &pos, &length);
	if (status != 0) {
		return status;
	}

	return mbedtls_x509_set_extension (extensions, MBEDTLS_OID_KEY_USAGE,
		MBEDTLS_OID_SIZE (MBEDTLS_OID_KEY_USAGE), 1, pos, length);
}

/**
 * Create and add the extended key usage extension to a certificate or CSR.
 *
 * @param extensions The list of extensions to update.
 * @param oid The encoded OID string to add.
 * @param oid_length Length of the OID string.
 * @param critical Critical flag for the extension.
 *
 * @return 0 if the extension was successfully added or an error code.
 */
static int x509_mbedtls_add_extended_key_usage_extension (mbedtls_asn1_named_data **extensions,
	const char *oid, int oid_length, bool critical)
{
	uint8_t ext[20];
	uint8_t *pos = ext;
	size_t length = sizeof (ext);
	int status;

	status = x509_mbedtls_build_extended_key_usage_extension_data (oid, oid_length, &pos, &length);
	if (status != 0) {
		return status;
	}

	return mbedtls_x509_set_extension (extensions, MBEDTLS_OID_EXTENDED_KEY_USAGE,
		MBEDTLS_OID_SIZE (MBEDTLS_OID_EXTENDED_KEY_USAGE), critical, pos, length);
}

/**
 * Create and add the basic constraints extension to a certificate or CSR.
 *
 * @param extensions The list of extensions to update.
 * @param ca Flag indicating if the cA flag should be set.
 * @param pathlen The value of the pathLengthConstraint.  Greater that the max path length will omit
 * the constraint.
 *
 * @return 0 if the extension was successfully added or an error code.
 */
static int x509_mbedtls_add_basic_constraints_extension (mbedtls_asn1_named_data **extensions,
	bool ca, int pathlen)
{
	uint8_t ext[9];
	uint8_t *pos = ext;
	size_t length = sizeof (ext);
	int status;

	status = x509_mbedtls_build_basic_constraints_extension_data (ca, pathlen, &pos, &length);
	if (status != 0) {
		return status;
	}

	return mbedtls_x509_set_extension (extensions, MBEDTLS_OID_BASIC_CONSTRAINTS,
		MBEDTLS_OID_SIZE (MBEDTLS_OID_BASIC_CONSTRAINTS), 1, pos, length);
}

/**
 * Add a custom extensions to a certificate or CSR.
 *
 * @param builder The extension to add.
 * @param is_cert Flag to indicate if the X.509 context is a certificate rather than a CSR.
 * @param extensions List of extensions for the certificate that will be updated with the new
 * extension.
 *
 * @return 0 if the extension was add successfully or an error code.
 */
static int x509_mbedtls_add_custom_extension (const struct x509_extension_builder *builder,
	bool is_cert, mbedtls_asn1_named_data **extensions)
{
	struct x509_extension extension = {0};
	int status;

	UNUSED (is_cert);

	if (builder == NULL) {
		/* Silently skip null extension builders. */
		return 0;
	}

	status = builder->build (builder, &extension);
	if (status != 0) {
		return status;
	}

	status = mbedtls_x509_set_extension (extensions, (char*) extension.oid, extension.oid_length,
		extension.critical, extension.data, extension.data_length);

	builder->free (builder, &extension);

	return status;
}
#endif	// MBEDTLS_IS_VERSION_3

int x509_mbedtls_create_csr (const struct x509_engine *engine, const uint8_t *priv_key,
	size_t key_length, enum hash_type sig_hash, const char *name, int type, const uint8_t *eku,
	size_t eku_length, const struct x509_extension_builder *const *extra_extensions,
	size_t ext_count, uint8_t **csr, size_t *csr_length)
{
	const struct x509_engine_mbedtls *mbedtls = (const struct x509_engine_mbedtls*) engine;
	mbedtls_x509write_csr x509;
	mbedtls_pk_context key;
	mbedtls_md_type_t md_alg;
	char *subject;
	uint8_t key_usage;
	size_t i;
	int status;

	if (csr == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	*csr = NULL;
	if ((mbedtls == NULL) || (priv_key == NULL) || (name == NULL) || (csr_length == NULL) ||
		(key_length == 0)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	if ((eku_length != 0) && (eku == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	if ((ext_count != 0) && (extra_extensions == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	if ((type == X509_CERT_END_ENTITY) && (eku != NULL)) {
		return X509_ENGINE_NOT_CA_CERT;
	}

	switch (sig_hash) {
		case HASH_TYPE_SHA256:
			md_alg = MBEDTLS_MD_SHA256;
			break;

		case HASH_TYPE_SHA384:
			md_alg = MBEDTLS_MD_SHA384;
			break;

		case HASH_TYPE_SHA512:
			md_alg = MBEDTLS_MD_SHA512;
			break;

		default:
			return X509_ENGINE_UNSUPPORTED_SIG_HASH;
	}

	mbedtls_x509write_csr_init (&x509);

	status = x509_mbedtls_load_key (mbedtls, &key, priv_key, key_length, true);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_X509_LOAD_KEY_EC, status, 0);

		goto err_free_csr;
	}

	mbedtls_x509write_csr_set_key (&x509, &key);

	subject = platform_malloc (strlen (name) + 4);
	if (subject == NULL) {
		status = X509_ENGINE_NO_MEMORY;
		goto err_free_key;
	}

	strcpy (subject, "CN=");
	strcpy (&subject[3], name);
	status = mbedtls_x509write_csr_set_subject_name (&x509, subject);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_X509_CSR_SET_SUBJECT_EC, status, 0);

		goto err_free_subject;
	}

	if (type) {
		key_usage = MBEDTLS_X509_KU_KEY_CERT_SIGN;
	}
	else {
		key_usage = MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_AGREEMENT;
	}

	status = x509_mbedtls_add_key_usage_extension (&X509_MBEDTLS_EXT_CONTEXT (x509), key_usage);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_X509_ADD_KEY_USAGE_EC, status, 0);

		goto err_free_subject;
	}

	if (eku != NULL) {
		status = x509_mbedtls_add_extended_key_usage_extension (&X509_MBEDTLS_EXT_CONTEXT (x509),
			(char*) eku, eku_length, false);
		if (status != 0) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
				CRYPTO_LOG_MSG_MBEDTLS_X509_ADD_EXT_KEY_USAGE_EC, status, 0);

			goto err_free_subject;
		}
	}

	if (type) {
		status = x509_mbedtls_add_basic_constraints_extension (&X509_MBEDTLS_EXT_CONTEXT (x509),
			true, X509_CERT_PATHLEN (type));
		if (status != 0) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
				CRYPTO_LOG_MSG_MBEDTLS_X509_ADD_BASIC_CONSTRAINTS_EC, status, 0);

			goto err_free_subject;
		}
	}

	for (i = 0; i < ext_count; i++) {
		status = x509_mbedtls_add_custom_extension (extra_extensions[i], false,
			&X509_MBEDTLS_EXT_CONTEXT (x509));
		if (status != 0) {
			goto err_free_subject;
		}
	}

	mbedtls_x509write_csr_set_md_alg (&x509, md_alg);
	status = mbedtls_x509write_csr_der (&x509, mbedtls->state->der_buf, X509_MAX_SIZE,
		mbedtls_ctr_drbg_random, &mbedtls->state->ctr_drbg);
	if (status < 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_X509_CSR_DER_WRITE_EC, status, 0);

		goto err_free_subject;
	}

	*csr = platform_malloc (status);
	if (*csr == NULL) {
		status = X509_ENGINE_NO_MEMORY;
		goto err_free_subject;
	}

	memcpy (*csr, &mbedtls->state->der_buf[X509_MAX_SIZE - status], status);
	*csr_length = status;
	status = 0;

err_free_subject:
	platform_free (subject);
err_free_key:
	mbedtls_pk_free (&key);
err_free_csr:
	mbedtls_x509write_csr_free (&x509);

	return status;
}

/**
 * Callback to use for handling any extra extensions that have been added to the certificate that
 * mbedTLS doesn't understand.  This callback does nothing except return success, indicating that
 * certificate parsing should continue.
 *
 * This should not be used with authentication flows, since it will cause unknown critical
 * extensions to be treated as valid.
 *
 * @param p_ctx Unused.  Necessary for mbedtls callback compatibility.
 * @param crt Unused.  Necessary for mbedtls callback compatibility.
 * @param oid Unused.  Necessary for mbedtls callback compatibility.
 * @param critical Unused.  Necessary for mbedtls callback compatibility.
 * @param p Unused.  Necessary for mbedtls callback compatibility.
 * @param end Unused.  Necessary for mbedtls callback compatibility.
 *
 * @return Always returns 0
 */
static int x509_mbedtls_accept_unknown_extensions (void *p_ctx, mbedtls_x509_crt const *crt,
	mbedtls_x509_buf const *oid, int critical, const unsigned char *p, const unsigned char *end)
{
	UNUSED (p_ctx);
	UNUSED (crt);
	UNUSED (oid);
	UNUSED (critical);
	UNUSED (p);
	UNUSED (end);

	return 0;
}

/**
 * Create a new certificate.  This can be self-signed, or signed by a CA.
 *
 * @param mbedtls The mbedTLS X.509 instance to use for creating the certificate.
 * @param cert The instance to initialize with the new certificate.
 * @param cert_key The key to use to create the certificate.  For self-signed certificates, this
 * must be a private key.
 * @param sig_hash The hash algorithm to use for signing the certificate.
 * @param serial_num The serial number to assign to the certificate.
 * @param serial_length The length of the serial number.
 * @param name The common name for the certificate subject.
 * @param type The type of certificate to create.
 * @param ca_key The private key of the CA to use for certificate signing.  Set this to null for a
 * self-signed certificate.
 * @param ca_cert The certificate for the CA key.  This is unused for a self-signed certificate and
 * can be set to null.
 * @param extra_extensions List of custom extensions that should be added to the certificate.
 * @param ext_count The number of custom extensions to add.
 *
 * @return 0 if the certificate was successfully created or an error code.
 */
static int x509_mbedtls_create_certificate (const struct x509_engine_mbedtls *mbedtls,
	struct x509_certificate *cert, mbedtls_pk_context *cert_key, enum hash_type sig_hash,
	const uint8_t *serial_num, size_t serial_length, const char *name, int type,
	mbedtls_pk_context *ca_key, const struct x509_certificate *ca_cert,
	const struct x509_extension_builder *const *extra_extensions, size_t ext_count)
{
	mbedtls_x509_crt *x509;
	mbedtls_x509_crt *ca_x509;
	mbedtls_x509write_cert x509_build;
	mbedtls_pk_context *signing_key;
	mbedtls_md_type_t md_alg;
	char *subject;
	size_t i;
	int status;

	switch (sig_hash) {
		case HASH_TYPE_SHA256:
			md_alg = MBEDTLS_MD_SHA256;
			break;

		case HASH_TYPE_SHA384:
			md_alg = MBEDTLS_MD_SHA384;
			break;

		case HASH_TYPE_SHA512:
			md_alg = MBEDTLS_MD_SHA512;
			break;

		default:
			return X509_ENGINE_UNSUPPORTED_SIG_HASH;
	}

	if (ca_key) {
		signing_key = ca_key;
		ca_x509 = (mbedtls_x509_crt*) ca_cert->context;
	}
	else {
		signing_key = cert_key;
		ca_x509 = NULL;
	}

	mbedtls_x509write_crt_init (&x509_build);
	mbedtls_x509write_crt_set_version (&x509_build, MBEDTLS_X509_CRT_VERSION_3);
	mbedtls_x509write_crt_set_subject_key (&x509_build, cert_key);
	mbedtls_x509write_crt_set_issuer_key (&x509_build, signing_key);

#if MBEDTLS_IS_VERSION_3
	{
		bool valid_serial = false;

		/* Ensure the serial number is not 0. */
		for (i = 0; i < serial_length; i++) {
			if (serial_num[i] != 0) {
				valid_serial = true;
				break;
			}
		}

		if (!valid_serial) {
			status = X509_ENGINE_INVALID_SERIAL_NUM;
			goto err_free_crt;
		}

		status = mbedtls_x509write_crt_set_serial_raw (&x509_build, (uint8_t*) serial_num,
			serial_length);
		if (status != 0) {
			status = X509_ENGINE_INVALID_SERIAL_NUM;
			goto err_free_crt;
		}
	}
#else
	status = mbedtls_mpi_read_binary (&x509_build.serial, serial_num, serial_length);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_MPI_READ_BIN_EC, status, 0);

		goto err_free_crt;
	}

	if (mbedtls_mpi_cmp_int (&x509_build.serial, 0) == 0) {
		status = X509_ENGINE_INVALID_SERIAL_NUM;
		goto err_free_crt;
	}
#endif

	subject = platform_malloc (strlen (name) + 4);
	if (subject == NULL) {
		status = X509_ENGINE_NO_MEMORY;
		goto err_free_crt;
	}

	strcpy (subject, "CN=");
	strcpy (&subject[3], name);
	status = mbedtls_x509write_crt_set_subject_name (&x509_build, subject);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_CRT_SET_SUBJECT_EC, status, 0);

		goto err_free_subject;
	}

	if (!ca_key) {
		status = mbedtls_x509write_crt_set_issuer_name (&x509_build, subject);
		if (status != 0) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
				CRYPTO_LOG_MSG_MBEDTLS_CRT_SET_ISSUER_EC, status, 0);
			goto err_free_subject;
		}
	}
	else {
		struct mbedtls_asn1_named_data *issuer_cn;

		/* The alternative to accessing internal fields is to use mbedtls_x509_dn_gets() to get the
		 * subject name from the issuer certificate and pass that to
		 * mbedtls_x509write_crt_set_issuer_name().  However, mbedtls_x509_dn_gets() returns an
		 * escaped string rather than the raw data.  This escaped string is rejected as invalid when
		 * to mbedtls_x509write_crt_set_issuer_name() using mbedTLS version 2.x.  It works fine with
		 * mbedTLS 3.x, but just keep the same flow in both cases (at least for now) to avoid the
		 * need to unnecessarily link in mbedtls_x509_dn_gets(). */
		issuer_cn = mbedtls_asn1_store_named_data (&x509_build.MBEDTLS_PRIVATE (issuer),
			(char*) ca_x509->subject.oid.p, ca_x509->subject.oid.len, ca_x509->subject.val.p,
			ca_x509->subject.val.len);
		if (issuer_cn == NULL) {
			status = X509_ENGINE_NO_MEMORY;
		}

		issuer_cn->val.tag = MBEDTLS_ASN1_UTF8_STRING;
	}

	status = mbedtls_x509write_crt_set_validity (&x509_build, "20180101000000", "99991231235959");
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_CRT_SET_VALIDITY_EC, status, 0);

		goto err_free_subject;
	}

	status = mbedtls_x509write_crt_set_subject_key_identifier (&x509_build);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_CRT_SET_SUBJECT_EC, status, 0);

		goto err_free_subject;
	}

	status = mbedtls_x509write_crt_set_authority_key_identifier (&x509_build);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_CRT_SET_AUTHORITY_EC, status, 0);

		goto err_free_subject;
	}

	if (type) {
		status = mbedtls_x509write_crt_set_key_usage (&x509_build, MBEDTLS_X509_KU_KEY_CERT_SIGN);
	}
	else {
		status = mbedtls_x509write_crt_set_key_usage (&x509_build,
			(MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_AGREEMENT));
	}

	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_X509_ADD_KEY_USAGE_EC, status, 0);

		goto err_free_subject;
	}

	if (type) {
		int pathlen = X509_CERT_PATHLEN (type);

		if (pathlen > X509_CERT_MAX_PATHLEN) {
			pathlen = -1;
		}

		status = mbedtls_x509write_crt_set_basic_constraints (&x509_build, true, pathlen);
		if (status != 0) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
				CRYPTO_LOG_MSG_MBEDTLS_X509_ADD_BASIC_CONSTRAINTS_EC, status, 0);

			goto err_free_subject;
		}
	}

	for (i = 0; i < ext_count; i++) {
		status = x509_mbedtls_add_custom_extension (extra_extensions[i], true,
			&X509_MBEDTLS_EXT_CONTEXT (x509_build));
		if (status != 0) {
			goto err_free_subject;
		}
	}

	mbedtls_x509write_crt_set_md_alg (&x509_build, md_alg);
	status = mbedtls_x509write_crt_der (&x509_build, mbedtls->state->der_buf, X509_MAX_SIZE,
		mbedtls_ctr_drbg_random, &mbedtls->state->ctr_drbg);
	if (status < 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_CRT_WRITE_DER_EC, status, 0);

		goto err_free_subject;
	}

	x509 = x509_mbedtls_new_cert ();
	if (x509 == NULL) {
		status = X509_ENGINE_NO_MEMORY;
		goto err_free_subject;
	}

	/* The certificate that is being parsed was just created here, so allow any unknown extensions
	 * to be parsed successfully, even if they are critical. */
	status = mbedtls_x509_crt_parse_der_with_ext_cb (x509,
		&mbedtls->state->der_buf[X509_MAX_SIZE - status], status, 1,
		x509_mbedtls_accept_unknown_extensions, NULL);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_CRT_PARSE_DER_EC, status, 0);

		x509_mbedtls_free_cert (x509);
		goto err_free_subject;
	}

	cert->context = x509;

err_free_subject:
	platform_free (subject);
err_free_crt:
	mbedtls_x509write_crt_free (&x509_build);

	return status;
}

int x509_mbedtls_create_self_signed_certificate (const struct x509_engine *engine,
	struct x509_certificate *cert, const uint8_t *priv_key, size_t key_length,
	enum hash_type sig_hash, const uint8_t *serial_num, size_t serial_length, const char *name,
	int type, const struct x509_extension_builder *const *extra_extensions, size_t ext_count)
{
	const struct x509_engine_mbedtls *mbedtls = (const struct x509_engine_mbedtls*) engine;
	mbedtls_pk_context cert_key;
	int status;

	if ((engine == NULL) || (cert == NULL) || (priv_key == NULL) || (key_length == 0) ||
		(serial_num == NULL) || (serial_length == 0) || (name == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	if ((ext_count != 0) && (extra_extensions == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	status = x509_mbedtls_load_key (mbedtls, &cert_key, priv_key, key_length, true);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_X509_LOAD_KEY_EC, status, 0);

		goto err_exit;
	}

	status = x509_mbedtls_create_certificate (mbedtls, cert, &cert_key, sig_hash, serial_num,
		serial_length, name, type, NULL, NULL, extra_extensions, ext_count);

	mbedtls_pk_free (&cert_key);
err_exit:

	return status;
}

int x509_mbedtls_create_ca_signed_certificate (const struct x509_engine *engine,
	struct x509_certificate *cert, const uint8_t *key, size_t key_length, const uint8_t *serial_num,
	size_t serial_length, const char *name, int type, const uint8_t *ca_priv_key,
	size_t ca_key_length, enum hash_type sig_hash, const struct x509_certificate *ca_cert,
	const struct x509_extension_builder *const *extra_extensions, size_t ext_count)
{
	const struct x509_engine_mbedtls *mbedtls = (const struct x509_engine_mbedtls*) engine;
	mbedtls_pk_context cert_key;
	mbedtls_pk_context ca_key;
	int status;

	if ((engine == NULL) || (cert == NULL) || (key == NULL) || (key_length == 0) ||
		(serial_num == NULL) || (serial_length == 0) || (name == NULL) || (ca_priv_key == NULL) ||
		(ca_key_length == 0) || (ca_cert == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	if ((ext_count != 0) && (extra_extensions == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	status = x509_mbedtls_load_key (mbedtls, &cert_key, key, key_length, false);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_X509_LOAD_KEY_EC, status, 0);

		goto err_exit;
	}

	status = x509_mbedtls_load_key (mbedtls, &ca_key, ca_priv_key, ca_key_length, true);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_X509_LOAD_KEY_EC, status, 0);

		goto err_free_key;
	}

	status = x509_mbedtls_create_certificate (mbedtls, cert, &cert_key, sig_hash, serial_num,
		serial_length, name, type, &ca_key, ca_cert, extra_extensions, ext_count);

	mbedtls_pk_free (&ca_key);
err_free_key:
	mbedtls_pk_free (&cert_key);
err_exit:

	return status;
}
#endif

int x509_mbedtls_load_certificate (const struct x509_engine *engine, struct x509_certificate *cert,
	const uint8_t *der, size_t length)
{
	mbedtls_x509_crt *x509;
	int status;

	if ((engine == NULL) || (cert == NULL) || (der == NULL) || (length == 0)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	x509 = x509_mbedtls_new_cert ();
	if (x509 == NULL) {
		return X509_ENGINE_NO_MEMORY;
	}

	status = mbedtls_x509_crt_parse_der (x509, der, length);
	if (status == 0) {
		cert->context = x509;
	}
	else {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_CRT_PARSE_DER_EC, status, 0);

		x509_mbedtls_free_cert (x509);
	}

	return status;
}

void x509_mbedtls_release_certificate (const struct x509_engine *engine,
	struct x509_certificate *cert)
{
	UNUSED (engine);

	if (cert) {
		x509_mbedtls_free_cert (cert->context);
		memset (cert, 0, sizeof (struct x509_certificate));
	}
}

#ifdef X509_ENABLE_CREATE_CERTIFICATES
int x509_mbedtls_get_certificate_der (const struct x509_engine *engine,
	const struct x509_certificate *cert, uint8_t **der, size_t *length)
{
	mbedtls_x509_crt *x509;

	if (der == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	*der = NULL;
	if ((engine == NULL) || (cert == NULL) || (length == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	x509 = (mbedtls_x509_crt*) cert->context;

	*der = platform_malloc (x509->raw.len);
	if (*der == NULL) {
		return X509_ENGINE_NO_MEMORY;
	}

	memcpy (*der, x509->raw.p, x509->raw.len);
	*length = x509->raw.len;

	return 0;
}
#endif

#ifdef X509_ENABLE_AUTHENTICATION
int x509_mbedtls_get_certificate_version (const struct x509_engine *engine,
	const struct x509_certificate *cert)
{
	if ((engine == NULL) || (cert == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	return ((mbedtls_x509_crt*) cert->context)->version;
}

int x509_mbedtls_get_serial_number (const struct x509_engine *engine,
	const struct x509_certificate *cert, uint8_t *serial_num, size_t length)
{
	mbedtls_x509_crt *x509;

	if ((engine == NULL) || (cert == NULL) || (serial_num == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	x509 = (mbedtls_x509_crt*) cert->context;
	if (length < x509->serial.len) {
		return X509_ENGINE_SMALL_SERIAL_BUFFER;
	}

	memcpy (serial_num, x509->serial.p, x509->serial.len);

	return x509->serial.len;
}

int x509_mbedtls_get_public_key_type (const struct x509_engine *engine,
	const struct x509_certificate *cert)
{
	if ((engine == NULL) || (cert == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	switch (mbedtls_pk_get_type (&((mbedtls_x509_crt*) cert->context)->pk)) {
		case MBEDTLS_PK_ECKEY:
			return X509_PUBLIC_KEY_ECC;

		case MBEDTLS_PK_RSA:
			return X509_PUBLIC_KEY_RSA;

		case MBEDTLS_PK_NONE:
			return X509_ENGINE_UNKNOWN_KEY_TYPE;

		default:
			return X509_ENGINE_UNSUPPORTED_KEY_TYPE;
	}
}

int x509_mbedtls_get_public_key_length (const struct x509_engine *engine,
	const struct x509_certificate *cert)
{
	if ((engine == NULL) || (cert == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	return mbedtls_pk_get_bitlen (&((mbedtls_x509_crt*) (cert->context))->pk);
}

int x509_mbedtls_get_public_key (const struct x509_engine *engine,
	const struct x509_certificate *cert, uint8_t **key, size_t *key_length)
{
	const struct x509_engine_mbedtls *mbedtls = (const struct x509_engine_mbedtls*) engine;
	int status;

	if (key == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	*key = NULL;
	if ((mbedtls == NULL) || (cert == NULL) || (key_length == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	status = mbedtls_pk_write_pubkey_der (&((mbedtls_x509_crt*) cert->context)->pk,
		mbedtls->state->der_buf, X509_MAX_SIZE);
	if (status < 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_PK_WRITE_PUBKEY_DER_EC, status, 0);

		return status;
	}

	*key = platform_malloc (status);
	if (*key == NULL) {
		return X509_ENGINE_NO_MEMORY;
	}

	memcpy (*key, &mbedtls->state->der_buf[X509_MAX_SIZE - status], status);
	*key_length = status;

	return 0;
}

/**
 * Verify only the signature of a certificate.
 *
 * @param cert The certificate to verify.
 * @param key The key to use for verification.
 *
 * @return 0 if the signature is valid or an error code.
 */
static int x509_mbedtls_verify_cert_signature (mbedtls_x509_crt *cert, mbedtls_pk_context *key)
{
	unsigned char hash[MBEDTLS_MD_MAX_SIZE];
	const mbedtls_md_info_t *md_info;
	int status;

	/* This function makes direct use of private fields in the X.509 structure.  Unfortunately, it
	 * seems this can't be avoided, since there are no APIs to easily verify the signature of a
	 * single certificate. */

	md_info = mbedtls_md_info_from_type (cert->MBEDTLS_PRIVATE (sig_md));
	if (md_info == NULL) {
		return X509_ENGINE_UNSUPPORTED_SIG_TYPE;
	}

	mbedtls_md (md_info, cert->tbs.p, cert->tbs.len, hash);

	status = mbedtls_pk_verify_ext (cert->MBEDTLS_PRIVATE (sig_pk),
		cert->MBEDTLS_PRIVATE (sig_opts), key, cert->MBEDTLS_PRIVATE (sig_md), hash,
		mbedtls_md_get_size (md_info), cert->MBEDTLS_PRIVATE (sig).p,
		cert->MBEDTLS_PRIVATE (sig).len);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_PK_VERIFY_EC, status, 0);
	}

	return status;
}

/**
 * Indicate if a certificate is self-signed.
 *
 * @param x509 The certificate to check.
 *
 * @return true if the certificate is self-signed or false if not.
 */
static bool x509_mbedtls_is_self_signed (mbedtls_x509_crt *x509)
{
	if ((x509->issuer_raw.len == x509->subject_raw.len) &&
		(memcmp (x509->issuer_raw.p, x509->subject_raw.p, x509->issuer_raw.len) == 0)) {
		return true;
	}
	else {
		return false;
	}
}

int x509_mbedtls_init_ca_cert_store (const struct x509_engine *engine, struct x509_ca_certs *store)
{
	struct x509_mbedtls_ca_store_context *store_ctx;

	if ((engine == NULL) || (store == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	store_ctx = platform_malloc (sizeof (struct x509_mbedtls_ca_store_context));
	if (store_ctx == NULL) {
		return X509_ENGINE_NO_MEMORY;
	}

	memset (store_ctx, 0, sizeof (struct x509_mbedtls_ca_store_context));
	store->context = store_ctx;

	return 0;
}

void x509_mbedtls_release_ca_cert_store (const struct x509_engine *engine,
	struct x509_ca_certs *store)
{
	UNUSED (engine);

	if (store && store->context) {
		struct x509_mbedtls_ca_store_context *store_ctx = store->context;

		mbedtls_x509_crt_free (store_ctx->root_ca);
		platform_free (store_ctx->root_ca);

		mbedtls_x509_crt_free (store_ctx->intermediate);
		platform_free (store_ctx->intermediate);

		platform_free (store_ctx);
		memset (store, 0, sizeof (struct x509_ca_certs));
	}
}

/**
 * Load a CA certificate and add it to a certificate chain.
 *
 * @param engine The X.509 instance to use for loading the certificate.
 * @param chain The certificate chain to update with the CA certificate.
 * @param der DER encoded data for the CA certificate.
 * @param length Length of the DER encoded data.
 * @param is_root Flag indicating if the certificate is a root CA.
 *
 * @return 0 if the certificate chain was updated successfully or an error code.
 */
static int x509_mbedtls_add_ca_to_cert_chain (const struct x509_engine *engine,
	mbedtls_x509_crt **chain, const uint8_t *der, size_t length, bool is_root)
{
	struct x509_certificate cert;
	mbedtls_x509_crt *x509;
	int status;

	status = x509_mbedtls_load_certificate (engine, &cert, der, length);
	if (status != 0) {
		goto err_exit;
	}

	x509 = (mbedtls_x509_crt*) cert.context;

	/* Not ideal to access the private field, but this information is not readily available from any
	 * other public field or API. */
	if (!x509->MBEDTLS_PRIVATE (ca_istrue)) {
		status = X509_ENGINE_NOT_CA_CERT;
		goto err_free_cert;
	}

	if (is_root) {
		/* Root CAs must be self signed and have a valid signature. */
		if (!x509_mbedtls_is_self_signed (x509)) {
			status = X509_ENGINE_NOT_SELF_SIGNED;
			goto err_free_cert;
		}

		status = x509_mbedtls_verify_cert_signature (x509, &x509->pk);
		if (status != 0) {
			status = X509_ENGINE_BAD_SIGNATURE;
			goto err_free_cert;
		}
	}
	else {
		/* ICAs must not be self signed. */
		if (x509_mbedtls_is_self_signed (x509)) {
			status = X509_ENGINE_IS_SELF_SIGNED;
			goto err_free_cert;
		}
	}

	x509->next = *chain;
	*chain = x509;

	return 0;

err_free_cert:
	x509_mbedtls_release_certificate (engine, &cert);
err_exit:

	return status;
}

int x509_mbedtls_add_root_ca (const struct x509_engine *engine, struct x509_ca_certs *store,
	const uint8_t *der, size_t length)
{
	if (store == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	return x509_mbedtls_add_ca_to_cert_chain (engine,
		&((struct x509_mbedtls_ca_store_context*) store->context)->root_ca, der, length, true);
}

int x509_mbedtls_add_trusted_ca (const struct x509_engine *engine, struct x509_ca_certs *store,
	const uint8_t *der, size_t length)
{
	if (store == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	return x509_mbedtls_add_ca_to_cert_chain (engine,
		&((struct x509_mbedtls_ca_store_context*) store->context)->root_ca, der, length, false);
}

int x509_mbedtls_add_intermediate_ca (const struct x509_engine *engine, struct x509_ca_certs *store,
	const uint8_t *der, size_t length)
{
	if (store == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	return x509_mbedtls_add_ca_to_cert_chain (engine,
		&((struct x509_mbedtls_ca_store_context*) store->context)->intermediate, der, length,
		false);
}

int x509_mbedtls_authenticate (const struct x509_engine *engine,
	const struct x509_certificate *cert, const struct x509_ca_certs *store)
{
	const struct x509_engine_mbedtls *mbedtls = (const struct x509_engine_mbedtls*) engine;
	struct x509_mbedtls_ca_store_context *store_ctx;
	mbedtls_x509_crt *x509;
	int status;
	uint32_t validation;

	if ((mbedtls == NULL) || (cert == NULL) || (store == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	store_ctx = store->context;
	x509 = (mbedtls_x509_crt*) cert->context;
	x509->next = store_ctx->intermediate;

	status = mbedtls_x509_crt_verify (x509, store_ctx->root_ca, NULL, NULL, &validation, NULL,
		NULL);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_CRT_CERT_AUTHENTICATE_EC, status, validation);
	}

	if (status == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
		status = X509_ENGINE_CERT_NOT_VALID;
	}

	x509->next = NULL;

	return status;
}
#endif

/**
 * Initialize an instance for handling X.509 certificates using mbedTLS.
 *
 * @param engine The X.509 engine to initialize.
 * @param state Variable context for X.509 operations.  This must be uninitialized.
 *
 * @return 0 if the X.509 engine was successfully initialized or an error code.
 */
int x509_mbedtls_init (struct x509_engine_mbedtls *engine, struct x509_engine_mbedtls_state *state)
{
	if (engine == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine, 0, sizeof (struct x509_engine_mbedtls));

#ifdef X509_ENABLE_CREATE_CERTIFICATES
	engine->base.create_csr = x509_mbedtls_create_csr;
	engine->base.create_self_signed_certificate = x509_mbedtls_create_self_signed_certificate;
	engine->base.create_ca_signed_certificate = x509_mbedtls_create_ca_signed_certificate;
#endif
	engine->base.load_certificate = x509_mbedtls_load_certificate;
	engine->base.release_certificate = x509_mbedtls_release_certificate;
#ifdef X509_ENABLE_CREATE_CERTIFICATES
	engine->base.get_certificate_der = x509_mbedtls_get_certificate_der;
#endif
#ifdef X509_ENABLE_AUTHENTICATION
	engine->base.get_certificate_version = x509_mbedtls_get_certificate_version;
	engine->base.get_serial_number = x509_mbedtls_get_serial_number;
	engine->base.get_public_key_type = x509_mbedtls_get_public_key_type;
	engine->base.get_public_key_length = x509_mbedtls_get_public_key_length;
	engine->base.get_public_key = x509_mbedtls_get_public_key;
	engine->base.init_ca_cert_store = x509_mbedtls_init_ca_cert_store;
	engine->base.release_ca_cert_store = x509_mbedtls_release_ca_cert_store;
	engine->base.add_root_ca = x509_mbedtls_add_root_ca;
	engine->base.add_trusted_ca = x509_mbedtls_add_trusted_ca;
	engine->base.add_intermediate_ca = x509_mbedtls_add_intermediate_ca;
	engine->base.authenticate = x509_mbedtls_authenticate;
#endif

	engine->state = state;

	return x509_mbedtls_init_state (engine);
}

/**
 * Initialize only the variable state of on mbedTLS X.509 engine.  The rest of the instance is
 * assumed to already have been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param engine The X.509 engine that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int x509_mbedtls_init_state (const struct x509_engine_mbedtls *engine)
{
	int status = 0;

	if ((engine == NULL) || (engine->state == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine->state, 0, sizeof (*engine->state));

#ifdef X509_ENABLE_CREATE_CERTIFICATES
	mbedtls_ctr_drbg_init (&engine->state->ctr_drbg);
	mbedtls_entropy_init (&engine->state->entropy);

	status = mbedtls_ctr_drbg_seed (&engine->state->ctr_drbg, mbedtls_entropy_func,
		&engine->state->entropy, NULL, 0);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_CTR_DRBG_SEED_EC, status, 0);

		goto exit;
	}

	return 0;

exit:
	mbedtls_entropy_free (&engine->state->entropy);
	mbedtls_ctr_drbg_free (&engine->state->ctr_drbg);
#endif

	return status;
}

/**
 * Release an mbedTLS X.509 engine.
 *
 * @param engine The X.509 engine to release.
 */
void x509_mbedtls_release (const struct x509_engine_mbedtls *engine)
{
#ifdef X509_ENABLE_CREATE_CERTIFICATES
	if (engine) {
		mbedtls_entropy_free (&engine->state->entropy);
		mbedtls_ctr_drbg_free (&engine->state->ctr_drbg);
	}
#else
	UNUSED (engine);
#endif
}
