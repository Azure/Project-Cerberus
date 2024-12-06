// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/conf.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "platform_api.h"
#include "asn1/x509_openssl.h"
#include "common/unused.h"


/**
 * OpenSSL data for managing CA certificates.
 */
struct x509_openssl_ca_store_context {
	X509_STORE *trusted;			/**< Store for Root CAs. */
	STACK_OF (X509) *intermediate;	/**< Store for intermediate CAs. */
	unsigned long flags;			/**< Verification flags to apply when verifying. */
};


#ifdef X509_ENABLE_CREATE_CERTIFICATES
/**
 * Load a DER formatted key.
 *
 * @param key The key instance that will be allocated.
 * @param der The DER formatted key to load.
 * @param length The length of the DER key.
 * @param require_priv Flag indicating if the key must be a private a key.
 *
 * @return 0 if the key was successfully loaded or an error code.
 */
static int x509_openssl_load_key (EVP_PKEY **key, const uint8_t *der, size_t length,
	bool require_priv)
{
	BIO *bio;
	int status;

	ERR_clear_error ();

	bio = BIO_new_mem_buf (der, length);
	if (bio == NULL) {
		status = ERR_get_error ();
		goto err_bio;
	}

	*key = d2i_PrivateKey_bio (bio, NULL);
	if (*key == NULL) {
		status = ERR_get_error ();
		if (require_priv) {
			goto err_key;
		}

		status = BIO_reset (bio);
		if (status <= 0) {
			status = ERR_get_error ();
			goto err_key;
		}

		*key = d2i_PUBKEY_bio (bio, NULL);
		if (*key == NULL) {
			status = ERR_get_error ();
			goto err_key;
		}
	}

	status = 0;

err_key:
	BIO_free (bio);
err_bio:
	return -status;
}

/**
 * Parse a custom OID that is already encoded, rather than being in a numerical format.
 *
 * @param encoded_oid The encoded OID to parse.
 * @param length Length of the encoded OID.
 * @param oid Output for the object for the OID.
 *
 * @return 0 if the OID was parsed successfully or an error code.
 */
int x509_openssl_parse_encoded_oid (const uint8_t *encoded_oid, size_t length, ASN1_OBJECT **oid)
{
	uint8_t oid_der[256];
	uint8_t *oid_ptr = oid_der;
	int status;

	if (length > (sizeof (oid_der) - 2)) {
		return X509_ENGINE_LONG_OID;
	}

	oid_der[0] = 0x06;
	oid_der[1] = length;
	memcpy (&oid_der[2], encoded_oid, length);

	*oid = d2i_ASN1_OBJECT (NULL, (const unsigned char**) &oid_ptr, length + 2);
	if (*oid == NULL) {
		status = -ERR_get_error ();
		return status;
	}

	return 0;
}

/**
 * Set the value of an ASN.1 BIT STRING, ensuring that the unused bits field is always 0.
 *
 * @param data The data to encode as a BIT STRING.
 * @param length Length of the data.
 * @param bits The BIT STRING object that will be updated.
 *
 * @return 0 if the bit string was updated successfully or an error code.
 */
int x509_openssl_set_bit_string (const uint8_t *data, size_t length, ASN1_BIT_STRING *bits)
{
	int status;

	status = ASN1_BIT_STRING_set (bits, (uint8_t*) data, length);
	if (status == 0) {
		status = -ERR_get_error ();
		return status;
	}

	/* Make sure unused bits is always 0. */
	bits->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
    bits->flags |= ASN1_STRING_FLAG_BITS_LEFT;

	return 0;
}

/**
 * Create an custom formatted X.509 extension.
 *
 * @param builder The extension to create.
 * @param ext Output for the new extension.
 * @param ext_data Output for the data object of the extension.
 *
 * @return 0 if the extension was created successfully or an error code.
 */
static int x509_openssl_create_custom_extension (const struct x509_extension_builder *builder,
	X509_EXTENSION **ext, ASN1_OCTET_STRING **ext_data)
{
	struct x509_extension extension;
	ASN1_OBJECT *ext_oid;
	int status;

	status = builder->build (builder, &extension);
	if (status != 0) {
		return status;
	}

	status = x509_openssl_parse_encoded_oid (extension.oid, extension.oid_length, &ext_oid);
	if (status != 0) {
		goto free_ext;
	}

	*ext_data = ASN1_OCTET_STRING_new ();
	if (*ext_data == NULL) {
		status = X509_ENGINE_NO_MEMORY;
		goto free_oid;
	}

	status = ASN1_OCTET_STRING_set (*ext_data, extension.data, extension.data_length);
	if (status == 0) {
		status = -ERR_get_error ();
		goto free_str;
	}

	*ext = X509_EXTENSION_create_by_OBJ (NULL, ext_oid, extension.critical, *ext_data);
	if (*ext == NULL) {
		status = -ERR_get_error ();
		goto free_str;
	}

	status = 0;
	goto free_oid;

free_str:
	ASN1_OCTET_STRING_free (*ext_data);
free_oid:
	ASN1_OBJECT_free (ext_oid);
free_ext:
	builder->free (builder, &extension);
	return status;
}

/**
 * Add a standard extension to a CSR to be included in the signed certificate.
 *
 * @param request The context for the CSR being generated.
 * @param extensions The set of extensions to update for the CSR.
 * @param nid The type of extension to add.
 * @param value The value to assign to the extension.
 *
 * @return 0 if the extension was added or an error code.
 */
static int x509_openssl_add_standard_csr_extension (X509_REQ *request,
	STACK_OF (X509_EXTENSION) *extenions, int nid, const char *value)
{
	X509V3_CTX ext_ctx;
	X509_EXTENSION *ext;
	int status;

	X509V3_set_ctx (&ext_ctx, NULL, NULL, request, NULL, 0);
	X509V3_set_ctx_nodb (&ext_ctx);

	ext = X509V3_EXT_conf_nid (NULL, &ext_ctx, nid, (char*) value);
	if (ext == NULL) {
		status = -ERR_get_error ();
		goto err_conf;
	}

	status = sk_X509_EXTENSION_push (extenions, ext);
	if (status == 0) {
		status = X509_ENGINE_NO_MEMORY;
		goto err_push;
	}

	return 0;

err_push:
	X509_EXTENSION_free (ext);
err_conf:
	return status;
}

/**
 * Add any extension to a CSR to be included in the signed certificate.
 *
 * @param request The context for the CSR being generated.
 * @param extensions The set of extensions to update for the CSR.
 * @param ext The extension to add to the CSR.  This will be freed as part of the call.
 * @param data The extension data.  This will be freed as part of the call.
 *
 * @return 0 if the extension was added or an error code.  On failure, the extension will be freed.
 */
static int x509_openssl_add_custom_csr_extension (X509_REQ *request,
	STACK_OF (X509_EXTENSION) *extensions, X509_EXTENSION *ext, ASN1_OCTET_STRING *data)
{
	X509V3_CTX ext_ctx;
	int status;

	X509V3_set_ctx (&ext_ctx, NULL, NULL, request, NULL, 0);
	X509V3_set_ctx_nodb (&ext_ctx);

	status = sk_X509_EXTENSION_push (extensions, ext);
	if (status == 0) {
		status = X509_ENGINE_NO_MEMORY;
		goto err_push;
	}

	ASN1_OCTET_STRING_free (data);
	return 0;

err_push:
	X509_EXTENSION_free (ext);
	ASN1_OCTET_STRING_free (data);
	return status;
}

int x509_openssl_create_csr (const struct x509_engine *engine, const uint8_t *priv_key,
	size_t key_length, enum hash_type sig_hash, const char *name, int type, const uint8_t *eku,
	size_t eku_length, const struct x509_extension_builder *const *extra_extensions,
	size_t ext_count, uint8_t **csr, size_t *csr_length)
{
	X509_REQ *request;
	EVP_PKEY *req_key;
	X509_NAME *subject;
	STACK_OF (X509_EXTENSION) *extensions;
	const EVP_MD *hash_algo;
	char *key_usage;
	size_t i;
	int status;

	if (csr == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	*csr = NULL;
	if ((engine == NULL) || (priv_key == NULL) || (name == NULL) || (csr_length == NULL) ||
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
			hash_algo = EVP_sha256 ();
			break;

#ifdef HASH_ENABLE_SHA384
		case HASH_TYPE_SHA384:
			hash_algo = EVP_sha384 ();
			break;
#endif

#ifdef HASH_ENABLE_SHA512
		case HASH_TYPE_SHA512:
			hash_algo = EVP_sha512 ();
			break;
#endif

		default:
			return X509_ENGINE_UNSUPPORTED_SIG_HASH;
	}

	ERR_clear_error ();

	request = X509_REQ_new ();
	if (request == NULL) {
		status = -ERR_get_error ();
		goto err_req;
	}

	status = x509_openssl_load_key (&req_key, priv_key, key_length, true);
	if (status != 0) {
		goto err_key;
	}

	status = X509_REQ_set_pubkey (request, req_key);
	if (status == 0) {
		status = -ERR_get_error ();
		goto err_req_key;
	}

	subject = X509_REQ_get_subject_name (request);
	status = X509_NAME_add_entry_by_txt (subject, "CN", MBSTRING_ASC, (unsigned char*) name,
		-1, -1, 0);
	if (status == 0) {
		status = -ERR_get_error ();
		goto err_req_key;
	}

	extensions = sk_X509_EXTENSION_new_null ();
	if (extensions == NULL) {
		status = X509_ENGINE_NO_MEMORY;
		goto err_req_key;
	}

	if (type) {
		key_usage = "critical,keyCertSign";
	}
	else {
		key_usage = "critical,digitalSignature,keyAgreement";
	}

	status = x509_openssl_add_standard_csr_extension (request, extensions, NID_key_usage,
		key_usage);
	if (status != 0) {
		goto err_ext;
	}

	if (type == X509_CERT_END_ENTITY) {
		status = x509_openssl_add_standard_csr_extension (request, extensions, NID_ext_key_usage,
			"critical,clientAuth");
		if (status != 0) {
			goto err_ext;
		}
	}

	if (eku != NULL) {
		ASN1_OBJECT *oid;
		char oid_str[256];

		status = x509_openssl_parse_encoded_oid (eku, eku_length, &oid);
		if (status != 0) {
			goto err_ext;
		}

		status = OBJ_obj2txt (oid_str, sizeof (oid_str), oid, 1);
		ASN1_OBJECT_free (oid);
		if (status > (int) sizeof (oid_str)) {
			status = X509_ENGINE_LONG_OID;
			goto err_ext;
		}

		status = x509_openssl_add_standard_csr_extension (request, extensions, NID_ext_key_usage,
			oid_str);
		if (status != 0) {
			goto err_ext;
		}
	}

	if (type) {
		char constraint[35];

		if (X509_CERT_PATHLEN (type) <= X509_CERT_MAX_PATHLEN) {
			sprintf (constraint, "critical,CA:TRUE,pathlen:%d", X509_CERT_PATHLEN (type));
		}
		else {
			strcpy (constraint, "critical,CA:TRUE");
		}

		status = x509_openssl_add_standard_csr_extension (request, extensions,
			NID_basic_constraints, constraint);
		if (status != 0) {
			goto err_ext;
		}
	}

	for (i = 0; i < ext_count; i++) {
		X509_EXTENSION *ext;
		ASN1_OCTET_STRING *ext_data;

		if (extra_extensions[i] != NULL) {
			status = x509_openssl_create_custom_extension (extra_extensions[i], &ext, &ext_data);
			if (status != 0) {
				goto err_ext;
			}

			status = x509_openssl_add_custom_csr_extension (request, extensions, ext, ext_data);
			if (status != 0) {
				goto err_ext;
			}
		}
	}

	status = X509_REQ_add_extensions (request, extensions);
	if (status == 0) {
		status = -ERR_get_error ();
		goto err_ext;
	}

	status = X509_REQ_sign (request, req_key, hash_algo);
	if (status == 0) {
		status = -ERR_get_error ();
		goto err_ext;
	}

	status = i2d_X509_REQ (request, csr);
	if (status >= 0) {
		*csr_length = status;
		status = 0;
	}
	else {
		status = -ERR_get_error ();
	}

err_ext:
	sk_X509_EXTENSION_pop_free (extensions, X509_EXTENSION_free);
err_req_key:
	EVP_PKEY_free (req_key);
err_key:
	X509_REQ_free (request);
err_req:
	return status;
}

/**
 * Add a standard X.509v3 extension to a certificate.
 *
 * @param cert The certificate to add the extension to.
 * @param issuer The issuing certificate instance.
 * @param nid The type of extension to add.
 * @param value The value to assign to the extension.
 *
 * @return 0 if the extension was added or an error code.
 */
static int x509_openssl_add_standard_v3_extension (X509 *cert, X509 *issuer, int nid,
	const char *value)
{
	X509V3_CTX ext_ctx;
	X509_EXTENSION *ext;
	int status;

	X509V3_set_ctx (&ext_ctx, issuer, cert, NULL, NULL, 0);
	X509V3_set_ctx_nodb (&ext_ctx);

	ext = X509V3_EXT_conf_nid (NULL, &ext_ctx, nid, value);
	if (ext == NULL) {
		status = ERR_get_error ();
		goto err_conf;
	}

	status = X509_add_ext (cert, ext, -1);
	if (status == 0) {
		status = ERR_get_error ();
	}
	else {
		status = 0;
	}

	X509_EXTENSION_free (ext);
err_conf:
	return -status;
}

/**
 * Add a custom X.509v3 extension to a certificate.
 *
 * @param cert The certificate to add the extension to.
 * @param ext The extension to add to the certificate.  This will be freed as part of the call.
 * @param data The extension data.  This will be freed as part of the call.
 *
 * @return 0 if the extension was added or an error code.
 */
static int x509_openssl_add_custom_v3_extension (X509 *cert, X509_EXTENSION *ext,
	ASN1_OCTET_STRING *data)
{
	int status;

	status = X509_add_ext (cert, ext, -1);
	if (status == 0) {
		status = -ERR_get_error ();
	}
	else {
		status = 0;
	}

	X509_EXTENSION_free (ext);
	ASN1_OCTET_STRING_free (data);
	return status;
}

/**
 * Create a new certificate.  This can be self-signed, or signed by a CA.
 *
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
static int x509_openssl_create_certificate (struct x509_certificate *cert, EVP_PKEY *cert_key,
	enum hash_type sig_hash, const uint8_t *serial_num, size_t serial_length, const char *name,
	int type, EVP_PKEY *ca_key, const struct x509_certificate *ca_cert,
	const struct x509_extension_builder *const *extra_extensions, size_t ext_count)
{
	X509 *x509;
	X509 *ca_x509;
	BIGNUM *serial;
	X509_NAME *subject;
	ASN1_TIME *validity;
	const EVP_MD *hash_algo;
	char *key_usage;
	size_t i;
	int status;

	switch (sig_hash) {
		case HASH_TYPE_SHA256:
			hash_algo = EVP_sha256 ();
			break;

#ifdef HASH_ENABLE_SHA384
		case HASH_TYPE_SHA384:
			hash_algo = EVP_sha384 ();
			break;
#endif

#ifdef HASH_ENABLE_SHA512
		case HASH_TYPE_SHA512:
			hash_algo = EVP_sha512 ();
			break;
#endif

		default:
			return X509_ENGINE_UNSUPPORTED_SIG_HASH;
	}

	ERR_clear_error ();

	x509 = X509_new ();
	if (x509 == NULL) {
		status = -ERR_get_error ();
		goto err_cert;
	}

	if (ca_key) {
		ca_x509 = (X509*) ca_cert->context;
	}
	else {
		ca_x509 = x509;
	}

	status = X509_set_pubkey (x509, cert_key);
	if (status == 0) {
		status = -ERR_get_error ();
		goto err_req_key;
	}

	status = X509_set_version (x509, 2);
	if (status == 0) {
		status = -ERR_get_error ();
		goto err_req_key;
	}

	serial = BN_bin2bn (serial_num, serial_length, NULL);
	if (serial == NULL) {
		status = -ERR_get_error ();
		goto err_serial;
	}

	if (BN_is_zero (serial)) {
		status = X509_ENGINE_INVALID_SERIAL_NUM;
		goto err_serial;
	}

	if (BN_to_ASN1_INTEGER (serial, X509_get_serialNumber (x509)) == NULL) {
		status = -ERR_get_error ();
		goto err_serial;
	}

	subject = X509_get_subject_name (x509);
	status = X509_NAME_add_entry_by_txt (subject, "CN", MBSTRING_ASC, (unsigned char*) name,
		-1, -1, 0);
	if (status == 0) {
		status = -ERR_get_error ();
		goto err_serial;
	}

	subject = X509_get_subject_name (ca_x509);
	status = X509_set_issuer_name (x509, subject);
	if (status == 0) {
		status = -ERR_get_error ();
		goto err_serial;
	}

	validity = X509_get_notBefore (x509);
	status = ASN1_TIME_set_string (validity, "180101000000Z");
	if (status == 0) {
		status = -ERR_get_error ();
		goto err_serial;
	}

	validity = X509_get_notAfter (x509);
	status = ASN1_TIME_set_string (validity, "99991231235959Z");
	if (status == 0) {
		status = -ERR_get_error ();
		goto err_serial;
	}

	status = x509_openssl_add_standard_v3_extension (x509, ca_x509, NID_subject_key_identifier,
		"hash");
	if (status != 0) {
		goto err_serial;
	}

	status = x509_openssl_add_standard_v3_extension (x509, ca_x509,
		NID_authority_key_identifier, "keyid");
	if (status != 0) {
		goto err_serial;
	}

	if (type) {
		key_usage = "critical,keyCertSign";
	}
	else {
		key_usage = "critical,digitalSignature,keyAgreement";
	}

	status = x509_openssl_add_standard_v3_extension (x509, ca_x509, NID_key_usage, key_usage);
	if (status != 0) {
		goto err_serial;
	}

	if (type == X509_CERT_END_ENTITY) {
		status = x509_openssl_add_standard_v3_extension (x509, ca_x509, NID_ext_key_usage,
			"critical,clientAuth");
		if (status != 0) {
			goto err_serial;
		}
	}

	if (type) {
		char constraint[35];

		if (X509_CERT_PATHLEN (type) <= X509_CERT_MAX_PATHLEN) {
			sprintf (constraint, "critical,CA:TRUE,pathlen:%d", X509_CERT_PATHLEN (type));
		}
		else {
			strcpy (constraint, "critical,CA:TRUE");
		}

		status = x509_openssl_add_standard_v3_extension (x509, ca_x509, NID_basic_constraints,
			constraint);
		if (status != 0) {
			goto err_serial;
		}
	}

	for (i = 0; i < ext_count; i++) {
		X509_EXTENSION *ext;
		ASN1_OCTET_STRING *ext_data;

		if (extra_extensions[i] != NULL) {
			status = x509_openssl_create_custom_extension (extra_extensions[i], &ext, &ext_data);
			if (status != 0) {
				goto err_serial;
			}

			status = x509_openssl_add_custom_v3_extension (x509, ext, ext_data);
			if (status != 0) {
				goto err_serial;
			}
		}
	}

	if (ca_key) {
		status = X509_sign (x509, ca_key, hash_algo);
	}
	else {
		status = X509_sign (x509, cert_key, hash_algo);
	}

	if (status == 0) {
		status = -ERR_get_error ();
		goto err_serial;
	}

	cert->context = x509;
	status = 0;

err_serial:
	BN_free (serial);
err_req_key:
	if (status != 0) {
		X509_free (x509);
	}
err_cert:
	return status;
}

int x509_openssl_create_self_signed_certificate (const struct x509_engine *engine,
	struct x509_certificate *cert, const uint8_t *priv_key, size_t key_length,
	enum hash_type sig_hash, const uint8_t *serial_num, size_t serial_length, const char *name,
	int type, const struct x509_extension_builder *const *extra_extensions, size_t ext_count)
{
	EVP_PKEY *cert_key;
	int status;

	if ((engine == NULL) || (cert == NULL) || (priv_key == NULL) || (serial_num == NULL) ||
		(name == NULL) || (key_length == 0) || (serial_length == 0)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	if ((ext_count != 0) && (extra_extensions == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	status = x509_openssl_load_key (&cert_key, priv_key, key_length, true);
	if (status != 0) {
		return status;
	}

	status = x509_openssl_create_certificate (cert, cert_key, sig_hash, serial_num, serial_length,
		name, type, NULL, NULL, extra_extensions, ext_count);

	EVP_PKEY_free (cert_key);
	return status;
}

int x509_openssl_create_ca_signed_certificate (const struct x509_engine *engine,
	struct x509_certificate *cert, const uint8_t *key, size_t key_length, const uint8_t *serial_num,
	size_t serial_length, const char *name, int type, const uint8_t* ca_priv_key,
	size_t ca_key_length, enum hash_type sig_hash, const struct x509_certificate *ca_cert,
	const struct x509_extension_builder *const *extra_extensions, size_t ext_count)
{
	EVP_PKEY *cert_key;
	EVP_PKEY *ca_key;
	int status;

	if ((engine == NULL) || (cert == NULL) || (key == NULL) || (serial_num == NULL) ||
		(name == NULL) || (ca_priv_key == NULL) || (ca_cert == NULL) || (key_length == 0) ||
		(serial_length == 0) || (ca_key_length == 0)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	if ((ext_count != 0) && (extra_extensions == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	status = x509_openssl_load_key (&cert_key, key, key_length, false);
	if (status != 0) {
		goto err_key;
	}

	status = x509_openssl_load_key (&ca_key, ca_priv_key, ca_key_length, true);
	if (status != 0) {
		goto err_ca_key;
	}

	status = x509_openssl_create_certificate (cert, cert_key, sig_hash, serial_num, serial_length,
		name, type, ca_key, ca_cert, extra_extensions, ext_count);

	EVP_PKEY_free (ca_key);
err_ca_key:
	EVP_PKEY_free (cert_key);
err_key:
	return status;
}
#endif

int x509_openssl_load_certificate (const struct x509_engine *engine, struct x509_certificate *cert,
	const uint8_t *der, size_t length)
{
	X509 *x509;
	BIO *bio;
	int status;

	if ((engine == NULL) || (cert == NULL) || (der == NULL) || (length == 0)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	ERR_clear_error ();

	bio = BIO_new_mem_buf (der, length);
	if (bio == NULL) {
		status = ERR_get_error ();
		goto err_bio;
	}

	x509 = d2i_X509_bio (bio, NULL);
	if (x509 == NULL) {
		status = ERR_get_error ();
		goto err_cert;
	}

	cert->context = x509;
	status = 0;

err_cert:
	BIO_free (bio);
err_bio:
	return -status;
}

void x509_openssl_release_certificate (const struct x509_engine *engine,
	struct x509_certificate *cert)
{
	UNUSED (engine);

	if (cert) {
		X509_free ((X509*) cert->context);
		memset (cert, 0, sizeof (struct x509_certificate));
	}
}

#ifdef X509_ENABLE_CREATE_CERTIFICATES
int x509_openssl_get_certificate_der (const struct x509_engine *engine,
	const struct x509_certificate *cert, uint8_t **der, size_t *length)
{
	int status;

	if (der == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	*der = NULL;
	if ((engine == NULL) || (cert == NULL) || (length == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	ERR_clear_error ();

	status = i2d_X509 ((X509*) cert->context, der);
	if (status >= 0) {
		*length = status;
		status = 0;
	}
	else {
		status = -ERR_get_error ();
	}

	return status;
}
#endif

#ifdef X509_ENABLE_AUTHENTICATION
int x509_openssl_get_certificate_version (const struct x509_engine *engine,
	const struct x509_certificate *cert)
{
	if ((engine == NULL) || (cert == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	return X509_get_version ((X509*) cert->context) + 1;
}

int x509_openssl_get_serial_number (const struct x509_engine *engine,
	const struct x509_certificate *cert, uint8_t *serial_num, size_t length)
{
	ASN1_INTEGER *encoded;
	BIGNUM *serial;
	int bytes;

	if ((engine == NULL) || (cert == NULL) || (serial_num == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	ERR_clear_error ();

	encoded = X509_get_serialNumber ((X509*) cert->context);

	serial = ASN1_INTEGER_to_BN (encoded, NULL);
	if (serial == NULL) {
		return -ERR_get_error ();
	}

	if ((int) length < BN_num_bytes (serial)) {
		bytes = X509_ENGINE_SMALL_SERIAL_BUFFER;
		goto err_length;
	}

	bytes = BN_bn2bin (serial, serial_num);

err_length:
	BN_free (serial);
	return bytes;
}

int x509_openssl_get_public_key_type (const struct x509_engine *engine,
	const struct x509_certificate *cert)
{
	EVP_PKEY *key;
	int type;

	if ((engine == NULL) || (cert == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	ERR_clear_error ();

	key = X509_get_pubkey ((X509*) cert->context);
	if (key == NULL) {
		type = -ERR_get_error ();
		return type;
	}

	type = EVP_PKEY_base_id (key);
	switch (type) {
		case EVP_PKEY_RSA:
			type = X509_PUBLIC_KEY_RSA;
			break;

		case EVP_PKEY_EC:
			type = X509_PUBLIC_KEY_ECC;
			break;

		case EVP_PKEY_NONE:
			type = X509_ENGINE_UNKNOWN_KEY_TYPE;
			break;

		default:
			type = X509_ENGINE_UNSUPPORTED_KEY_TYPE;
	}

	EVP_PKEY_free (key);
	return type;
}

int x509_openssl_get_public_key_length (const struct x509_engine *engine,
	const struct x509_certificate *cert)
{
	EVP_PKEY *key;
	int bits;

	if ((engine == NULL) || (cert == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	ERR_clear_error ();

	key = X509_get_pubkey ((X509*) cert->context);
	if (key == NULL) {
		return -ERR_get_error ();
	}

	bits = EVP_PKEY_bits (key);

	EVP_PKEY_free (key);
	return bits;
}

int x509_openssl_get_public_key (const struct x509_engine *engine,
	const struct x509_certificate *cert, uint8_t **key, size_t *key_length)
{
	EVP_PKEY *cert_key;
	int status;

	if (key == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	*key = NULL;
	if ((engine == NULL) || (cert == NULL) || (key_length == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	ERR_clear_error ();

	cert_key = X509_get_pubkey ((X509*) cert->context);
	if (cert_key == NULL) {
		status = ERR_get_error ();
		goto err_key;
	}

	status = i2d_PUBKEY (cert_key, key);
	if (status >= 0) {
		*key_length = status;
		status = 0;
	}
	else {
		status = ERR_get_error ();
	}

	EVP_PKEY_free (cert_key);
err_key:
	return -status;
}

int x509_openssl_init_ca_cert_store (const struct x509_engine *engine, struct x509_ca_certs *store)
{
	struct x509_openssl_ca_store_context *store_ctx;
	int status;

	if ((engine == NULL) || (store == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	store_ctx = platform_malloc (sizeof (struct x509_openssl_ca_store_context));
	if (store_ctx == NULL) {
		return X509_ENGINE_NO_MEMORY;
	}

	memset (store_ctx, 0, sizeof (*store_ctx));

	ERR_clear_error ();

	store_ctx->trusted = X509_STORE_new ();
	if (store_ctx->trusted == NULL) {
		status = -ERR_get_error ();
		goto ctx_free;
	}

	store_ctx->intermediate = sk_X509_new_null ();
	if (store_ctx->intermediate == NULL) {
		status = -ERR_get_error ();
		goto store_free;
	}

	store->context = store_ctx;
	return 0;

store_free:
	X509_STORE_free (store_ctx->trusted);
ctx_free:
	platform_free (store_ctx);

	return status;
}

void x509_openssl_release_ca_cert_store (const struct x509_engine *engine,
	struct x509_ca_certs *store)
{
	UNUSED (engine);

	if (store && store->context) {
		struct x509_openssl_ca_store_context *store_ctx = store->context;

		X509_STORE_free (store_ctx->trusted);
		sk_X509_pop_free (store_ctx->intermediate, X509_free);
		platform_free (store_ctx);
		memset (store, 0, sizeof (struct x509_ca_certs));
	}
}

int x509_openssl_add_root_ca (const struct x509_engine *engine, struct x509_ca_certs *store,
	const uint8_t *der, size_t length)
{
	struct x509_certificate cert;
	EVP_PKEY *cert_key;
	int status;

	if (store == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	status = x509_openssl_load_certificate (engine, &cert, der, length);
	if (status != 0) {
		goto err_cert;
	}

	ERR_clear_error ();

	status = X509_check_ca ((X509*) cert.context);
	if (status == 0) {
		status = X509_ENGINE_NOT_CA_CERT;
		goto err_chk;
	}

	status = X509_check_issued ((X509*) cert.context, (X509*) cert.context);
	if (status != X509_V_OK) {
		status = X509_ENGINE_NOT_SELF_SIGNED;
		goto err_chk;
	}

	cert_key = X509_get_pubkey ((X509*) cert.context);
	if (cert_key == NULL) {
		status = -ERR_get_error ();
		goto err_chk;
	}

	status = X509_verify ((X509*) cert.context, cert_key);
	if (status == 1) {
		status = 0;
	}
	else {
		status = X509_ENGINE_BAD_SIGNATURE;
		goto err_sig;
	}

	status = X509_STORE_add_cert (((struct x509_openssl_ca_store_context*) store->context)->trusted,
		(X509*) cert.context);
	if (status == 0) {
		status = -ERR_get_error ();
		goto err_sig;
	}

	status = 0;

err_sig:
	EVP_PKEY_free (cert_key);
err_chk:
	x509_openssl_release_certificate (engine, &cert);
err_cert:
	return status;
}

int x509_openssl_add_trusted_ca (const struct x509_engine *engine, struct x509_ca_certs *store,
	const uint8_t *der, size_t length)
{
	struct x509_openssl_ca_store_context *store_ctx;
	struct x509_certificate cert;
	int status;

	if (store == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	status = x509_openssl_load_certificate (engine, &cert, der, length);
	if (status != 0) {
		goto err_cert;
	}

	ERR_clear_error ();

	status = X509_check_ca ((X509*) cert.context);
	if (status == 0) {
		status = X509_ENGINE_NOT_CA_CERT;
		goto err_chk;
	}

	status = X509_check_issued ((X509*) cert.context, (X509*) cert.context);
	if (status == X509_V_OK) {
		status = X509_ENGINE_IS_SELF_SIGNED;
		goto err_chk;
	}

	store_ctx = (struct x509_openssl_ca_store_context*) store->context;

	status = X509_STORE_add_cert (store_ctx->trusted, (X509*) cert.context);
	if (status == 0) {
		status = -ERR_get_error ();
		goto err_chk;
	}

	/* There is an ICA in the trusted store, so allow partial chain verification. */
	store_ctx->flags = X509_V_FLAG_PARTIAL_CHAIN;

	status = 0;

err_chk:
	x509_openssl_release_certificate (engine, &cert);
err_cert:
	return status;
}

int x509_openssl_add_intermediate_ca (const struct x509_engine *engine,
	struct x509_ca_certs *store, const uint8_t *der, size_t length)
{
	struct x509_certificate cert;
	int status;

	if (store == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	status = x509_openssl_load_certificate (engine, &cert, der, length);
	if (status != 0) {
		goto err_cert;
	}

	status = X509_check_ca ((X509*) cert.context);
	if (status == 0) {
		status = X509_ENGINE_NOT_CA_CERT;
		goto err_chk;
	}

	status = X509_check_issued ((X509*) cert.context, (X509*) cert.context);
	if (status == X509_V_OK) {
		status = X509_ENGINE_IS_SELF_SIGNED;
		goto err_chk;
	}

	status = sk_X509_push (((struct x509_openssl_ca_store_context*) store->context)->intermediate,
		(X509*) cert.context);
	if (status == 0) {
		status = X509_ENGINE_NO_MEMORY;
		goto err_chk;
	}

	return 0;

err_chk:
	x509_openssl_release_certificate (engine, &cert);
err_cert:
	return status;
}

int x509_openssl_authenticate (const struct x509_engine *engine,
	const struct x509_certificate *cert, const struct x509_ca_certs *store)
{
	struct x509_openssl_ca_store_context *store_ctx = NULL;
	X509_STORE_CTX *auth_ctx;
	X509_VERIFY_PARAM *verify_param;
	int status;

	if ((engine == NULL) || (cert == NULL) || (store == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	ERR_clear_error ();

	auth_ctx = X509_STORE_CTX_new ();
	if (auth_ctx == NULL) {
		status = -ERR_get_error ();
		goto err_ctx;
	}

	if (store) {
		store_ctx = store->context;
	}

	status = X509_STORE_CTX_init (auth_ctx, store_ctx->trusted, (X509*) cert->context,
		store_ctx->intermediate);
	if (status == 0) {
		status = -ERR_get_error ();
		goto err_init;
	}

	/* Apply any verification flags that are configured for this cert store. */
	verify_param = X509_STORE_CTX_get0_param (auth_ctx);
	status = X509_VERIFY_PARAM_set_flags (verify_param, store_ctx->flags);
	if (status == 0) {
		status = -ERR_get_error ();
		goto err_init;
	}

	X509_verify_cert (auth_ctx);
	status = X509_STORE_CTX_get_error (auth_ctx);
	if (status != 0) {
		status = X509_ENGINE_CERT_NOT_VALID;
	}

err_init:
	X509_STORE_CTX_free (auth_ctx);
err_ctx:
	return status;
}
#endif

/**
 * Initialize an instance for handling X.509 certificates using OpenSSL.
 *
 * @param engine The X.509 engine to initialize.
 *
 * @return 0 if the X.509 engine was successfully initialized or an error code.
 */
int x509_openssl_init (struct x509_engine_openssl *engine)
{
	if (engine == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine, 0, sizeof (struct x509_engine_openssl));

#ifdef X509_ENABLE_CREATE_CERTIFICATES
	engine->base.create_csr = x509_openssl_create_csr;
	engine->base.create_self_signed_certificate = x509_openssl_create_self_signed_certificate;
	engine->base.create_ca_signed_certificate = x509_openssl_create_ca_signed_certificate;
#endif
	engine->base.load_certificate = x509_openssl_load_certificate;
	engine->base.release_certificate = x509_openssl_release_certificate;
#ifdef X509_ENABLE_CREATE_CERTIFICATES
	engine->base.get_certificate_der = x509_openssl_get_certificate_der;
#endif
#ifdef X509_ENABLE_AUTHENTICATION
	engine->base.get_certificate_version = x509_openssl_get_certificate_version;
	engine->base.get_serial_number = x509_openssl_get_serial_number;
	engine->base.get_public_key_type = x509_openssl_get_public_key_type;
	engine->base.get_public_key_length = x509_openssl_get_public_key_length;
	engine->base.get_public_key = x509_openssl_get_public_key;
	engine->base.init_ca_cert_store = x509_openssl_init_ca_cert_store;
	engine->base.release_ca_cert_store = x509_openssl_release_ca_cert_store;
	engine->base.add_root_ca = x509_openssl_add_root_ca;
	engine->base.add_trusted_ca = x509_openssl_add_trusted_ca;
	engine->base.add_intermediate_ca = x509_openssl_add_intermediate_ca;
	engine->base.authenticate = x509_openssl_authenticate;
#endif

	return 0;
}

/**
 * Release an OpenSSL X.509 engine.
 *
 * @param engine The X.509 engine to release.
 */
void x509_openssl_release (const struct x509_engine_openssl *engine)
{
	UNUSED (engine);
}
