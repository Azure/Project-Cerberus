// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "platform_api.h"
#include "x509_cert_build.h"
#include "asn1/ecc_der_util.h"
#include "common/unused.h"
#include "crypto/ecc.h"
#include "riot/reference/include/RiotDerDec.h"
#include "riot/reference/include/RiotDerEnc.h"
#include "riot/reference/include/RiotX509Bldr.h"


/**
 * Certificate validity period (UTCTime).
 */
#define VALID_FROM	"180101000000Z"
#define VALID_TO	"99991231235959Z"

/**
 * Update the DER encoding and fail if the result is non-zero.
 *
 * TODO:  Put this is a common location.
 */
#define	DER_CHK_ENCODE(func)	if ((status = (func)) != 0) {goto error;}


/**
 * Create a new DER certificate instance.
 *
 * @param x509 The certificate builder to use for cert allocation.
 *
 * @return The allocated certificate or null.
 */
static DERBuilderContext* x509_cert_build_new_cert (const struct x509_engine_cert_build *x509)
{
	DERBuilderContext *der;
	uint8_t *der_buf;

	der = platform_malloc (sizeof (DERBuilderContext));
	if (der == NULL) {
		return NULL;
	}

	der_buf = platform_malloc (x509->max_cert_length);
	if (der_buf == NULL) {
		platform_free (der);

		return NULL;
	}

	DERInitContext (der, der_buf, x509->max_cert_length);

	return der;
}

/**
 * Free a DER certificate instance.
 *
 * @param cert The certificate to free.
 */
static void x509_cert_build_free_cert (void *cert)
{
	DERBuilderContext *x509 = (DERBuilderContext*) cert;

	if (x509) {
		if (x509->Buffer) {
			platform_free (x509->Buffer);
		}
		platform_free (x509);
	}
}

#ifdef X509_ENABLE_CREATE_CERTIFICATES
/**
 * Add a Subject Key Identifier extension to the certificate.
 *
 * @param der DER encoder to update.
 * @param key_identifier The key identifier for the subject public key.  This is typically a SHA1
 * hash of the public key data.
 * @param id_length Length the key key identifier.
 *
 * @return 0 if the extension was added successfully or an error code.
 */
static int x509_cert_build_add_subject_key_identifier_extension (DERBuilderContext *der,
	const uint8_t *key_identifier, size_t id_length)
{
	int status;

	DER_CHK_ENCODE (DERStartSequenceOrSet (der, true));
	DER_CHK_ENCODE (DERAddOID (der, extSubjectKeyIdentifierOID));
	DER_CHK_ENCODE (DERStartEnvelopingOctetString (der));
	DER_CHK_ENCODE (DERAddOctetString (der, key_identifier, id_length));
	DER_CHK_ENCODE (DERPopNesting (der));
	DER_CHK_ENCODE (DERPopNesting (der));

	return 0;

error:

	return status;
}

/**
 * Add an Authority Key Identifier extension to the certificate.
 *
 * @param der DER encoder to update.
 * @param key_identifier The key identifier for the issuer public key.  This is typically a SHA1
 * hash of the public key data.
 * @param id_length Length the key key identifier.
 *
 * @return 0 if the extension was added successfully or an error code.
 */
static int x509_cert_build_add_authority_key_identifier_extension (DERBuilderContext *der,
	const uint8_t *key_identifier, size_t id_length)
{
	int status;

	DER_CHK_ENCODE (DERStartSequenceOrSet (der, true));
	DER_CHK_ENCODE (DERAddOID (der, extAuthKeyIdentifierOID));
	DER_CHK_ENCODE (DERStartEnvelopingOctetString (der));
	DER_CHK_ENCODE (DERStartSequenceOrSet (der, true));
	DER_CHK_ENCODE (DERAddAuthKeyBitString (der, key_identifier, id_length));
	DER_CHK_ENCODE (DERPopNesting (der));
	DER_CHK_ENCODE (DERPopNesting (der));
	DER_CHK_ENCODE (DERPopNesting (der));

	return 0;

error:

	return status;
}

/**
 * Add a Key Usage extension to the certificate.
 *
 * @param der DER encoder to update.
 * @param type The type of certificate being created.
 *
 * @return 0 if the extension was added successfully or an error code.
 */
static int x509_cert_build_add_key_usage_extension (DERBuilderContext *der, int type)
{
	uint8_t key_usage;
	uint8_t bits;
	int status;

	if (type != X509_CERT_END_ENTITY) {
		key_usage = RIOT_X509_KEY_USAGE_CERT_SIGN;
		bits = 6;
	}
	else {
		key_usage = RIOT_X509_KEY_USAGE_END_ENTITY;
		bits = 5;
	}

	DER_CHK_ENCODE (DERStartSequenceOrSet (der, true));
	DER_CHK_ENCODE (DERAddOID (der, keyUsageOID));	/* TODO:  Statically encode all OIDs. */
	DER_CHK_ENCODE (DERAddBoolean (der, true));
	DER_CHK_ENCODE (DERStartEnvelopingOctetString (der));
	DER_CHK_ENCODE (DERAddNamedBitString (der, &key_usage, 1, bits));
	DER_CHK_ENCODE (DERPopNesting (der));
	DER_CHK_ENCODE (DERPopNesting (der));

	return 0;

error:

	return status;
}

/**
 * Add an Extended Key Usage extension to the certificate.
 *
 * @param der DER encoder to update.
 * @param oid The key usage OID to add in the extension.
 * @param oid_length Length of the key usage OID.
 * @param critical True to indicate the EKU extension should be marked as critical.
 *
 * @return 0 if the extension was added successfully or an error code.
 */
static int x509_cert_build_add_extended_key_usage_extension (DERBuilderContext *der,
	const uint8_t *oid, size_t oid_length, bool critical)
{
	int status;

	DER_CHK_ENCODE (DERStartSequenceOrSet (der, true));
	DER_CHK_ENCODE (DERAddOID (der, extKeyUsageOID));
	if (critical) {
		DER_CHK_ENCODE (DERAddBoolean (der, true));
	}
	DER_CHK_ENCODE (DERStartEnvelopingOctetString (der));
	DER_CHK_ENCODE (DERStartSequenceOrSet (der, true));
	if (oid == NULL) {
		DER_CHK_ENCODE (DERAddOID (der, clientAuthOID));
	}
	else {
		DER_CHK_ENCODE (DERAddEncodedOID (der, oid, oid_length));
	}
	DER_CHK_ENCODE (DERPopNesting (der));
	DER_CHK_ENCODE (DERPopNesting (der));
	DER_CHK_ENCODE (DERPopNesting (der));

	return 0;

error:

	return status;
}

/**
 * Add a Basic Constraints extension to the certificate.
 *
 * @param der DER encoder to update.
 * @param type The type of certificate being created.
 *
 * @return 0 if the extension was added successfully or an error code.
 */
static int x509_cert_build_add_basic_constraints_extension (DERBuilderContext *der, int type)
{
	int status;

	/* End entity certificates don't need basic constraints. */
	if (type != X509_CERT_END_ENTITY) {
		DER_CHK_ENCODE (DERStartSequenceOrSet (der, true));
		DER_CHK_ENCODE (DERAddOID (der, basicConstraintsOID));
		DER_CHK_ENCODE (DERAddBoolean (der, true));
		DER_CHK_ENCODE (DERStartEnvelopingOctetString (der));
		DER_CHK_ENCODE (DERStartSequenceOrSet (der, true));
		DER_CHK_ENCODE (DERAddBoolean (der, true));
		if (type < X509_CERT_CA_NO_PATHLEN) {
			DER_CHK_ENCODE (DERAddInteger (der, X509_CERT_PATHLEN (type)));
		}
		DER_CHK_ENCODE (DERPopNesting (der));
		DER_CHK_ENCODE (DERPopNesting (der));
		DER_CHK_ENCODE (DERPopNesting (der));
	}

	return 0;

error:

	return status;
}

/**
 * Add a custom extension to the certificate.
 *
 * @param der DER encoder to update.
 * @param builder The extension to add.
 *
 * @return 0 if the extension was added successfully or an error code.
 */
static int x509_cert_build_add_custom_extension (DERBuilderContext *der,
	const struct x509_extension_builder *builder)
{
	struct x509_extension extension = {0};
	int status;

	if (builder == NULL) {
		/* Silently skip null extensions. */
		return 0;
	}

	status = builder->build (builder, &extension);
	if (status != 0) {
		return status;
	}

	DER_CHK_ENCODE (DERStartSequenceOrSet (der, true));
	DER_CHK_ENCODE (DERAddEncodedOID (der, extension.oid, extension.oid_length));
	if (extension.critical) {
		DER_CHK_ENCODE (DERAddBoolean (der, true));
	}
	DER_CHK_ENCODE (DERAddOctetString (der, extension.data, extension.data_length));
	DER_CHK_ENCODE (DERPopNesting (der));

	builder->free (builder, &extension);

	return 0;

error:
	builder->free (builder, &extension);

	return status;
}

/**
 * Add an X.509 Name to the certificate.
 *
 * @param der DER encoder to update.
 * @param common_name The common name to encode in the certificate.
 *
 * @return 0 if the name was added successfully or an error code.
 */
static int x509_cert_build_add_x509_name (DERBuilderContext *der, const char *common_name)
{
	int status;

	DER_CHK_ENCODE (DERStartSequenceOrSet (der, true));
	DER_CHK_ENCODE (DERStartSequenceOrSet (der, false));
	DER_CHK_ENCODE (DERStartSequenceOrSet (der, true));
	DER_CHK_ENCODE (DERAddOID (der, commonNameOID));
	DER_CHK_ENCODE (DERAddUTF8String (der, common_name));
	DER_CHK_ENCODE (DERPopNesting (der));
	DER_CHK_ENCODE (DERPopNesting (der));
	DER_CHK_ENCODE (DERPopNesting (der));

	return 0;

error:

	return status;
}

/**
 * Build the TBS (To Be Signed) data for a CSR.
 *
 * @param der DER encoder to update.
 * @param subject_name Common name for the subject of the CSR.
 * @param pub_key_der DER encoded public key for the CSR.
 * @param pub_key_length Length of the CSR public key.
 * @param type The type of CSR being generated.
 * @param eku Optional OID to assign to an Extended Key Usage extension.  Only valid for CA CSRs.
 * @param eku_length Length of the EKU OID.
 * @param extra_extensions List of custom extensions that should be added to the CSR.
 * @param ext_count The number of custom extensions in the list.
 *
 * @return 0 if the CSR TBS was generated successfully or an error code.
 */
static int x509_cert_build_build_csr_tbs_data (DERBuilderContext *der, const char *subject_name,
	const uint8_t *pub_key_der, size_t pub_key_length, int type, const uint8_t *eku,
	size_t eku_length, const struct x509_extension_builder *const *extra_extensions,
	size_t ext_count)
{
	size_t i;
	int status;

	DER_CHK_ENCODE (DERStartSequenceOrSet (der, true));
	DER_CHK_ENCODE (DERAddInteger (der, 0));
	DER_CHK_ENCODE (x509_cert_build_add_x509_name (der, subject_name));
	DER_CHK_ENCODE (DERAddPublicKey (der, pub_key_der, pub_key_length));
	DER_CHK_ENCODE (DERStartExplicit (der, 0));
	DER_CHK_ENCODE (DERStartSequenceOrSet (der, true));
	DER_CHK_ENCODE (DERAddOID (der, extensionRequestOID));
	DER_CHK_ENCODE (DERStartSequenceOrSet (der, false));
	DER_CHK_ENCODE (DERStartSequenceOrSet (der, true));
	DER_CHK_ENCODE (x509_cert_build_add_key_usage_extension (der, type));
	if ((type == X509_CERT_END_ENTITY) || (eku != NULL)) {
		DER_CHK_ENCODE (x509_cert_build_add_extended_key_usage_extension (der, eku,	eku_length,
			(type == X509_CERT_END_ENTITY)));
	}
	DER_CHK_ENCODE (x509_cert_build_add_basic_constraints_extension (der, type));
	for (i = 0; i < ext_count; i++) {
		DER_CHK_ENCODE (x509_cert_build_add_custom_extension (der, extra_extensions[i]));
	}
	DER_CHK_ENCODE (DERPopNesting (der));
	DER_CHK_ENCODE (DERPopNesting (der));
	DER_CHK_ENCODE (DERPopNesting (der));
	DER_CHK_ENCODE (DERPopNesting (der));
	DER_CHK_ENCODE (DERPopNesting (der));

	return 0;

error:

	return status;
}

/**
 * Sign the "To Be Signed" region of the certificate using ECDSA and update the certificate with the
 * signature.
 *
 * @param der The DER encoder that contains the TBS certificate region to sign.
 * @param priv_key The signing key.
 * @param ecc The ECC engine to use for signature generation.
 * @param hash The hash engine to use for signature generation.
 * @param sig_hash The type of hash to use when generating the signature.
 * @param sig_oid OID indicating the type of signature being generated.
 *
 * @return 0 if the certificate was signed successfully or an error code.
 */
static int x509_cert_build_sign_certificate (DERBuilderContext *der,
	const struct ecc_private_key *priv_key, const struct ecc_engine *ecc,
	const struct hash_engine *hash, enum hash_type sig_hash, const int *sig_oid)
{
	uint8_t digest[HASH_MAX_HASH_LEN];
	uint8_t tbs_sig[ECC_DER_ECDSA_MAX_LENGTH];
	int sig_len;
	int status;

	/* Sanity check that the ECC engine is not going to generate too much data. */
	sig_len = ecc->get_signature_max_length (ecc, priv_key);
	if (ROT_IS_ERROR (sig_len)) {
		return sig_len;
	}

	if ((size_t) sig_len > sizeof (tbs_sig)) {
		return X509_ENGINE_CERT_SIGN_FAILED;
	}

	status = hash_calculate (hash, sig_hash, der->Buffer, DERGetEncodedLength (der), digest,
		sizeof (digest));
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	sig_len = ecc->sign (ecc, priv_key, digest, status, NULL, tbs_sig, sizeof (tbs_sig));
	if (ROT_IS_ERROR (sig_len)) {
		return sig_len;
	}

	/* Update the DER encoding with the signature data. */
	DER_CHK_ENCODE (DERTbsToCert (der));
	DER_CHK_ENCODE (DERStartSequenceOrSet (der, true));
	DER_CHK_ENCODE (DERAddOID (der, sig_oid));
	DER_CHK_ENCODE (DERPopNesting (der));
	DER_CHK_ENCODE (DERAddBitString (der, tbs_sig, sig_len));
	DER_CHK_ENCODE (DERPopNesting (der));

	return 0;

error:

	return status;
}

int x509_cert_build_create_csr (const struct x509_engine *engine, const uint8_t *priv_key,
	size_t key_length, enum hash_type sig_hash, const char *name, int type, const uint8_t *eku,
	size_t eku_length, const struct x509_extension_builder *const *extra_extensions,
	size_t ext_count, uint8_t **csr, size_t *csr_length)
{
	const struct x509_engine_cert_build *x509 = (const struct x509_engine_cert_build*) engine;
	DERBuilderContext *der;
	struct ecc_private_key ecc_priv_key;
	struct ecc_public_key ecc_pub_key;
	uint8_t *pub_key_der = NULL;
	size_t pub_key_der_len;
	const int *sig_oid;
	int status;

	if (csr == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	*csr = NULL;

	if ((x509 == NULL) || (priv_key == NULL) || (name == NULL) || (csr_length == NULL) ||
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
			sig_oid = ecdsaWithSHA256OID;
			break;

		case HASH_TYPE_SHA384:
			sig_oid = ecdsaWithSHA384OID;
			break;

		case HASH_TYPE_SHA512:
			sig_oid = ecdsaWithSHA512OID;
			break;

		default:
			return X509_ENGINE_UNSUPPORTED_SIG_HASH;
	}

	status = x509->ecc->init_key_pair (x509->ecc, priv_key, key_length, &ecc_priv_key,
		&ecc_pub_key);
	if (status != 0) {
		return status;
	}

	status = x509->ecc->get_public_key_der (x509->ecc, &ecc_pub_key, &pub_key_der,
		&pub_key_der_len);
	if (status != 0) {
		goto err_free_key;
	}

	der = x509_cert_build_new_cert (x509);
	if (der == NULL) {
		status = X509_ENGINE_NO_MEMORY;
		goto err_free_key_der;
	}

	status = x509_cert_build_build_csr_tbs_data (der, name, pub_key_der, pub_key_der_len, type,	eku,
		eku_length, extra_extensions, ext_count);
	if (status != 0) {
		status = (status == -1) ? X509_ENGINE_CSR_FAILED : status;
		goto err_free_cert;
	}

	status = x509_cert_build_sign_certificate (der, &ecc_priv_key, x509->ecc, x509->hash, sig_hash,
		sig_oid);
	if (status != 0) {
		status = (status == -1) ? X509_ENGINE_CSR_FAILED : status;
		goto err_free_cert;
	}

	*csr_length = DERGetEncodedLength (der);
	*csr = der->Buffer;

	der->Buffer = NULL;
	status = 0;

err_free_cert:
	x509_cert_build_free_cert (der);
err_free_key_der:
	platform_free (pub_key_der);
err_free_key:
	x509->ecc->release_key_pair (x509->ecc, &ecc_priv_key, &ecc_pub_key);

	return status;
}

/**
 * Validate that the provided serial number is non-zero.
 *
 * @param serial_num The serial number to check.
 * @param serial_length The length of the serial number.
 *
 * @return 0 if the serial number is valid or an error code.
 */
static int x509_cert_build_check_serial_number (const uint8_t *serial_num, size_t serial_length)
{
	size_t i;
	int status;

	status = X509_ENGINE_INVALID_SERIAL_NUM;
	for (i = 0; i < serial_length; i++) {
		if (serial_num[i] != 0) {
			return 0;
		}
	}

	return status;
}

/**
 * Build the TBS (To Be Signed) data for an X.509 certificate.
 *
 * @param der DER encoder to update.
 * @param issuer_name Common name for the issuer for this certificate.
 * @param auth_key_id SHA1 hash of the issuer's public key.
 * @param subject_name Common name of the subject of this certificate.
 * @param subject_key_id SHA1 hash of the subject's public key.
 * @param serial_num The serial number to assign to the certificate.
 * @param serial_length Length of the serial number.
 * @param pub_key_der DER encoded public key for the certificate.
 * @param pub_key_length Length of the certificate public key.
 * @param sig_oid OID indicating the type of signature that will be generated for the certificate.
 * @param type The type of certificate being generated.
 * @param extra_extensions List of custom extensions that should be added to the certificate.
 * @param ext_count The number of custom extensions to add.
 *
 * @return 0 if the certificate TBS was generated successfully or an error code.
 */
static int x509_cert_build_build_certificate_tbs_data (DERBuilderContext *der,
	const char *issuer_name, const uint8_t *auth_key_id, const char *subject_name,
	const uint8_t *subject_key_id, const uint8_t *serial_num, size_t serial_length,
	const uint8_t *pub_key_der, size_t pub_key_length, const int *sig_oid, int type,
	const struct x509_extension_builder *const *extra_extensions, size_t ext_count)
{
	size_t i;
	int status;

	DER_CHK_ENCODE (DERStartSequenceOrSet (der, true));
	DER_CHK_ENCODE (DERAddShortExplicitInteger (der, 2));
	DER_CHK_ENCODE (DERAddIntegerFromArray (der, serial_num, serial_length));
	DER_CHK_ENCODE (DERStartSequenceOrSet (der, true));
	DER_CHK_ENCODE (DERAddOID (der, sig_oid));
	DER_CHK_ENCODE (DERPopNesting (der));
	DER_CHK_ENCODE (x509_cert_build_add_x509_name (der, issuer_name));
	DER_CHK_ENCODE (DERStartSequenceOrSet (der, true));
	DER_CHK_ENCODE (DERAddTime (der, VALID_FROM));
	DER_CHK_ENCODE (DERAddTime (der, VALID_TO));
	DER_CHK_ENCODE (DERPopNesting (der));
	DER_CHK_ENCODE (x509_cert_build_add_x509_name (der, subject_name));
	DER_CHK_ENCODE (DERAddPublicKey (der, pub_key_der, pub_key_length));
	DER_CHK_ENCODE (DERStartExplicit (der, 3));
	DER_CHK_ENCODE (DERStartSequenceOrSet (der, true));
	DER_CHK_ENCODE (x509_cert_build_add_subject_key_identifier_extension (der, subject_key_id,
		SHA1_HASH_LENGTH));
	DER_CHK_ENCODE (x509_cert_build_add_authority_key_identifier_extension (der, auth_key_id,
		SHA1_HASH_LENGTH));
	DER_CHK_ENCODE (x509_cert_build_add_key_usage_extension (der, type));
	if (type == X509_CERT_END_ENTITY) {
		DER_CHK_ENCODE (x509_cert_build_add_extended_key_usage_extension (der, NULL, 0,	true));
	}
	DER_CHK_ENCODE (x509_cert_build_add_basic_constraints_extension (der, type));
	for (i = 0; i < ext_count; i++) {
		DER_CHK_ENCODE (x509_cert_build_add_custom_extension (der, extra_extensions[i]));
	}
	DER_CHK_ENCODE (DERPopNesting (der));
	DER_CHK_ENCODE (DERPopNesting (der));
	DER_CHK_ENCODE (DERPopNesting (der));

	return 0;

error:

	return status;
}

int x509_cert_build_create_self_signed_certificate (const struct x509_engine *engine,
	struct x509_certificate *cert, const uint8_t *priv_key, size_t key_length,
	enum hash_type sig_hash, const uint8_t *serial_num, size_t serial_length, const char *name,
	int type, const struct x509_extension_builder *const *extra_extensions, size_t ext_count)
{
	const struct x509_engine_cert_build *x509 = (const struct x509_engine_cert_build*) engine;
	DERBuilderContext *der;
	struct ecc_private_key ecc_priv_key;
	struct ecc_public_key ecc_pub_key;
	uint8_t *pub_key_der = NULL;
	size_t pub_key_der_len;
	const uint8_t *auth_key;
	uint8_t auth_key_digest[SHA1_DIGEST_LENGTH];
	const int *sig_oid;
	int status;

	if ((x509 == NULL) || (cert == NULL) || (priv_key == NULL) || (key_length == 0) ||
		(serial_num == NULL) || (serial_length == 0) || (name == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	if ((ext_count != 0) && (extra_extensions == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	switch (sig_hash) {
		case HASH_TYPE_SHA256:
			sig_oid = ecdsaWithSHA256OID;
			break;

		case HASH_TYPE_SHA384:
			sig_oid = ecdsaWithSHA384OID;
			break;

		case HASH_TYPE_SHA512:
			sig_oid = ecdsaWithSHA512OID;
			break;

		default:
			return X509_ENGINE_UNSUPPORTED_SIG_HASH;
	}

	status = x509_cert_build_check_serial_number (serial_num, serial_length);
	if (status != 0) {
		return status;
	}

	cert->context = NULL;

	status = x509->ecc->init_key_pair (x509->ecc, priv_key, key_length, &ecc_priv_key,
		&ecc_pub_key);
	if (status != 0) {
		return status;
	}

	status = x509->ecc->get_public_key_der (x509->ecc, &ecc_pub_key, &pub_key_der,
		&pub_key_der_len);
	if (status != 0) {
		goto err_free_key;
	}

	status = ecc_der_decode_public_key_no_copy (pub_key_der, pub_key_der_len, &auth_key);
	if (ROT_IS_ERROR (status)) {
		/* This is highly unlikely since the encoded DER just came from the ECC engine. */
		goto err_free_key;
	}

	status = x509->hash->calculate_sha1 (x509->hash, auth_key, status, auth_key_digest,
		sizeof (auth_key_digest));
	if (status != 0) {
		goto err_free_key_der;
	}

	der = x509_cert_build_new_cert (x509);
	if (der == NULL) {
		status = X509_ENGINE_NO_MEMORY;
		goto err_free_key_der;
	}

	status = x509_cert_build_build_certificate_tbs_data (der, name, auth_key_digest, name,
		auth_key_digest, serial_num, serial_length, pub_key_der, pub_key_der_len, sig_oid, type,
		extra_extensions, ext_count);
	if (status != 0) {
		status = (status == -1) ? X509_ENGINE_SELF_SIGNED_FAILED : status;
		goto err_free_cert;
	}

	status = x509_cert_build_sign_certificate (der, &ecc_priv_key, x509->ecc, x509->hash, sig_hash,
		sig_oid);
	if (status == -1) {
		status = X509_ENGINE_SELF_SIGNED_FAILED;
	}

err_free_cert:
	if (status == 0) {
		cert->context = der;
	}
	else {
		x509_cert_build_free_cert (der);
	}
err_free_key_der:
	platform_free (pub_key_der);
err_free_key:
	x509->ecc->release_key_pair (x509->ecc, &ecc_priv_key, &ecc_pub_key);

	return status;
}

int x509_cert_build_create_ca_signed_certificate (const struct x509_engine *engine,
	struct x509_certificate *cert, const uint8_t *key, size_t key_length, const uint8_t *serial_num,
	size_t serial_length, const char *name, int type, const uint8_t *ca_priv_key,
	size_t ca_key_length, enum hash_type sig_hash, const struct x509_certificate *ca_cert,
	const struct x509_extension_builder *const *extra_extensions, size_t ext_count)
{
	const struct x509_engine_cert_build *x509 = (const struct x509_engine_cert_build*) engine;
	DERBuilderContext *der;
	DERBuilderContext *ca_ctx;
	struct ecc_private_key auth_priv_key;
	struct ecc_public_key auth_pub_key;
	uint8_t *auth_key_der;
	size_t auth_key_der_len;
	const uint8_t *auth_key;
	uint8_t auth_key_digest[SHA1_DIGEST_LENGTH];
	struct ecc_public_key subject_pub_key;
	const uint8_t *subject_key_der = key;
	size_t subject_key_der_len = key_length;
	const uint8_t *subject_key;
	size_t subject_key_len;
	uint8_t subject_key_digest[SHA1_DIGEST_LENGTH];
	const int *sig_oid;
	char *issuer = NULL;
	int status;

	if ((x509 == NULL) || (cert == NULL) || (key == NULL) || (key_length == 0) ||
		(serial_num == NULL) || (serial_length == 0) || (name == NULL) || (ca_priv_key == NULL) ||
		(ca_key_length == 0) || (ca_cert == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	if ((ext_count != 0) && (extra_extensions == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	switch (sig_hash) {
		case HASH_TYPE_SHA256:
			sig_oid = ecdsaWithSHA256OID;
			break;

		case HASH_TYPE_SHA384:
			sig_oid = ecdsaWithSHA384OID;
			break;

		case HASH_TYPE_SHA512:
			sig_oid = ecdsaWithSHA512OID;
			break;

		default:
			return X509_ENGINE_UNSUPPORTED_SIG_HASH;
	}

	status = x509_cert_build_check_serial_number (serial_num, serial_length);
	if (status != 0) {
		return status;
	}

	cert->context = NULL;
	ca_ctx = (DERBuilderContext*) ca_cert->context;

	status = x509->ecc->init_key_pair (x509->ecc, ca_priv_key, ca_key_length, &auth_priv_key,
		&auth_pub_key);
	if (status != 0) {
		return status;
	}

	status = x509->ecc->get_public_key_der (x509->ecc, &auth_pub_key, &auth_key_der,
		&auth_key_der_len);
	if (status != 0) {
		goto err_free_key;
	}

	status = ecc_der_decode_public_key_no_copy (auth_key_der, auth_key_der_len, &auth_key);
	if (ROT_IS_ERROR (status)) {
		/* This is highly unlikely since the encoded DER just came from the ECC engine. */
		goto err_free_key;
	}

	status = x509->hash->calculate_sha1 (x509->hash, auth_key, status, auth_key_digest,
		sizeof (auth_key_digest));
	if (status != 0) {
		goto err_free_key_der;
	}

	status = DERDECGetPubKey (&subject_key, &subject_key_len, key, key_length);
	if (status != 0) {
		/* The key data does not contain a public key.  Get the public key from the private key. */
		status = x509->ecc->init_key_pair (x509->ecc, key, key_length, NULL, &subject_pub_key);
		if (status != 0) {
			goto err_free_key_der;
		}

		status = x509->ecc->get_public_key_der (x509->ecc, &subject_pub_key,
			(uint8_t**) &subject_key_der, &subject_key_der_len);
		x509->ecc->release_key_pair (x509->ecc, NULL, &subject_pub_key);
		if (status != 0) {
			goto err_free_key_der;
		}

		status = ecc_der_decode_public_key_no_copy (subject_key_der, subject_key_der_len,
			&subject_key);
		if (ROT_IS_ERROR (status)) {
			/* This is highly unlikely since the encoded DER just came from the ECC engine. */
			goto err_free_key_der;
		}

		subject_key_len = status;
	}

	status = x509->hash->calculate_sha1 (x509->hash, subject_key, subject_key_len,
		subject_key_digest, sizeof (subject_key_digest));
	if (status != 0) {
		goto err_free_key_der;
	}

	status = DERDECGetSubjectName (&issuer, ca_ctx->Buffer, DERGetEncodedLength (ca_ctx));
	if (status != RIOT_SUCCESS) {
		status = X509_ENGINE_CA_SIGNED_FAILED;
		goto err_free_key_der;
	}

	der = x509_cert_build_new_cert (x509);
	if (der == NULL) {
		status = X509_ENGINE_NO_MEMORY;
		goto err_free_name;
	}

	status = x509_cert_build_build_certificate_tbs_data (der, issuer, auth_key_digest, name,
		subject_key_digest, serial_num, serial_length, subject_key_der, subject_key_der_len,
		sig_oid, type, extra_extensions, ext_count);
	if (status != 0) {
		status = (status == -1) ? X509_ENGINE_CA_SIGNED_FAILED : status;
		goto err_free_cert;
	}

	status = x509_cert_build_sign_certificate (der, &auth_priv_key, x509->ecc, x509->hash, sig_hash,
		sig_oid);
	if (status == -1) {
		status = X509_ENGINE_CA_SIGNED_FAILED;
	}

err_free_cert:
	if (status == 0) {
		cert->context = der;
	}
	else {
		x509_cert_build_free_cert (der);
	}
err_free_name:
	platform_free (issuer);
err_free_key_der:
	platform_free (auth_key_der);
	if (subject_key_der != key) {
		platform_free ((void*) subject_key_der);
	}
err_free_key:
	x509->ecc->release_key_pair (x509->ecc, &auth_priv_key, &auth_pub_key);

	return status;
}
#endif

int x509_cert_build_load_certificate (const struct x509_engine *engine,
	struct x509_certificate *cert, const uint8_t *der, size_t length)
{
	const struct x509_engine_cert_build *x509 = (const struct x509_engine_cert_build*) engine;
	DERBuilderContext *load_cert;
	int status;

	if ((x509 == NULL) || (cert == NULL) || (der == NULL) || (length == 0)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	if (length > x509->max_cert_length) {
		return X509_ENGINE_BIG_CERT_SIZE;
	}

	cert->context = NULL;

	status = DERDECVerifyCert (der, length);
	if (status != RIOT_SUCCESS) {
		return X509_ENGINE_LOAD_FAILED;
	}

	load_cert = x509_cert_build_new_cert (x509);
	if (load_cert == NULL) {
		return X509_ENGINE_NO_MEMORY;
	}

	memcpy (load_cert->Buffer, der, length);
	load_cert->Position = length;

	cert->context = load_cert;

	return 0;
}

void x509_cert_build_release_certificate (const struct x509_engine *engine,
	struct x509_certificate *cert)
{
	UNUSED (engine);

	if (cert) {
		x509_cert_build_free_cert (cert->context);
		memset (cert, 0, sizeof (struct x509_certificate));
	}
}

#ifdef X509_ENABLE_CREATE_CERTIFICATES
int x509_cert_build_get_certificate_der (const struct x509_engine *engine,
	const struct x509_certificate *cert, uint8_t **der, size_t *length)
{
	DERBuilderContext *cert_ctx;
	size_t enc_len;

	if (der == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	*der = NULL;
	if ((engine == NULL) || (cert == NULL) || (length == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	cert_ctx = (DERBuilderContext*) cert->context;
	enc_len = DERGetEncodedLength (cert_ctx);

	*der = platform_malloc (enc_len);
	if (*der == NULL) {
		return X509_ENGINE_NO_MEMORY;
	}

	memcpy (*der, cert_ctx->Buffer, enc_len);
	*length = enc_len;

	return 0;
}
#endif

/**
 * Initialize an instance for building X.509 certificates using a native ASN.1/DER encoder and
 * abstracted crypto engines.
 *
 * @param engine The X.509 engine to initialize.
 * @param ecc The ECC engine to use for ECC key operations.
 * @param hash The hash engine to use for calculating digests.
 * @param max_length The maximum certificate length that can be constructed.
 *
 * @return 0 if the X.509 engine was successfully initialized or an error code.
 */
int x509_cert_build_init (struct x509_engine_cert_build *engine, const struct ecc_engine *ecc,
	const struct hash_engine *hash, size_t max_cert_length)
{
	if ((engine == NULL) || (ecc == NULL) || (hash == NULL) || (max_cert_length == 0)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine, 0, sizeof (struct x509_engine_cert_build));

	engine->ecc = ecc;
	engine->hash = hash;
	engine->max_cert_length = max_cert_length;

#ifdef X509_ENABLE_CREATE_CERTIFICATES
	engine->base.create_csr = x509_cert_build_create_csr;
	engine->base.create_self_signed_certificate = x509_cert_build_create_self_signed_certificate;
	engine->base.create_ca_signed_certificate = x509_cert_build_create_ca_signed_certificate;
#endif
	engine->base.load_certificate = x509_cert_build_load_certificate;
	engine->base.release_certificate = x509_cert_build_release_certificate;
#ifdef X509_ENABLE_CREATE_CERTIFICATES
	engine->base.get_certificate_der = x509_cert_build_get_certificate_der;
#endif
#ifdef X509_ENABLE_AUTHENTICATION
	/* None of the authentication APIs are supported by this implementation and will remain NULL. */
#endif

	return 0;
}

/**
 * Release an X.509 engine for building certificates.
 *
 * @param engine The X.509 engine to release.
 */
void x509_cert_build_release (struct x509_engine_cert_build *engine)
{
	UNUSED (engine);
}
