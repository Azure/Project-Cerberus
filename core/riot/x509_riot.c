// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include "platform.h"
#include "x509_riot.h"
#include "reference/include/RiotDerEnc.h"
#include "reference/include/RiotX509Bldr.h"
#include "reference/include/RiotDerDec.h"
#include "crypto/ecc.h"

/**
 * Certificate validity period (UTCTime).
 */
#define VALID_FROM	"180101000000Z"
#define VALID_TO	"99991231235959Z"


/**
 * Create a new riot certificate instance.
 *
 * @return The allocated certificate or null.
 */
static DERBuilderContext* x509_riot_new_cert ()
{
	DERBuilderContext *x509;
	uint8_t *der_buf;

	x509 = platform_malloc (sizeof (DERBuilderContext));
	if (x509 == NULL) {
		return NULL;
	}

	der_buf = platform_malloc (X509_MAX_SIZE);
	if (der_buf == NULL) {
		platform_free (x509);
		return NULL;
	}

	DERInitContext (x509, der_buf, X509_MAX_SIZE);

	return x509;
}

/**
 * Free a riot certificate instance.
 *
 * @param cert The certificate to free.
 */
static void x509_riot_free_cert (void *cert)
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
 * Signs the TBS region of the certificate using ECDSA.
 *
 * @param cert_sig The output ECDSA signature.
 * @param ecc The abstract ECC crypto engine.
 * @param hash The abstract hash crypto engine.
 * @param der_ctx The context storing the TBS certificate region to be signed.
 * @param priv_key The signing key.
 *
 * @return 0 if signing was successful or an error code.
 */
static int x509_riot_get_cert_signature (RIOT_ECC_SIGNATURE *cert_sig, struct ecc_engine *ecc,
	struct hash_engine *hash, DERBuilderContext *der_ctx, struct ecc_private_key *priv_key)
{
	size_t enc_len;
	int enc_sig_len;
	uint8_t digest[SHA256_DIGEST_LENGTH];
	int sig_max_len;
	uint8_t *signature;
	int status;

	sig_max_len = ecc->get_signature_max_length (ecc, priv_key);
	if (ROT_IS_ERROR (sig_max_len)) {
		return sig_max_len;
	}

	signature = platform_malloc (sig_max_len);
	if (signature == NULL) {
		return X509_ENGINE_NO_MEMORY;
	}

	enc_len = DERGetEncodedLength (der_ctx);
	status = hash->calculate_sha256 (hash, der_ctx->Buffer, enc_len, digest, sizeof (digest));
	if (status != 0) {
		goto err_free_sig;
	}

	enc_sig_len = ecc->sign (ecc, priv_key, digest, sizeof (digest), signature, sig_max_len);
	if (ROT_IS_ERROR (enc_sig_len)) {
		status = enc_sig_len;
		goto err_free_sig;
	}

	status = RIOT_DSA_decode_signature (cert_sig, signature, enc_sig_len);
	if (status != RIOT_SUCCESS) {
		status = X509_ENGINE_CERT_SIGN_FAILED;
		goto err_free_sig;
	}

	status = 0;

err_free_sig:
	platform_free (signature);

	return status;
}

static int x509_riot_create_csr (struct x509_engine *engine, const uint8_t *priv_key,
	size_t key_length, const char *name, int type, const char *eku,
	const struct x509_dice_tcbinfo *dice, uint8_t **csr, size_t *csr_length)
{
	struct x509_engine_riot *riot = (struct x509_engine_riot*) engine;
	DERBuilderContext der_ctx;
	struct ecc_private_key ecc_priv_key;
	struct ecc_public_key ecc_pub_key;
	RIOT_ECC_SIGNATURE tbs_sig;
	RIOT_X509_TBS_DATA x509_tbs_data;
	size_t enc_len;
	uint8_t der_buf[X509_MAX_SIZE];
	int status;
	uint8_t pub_key_dec[RIOT_X509_MAX_KEY_LEN];
	size_t pub_key_dec_len;
	uint8_t *pub_key_der = NULL;
	size_t pub_key_der_len;

	if (csr == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	*csr = NULL;

	if ((riot == NULL) || (priv_key == NULL) || (name == NULL) || (csr_length == NULL) ||
		(key_length == 0)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	if ((type == X509_CERT_END_ENTITY) && (eku != NULL)) {
		return X509_ENGINE_NOT_CA_CERT;
	}

	status = riot->ecc->init_key_pair (riot->ecc, priv_key, key_length, &ecc_priv_key,
		&ecc_pub_key);
	if (status != 0) {
		return status;
	}

	status = riot->ecc->get_public_key_der (riot->ecc, &ecc_pub_key, &pub_key_der,
		&pub_key_der_len);
	if (status != 0) {
		goto err_free_key;
	}

	status = DERDECGetPubKey (pub_key_dec, &pub_key_dec_len, pub_key_der, pub_key_der_len);
	if (status != RIOT_SUCCESS) {
		status = X509_ENGINE_CSR_FAILED;
		goto err_free_key_der;
	}

	memset (&x509_tbs_data, 0, sizeof (RIOT_X509_TBS_DATA));
	x509_tbs_data.IssuerCommon = name;

	DERInitContext (&der_ctx, der_buf, X509_MAX_SIZE);
	status = X509GetDERCsrTbs (&der_ctx, &x509_tbs_data, &pub_key_dec[1], pub_key_dec_len - 1, type,
		eku, dice);
	if (status != 0) {
		status = (status == -1) ? X509_ENGINE_CSR_FAILED : status;
		goto err_free_key_der;
	}

	status = x509_riot_get_cert_signature (&tbs_sig, riot->ecc, riot->hash, &der_ctx,
		&ecc_priv_key);
	if (status != 0) {
		goto err_free_key_der;
	}

	status = X509GetDERCsr (&der_ctx, &tbs_sig);
	if (status < 0) {
		status = X509_ENGINE_CSR_FAILED;
		goto err_free_key_der;
	}

	enc_len = DERGetEncodedLength (&der_ctx);
	*csr = platform_malloc (enc_len);
	if (*csr == NULL) {
		status = X509_ENGINE_NO_MEMORY;
		goto err_free_key_der;
	}

	memcpy (*csr, der_ctx.Buffer, enc_len);
	*csr_length = enc_len;

	status = 0;

err_free_key_der:
	platform_free (pub_key_der);
err_free_key:
	riot->ecc->release_key_pair (riot->ecc, &ecc_priv_key, &ecc_pub_key);

	return status;
}

/**
 * Validate that the provided serial number is acceptable.
 *
 * @param serial_num The serial number to check.
 * @param serial_length The length of the serial number.
 *
 * @return 0 if the serial number is valid or an error code.
 */
static int x509_riot_check_serial_number (const uint8_t *serial_num, size_t serial_length)
{
	size_t i;
	int status;

	if (serial_length > RIOT_X509_SNUM_LEN) {
		return X509_ENGINE_LONG_SERIAL_NUM;
	}

	status = X509_ENGINE_INVALID_SERIAL_NUM;
	for (i = 0; i < serial_length; i++) {
		if (serial_num[i] != 0) {
			status = 0;
			break;
		}
	}

	return status;
}

static int x509_riot_create_self_signed_certificate (struct x509_engine *engine,
	struct x509_certificate *cert, const uint8_t *priv_key, size_t key_length,
	const uint8_t *serial_num, size_t serial_length, const char *name, int type,
	const struct x509_dice_tcbinfo *dice)
{
	struct x509_engine_riot *riot = (struct x509_engine_riot*) engine;
	struct ecc_private_key ecc_priv_key;
	struct ecc_public_key ecc_pub_key;
	DERBuilderContext *x509_ctx;
	RIOT_ECC_SIGNATURE tbs_sig;
	RIOT_X509_TBS_DATA x509_tbs_data;
	int status;
	uint8_t pub_key_dec[RIOT_X509_MAX_KEY_LEN];
	size_t pub_key_dec_len;
	uint8_t *pub_key_der = NULL;
	size_t pub_key_der_len;
	uint8_t auth_key_digest[SHA1_DIGEST_LENGTH];

	if ((riot == NULL) || (cert == NULL) || (priv_key == NULL) || (key_length == 0) ||
		(serial_num == NULL) || (serial_length == 0) || (name == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	status = x509_riot_check_serial_number (serial_num, serial_length);
	if (status != 0) {
		return status;
	}

	cert->context = NULL;

	status = riot->ecc->init_key_pair (riot->ecc, priv_key, key_length, &ecc_priv_key,
		&ecc_pub_key);
	if (status != 0) {
		return status;
	}

	status = riot->ecc->get_public_key_der (riot->ecc, &ecc_pub_key, &pub_key_der,
		&pub_key_der_len);
	if (status != 0) {
		goto err_free_key;
	}

	status = DERDECGetPubKey (pub_key_dec, &pub_key_dec_len, pub_key_der, pub_key_der_len);
	if (status != RIOT_SUCCESS) {
		status = X509_ENGINE_SELF_SIGNED_FAILED;
		goto err_free_key_der;
	}

	status = riot->hash->calculate_sha1 (riot->hash, &pub_key_dec[1], pub_key_dec_len - 1,
		auth_key_digest, sizeof (auth_key_digest));
	if (status != 0) {
		goto err_free_key_der;
	}

	x509_ctx = x509_riot_new_cert ();
	if (x509_ctx ==  NULL) {
		status = X509_ENGINE_NO_MEMORY;
		goto err_free_key_der;
	}

	memset (&x509_tbs_data, 0, sizeof (RIOT_X509_TBS_DATA));
	memcpy (x509_tbs_data.SerialNum, serial_num, serial_length);
	x509_tbs_data.SerialLen = serial_length;
	x509_tbs_data.IssuerCommon = name;
	x509_tbs_data.SubjectCommon = name;
	x509_tbs_data.ValidFrom = VALID_FROM;
	x509_tbs_data.ValidTo = VALID_TO;

	status = X509GetDeviceCertTBS (x509_ctx, &x509_tbs_data, &pub_key_dec[1], pub_key_dec_len - 1,
		auth_key_digest, type, dice);
	if (status != 0) {
		status = (status == -1) ? X509_ENGINE_SELF_SIGNED_FAILED : status;
		goto err_free_cert;
	}

	status = x509_riot_get_cert_signature (&tbs_sig, riot->ecc, riot->hash, x509_ctx,
		&ecc_priv_key);
	if (status != 0) {
		goto err_free_cert;
	}

	status = X509MakeDeviceCert (x509_ctx, &tbs_sig);
	if (status < 0) {
		status = X509_ENGINE_SELF_SIGNED_FAILED;
		goto err_free_cert;
	}

	cert->context = x509_ctx;
	platform_free (pub_key_der);
	riot->ecc->release_key_pair (riot->ecc, &ecc_priv_key, &ecc_pub_key);

	return 0;

err_free_cert:
	x509_riot_free_cert (x509_ctx);
err_free_key_der:
	platform_free (pub_key_der);
err_free_key:
	riot->ecc->release_key_pair (riot->ecc, &ecc_priv_key, &ecc_pub_key);

	return status;
}

static int x509_riot_create_ca_signed_certificate (struct x509_engine *engine,
	struct x509_certificate *cert, const uint8_t *key, size_t key_length, const uint8_t *serial_num,
	size_t serial_length, const char *name, int type, const uint8_t* ca_priv_key,
	size_t ca_key_length, const struct x509_certificate *ca_cert,
	const struct x509_dice_tcbinfo *dice)
{
	struct x509_engine_riot *riot_engine = (struct x509_engine_riot*) engine;
	struct ecc_private_key auth_priv_key;
	struct ecc_public_key auth_pub_key;
	DERBuilderContext *x509_ctx;
	DERBuilderContext *ca_ctx;
	RIOT_ECC_SIGNATURE tbs_sig;
	RIOT_X509_TBS_DATA x509_tbs_data;
	char *subject = NULL;
	int status;
	uint8_t pub_key_dec[RIOT_X509_MAX_KEY_LEN];
	size_t pub_key_dec_len;
	uint8_t *pub_key_der = NULL;
	size_t pub_key_der_len;

	if ((engine == NULL) || (cert == NULL) || (key == NULL) || (key_length == 0) ||
		(serial_num == NULL) || (serial_length == 0) || (name == NULL) || (ca_priv_key == NULL) ||
		(ca_key_length == 0) || (ca_cert == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	status = x509_riot_check_serial_number (serial_num, serial_length);
	if (status != 0) {
		return status;
	}

	cert->context = NULL;
	ca_ctx = (DERBuilderContext*) ca_cert->context;

	status = riot_engine->ecc->init_key_pair (riot_engine->ecc, ca_priv_key, ca_key_length,
		&auth_priv_key, &auth_pub_key);
	if (status != 0) {
		return status;
	}

	status = riot_engine->ecc->get_public_key_der (riot_engine->ecc, &auth_pub_key, &pub_key_der,
		&pub_key_der_len);
	if (status != 0) {
		goto err_free_key;
	}

	status = DERDECGetPubKey (pub_key_dec, &pub_key_dec_len, pub_key_der, pub_key_der_len);
	if (status != RIOT_SUCCESS) {
		status = X509_ENGINE_CA_SIGNED_FAILED;
		goto err_free_key_der;
	}

	memset (&x509_tbs_data, 0, sizeof (RIOT_X509_TBS_DATA));
	memcpy (x509_tbs_data.SerialNum, serial_num, serial_length);
	x509_tbs_data.SerialLen = serial_length;
	x509_tbs_data.SubjectCommon = name;
	x509_tbs_data.ValidFrom = VALID_FROM;
	x509_tbs_data.ValidTo = VALID_TO;

	status = DERDECGetSubjectName (&subject, ca_ctx->Buffer, DERGetEncodedLength(ca_ctx));
	if (status != RIOT_SUCCESS) {
		status = X509_ENGINE_CA_SIGNED_FAILED;
		goto err_free_key_der;
	}
	x509_tbs_data.IssuerCommon = subject;

	x509_ctx = x509_riot_new_cert ();
	if (x509_ctx ==  NULL) {
		status = X509_ENGINE_NO_MEMORY;
		goto err_free_name;
	}

	status = X509GetCASignedCertTBS (x509_ctx, &x509_tbs_data, key, key_length, pub_key_dec,
		pub_key_dec_len, type, dice, riot_engine->hash);
	if (status != 0) {
		status = (status == -1) ? X509_ENGINE_CA_SIGNED_FAILED : status;
		goto err_free_cert;
	}

	status = x509_riot_get_cert_signature (&tbs_sig, riot_engine->ecc, riot_engine->hash, x509_ctx,
		&auth_priv_key);
	if (status != 0) {
		goto err_free_cert;
	}

	status = X509MakeAliasCert (x509_ctx, &tbs_sig);
	if (status < 0) {
		status = X509_ENGINE_CA_SIGNED_FAILED;
		goto err_free_cert;
	}

	cert->context = x509_ctx;

	platform_free (subject);
	platform_free (pub_key_der);
	riot_engine->ecc->release_key_pair (riot_engine->ecc, &auth_priv_key, &auth_pub_key);

	return 0;

err_free_cert:
	x509_riot_free_cert (x509_ctx);
err_free_name:
	platform_free (subject);
err_free_key_der:
	platform_free (pub_key_der);
err_free_key:
	riot_engine->ecc->release_key_pair (riot_engine->ecc, &auth_priv_key, &auth_pub_key);

	return status;
}
#endif

static int x509_riot_load_certificate (struct x509_engine *engine, struct x509_certificate *cert,
	const uint8_t *der, size_t length)
{
	DERBuilderContext *x509;
	int status;

	if ((engine == NULL) || (cert == NULL) || (der == NULL) || (length == 0)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	if (length > X509_MAX_SIZE) {
		return X509_ENGINE_BIG_CERT_SIZE;
	}

	cert->context = NULL;

	status = DERDECVerifyCert (der, length);
	if (status != RIOT_SUCCESS) {
		return X509_ENGINE_LOAD_FAILED;
	}

	x509 = x509_riot_new_cert ();
	if (x509 == NULL) {
		return X509_ENGINE_NO_MEMORY;
	}

	memcpy (x509->Buffer, der, length);
	x509->Position = length;

	cert->context = x509;

	return 0;
}

static void x509_riot_release_certificate (struct x509_engine *engine,
	struct x509_certificate *cert)
{
	if (cert) {
		x509_riot_free_cert (cert->context);
		memset (cert, 0, sizeof (struct x509_certificate));
	}
}

#ifdef X509_ENABLE_CREATE_CERTIFICATES
static int x509_riot_get_certificate_der (struct x509_engine *engine,
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
 * Initialize an instance for handling X.509 certificates using riot.
 *
 * @param engine The X.509 engine to initialize.
 * @param ecc The ECC engine to use for X.509 operations.
 * @param hash The hash engine to use for X.509 operations.
 *
 * @return 0 if the X.509 engine was successfully initialized or an error code.
 */
int x509_riot_init (struct x509_engine_riot *engine, struct ecc_engine *ecc,
	struct hash_engine *hash)
{
	if ((engine == NULL) || (ecc == NULL) || (hash == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine, 0, sizeof (struct x509_engine_riot));

	engine->ecc = ecc;
	engine->hash = hash;

#ifdef X509_ENABLE_CREATE_CERTIFICATES
	engine->base.create_csr = x509_riot_create_csr;
	engine->base.create_self_signed_certificate = x509_riot_create_self_signed_certificate;
	engine->base.create_ca_signed_certificate = x509_riot_create_ca_signed_certificate;
#endif
	engine->base.load_certificate = x509_riot_load_certificate;;
	engine->base.release_certificate = x509_riot_release_certificate;
#ifdef X509_ENABLE_CREATE_CERTIFICATES
	engine->base.get_certificate_der = x509_riot_get_certificate_der;
#endif
#ifdef X509_ENABLE_AUTHENTICATION
	engine->base.get_public_key_type = NULL;
	engine->base.get_public_key = NULL;
	engine->base.init_ca_cert_store = NULL;
	engine->base.release_ca_cert_store = NULL;
	engine->base.add_root_ca = NULL;
	engine->base.add_intermediate_ca = NULL;
	engine->base.authenticate = NULL;
#endif

	return 0;
}

/**
 * Release a riot X.509 engine.
 *
 * @param engine The X.509 engine to release.
 */
void x509_riot_release (struct x509_engine_riot *engine)
{

}
