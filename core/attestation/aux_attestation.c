// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include "platform.h"
#include "aux_attestation.h"
#include "riot/riot_core.h"


/* The size of the auxiliary attestation key. */
#define	AUX_ATTESTATION_KEY_BITS			3072
#define	AUX_ATTESTATION_KEY_BYTES			(AUX_ATTESTATION_KEY_BITS / 8)

/**
 * The label to use when deriving the encryption key.
 */
static const char AUX_ATTESTATION_ENCRYPTION_LABEL[] = "encryption key";

/**
 * The label to use when deriving the signing key.
 */
static const char AUX_ATTESTATION_SIGNING_LABEL[] = "signing key";


/**
 * Initialize the handler for auxiliary attestation requests.
 *
 * @param aux The attestation handler to initialize.
 * @param keystore The keystore used to store the private key.
 * @param rsa The RSA engine to use with the private key.
 *
 * @return 0 if the attestation handler was successfully initialized or an error code.
 */
int aux_attestation_init (struct aux_attestation *aux, struct keystore *keystore,
	struct rsa_engine *rsa)
{
	if ((aux == NULL) || (keystore == NULL) || (rsa == NULL)) {
		return AUX_ATTESTATION_INVALID_ARGUMENT;
	}

	memset (aux, 0, sizeof (struct aux_attestation));

	aux->keystore = keystore;
	aux->rsa = rsa;

	return 0;
}

/**
 * Release the stored certificate for the attestation key.
 *
 * @param aux The attestation handler for the certificate to release.
 */
static void aux_attestation_free_cert (struct aux_attestation *aux)
{
	if (aux) {
		if (!aux->is_static) {
			platform_free ((void*) aux->cert.cert);
		}
		aux->cert.cert = NULL;
		aux->cert.length = 0;
		aux->is_static = false;
	}
}

/**
 * Release the resources used by the auxiliary attestation handler.
 *
 * @param aux The attestation handler to release.
 */
void aux_attestation_release (struct aux_attestation *aux)
{
	aux_attestation_free_cert (aux);
}

/**
 * Generate a new RSA key to use for attestation and save it in the keystore.  Since the
 * attestation key is an RSA-3072 key, this function could take a very long time to complete.
 *
 * No certificate will be generated for the key.
 *
 * @param aux The attestation handler.
 *
 * @return 0 if the key was generated and stored successfully or an error code.
 */
int aux_attestation_generate_key (struct aux_attestation *aux)
{
	struct rsa_private_key rsa_key;
	uint8_t *priv;
	size_t length;
	int status;

	if (aux == NULL) {
		return AUX_ATTESTATION_INVALID_ARGUMENT;
	}

	status = aux->rsa->generate_key (aux->rsa, &rsa_key, AUX_ATTESTATION_KEY_BITS);
	if (status != 0) {
		return status;
	}

	status = aux->rsa->get_private_key_der (aux->rsa, &rsa_key, &priv, &length);
	aux->rsa->release_key (aux->rsa, &rsa_key);
	if (status != 0) {
		return status;
	}

	status = aux->keystore->save_key (aux->keystore, 0, priv, length);

	riot_core_clear (priv, length);
	platform_free (priv);

	return status;
}

/**
 * Erase the RSA private key in the keystore.  The certificate for the key will also be invalidated.
 *
 * @param aux The attestation handler to update.
 *
 * @return 0 if the key was erased successfully or an error code.
 */
int aux_attestation_erase_key (struct aux_attestation *aux)
{
	if (aux == NULL) {
		return AUX_ATTESTATION_INVALID_ARGUMENT;
	}

	/* There is no synchronization on these calls, but that shouldn't be an issue.  This will only
	 * get called in very rare scenarios and/or development situations.  The certificate and key
	 * are also only rarely used, reducing the chance of conflict. */
	aux_attestation_free_cert (aux);

	return aux->keystore->erase_key (aux->keystore, 0);
}

#ifdef X509_ENABLE_CREATE_CERTIFICATES
/**
 * Generate the signed attestation certificate for the attestation RSA key in the keystore.
 *
 * @param aux The attestation handler.
 * @param x509 The X.509 engine to use for certificate generation.
 * @param rng Generator for a random serial number.
 * @param ca DER encoded data of the CA certificate that will sign the attestation certificate.
 * @param ca_length The length of the CA certificate.
 * @param ca_key DER encoded data of private key for the CA certificate.
 * @param key_length The length of the CA private key.
 *
 * @return 0 if the certificate was create successfully or an error code.  The certificate itself
 * can be retrieved from aux_attestation_get_certificate.
 */
int aux_attestation_create_certificate (struct aux_attestation *aux, struct x509_engine *x509,
	struct rng_engine *rng, const uint8_t *ca, size_t ca_length, const uint8_t *ca_key,
	size_t key_length)
{
	uint8_t *priv;
	size_t length;
	struct x509_certificate ca_cert;
	struct x509_certificate attestation_cert;
	int status;
	uint8_t serial_num[8];
	int i;

	if ((aux == NULL) || (x509 == NULL) || (rng == NULL) || (ca == NULL) || (ca_length == 0) ||
		(ca_key == NULL) || (key_length == 0)) {
		return AUX_ATTESTATION_INVALID_ARGUMENT;
	}

	status = aux->keystore->load_key (aux->keystore, 0, &priv, &length);
	if (status != 0) {
		return status;
	}

	status = x509->load_certificate (x509, &ca_cert, ca, ca_length);
	if (status != 0) {
		goto exit_free_key;
	}

	do {
		status = rng->generate_random_buffer (rng, sizeof (serial_num), serial_num);
		if (status != 0) {
			goto exit_free_ca;
		}

		/* If the RNG gives us all 0's, we want to try again. */
		for (i = 0; i < sizeof (serial_num); i++) {
			if (serial_num[i] != 0) {
				break;
			}
		}
	} while (i == sizeof (serial_num));

	status = x509->create_ca_signed_certificate (x509, &attestation_cert, priv, length, serial_num,
		sizeof (serial_num), "AUX", X509_CERT_END_ENTITY, ca_key, key_length, &ca_cert, NULL);
	if (status != 0) {
		goto exit_free_ca;
	}

	if (aux->cert.cert) {
		aux_attestation_free_cert (aux);
	}
	status = x509->get_certificate_der (x509, &attestation_cert, (uint8_t**) &aux->cert.cert,
		&aux->cert.length);

	x509->release_certificate (x509, &attestation_cert);
exit_free_ca:
	x509->release_certificate (x509, &ca_cert);
exit_free_key:
	riot_core_clear (priv, length);
	platform_free (priv);
	return status;
}
#endif

/**
 * Provide the signed certificate for the attestation RSA key to the handler.  If the handler
 * already has a certificate, this request will be rejected.
 *
 * @param aux The attestation handler to update.
 * @param cert The DER encoded certificate for the attestation key.  The memory for this data must
 * be dynamically allocated and is owned by the attestation handler upon successful return.
 * @param length The length of the certificate data.
 *
 * @return 0 if the certificate was taken by the handler or an error code.
 */
int aux_attestation_set_certificate (struct aux_attestation *aux, uint8_t *cert, size_t length)
{
	if ((aux == NULL) || (cert == NULL) || (length == 0)) {
		return AUX_ATTESTATION_INVALID_ARGUMENT;
	}

	if (aux->cert.cert) {
		return AUX_ATTESTATION_HAS_CERTIFICATE;
	}

	aux->cert.cert = cert;
	aux->cert.length = length;

	return 0;
}

/**
 * Provide the signed certificate for the attestation RSA key to the handler.  If the handler
 * already has a certificate, this request will be rejected.
 *
 * @param aux The attestation handler to update.
 * @param cert The DER encoded certificate for the attestation key.  The memory for this data must
 * be statically allocated.
 * @param length The length of the certificate data.
 *
 * @return 0 if the certificate was taken by the handler or an error code.
 */
int aux_attestation_set_static_certificate (struct aux_attestation *aux, const uint8_t *cert,
	size_t length)
{
	int status;

	status = aux_attestation_set_certificate (aux, (uint8_t*) cert, length);
	if (status != 0) {
		return status;
	}

	aux->is_static = true;
	return 0;
}

/**
 * Get the certificate for the attestation key.
 *
 * @param aux The attestion handler to query.
 *
 * @return The attestation certificate or null if there is no certificate.  The memory for this
 * certificate is owned by the attestation handler and must not be freed.
 */
const struct der_cert* aux_attestation_get_certificate (struct aux_attestation *aux)
{
	if (aux && aux->cert.cert) {
		return &aux->cert;
	}
	else {
		return NULL;
	}
}

/**
 * Process an attestation request to unseal the encrypted attestation data.
 *
 * @param aux The attestation handler to run.
 * @param hash The hash engine to use for unsealing.
 * @param seed The request seed encrypted with the attestation public key.
 * @param seed_length The length of the request seed.
 * @param hmac The HMAC for the attestation request.  This is an HMAC-SHA256 value.
 * @param ciphertext The encrypted attestation data.
 * @param cipher_length Length of the encrypted data.
 * @param sealing A 64-byte sealing value for the attestation data.
 * @param pcr The platform PCR from local firmware measurements.  This is an HMAC-SHA256 value.
 * @param key Output for the unsealed encryption key that will decrypt the attestation data.  This
 * is a dynamically allocated buffer and is the responsibility of the caller to free.  This will be
 * null on error.
 * @param key_length Output for the length of the encryption key.
 *
 * @return 0 if the unsealing was successful or an error code.
 */
int aux_attestation_unseal (struct aux_attestation *aux, struct hash_engine *hash,
	const uint8_t *seed, size_t seed_length, const uint8_t *hmac, const uint8_t *ciphertext,
	size_t cipher_length, const uint8_t *sealing, const uint8_t *pcr, uint8_t **key,
	size_t *key_length)
{
	struct rsa_private_key priv;
	uint8_t *priv_der;
	size_t priv_length;
	uint8_t secret[AUX_ATTESTATION_KEY_BYTES];
	int secret_length;
	struct hmac_engine run_hmac;
	uint8_t i[4] = {0};
	uint8_t L[4] = {0};
	uint8_t signing_key[SHA256_HASH_LENGTH];
	uint8_t payload_hmac[SHA256_HASH_LENGTH];
	bool bypass = true;
	int j;
	int status;

	if (key == NULL) {
		return AUX_ATTESTATION_INVALID_ARGUMENT;
	}

	*key = NULL;
	if ((aux == NULL) || (hash == NULL) || (seed == NULL) || (seed_length == 0) ||
		(hmac == NULL) || (ciphertext == NULL) || (cipher_length == 0) || (sealing == NULL) ||
		(pcr == NULL) || (key_length == NULL)) {
		return AUX_ATTESTATION_INVALID_ARGUMENT;
	}

	status = aux->keystore->load_key (aux->keystore, 0, &priv_der, &priv_length);
	if (status != 0) {
		return status;
	}

	/* Decrypt the key derivation seed. */
	status = aux->rsa->init_private_key (aux->rsa, &priv, priv_der, priv_length);
	if (status != 0) {
		goto rsa_init_error;
	}

	secret_length = aux->rsa->decrypt (aux->rsa, &priv, seed, seed_length, NULL, 0,
		HASH_TYPE_SHA1, secret, sizeof (secret));
	if (ROT_IS_ERROR (secret_length)) {
		status = secret_length;
		goto rsa_decrypt_error;
	}

	aux->rsa->release_key (aux->rsa, &priv);
	riot_core_clear (priv_der, priv_length);
	platform_free (priv_der);

	i[3] = 1;
	L[2] = 1;

	/* Derive the signing key. */
	status = hash_hmac_init (&run_hmac, hash, HMAC_SHA256, secret, secret_length);
	if (status != 0) {
		return status;
	}

	status = hash_hmac_update (&run_hmac, i, sizeof (i));
	if (status != 0) {
		goto hmac_error;
	}

	status = hash_hmac_update (&run_hmac, (const uint8_t*) AUX_ATTESTATION_SIGNING_LABEL,
		sizeof (AUX_ATTESTATION_SIGNING_LABEL));
	if (status != 0) {
		goto hmac_error;
	}

	status = hash_hmac_update (&run_hmac, L, sizeof (L));
	if (status != 0) {
		goto hmac_error;
	}

	status = hash_hmac_finish (&run_hmac, signing_key, sizeof (signing_key));
	if (status != 0) {
		return status;
	}

	/* Validate the payload. */
	status = hash_hmac_init (&run_hmac, hash, HMAC_SHA256, signing_key, SHA256_HASH_LENGTH);
	if (status != 0) {
		return status;
	}

	status = hash_hmac_update (&run_hmac, ciphertext, cipher_length);
	if (status != 0) {
		goto hmac_error;
	}

	status = hash_hmac_update (&run_hmac, sealing, 64);
	if (status != 0) {
		goto hmac_error;
	}

	status = hash_hmac_finish (&run_hmac, payload_hmac, sizeof (payload_hmac));
	if (status != 0) {
		return status;
	}

	if (memcmp (hmac, payload_hmac, SHA256_HASH_LENGTH) != 0) {
		return AUX_ATTESTATION_HMAC_MISMATCH;
	}

	j = 0;
	while (bypass && (j < 64)) {
		if (sealing[j++] != 0) {
			bypass = false;
		}
	}

	if (!bypass) {
		if (memcmp (pcr, &sealing[32], SHA256_HASH_LENGTH) != 0) {
			return AUX_ATTESTATION_PCR_MISMATCH;
		}
	}

	/* Derive the encryption key. */
	status = hash_hmac_init (&run_hmac, hash, HMAC_SHA256, secret, secret_length);
	if (status != 0) {
		return status;
	}

	status = hash_hmac_update (&run_hmac, i, sizeof (i));
	if (status != 0) {
		goto hmac_error;
	}

	status = hash_hmac_update (&run_hmac, (const uint8_t*) AUX_ATTESTATION_ENCRYPTION_LABEL,
		sizeof (AUX_ATTESTATION_ENCRYPTION_LABEL));
	if (status != 0) {
		goto hmac_error;
	}

	status = hash_hmac_update (&run_hmac, L, sizeof (L));
	if (status != 0) {
		goto hmac_error;
	}

	*key = platform_malloc (SHA256_HASH_LENGTH);
	if (*key == NULL) {
		status = AUX_ATTESTATION_NO_MEMORY;
		goto hmac_error;
	}

	status = hash_hmac_finish (&run_hmac, *key, SHA256_HASH_LENGTH);
	if (status != 0) {
		platform_free (*key);
		*key = NULL;
		return status;
	}

	*key_length = SHA256_HASH_LENGTH;
	return 0;

rsa_decrypt_error:
	aux->rsa->release_key (aux->rsa, &priv);
rsa_init_error:
	riot_core_clear (priv_der, priv_length);
	platform_free (priv_der);
	return status;

hmac_error:
	hash_hmac_cancel (&run_hmac);
	return status;
}

/**
 * Decrypt a payload using the attestation key.
 *
 * @param aux The attestation handler to run.
 * @param encrypted Payload to decrypt.
 * @param len_encrypted Length of payload to decrypt.
 * @param label Optional label to use during decryption.
 * @param len_label Length of the optional label.
 * @param pad_hash Algorithm used for padding generation.
 * @param decrypted Output for the decrypted payload.
 * @param len_decrypted Length of decrypted payload buffer.
 *
 * @return Decrypted payload length if the decryption was successful or an error code.
 */
int aux_attestation_decrypt (struct aux_attestation *aux, const uint8_t *encrypted,
	size_t len_encrypted, const uint8_t *label, size_t len_label, enum hash_type pad_hash,
	uint8_t *decrypted, size_t len_decrypted)
{
	struct rsa_private_key priv;
	uint8_t *priv_der;
	size_t priv_length;
	int status;

	if ((aux == NULL) || (encrypted == NULL) || (decrypted == NULL)) {
		return AUX_ATTESTATION_INVALID_ARGUMENT;
	}

	status = aux->keystore->load_key (aux->keystore, 0, &priv_der, &priv_length);
	if (status != 0) {
		return status;
	}

	status = aux->rsa->init_private_key (aux->rsa, &priv, priv_der, priv_length);
	if (status != 0) {
		goto rsa_init_error;
	}

	status = aux->rsa->decrypt (aux->rsa, &priv, encrypted, len_encrypted, label, len_label,
		pad_hash, decrypted, len_decrypted);

	aux->rsa->release_key (aux->rsa, &priv);

rsa_init_error:
	riot_core_clear (priv_der, priv_length);
	platform_free (priv_der);

	return status;
}
