// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <string.h>
#include "platform.h"
#include "attestation_slave.h"


static int attestation_slave_get_digests (struct attestation_slave *attestation, uint8_t slot_num,
	uint8_t *buf, size_t buf_len, uint8_t *num_cert)
{
	const struct riot_keys *keys;
	const struct der_cert *root_ca;
	const struct der_cert *int_ca;
	const struct der_cert *aux_cert = NULL;
	size_t offset = 0;
	int status;

	if ((attestation == NULL) || (buf == NULL) || (num_cert == NULL)) {
		return ATTESTATION_INVALID_ARGUMENT;
	}

	if (slot_num > ATTESTATION_AUX_SLOT_NUM) {
		return ATTESTATION_INVALID_SLOT_NUM;
	}

#ifdef ATTESTATION_SUPPORT_RSA_UNSEAL
	aux_cert = aux_attestation_get_certificate (attestation->aux);
#endif
	if (slot_num == ATTESTATION_AUX_SLOT_NUM) {
		if (attestation->aux == NULL) {
			return ATTESTATION_INVALID_SLOT_NUM;
		}
		else if (aux_cert == NULL) {
			return ATTESTATION_CERT_NOT_AVAILABLE;
		}
	}

	keys = riot_key_manager_get_riot_keys (attestation->riot);
	if ((keys->devid_cert == NULL) || (keys->devid_cert_length == 0)) {
		status = ATTESTATION_CERT_NOT_AVAILABLE;
		goto exit;
	}
	else if ((slot_num == ATTESTATION_RIOT_SLOT_NUM) &&
		((keys->alias_cert == NULL) || (keys->alias_cert_length == 0))) {
		status = ATTESTATION_CERT_NOT_AVAILABLE;
		goto exit;
	}

	root_ca = riot_key_manager_get_root_ca (attestation->riot);
	int_ca = riot_key_manager_get_intermediate_ca (attestation->riot);

	*num_cert = 2;
	if (root_ca != NULL) {
		*num_cert += 1;
	}
	if (int_ca != NULL) {
		*num_cert += 1;
	}
	if (buf_len < (SHA256_HASH_LENGTH * (*num_cert))) {
		status = ATTESTATION_BUF_TOO_SMALL;
		goto exit;
	}

	platform_mutex_lock (&attestation->lock);

	if (root_ca != NULL) {
		status = attestation->hash->calculate_sha256 (attestation->hash, root_ca->cert,
			root_ca->length, buf, SHA256_HASH_LENGTH);
		if (status != 0) {
			goto unlock;
		}

		offset += SHA256_HASH_LENGTH;
	}

	if (int_ca != NULL) {
		status = attestation->hash->calculate_sha256 (attestation->hash, int_ca->cert,
			int_ca->length, &buf[offset], SHA256_HASH_LENGTH);
		if (status != 0) {
			goto unlock;
		}

		offset += SHA256_HASH_LENGTH;
	}

	status = attestation->hash->calculate_sha256 (attestation->hash, keys->devid_cert,
		keys->devid_cert_length, &buf[offset], SHA256_HASH_LENGTH);
	if (status != 0) {
		goto unlock;
	}

	offset += SHA256_HASH_LENGTH;

	switch (slot_num) {
		case ATTESTATION_RIOT_SLOT_NUM:
			status = attestation->hash->calculate_sha256 (attestation->hash, keys->alias_cert,
				keys->alias_cert_length, &buf[offset], SHA256_HASH_LENGTH);
			break;

		case ATTESTATION_AUX_SLOT_NUM:
			status = attestation->hash->calculate_sha256 (attestation->hash, aux_cert->cert,
				aux_cert->length, &buf[offset], SHA256_HASH_LENGTH);
			break;
	}
	if (status != 0) {
		goto unlock;
	}

	status = offset + SHA256_HASH_LENGTH;

unlock:
	platform_mutex_unlock (&attestation->lock);
exit:
	riot_key_manager_release_riot_keys (attestation->riot, keys);
	return status;
}

/**
 * Get the last certificate in the specified chain.
 *
 * @param attestation The attestation instance.
 * @param slot_num The certificate chain being queried.
 * @param riot Keys for RIoT attesatation.
 * @param aux_cert Certificate for auxiliary attestation.  This must not be null.
 * @param cert Output for the certificate information.
 */
static void attestation_slave_get_last_certificate (struct attestation_slave *attestation,
	uint8_t slot_num, const struct riot_keys *riot, const struct der_cert *aux_cert,
	struct der_cert *cert)
{
	switch (slot_num) {
		case ATTESTATION_RIOT_SLOT_NUM:
			cert->cert = riot->alias_cert;
			cert->length = riot->alias_cert_length;
			break;

		case ATTESTATION_AUX_SLOT_NUM:
			cert->cert = aux_cert->cert;
			cert->length = aux_cert->length;
			break;
	}
}

static int attestation_slave_get_certificate (struct attestation_slave *attestation,
	uint8_t slot_num, uint8_t cert_num, struct der_cert *cert)
{
	const struct riot_keys *keys;
	const struct der_cert *int_ca;
	const struct der_cert *root_ca;
	const struct der_cert *aux_cert = NULL;
	int status = 0;

	if ((attestation == NULL) || (cert == NULL)) {
		return ATTESTATION_INVALID_ARGUMENT;
	}

	if (slot_num > ATTESTATION_AUX_SLOT_NUM) {
		return ATTESTATION_INVALID_SLOT_NUM;
	}

	root_ca = riot_key_manager_get_root_ca (attestation->riot);
	int_ca = riot_key_manager_get_intermediate_ca (attestation->riot);

	if (int_ca) {
		if (cert_num > 3) {
			return ATTESTATION_INVALID_CERT_NUM;
		}
	}
	else if (root_ca) {
		if (cert_num > 2) {
			return ATTESTATION_INVALID_CERT_NUM;
		}
	}
	else if (cert_num > 1) {
		return ATTESTATION_INVALID_CERT_NUM;
	}

#ifdef ATTESTATION_SUPPORT_RSA_UNSEAL
	aux_cert = aux_attestation_get_certificate (attestation->aux);
#endif
	if (slot_num == ATTESTATION_AUX_SLOT_NUM) {
		if (attestation->aux == NULL) {
			return ATTESTATION_INVALID_SLOT_NUM;
		}
		else if (aux_cert == NULL) {
			return ATTESTATION_CERT_NOT_AVAILABLE;
		}
	}

	keys = riot_key_manager_get_riot_keys (attestation->riot);
	if ((keys->devid_cert == NULL) || (keys->devid_cert_length == 0)) {
		status = ATTESTATION_CERT_NOT_AVAILABLE;
		goto exit;
	}
	else if ((slot_num == ATTESTATION_RIOT_SLOT_NUM) &&
		((keys->alias_cert == NULL) || (keys->alias_cert_length == 0))) {
		status = ATTESTATION_CERT_NOT_AVAILABLE;
		goto exit;
	}

	memset (cert, 0, sizeof (struct der_cert));

	switch (cert_num) {
		case 0:
			if (root_ca) {
				cert->cert = root_ca->cert;
				cert->length = root_ca->length;
			}
			else {
				cert->cert = keys->devid_cert;
				cert->length = keys->devid_cert_length;
			}
			break;

		case 1:
			if (int_ca) {
				cert->cert = int_ca->cert;
				cert->length = int_ca->length;
			}
			else if (root_ca) {
				cert->cert = keys->devid_cert;
				cert->length = keys->devid_cert_length;
			}
			else {
				attestation_slave_get_last_certificate (attestation, slot_num, keys, aux_cert,
					cert);
			}
			break;

		case 2:
			if (int_ca) {
				cert->cert = keys->devid_cert;
				cert->length = keys->devid_cert_length;
			}
			else {
				attestation_slave_get_last_certificate (attestation, slot_num, keys, aux_cert,
					cert);
			}
			break;

		case 3:
			attestation_slave_get_last_certificate (attestation, slot_num, keys, aux_cert,
				cert);
			break;
	}

exit:
	riot_key_manager_release_riot_keys (attestation->riot, keys);
	return status;
}

static int attestation_slave_challenge_response (struct attestation_slave *attestation,
	uint8_t *buf, size_t buf_len)
{
	struct attestation_challenge *challenge = (struct attestation_challenge*)buf;
	struct attestation_response *response = (struct attestation_response*)buf;
	uint8_t measurement[PCR_DIGEST_LENGTH];
	uint8_t buf_hash[SHA256_HASH_LENGTH];
	uint16_t response_len;
	uint8_t slot_num;
	int num_measurements;
	int status;

	if ((attestation == NULL) || (buf == NULL)) {
		return ATTESTATION_INVALID_ARGUMENT;
	}

	if (buf_len < sizeof (struct attestation_challenge)) {
		return ATTESTATION_BAD_LENGTH;
	}

	slot_num = challenge->slot_num;

	if (slot_num != ATTESTATION_RIOT_SLOT_NUM) {
		return ATTESTATION_INVALID_SLOT_NUM;
	}

	platform_mutex_lock (&attestation->lock);

	num_measurements = pcr_store_compute (attestation->pcr_store, attestation->hash, 0,
		measurement);
	if (ROT_IS_ERROR (num_measurements)) {
		status = num_measurements;
		goto unlock;
	}

	response_len = sizeof (struct attestation_response) + sizeof (measurement);

	if (buf_len <= response_len) {
		status = ATTESTATION_BUF_TOO_SMALL;
		goto unlock;
	}

	status = attestation->hash->start_sha256 (attestation->hash);
	if (status != 0) {
		goto unlock;
	}

	status = attestation->hash->update (attestation->hash, (uint8_t*) challenge,
		sizeof (struct attestation_challenge));
	if (status != 0) {
		goto cleanup;
	}

	memset (buf, 0, response_len);

	response->slot_num = slot_num;
	response->slot_mask = 1;
	response->min_protocol_version = attestation->min_protocol_version;
	response->max_protocol_version = attestation->max_protocol_version;
	response->num_digests = num_measurements;
	response->digests_size = sizeof (measurement);

	status = attestation->rng->generate_random_buffer (attestation->rng, ATTESTATION_NONCE_LEN,
		response->nonce);
	if (status != 0) {
		goto cleanup;
	}

	memcpy (buf + sizeof (struct attestation_response), measurement, sizeof (measurement));

	status = attestation->hash->update (attestation->hash, buf, response_len);
	if (status != 0) {
		goto cleanup;
	}

	status = attestation->hash->finish (attestation->hash, buf_hash, sizeof (buf_hash));
	if (status != 0) {
		goto cleanup;
	}

	status = attestation->ecc->sign (attestation->ecc, &attestation->ecc_priv_key, buf_hash,
		SHA256_HASH_LENGTH, buf + response_len, buf_len - response_len);
	if (ROT_IS_ERROR (status)) {
		goto unlock;
	}

	platform_mutex_unlock (&attestation->lock);
	return response_len + status;

cleanup:
	attestation->hash->cancel (attestation->hash);
unlock:
	platform_mutex_unlock (&attestation->lock);
	return status;
}

static int attestation_slave_aux_attestation_unseal (struct attestation_slave *attestation,
	struct hash_engine *hash, enum aux_attestation_key_length key_type, const uint8_t *seed,
	size_t seed_length, enum aux_attestation_seed_type seed_type,
	enum aux_attestation_seed_param seed_param, const uint8_t *hmac, enum hmac_hash hmac_type,
	const uint8_t *ciphertext, size_t cipher_length, const uint8_t sealing[][64], size_t pcr_count,
	uint8_t *key, size_t key_length)
{
	if (attestation == NULL) {
		return ATTESTATION_INVALID_ARGUMENT;
	}

	return aux_attestation_unseal (attestation->aux, hash, attestation->pcr_store, key_type, seed,
		seed_length, seed_type, seed_param, hmac, hmac_type, ciphertext, cipher_length, sealing,
		pcr_count, key, key_length);
}

static int attestation_slave_aux_attestation_unseal_unsupported (
	struct attestation_slave *attestation, struct hash_engine *hash,
	enum aux_attestation_key_length key_type, const uint8_t *seed, size_t seed_length,
	enum aux_attestation_seed_type seed_type, enum aux_attestation_seed_param seed_param,
	const uint8_t *hmac, enum hmac_hash hmac_type, const uint8_t *ciphertext, size_t cipher_length,
	const uint8_t sealing[][64], size_t pcr_count, uint8_t *key, size_t key_length)
{
	return ATTESTATION_UNSUPPORTED_OPERATION;
}

static int attestation_slave_aux_decrypt (struct attestation_slave *attestation,
	const uint8_t *encrypted, size_t len_encrypted, const uint8_t *label, size_t len_label,
	enum hash_type pad_hash, uint8_t *decrypted, size_t len_decrypted)
{
	if (attestation == NULL) {
		return ATTESTATION_INVALID_ARGUMENT;
	}

	return aux_attestation_decrypt (attestation->aux, encrypted, len_encrypted, label,
		len_label, pad_hash, decrypted, len_decrypted);
}

static int attestation_slave_aux_decrypt_unsupported (struct attestation_slave *attestation,
	const uint8_t *encrypted, size_t len_encrypted, const uint8_t *label, size_t len_label,
	enum hash_type pad_hash, uint8_t *decrypted, size_t len_decrypted)
{
	return ATTESTATION_UNSUPPORTED_OPERATION;
}

static int attestation_slave_generate_ecdh_seed (struct attestation_slave *attestation,
	const uint8_t *pub_key, size_t key_length, bool hash_seed, uint8_t *seed, size_t seed_length)
{
	if (attestation == NULL) {
		return ATTESTATION_INVALID_ARGUMENT;
	}

	return aux_attestation_generate_ecdh_seed (attestation->aux, pub_key, key_length,
		(hash_seed) ? attestation->hash : NULL, seed, seed_length);
}

static int attestation_slave_generate_ecdh_seed_unsupported (struct attestation_slave *attestation,
	const uint8_t *pub_key, size_t key_length, bool hash_seed, uint8_t *seed, size_t seed_length)
{
	return ATTESTATION_UNSUPPORTED_OPERATION;
}

/**
 * Initialize the common components for slave attestation management.
 *
 * @param attestation Slave attestation manager instance to initialize.
 * @param riot RIoT key manager.
 * @param hash The hash engine to utilize.
 * @param ecc The ECC engine to utilize.
 * @param rng The RNG engine to utilize.
 * @param store PCR store to utilize.
 * @param min_protocol_version Minimum protocol version supported by the device.
 * @param max_protocol_version Maximum protocol version supported by the device.
 *
 * @return Initialization status, 0 if success or an error code.
 */
static int attestation_slave_init_common (struct attestation_slave *attestation,
	struct riot_key_manager *riot, struct hash_engine *hash, struct ecc_engine *ecc,
	struct rng_engine *rng, struct pcr_store *store, uint8_t min_protocol_version,
	uint8_t max_protocol_version)
{
	const struct riot_keys *keys;
	int status;

	if ((attestation == NULL) || (riot == NULL) || (hash == NULL) || (ecc == NULL) ||
		(rng == NULL) || (store == NULL)) {
		return ATTESTATION_INVALID_ARGUMENT;
	}

	memset (attestation, 0, sizeof (struct attestation_slave));

	keys = riot_key_manager_get_riot_keys (riot);
	status = ecc->init_key_pair (ecc, keys->alias_key, keys->alias_key_length,
		&attestation->ecc_priv_key, NULL);
	riot_key_manager_release_riot_keys (riot, keys);
	if (status != 0) {
		return status;
	}

	status = platform_mutex_init (&attestation->lock);
	if (status != 0) {
		ecc->release_key_pair (ecc, &attestation->ecc_priv_key, NULL);
		return status;
	}

	attestation->riot = riot;
	attestation->hash = hash;
	attestation->ecc = ecc;
	attestation->rng = rng;
	attestation->pcr_store = store;
	attestation->min_protocol_version = min_protocol_version;
	attestation->max_protocol_version = max_protocol_version;

	attestation->get_digests = attestation_slave_get_digests;
	attestation->get_certificate = attestation_slave_get_certificate;
	attestation->challenge_response = attestation_slave_challenge_response;

	return 0;
}

/**
 * Initialize a slave attestation manager.
 *
 * @param attestation Slave attestation manager instance to initialize.
 * @param riot RIoT key manager.
 * @param hash The hash engine to utilize.
 * @param ecc The ECC engine to utilize.
 * @param rng The RNG engine to utilize.
 * @param store PCR store to utilize.
 * @param aux Aux attestation service handler to utilize.
 * @param min_protocol_version Minimum protocol version supported by the device.
 * @param max_protocol_version Maximum protocol version supported by the device.
 *
 * @return Initialization status, 0 if success or an error code.
 */
int attestation_slave_init (struct attestation_slave *attestation,
	struct riot_key_manager *riot, struct hash_engine *hash, struct ecc_engine *ecc,
	struct rng_engine *rng, struct pcr_store *store, struct aux_attestation *aux,
	uint8_t min_protocol_version, uint8_t max_protocol_version)
{
	int status;

	if (aux == NULL) {
		return ATTESTATION_INVALID_ARGUMENT;
	}

	status = attestation_slave_init_common (attestation, riot, hash, ecc, rng, store,
		min_protocol_version, max_protocol_version);
	if (status != 0) {
		return status;
	}

	attestation->aux = aux;

	attestation->aux_attestation_unseal = attestation_slave_aux_attestation_unseal;
	attestation->aux_decrypt = attestation_slave_aux_decrypt;
	attestation->generate_ecdh_seed = attestation_slave_generate_ecdh_seed;

	return 0;
}

/**
 * Initialize a slave attestation manager that does not support auxiliary attestation requests.
 *
 * @param attestation Slave attestation manager instance to initialize.
 * @param riot RIoT key manager.
 * @param hash The hash engine to utilize.
 * @param ecc The ECC engine to utilize.
 * @param rng The RNG engine to utilize.
 * @param store PCR store to utilize.
 * @param min_protocol_version Minimum protocol version supported by the device.
 * @param max_protocol_version Maximum protocol version supported by the device.
 *
 * @return Initialization status, 0 if success or an error code.
 */
int attestation_slave_init_no_aux (struct attestation_slave *attestation,
	struct riot_key_manager *riot, struct hash_engine *hash, struct ecc_engine *ecc,
	struct rng_engine *rng, struct pcr_store *store, uint8_t min_protocol_version,
	uint8_t max_protocol_version)
{
	int status;

	status = attestation_slave_init_common (attestation, riot, hash, ecc, rng, store,
		min_protocol_version, max_protocol_version);
	if (status != 0) {
		return status;
	}

	attestation->aux_attestation_unseal = attestation_slave_aux_attestation_unseal_unsupported;
	attestation->aux_decrypt = attestation_slave_aux_decrypt_unsupported;
	attestation->generate_ecdh_seed = attestation_slave_generate_ecdh_seed_unsupported;

	return 0;
}

/**
 * Release slave attestation manager
 *
 * @param attestation Slave attestation manager instance to release
 */
void attestation_slave_release (struct attestation_slave *attestation)
{
	if (attestation) {
		attestation->ecc->release_key_pair (attestation->ecc, &attestation->ecc_priv_key, NULL);
		platform_mutex_free (&attestation->lock);
	}
}
