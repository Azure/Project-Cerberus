// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <string.h>
#include "platform.h"
#include "crypto/ecc.h"
#include "crypto/x509.h"
#include "crypto/hash.h"
#include "crypto/rng.h"
#include "crypto/rsa.h"
#include "riot/riot_key_manager.h"
#include "common/certificate.h"
#include "cmd_interface/device_manager.h"
#include "attestation.h"
#include "attestation_master.h"


/**
 * Load and authenticate certifcate chain then return leaf DER public key.
 *
 * @param attestation The attestation manager to utilize.
 * @param chain Certificate chain buffer.
 * @param der Output DER public key.
 * @param length Output DER public key length.
 *
 * @return 0 if completed successfully or an error code.
 */
static int attestation_verify_and_load_leaf_key (struct attestation_master *attestation,
	struct device_manager_cert_chain *chain, uint8_t **der, size_t *length)
{
	struct x509_ca_certs certs_chain;
	struct x509_certificate cert;
	const struct der_cert *root_ca = riot_key_manager_get_root_ca (attestation->riot);
	uint8_t *leaf_key = NULL;
	size_t leaf_key_len = 0;
	int8_t i_cert;
	int status;

	if (chain->num_cert < 2) {
		return ATTESTATION_INVALID_CERT_CHAIN;
	}

	status = attestation->x509->init_ca_cert_store (attestation->x509, &certs_chain);
	if (status != 0) {
		return status;
	}

	if (root_ca != NULL) {
		status = attestation->x509->add_root_ca (attestation->x509, &certs_chain, root_ca->cert,
			root_ca->length);
		if (status != 0) {
			goto release_cert_store;
		}
	}
	else {
		status = attestation->x509->add_root_ca (attestation->x509, &certs_chain,
			chain->cert[0].cert, chain->cert[0].length);
		if (status != 0) {
			goto release_cert_store;
		}
	}

	for (i_cert = 1; i_cert < (chain->num_cert - 1); ++i_cert) {
		status = attestation->x509->add_intermediate_ca (attestation->x509, &certs_chain,
			chain->cert[i_cert].cert, chain->cert[i_cert].length);
		if (status != 0) {
			goto release_cert_store;
		}
	}

	status = attestation->x509->load_certificate (attestation->x509, &cert,
		chain->cert[chain->num_cert - 1].cert, chain->cert[chain->num_cert - 1].length);
	if (status != 0) {
		goto release_cert_store;
	}

	status = attestation->x509->authenticate (attestation->x509, &cert, &certs_chain);
	if (status != 0) {
		goto release_leaf_cert;
	}

	status = attestation->x509->get_public_key (attestation->x509, &cert, &leaf_key, &leaf_key_len);
	if (status != 0) {
		goto release_leaf_cert;
	}

	*der = leaf_key;
	*length = leaf_key_len;

release_leaf_cert:
	attestation->x509->release_certificate (attestation->x509, &cert);

release_cert_store:
	attestation->x509->release_ca_cert_store (attestation->x509, &certs_chain);

	return status;
}

/**
 * Load and authenticate certifcate chain then return leaf certificate public key.
 *
 * @param attestation The attestation manager to utilize.
 * @param chain Certificate chain buffer.
 * @param key Output ECC public key.
 *
 * @return 0 if completed successfully or an error code.
 */
static int attestation_verify_and_load_ecc_leaf_key (struct attestation_master *attestation,
	struct device_manager_cert_chain *chain, struct ecc_public_key *key)
{
	uint8_t *der;
	size_t length;
	int status;

	status = attestation_verify_and_load_leaf_key (attestation, chain, &der, &length);
	if (status != 0) {
		return status;
	}

	status = attestation->ecc->init_public_key (attestation->ecc, der, length, key);

	platform_free (der);

	return status;
}

#ifdef ATTESTATION_SUPPORT_RSA_CHALLENGE
/**
 * Load and authenticate certificate chain then return leaf certificate public key.
 *
 * @param attestation The attestation manager to utilize.
 * @param chain Certificate chain buffer.
 * @param key Output RSA public key.
 *
 * @return 0 if completed successfully or an error code.
 */
static int attestation_verify_and_load_rsa_leaf_key (struct attestation_master *attestation,
	struct device_manager_cert_chain *chain, struct rsa_public_key *key)
{
	uint8_t *der;
	size_t length;
	int status;

	status = attestation_verify_and_load_leaf_key (attestation, chain, &der, &length);
	if (status != 0) {
		return status;
	}

	status = attestation->rsa->init_public_key (attestation->rsa, key, der, length);

	platform_free (der);

	return status;
}
#endif

/**
 * Generate digests for certificates in device certificate chain
 *
 * @param attestation The attestation manager to utilize.
 * @param device_num Device number.
 * @param digest_buffer Output digest buffer. CALLER MUST FREE.
 *
 * @return 0 if the digests were successfully computed or an error code.
 */
static int attestation_get_chain_digests (struct attestation_master *attestation,
	uint8_t device_num, struct attestation_chain_digest *digests)
{
	struct device_manager_cert_chain chain;
	uint8_t i_cert;
	int status;

	status = device_manager_get_device_cert_chain (attestation->device_manager, device_num,
		&chain);
	if (status != 0) {
		return status;
	}

	digests->digest = platform_calloc (chain.num_cert, SHA256_HASH_LENGTH);
	if (digests->digest == NULL) {
		return ATTESTATION_NO_MEMORY;
	}

	for (i_cert = 0; i_cert < chain.num_cert; ++i_cert) {
		if ((chain.cert[i_cert].cert == NULL) || (chain.cert[i_cert].length == 0)) {
			continue;
		}

		status = attestation->hash->calculate_sha256 (attestation->hash, chain.cert[i_cert].cert,
			chain.cert[i_cert].length, &digests->digest[i_cert * SHA256_HASH_LENGTH],
			SHA256_HASH_LENGTH);
		if (status != 0) {
			platform_free (digests->digest);

			return status;
		}
	}

	digests->digest_len = SHA256_HASH_LENGTH;
	digests->num_cert = chain.num_cert;

	return 0;
}

/**
 * Retrieve public key algorithm from x509 certificate
 *
 * @param x509 x509 engine to utilize.
 * @param cert DER formatted certificate to inspect.
 *
 * @return Public key type if found successfully or an error code.
 */
static int attestation_get_cert_algorithm (struct x509_engine *x509, struct der_cert *cert)
{
	struct x509_certificate x509_cert;
	int status;

	status = x509->load_certificate (x509, &x509_cert, cert->cert, cert->length);
	if (status != 0) {
		return status;
	}

	status = x509->get_public_key_type (x509, &x509_cert);
	x509->release_certificate (x509, &x509_cert);

	return status;
}

static int attestation_generate_challenge_request (struct attestation_master *attestation, 
	uint8_t eid, uint8_t slot_num, struct attestation_challenge *challenge)
{
	int device_num;
	int status;

	if ((attestation == NULL) || (challenge == NULL)) {
		return ATTESTATION_INVALID_ARGUMENT;
	}

	if (slot_num != ATTESTATION_RIOT_SLOT_NUM) {
		return ATTESTATION_INVALID_SLOT_NUM;
	}

	device_num = device_manager_get_device_num (attestation->device_manager, eid);
	if (ROT_IS_ERROR (device_num)) {
		return device_num;
	}

	memset (challenge, 0, sizeof (struct attestation_challenge));

	challenge->slot_num = slot_num;

	status = attestation->rng->generate_random_buffer (attestation->rng,
		sizeof (challenge->nonce), challenge->nonce);
	if (status != 0) {
		return status;
	}

	memcpy (&attestation->challenge[device_num], challenge, sizeof (struct attestation_challenge));

	return sizeof (struct attestation_challenge);
}

static int attestation_compare_digests (struct attestation_master *attestation, uint8_t eid,
	struct attestation_chain_digest *digests)
{
	struct attestation_chain_digest computed_digests;
	struct device_manager_cert_chain chain;
	uint8_t i_digest;
	int device_num;
	int status;

	if ((attestation == NULL) || (digests == NULL)) {
		return ATTESTATION_INVALID_ARGUMENT;
	}

	device_num = device_manager_get_device_num (attestation->device_manager, eid);
	if (ROT_IS_ERROR (device_num)) {
		return device_num;
	}

	status = device_manager_get_device_cert_chain (attestation->device_manager, device_num, &chain);
	if (status != 0) {
		return status;
	}

	if (chain.num_cert != digests->num_cert) {
		status = device_manager_init_cert_chain (attestation->device_manager, device_num,
			digests->num_cert);
		if (status != 0) {
			return status;
		}

		return 1;
	}

	status = attestation_get_chain_digests (attestation, device_num, &computed_digests);
	if (status != 0) {
		return status;
	}

	for (i_digest = 0; i_digest < computed_digests.num_cert; ++i_digest) {
		if (memcmp (&computed_digests.digest[computed_digests.digest_len * i_digest],
			&digests->digest[computed_digests.digest_len * i_digest], computed_digests.digest_len)){
			status = i_digest + 1;
			break;
		}
	}

	platform_free (computed_digests.digest);

	return status;
}

static int attestation_store_certificate (struct attestation_master *attestation, uint8_t eid,
	uint8_t slot_num, uint8_t cert_num, const uint8_t *buf, size_t buf_len)
{
	int device_num;

	if (attestation == NULL) {
		return ATTESTATION_INVALID_ARGUMENT;
	}

	if (slot_num != ATTESTATION_RIOT_SLOT_NUM) {
		return ATTESTATION_INVALID_SLOT_NUM;
	}

	device_num = device_manager_get_device_num (attestation->device_manager, eid);
	if (ROT_IS_ERROR (device_num)) {
		return device_num;
	}

	return device_manager_update_cert (attestation->device_manager, device_num, cert_num, buf, buf_len);
}

static int attestation_process_challenge_response (struct attestation_master *attestation,
	uint8_t *buf, size_t buf_len, uint8_t eid)
{
	struct device_manager_cert_chain chain;
	uint8_t challenge[ATTESTATION_NONCE_LEN + 2];
	uint8_t digest[SHA256_HASH_LENGTH];
	int device_num;
	int sig_len;
	int key_type;
	int status;

	if ((attestation == NULL) || (buf == NULL)) {
		return ATTESTATION_INVALID_ARGUMENT;
	}

	if (buf_len <= 72) {
		return ATTESTATION_INVALID_ARGUMENT;
	}

	sig_len = buf_len - 72;
	device_num = device_manager_get_device_num (attestation->device_manager, eid);
	if (ROT_IS_ERROR (device_num)) {
		return device_num;
	}

	if (buf[0] != 0) {
		return ATTESTATION_INVALID_SLOT_NUM;
	}

	if ((attestation->protocol_version < buf[2]) || (attestation->protocol_version > buf[3])) {
		return ATTESTATION_UNSUPPORTED_PROTOCOL_VERSION;
	}

	status = device_manager_get_device_cert_chain (attestation->device_manager, device_num, &chain);
	if (status != 0) {
		return status;
	}

	key_type = attestation_get_cert_algorithm (attestation->x509, &chain.cert[chain.num_cert - 1]);
	if (ROT_IS_ERROR (key_type)) {
		return key_type;
	}

	memcpy (&challenge, (uint8_t*) &attestation->challenge[device_num],
		sizeof (struct attestation_challenge));

	status = attestation->hash->start_sha256 (attestation->hash);
	if (status != 0) {
		return status;
	}

	status = attestation->hash->update (attestation->hash, challenge, sizeof (challenge));
	if (status != 0) {
		goto hash_cancel;
	}

	status = attestation->hash->update (attestation->hash, buf, buf_len - sig_len);
	if (status != 0) {
		goto hash_cancel;
	}

	status = attestation->hash->finish (attestation->hash, digest, SHA256_HASH_LENGTH);
	if (status != 0) {
		goto hash_cancel;
	}

	if (key_type == X509_PUBLIC_KEY_ECC) {
		struct ecc_public_key ecc_key;

		status = attestation_verify_and_load_ecc_leaf_key (attestation, &chain, &ecc_key);
		if (status != 0) {
			return status;
		}

		status = attestation->ecc->verify (attestation->ecc, &ecc_key, digest, SHA256_HASH_LENGTH,
			&buf[buf_len - sig_len], sig_len);

		attestation->ecc->release_key_pair (attestation->ecc, NULL, &ecc_key);
	}
#ifdef ATTESTATION_SUPPORT_RSA_CHALLENGE
	else if ((key_type == X509_PUBLIC_KEY_RSA) && (attestation->rsa != NULL)) {
		struct rsa_public_key rsa_key;

		status = attestation_verify_and_load_rsa_leaf_key (attestation, &chain, &rsa_key);
		if (status != 0) {
			return status;
		}

		status = attestation->rsa->sig_verify (attestation->rsa, &rsa_key, &buf[buf_len - sig_len],
			sig_len, digest, SHA256_HASH_LENGTH);
	}
#endif
	else {
		return ATTESTATION_UNSUPPORTED_ALGORITHM;
	}

	if (status == 0) {
		status = device_manager_update_device_state (attestation->device_manager, device_num,
			DEVICE_MANAGER_AUTHENTICATED);
	}
	else {
		device_manager_update_device_state (attestation->device_manager, device_num,
			DEVICE_MANAGER_AVAILABLE);
	}

	return status;

hash_cancel:
	attestation->hash->cancel (attestation->hash);

	return status;
}

/**
 * Initialize an master attestation manager.
 *
 * @param attestation Master attestation manager instance to initialize.
 * @param riot RIoT key manager.
 * @param hash The hash engine to utilize.
 * @param ecc The ECC engine to utilize.
 * @param rsa The RSA engine to utilize.
 * @param x509 The x509 engine to utilize.
 * @param rng The RNG engine to utilize.
 * @param device_manager Device manager table.
 * @param protocol_version Cerberus protocol version
 *
 * @return Initialization status, 0 if success or an error code.
 */
int attestation_master_init (struct attestation_master *attestation,
	struct riot_key_manager *riot, struct hash_engine *hash, struct ecc_engine *ecc,
	struct rsa_engine *rsa, struct x509_engine *x509, struct rng_engine *rng,
	struct device_manager *device_manager, uint8_t protocol_version)
{
	if ((attestation == NULL) || (riot == NULL) || (hash == NULL) || (x509 == NULL) ||
		(rng == NULL) || (device_manager == NULL) || (ecc == NULL)) {
		return ATTESTATION_INVALID_ARGUMENT;
	}

	memset (attestation, 0, sizeof (struct attestation_master));

	attestation->challenge = platform_calloc (device_manager->num_devices,
		sizeof (struct attestation_challenge));
	if (attestation->challenge == NULL) {
		return ATTESTATION_NO_MEMORY;
	}

	attestation->riot = riot;
	attestation->hash = hash;
	attestation->ecc = ecc;
	attestation->rsa = rsa;
	attestation->x509 = x509;
	attestation->rng = rng;
	attestation->device_manager = device_manager;
	attestation->protocol_version = protocol_version;

	attestation->generate_challenge_request = attestation_generate_challenge_request;
	attestation->compare_digests = attestation_compare_digests;
	attestation->store_certificate = attestation_store_certificate;
	attestation->process_challenge_response = attestation_process_challenge_response;

	return 0;
}

/**
 * Release master attestation manager
 *
 * @param attestation Master attestation manager instance to release
 */
void attestation_master_release (struct attestation_master *attestation)
{
	if (attestation) {
		platform_free (attestation->challenge);
	}
}
