// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "spdm_certificate_chain_dice.h"
#include "common/buffer_util.h"
#include "common/type_cast.h"
#include "common/unused.h"
#include "crypto/ecdsa.h"


/**
 * Prepare the SPDM certificate chain header for the device DICE certificates.  This will also
 * retrieve the certs from the DICE key manager.  The DICE keys will need to be released after a
 * successful return.
 *
 * @param dice The SPDM DICE certificate manager.
 * @param hash The hash engine to use for root CA digest calculation.
 * @param root_ca_hash Hash algorithm to use for the root CA hash.
 * @param header Output for the SPDM certificate chain header.
 * @param digest_length Output for the length of the root CA digest.
 * @param keys Output for the device DICE certificates.
 * @param root_ca Output for the root CA for the DICE certificate chain.
 * @param intermediate_ca Outut for the intermediate CA for the DICE certificate chain.
 *
 * @return 0 if the certificate chain header was created successfully or an error code.
 */
static int spdm_certificate_chain_dice_prepare_header (
	const struct spdm_certificate_chain_dice *dice, const struct hash_engine *hash,
	enum hash_type root_ca_hash, struct spdm_certificate_chain_header *header, int *digest_length,
	const struct riot_keys **keys, const struct der_cert **root_ca,
	const struct der_cert **intermediate_ca)
{
	int status;
	const struct riot_keys *local_keys;
	const struct der_cert *local_root_ca;
	const struct der_cert *local_intermediate_ca;

	local_keys = riot_key_manager_get_riot_keys (dice->certs);

	/* There should never be a scenario where either the Device ID or Alias cert don't have valid
	 * data, but just sanity check them to make sure. */
	if ((local_keys->devid_cert == NULL) || (local_keys->devid_cert_length == 0) ||
		(local_keys->alias_cert == NULL) || (local_keys->alias_cert_length == 0)) {
		status = SPDM_CERT_CHAIN_MISSING_CERT;
		goto error;
	}

	local_root_ca = riot_key_manager_get_root_ca (dice->certs);
	local_intermediate_ca = riot_key_manager_get_intermediate_ca (dice->certs);

	if (root_ca != NULL) {
		*root_ca = local_root_ca;
	}
	if (intermediate_ca != NULL) {
		*intermediate_ca = local_intermediate_ca;
	}

	/* Get the appropriate digest for the current root CA certificate. */
	if (hash != NULL) {
		if (local_root_ca != NULL) {
			*digest_length = hash_calculate (hash, root_ca_hash, (local_root_ca)->cert,
				(local_root_ca)->length, header->root_hash, sizeof (header->root_hash));
		}
		else {
			*digest_length = hash_calculate (hash, root_ca_hash, local_keys->devid_cert,
				local_keys->devid_cert_length, header->root_hash, sizeof (header->root_hash));
		}
	}
	else {
		*digest_length = hash_get_hash_length (root_ca_hash);
	}

	if (ROT_IS_ERROR (*digest_length)) {
		status = *digest_length;
		goto error;
	}

	/* Calculate the total length of the SPDM certificate chain. */
	header->min_hdr.length = sizeof (header->min_hdr) + *digest_length;
	if (local_root_ca != NULL) {
		header->min_hdr.length += local_root_ca->length;
	}
	if (local_intermediate_ca != NULL) {
		header->min_hdr.length += local_intermediate_ca->length;
	}
	header->min_hdr.length += local_keys->devid_cert_length;
	header->min_hdr.length += local_keys->alias_cert_length;

	if (keys != NULL) {
		*keys = local_keys;
		local_keys = NULL;
	}

	status = 0;

error:
	if (local_keys != NULL) {
		riot_key_manager_release_riot_keys (dice->certs, local_keys);
	}

	return status;
}

int spdm_certificate_chain_dice_get_digest (const struct spdm_certificate_chain *chain,
	const struct hash_engine *hash, enum hash_type hash_type, uint8_t *digest, size_t length)
{
	const struct spdm_certificate_chain_dice *dice = TO_DERIVED_TYPE (chain,
		const struct spdm_certificate_chain_dice, base);
	struct spdm_certificate_chain_header header = {0};
	int digest_length;
	const struct riot_keys *keys;
	const struct der_cert *root_ca;
	const struct der_cert *intermediate_ca;
	int status;

	if ((chain == NULL) || (hash == NULL) || (digest == NULL)) {
		return SPDM_CERT_CHAIN_INVALID_ARGUMENT;
	}

	status = spdm_certificate_chain_dice_prepare_header (dice, hash, hash_type, &header,
		&digest_length, &keys, &root_ca, &intermediate_ca);
	if (status != 0) {
		return status;
	}

	status = hash_start_new_hash (hash, hash_type);
	if (status != 0) {
		goto exit;
	}

	status = hash->update (hash, (uint8_t*) &header, sizeof (header.min_hdr) + digest_length);
	if (status != 0) {
		goto cancel;
	}

	if (root_ca != NULL) {
		status = hash->update (hash, root_ca->cert, root_ca->length);
		if (status != 0) {
			goto cancel;
		}
	}

	if (intermediate_ca != NULL) {
		status = hash->update (hash, intermediate_ca->cert, intermediate_ca->length);
		if (status != 0) {
			goto cancel;
		}
	}

	status = hash->update (hash, keys->devid_cert, keys->devid_cert_length);
	if (status != 0) {
		goto cancel;
	}

	status = hash->update (hash, keys->alias_cert, keys->alias_cert_length);
	if (status != 0) {
		goto cancel;
	}

	status = hash->finish (hash, digest, length);

cancel:
	if (status != 0) {
		hash->cancel (hash);
	}

exit:
	riot_key_manager_release_riot_keys (dice->certs, keys);

	return status;
}

int spdm_certificate_chain_dice_get_certificate_chain_length (
	const struct spdm_certificate_chain *chain, enum hash_type hash_type, size_t *total_length)
{
	const struct spdm_certificate_chain_dice *dice = TO_DERIVED_TYPE (chain,
		const struct spdm_certificate_chain_dice, base);
	struct spdm_certificate_chain_header header = {0};
	int digest_length;
	int status;

	if ((chain == NULL) || (total_length == NULL)) {
		return SPDM_CERT_CHAIN_INVALID_ARGUMENT;
	}

	status = spdm_certificate_chain_dice_prepare_header (dice, NULL, hash_type, &header,
		&digest_length, NULL, NULL, NULL);
	if (status != 0) {
		return status;
	}

	*total_length = header.min_hdr.length;

	return status;
}

int spdm_certificate_chain_dice_get_certificate_chain (const struct spdm_certificate_chain *chain,
	const struct hash_engine *hash, enum hash_type root_ca_hash, size_t offset, uint8_t *buffer,
	size_t *length, size_t *total_length)
{
	const struct spdm_certificate_chain_dice *dice = TO_DERIVED_TYPE (chain,
		const struct spdm_certificate_chain_dice, base);
	struct spdm_certificate_chain_header header = {0};
	size_t copied_length;
	int digest_length;
	const struct riot_keys *keys;
	const struct der_cert *root_ca;
	const struct der_cert *intermediate_ca;
	int status;

	if ((chain == NULL) || (hash == NULL) || (buffer == NULL) || (length == NULL) ||
		(total_length == NULL) || (*length == 0)) {
		return SPDM_CERT_CHAIN_INVALID_ARGUMENT;
	}

	status = spdm_certificate_chain_dice_prepare_header (dice, hash, root_ca_hash, &header,
		&digest_length, &keys, &root_ca, &intermediate_ca);
	if (status != 0) {
		return status;
	}

	/* Copy the requested certificate chain data into the output buffer. */
	copied_length = buffer_copy ((uint8_t*) &header, sizeof (header.min_hdr) + digest_length,
		&offset, length, buffer);

	if (root_ca != NULL) {
		copied_length += buffer_copy (root_ca->cert, root_ca->length, &offset, length,
			&buffer[copied_length]);
	}

	if (intermediate_ca != NULL) {
		copied_length += buffer_copy (intermediate_ca->cert, intermediate_ca->length, &offset,
			length, &buffer[copied_length]);
	}

	copied_length += buffer_copy (keys->devid_cert, keys->devid_cert_length, &offset, length,
		&buffer[copied_length]);

	copied_length += buffer_copy (keys->alias_cert, keys->alias_cert_length, &offset, length,
		&buffer[copied_length]);

	*length = copied_length;
	*total_length = header.min_hdr.length;

	riot_key_manager_release_riot_keys (dice->certs, keys);

	return 0;
}

int spdm_certificate_chain_dice_sign_message (const struct spdm_certificate_chain *chain,
	const struct ecc_engine *ecc, const struct hash_engine *hash, enum hash_type hash_algo,
	const uint8_t *message, size_t msg_length, uint8_t *signature, size_t sig_length)
{
	const struct spdm_certificate_chain_dice *dice = TO_DERIVED_TYPE (chain,
		const struct spdm_certificate_chain_dice, base);
	const struct riot_keys *keys;
	int sig_out_length;

	if (chain == NULL) {
		return SPDM_CERT_CHAIN_INVALID_ARGUMENT;
	}

	keys = riot_key_manager_get_riot_keys (dice->certs);

	sig_out_length = ecdsa_sign_message (ecc, hash, hash_algo, NULL, keys->alias_key,
		keys->alias_key_length, message, msg_length, signature, sig_length);

	riot_key_manager_release_riot_keys (dice->certs, keys);

	return sig_out_length;
}

/**
 * Initialize a DICE certificate chain manager for SPDM.
 *
 * @param chain The certificate chain manager to initialize.
 * @param dice_certs Device manager for the DICE certificate chain.
 *
 * @return 0 if the SPDM manager was initialized successfully or an error code.
 */
int spdm_certificate_chain_dice_init (struct spdm_certificate_chain_dice *chain,
	const struct riot_key_manager *dice_certs)
{
	if ((chain == NULL) || (dice_certs == NULL)) {
		return SPDM_CERT_CHAIN_INVALID_ARGUMENT;
	}

	memset (chain, 0, sizeof (*chain));

	chain->base.get_digest = spdm_certificate_chain_dice_get_digest;
	chain->base.get_certificate_chain_length =
		spdm_certificate_chain_dice_get_certificate_chain_length;
	chain->base.get_certificate_chain = spdm_certificate_chain_dice_get_certificate_chain;
	chain->base.sign_message = spdm_certificate_chain_dice_sign_message;

	chain->certs = dice_certs;

	return 0;
}

/**
 * Release the resources used to manage the DICE certificate chain for SPDM.
 *
 * @param chain The certificate chain manager to release.
 */
void spdm_certificate_chain_dice_release (const struct spdm_certificate_chain_dice *chain)
{
	UNUSED (chain);
}
