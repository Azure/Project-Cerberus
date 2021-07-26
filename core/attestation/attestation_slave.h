// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ATTESTATION_SLAVE_H_
#define ATTESTATION_SLAVE_H_

#include <stdint.h>
#include <stdbool.h>
#include "status/rot_status.h"
#include "platform.h"
#include "crypto/ecc.h"
#include "crypto/hash.h"
#include "crypto/rng.h"
#include "common/certificate.h"
#include "riot/riot_key_manager.h"
#include "attestation/pcr_store.h"
#include "attestation/aux_attestation.h"
#include "attestation/attestation.h"


struct attestation_slave {
	/**
	 * Get the digests for all certificates in the certificate chain utilized by the attestation
	 * manager.
	 *
	 * @param attestation The slave attestation manager interface to utilize.
	 * @param slot_num The slot number for the certificate chain to query.
	 * @param buf Output buffer to be filled with the certificate digests.
	 * @param buf_len Maximum length of buffer as input.
	 * @param num_cert Number of certificates in output buffer
	 *
	 * @return Output length if the digests was successfully computed or an error code.
	 */
	int (*get_digests) (struct attestation_slave *attestation, uint8_t slot_num, uint8_t *buf,
		size_t buf_len, uint8_t *num_cert);

	/**
	 * Get certificate from the attestation manager certificate chain.
	 *
	 * @param attestation The slave attestation manager interface to utilize.
	 * @param slot_num The slot number for the certificate chain to retrieve.
	 * @param cert_num The certificate number in the chain to retrieve.
	 * @param cert Certificate buffer to fill. Caller must not free certificate buffers.
	 *
	 * @return 0 if the certificate was successfully retrieved or an error code.
	 */
	int (*get_certificate) (struct attestation_slave *attestation, uint8_t slot_num,
		uint8_t cert_num, struct der_cert *cert);

	/**
	 * Create authentication challenge response
	 *
	 * @param attestation The slave attestation manager interface to utilize.
	 * @param buf Buffer filled with incoming challenge and to be filled with outgoing response.
	 * @param buf_len Maximum length of buffer.
	 *
	 * @return Output length if the challenge was successfully created or an error code.
	 */
	int (*challenge_response) (struct attestation_slave *attestation, uint8_t *buf, size_t buf_len);

	/**
	 * Unseal an encryption key for auxiliary attestation flows.
	 *
	 * @param attestation The slave attestation manager interface to utilize.
	 * @param hash The hash engine to use for unsealing.
	 * @param key_type The length of the encryption and signing keys that will be generated.
	 * @param seed The obfuscated seed to use for key derivation.
	 * @param seed_length The length of the obfuscated seed.
	 * @param seed_type The method to use for determining the KDF seed.
	 * @param seed_param Details about the method used to determine the KDF seed.
	 * @param hmac HMAC of the ciphertext and sealing data using the signing key.
	 * @param hmac_type The type of HMAC used.
	 * @param ciphertext The encrypted attestation data.
	 * @param cipher_length Length of the encrypted data.
	 * @param sealing A list of 64-byte sealing values for the attestation data.
	 * @param pcr_count The number of PCRs used for sealing.
	 * @param key Output for the unsealed encryption key that will decrypt the attestation data.
	 * @param key_length Length of the encryption key buffer.  This must be large enough to support
	 * the requested key length.
	 *
	 * @return 0 if the unsealing was successful or an error code.
	 */
	int (*aux_attestation_unseal) (struct attestation_slave *attestation, struct hash_engine *hash,
		enum aux_attestation_key_length key_type, const uint8_t *seed, size_t seed_length,
		enum aux_attestation_seed_type seed_type, enum aux_attestation_seed_param seed_param,
		const uint8_t *hmac, enum hmac_hash hmac_type, const uint8_t *ciphertext,
		size_t cipher_length, const uint8_t sealing[][64], size_t pcr_count, uint8_t *key,
		size_t key_length);

	/**
	 * Decrypt a payload using the the auxiliary attestation key.
	 *
	 * @param attestation The slave attestation manager interface to utilize.
	 * @param encrypted Payload to decrypt.
	 * @param len_encrypted Length of payload to decrypt.
	 * @param label Optional label to use during decryption.
	 * @param len_label Length of the optional label.
	 * @param pad_hash Hash algorithm used for padding generation.
	 * @param decrypted Decrypted payload.
	 * @param len_decrypted Length of decrypted payload buffer.
	 *
	 * @return Decrypted payload length if the decryption was successful or an error code.  Use
	 * ROT_IS_ERROR to check the return value.
	 */
	int (*aux_decrypt) (struct attestation_slave *attestation, const uint8_t *encrypted,
		size_t len_encrypted, const uint8_t *label, size_t len_label, enum hash_type pad_hash,
		uint8_t *decrypted, size_t len_decrypted);

	/**
	 * Generate an attestation seed using ECDH.
	 *
	 * @param attestation The slave attestation manager interface to utilize.
	 * @param pub_key The DER encoded ECC public key to use for seed generation.
	 * @param key_length Length of the ECC public key.
	 * @param hash_seed true to calculate the SHA256 hash of the seed.
	 * @param seed Output for the generated attestation seed.
	 * @param seed_length Length of the seed output buffer.
	 *
	 * @return Length of the generated seed or an error code.  Use ROT_IS_ERROR to check the return
	 * value.
	 */
	int (*generate_ecdh_seed) (struct attestation_slave *attestation, const uint8_t *pub_key,
		size_t key_length, bool hash_seed, uint8_t *seed, size_t seed_length);

	struct ecc_private_key ecc_priv_key;	/**< RIoT ECC private key. */
	struct hash_engine *hash;				/**< The hashing engine for attestation authentication operations. */
	struct ecc_engine *ecc;					/**< The ECC engine for attestation authentication operations. */
	struct rng_engine *rng;					/**< The RNG engine for attestation authentication operations. */
	struct riot_key_manager *riot;			/**< The manager for RIoT keys. */
	struct pcr_store *pcr_store;			/**< Storage for device measurements. */
	struct aux_attestation *aux;			/**< Auxiliary attestation service handler. */
	uint8_t key_exchange_algorithm;			/**< Key exchange algorithm requested by caller. */
	uint8_t min_protocol_version;			/**< Minimum protocol version supported by the device. */
	uint8_t max_protocol_version;			/**< Maximum protocol version supported by the device. */
	platform_mutex lock;					/**< Synchronization for shared handlers. */
};


int attestation_slave_init (struct attestation_slave *attestation, struct riot_key_manager *riot,
	struct hash_engine *hash, struct ecc_engine *ecc, struct rng_engine *rng,
	struct pcr_store *store, struct aux_attestation *aux, uint8_t min_protocol_version,
	uint8_t max_protocol_version);
int attestation_slave_init_no_aux (struct attestation_slave *attestation,
	struct riot_key_manager *riot, struct hash_engine *hash, struct ecc_engine *ecc,
	struct rng_engine *rng, struct pcr_store *store, uint8_t min_protocol_version,
	uint8_t max_protocol_version);

void attestation_slave_release (struct attestation_slave *attestation);


#endif /* ATTESTATION_SLAVE_H_ */
