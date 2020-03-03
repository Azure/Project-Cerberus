// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ATTESTATION_SLAVE_H_
#define ATTESTATION_SLAVE_H_

#include <stdint.h>
#include "status/rot_status.h"
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
	 * @param buf Output buffer to be filled with the certificate digests.
	 * @param buf_len Maximum length of buffer as input.
	 * @param num_cert Number of certificates in output buffer
	 *
	 * @return Output length if the digests was successfully computed or an error code.
	 */
	int (*get_digests) (struct attestation_slave *attestation, uint8_t *buf, int buf_len,
		uint8_t *num_cert);

	/**
	 * Get certificate from the attestation manager certificate chain.
	 *
	 * @param attestation The slave attestation manager interface to utilize.
	 * @param slot_num The slot number for the certificate chain to utilize.
	 * @param cert_num The certificate number of the chain to retrieve.
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
	int (*challenge_response) (struct attestation_slave *attestation, uint8_t *buf, int buf_len);

	/**
	 * Unseal an encryption key for auxiliary attestation flows.
	 *
	 * @param attestation The slave attestation manager interface to utilize.
	 * @param hash Hashing engine to utilize.
	 * @param seed The request seed encrypted with the attestation public key.
	 * @param seed_length The length of the request seed.
	 * @param hmac The HMAC for the attestation request. This is an HMAC-SHA256 value.
	 * @param ciphertext The encrypted attestation data.
	 * @param cipher_length Length of the encrypted data.
	 * @param sealing A 64-byte sealing value for the attestation data.
	 * @param key Output for the unsealed encryption key that will decrypt the attestation data.
	 * @param key_length Length of the key buffer.
	 * @param platform_pcr PCR to utilize for platform measurement.
	 *
	 * @return Encryption key length if the unsealing was successful or an error code.
	 */
	int (*aux_attestation_unseal) (struct attestation_slave *attestation, struct hash_engine *hash,
		const uint8_t *seed, size_t seed_length, const uint8_t *hmac, const uint8_t *ciphertext,
		size_t cipher_length, const uint8_t *sealing, uint8_t *key, size_t key_length,
		uint8_t platform_pcr);

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
	 * @return Decrypted payload length if the decryption was successful or an error code.
	 */
	int (*aux_decrypt) (struct attestation_slave *attestation, const uint8_t *encrypted,
		size_t len_encrypted, const uint8_t *label, size_t len_label, enum hash_type pad_hash,
		uint8_t *decrypted, size_t len_decrypted);

	struct ecc_private_key ecc_priv_key;	/**< RIoT ECC private key. */
	struct hash_engine *hash;				/**< The hashing engine for attestation authentication operations. */
	struct ecc_engine *ecc;					/**< The ECC engine for attestation authentication operations. */
	struct rng_engine *rng;					/**< The RNG engine for attestation authentication operations. */
	struct riot_key_manager *riot;			/**< The manager for RIoT keys. */
	struct pcr_store *pcr_store;			/**< Storage for device measurements. */
	struct aux_attestation *aux;			/**< Auxiliary attestation service handler. */
};


int attestation_slave_init (struct attestation_slave *attestation, struct riot_key_manager *riot,
	struct hash_engine *hash, struct ecc_engine *ecc, struct rng_engine *rng,
	struct pcr_store *store, struct aux_attestation *aux);
int attestation_slave_init_no_aux (struct attestation_slave *attestation,
	struct riot_key_manager *riot, struct hash_engine *hash, struct ecc_engine *ecc,
	struct rng_engine *rng, struct pcr_store *store);

void attestation_slave_release (struct attestation_slave *attestation);


#endif // ATTESTATION_SLAVE_H_
