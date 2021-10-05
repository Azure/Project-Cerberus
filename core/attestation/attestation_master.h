// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ATTESTATION_MASTER_H_
#define ATTESTATION_MASTER_H_

#include <stdint.h>
#include <stddef.h>
#include "status/rot_status.h"
#include "crypto/ecc.h"
#include "crypto/rsa.h"
#include "crypto/hash.h"
#include "crypto/x509.h"
#include "crypto/rng.h"
#include "riot/riot_key_manager.h"
#include "cmd_interface/device_manager.h"
#include "attestation.h"


struct attestation_master {
	/**
	 * Create an authentication challenge request.
	 *
	 * @param attestation The master attestation manager interface to utilize.
	 * @param eid EID of device to challenge.
	 * @param slot_num The slot number of the chain to use.
	 * @param challenge Buffer to be filled with challenge generated.
	 *
	 * @return Output length if the challenge was successfully created or an error code.
	 */
	int (*generate_challenge_request) (struct attestation_master *attestation, uint8_t eid,
		uint8_t slot_num, struct attestation_challenge *challenge);

	/**
	 * Process received certificate digests, and compare with stored digests.
	 *
	 * @param attestation The master attestation manager interface to utilize.
	 * @param eid Device EID.
	 * @param digests Received digests buffer.
	 *
	 * @return 0 if the digests match stored digests, index + 1 of certificate if mismatch,
	 *  or an error code if completed unsuccessfully.
	 */
	int (*compare_digests) (struct attestation_master *attestation, uint8_t eid,
		struct attestation_chain_digest *digests);

	/**
	 * Process and store received certificate from device.
	 *
	 * @param attestation The master attestation manager interface to utilize.
	 * @param eid EID of device being attested.
	 * @param slot_num Certificate chain slot number to utilize.
	 * @param cert_num Index in chain to store certificate in.
	 * @param buf Input buffer with certificate to store.
	 * @param buf_len Length of certificate buffer.
	 *
	 * @return 0 if the certificate was stored successfully or an error code.
	 */
	int (*store_certificate) (struct attestation_master *attestation, uint8_t eid, uint8_t slot_num,
		uint8_t cert_num, const uint8_t *buf, size_t buf_len);

	/**
	 * Process received challenge response, and update device authentication status.
	 *
	 * @param attestation The master attestation manager interface to utilize.
	 * @param buf Buffer containing received challenge response.
	 * @param buf_len Received challenge response buffer length.
	 * @param eid Address of device being challenged for attestation.
	 *
	 * @return 0 if processing completed successfully or an error code.
	 */
	int (*process_challenge_response) (struct attestation_master *attestation, uint8_t *buf,
		size_t buf_len, uint8_t eid);

	struct hash_engine *hash;					   		/**< The hashing engine for attestation authentication operations. */
	struct ecc_engine *ecc;						  		/**< The ECC engine for attestation authentication operations. */
	struct x509_engine *x509;					   		/**< The X509 engine for attestation authentication operations. */
	struct rng_engine *rng;						   		/**< The RNG engine for attestation authentication operations. */
	struct riot_key_manager *riot;						/**< RIoT key manager */
	struct device_manager *device_manager;				/**< Device manager */
	struct rsa_engine *rsa;								/**< The RSA engine for attestation authentication operations. */
	struct attestation_challenge *challenge;			/**< Store challenge sent out to device. */
	uint8_t protocol_version;							/**< Cerberus protocol version. */
};


int attestation_master_init (struct attestation_master *attestation,
	struct riot_key_manager *riot, struct hash_engine *hash, struct ecc_engine *ecc,
	struct rsa_engine *rsa, struct x509_engine *x509, struct rng_engine *rng,
	struct device_manager *device_manager, uint8_t protocol_version);

void attestation_master_release (struct attestation_master *attestation);


#endif // ATTESTATION_MASTER_H_
