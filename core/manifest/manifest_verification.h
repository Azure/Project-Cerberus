// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MANIFEST_VERIFICATION_H_
#define MANIFEST_VERIFICATION_H_

#include <stdbool.h>
#include <stdint.h>
#include "platform_api.h"
#include "asn1/ecc_der_util.h"
#include "cfm/cfm_observer.h"
#include "crypto/hash.h"
#include "crypto/rsa.h"
#include "crypto/signature_verification.h"
#include "firmware/firmware_update_observer.h"
#include "keystore/keystore.h"
#include "pcd/pcd_observer.h"
#include "pfm/pfm_observer.h"
#include "status/rot_status.h"


#pragma pack(push,1)
/**
 * Common header that exists on all public keys that can be used for manifest verification,
 * regardless of what signing algorithm is utilized.
 */
struct manifest_verification_key_header {
	uint32_t id;		/**< ID of the key for revocation. */
	uint8_t pub_key;	/**< First byte of the public key data. */
};

/**
 * An RSA public key used for manifest verification.
 */
struct manifest_verification_key_rsa {
	uint32_t id;							/**< ID of the key for revocation. */
	struct rsa_public_key key;				/**< The RSA public key. */
	uint8_t signature[RSA_MAX_KEY_LENGTH];	/**< Signature of the key data using the root key. */
};

/**
 * An ECC public key to use for manifest verification.
 */
struct manifest_verification_key_ecc {
	uint32_t id;									/**< ID of the key for revocation. */
	uint8_t key[ECC_DER_MAX_PUBLIC_LENGTH];			/**< The DER-encoded ECC public key. */
	uint8_t signature[ECC_DER_ECDSA_MAX_LENGTH];	/**< Signature of the key data using the root key. */
};

/*
 * The manifest verification handler does not require using either RSA or ECC keys for verification.
 * Any type of signature verification can be used as long as an appropriate signature_verification
 * instance is used and a key structure is provided that satisfies two requirements.
 *
 * 1. The key structure must be constant size across all possible keys.  The fields within the key
 *    structure must also be constant size.
 * 2. The key structure must follow the same general structure as the RSA and ECC keys.
 *      - 32-bit ID
 *      - Public key
 *      - Signature
 */
#pragma pack(pop)

/**
 * Public key used for manifest verification.
 */
struct manifest_verification_key {
	const uint8_t *key_data;							/**< Raw key data including header and signature. */
	size_t key_data_length;								/**< Total length of the raw key data. */
	const struct manifest_verification_key_header *key;	/**< Pointer to the beginning of the key data. */
	size_t pub_key_length;								/**< Maximum length of the public key in the key data. */
	const uint8_t *signature;							/**< Pointer to the first byte of the key signature. */
	size_t sig_length;									/**< Maximum length of the signature in the key data. */
	enum hash_type sig_hash;							/**< Hash type used for the key signature. */
};

/**
 * Variable context for verification of firmware manifests.
 */
struct manifest_verification_state {
	struct manifest_verification_key stored_key;	/**< Verification key from the keystore. */
	bool default_valid;								/**< Flag indicating if the default key is valid or revoked. */
	bool save_failed;								/**< Flag indicating if the key was not saved. */
	platform_mutex lock;							/**< Synchronization for key operations. */
};

/**
 * Handler for verification of firmware manifests.  As part of verification, the key used to
 * verify the manifests is maintained and revocation operations are performed.
 */
struct manifest_verification {
	struct signature_verification base_verify;				/**< Base verification instance. */
	struct pfm_observer base_observer;						/**< Base manifest observer instance. */
	struct firmware_update_observer base_update;			/**< Base update observer instance. */
	struct manifest_verification_state *state;				/**< Variable context for verification. */
	const struct manifest_verification_key *default_key;	/**< Default key for verification. */
	const struct signature_verification *manifest_verify;	/**< Handler for signature verification of keys and manifests. */
	const struct hash_engine *hash;							/**< Hash engine for manifest validation. */
	const struct keystore *keystore;						/**< Storage for the verification key. */
	int key_id;												/**< ID of the key in the keystore. */
};


int manifest_verification_init (struct manifest_verification *verification,
	struct manifest_verification_state *state, const struct hash_engine *hash,
	const struct signature_verification *sig_verify, const uint8_t *root_key,
	size_t root_key_length, const struct manifest_verification_key *manifest_key,
	const struct keystore *manifest_keystore, int key_id);
int manifest_verification_init_state (const struct manifest_verification *verification,
	const uint8_t *root_key, size_t root_key_length);
void manifest_verification_release (const struct manifest_verification *verification);

const struct pfm_observer* manifest_verification_get_pfm_observer (
	const struct manifest_verification *verification);
const struct cfm_observer* manifest_verification_get_cfm_observer (
	const struct manifest_verification *verification);
const struct pcd_observer* manifest_verification_get_pcd_observer (
	const struct manifest_verification *verification);


#define	MANIFEST_VERIFICATION_ERROR(code)		ROT_ERROR (ROT_MODULE_MANIFEST_VERIFICATION, code)

/**
 * Error codes that can be generated by manifest verification.
 */
enum {
	MANIFEST_VERIFICATION_INVALID_ARGUMENT = MANIFEST_VERIFICATION_ERROR (0x00),	/**< Input parameter is null or not valid. */
	MANIFEST_VERIFICATION_NO_MEMORY = MANIFEST_VERIFICATION_ERROR (0x01),			/**< Memory allocation failed. */
	MANIFEST_VERIFICATION_INVALID_STORED_KEY = MANIFEST_VERIFICATION_ERROR (0x02),	/**< The stored key is not valid. */
};


#endif	/* MANIFEST_VERIFICATION_H_ */
