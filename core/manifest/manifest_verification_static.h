// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MANIFEST_VERIFICATION_STATIC_H_
#define MANIFEST_VERIFICATION_STATIC_H_

#include "manifest/manifest_verification.h"


/* Internal functions declared to allow for static initialization. */
int manifest_verification_verify_signature (const struct signature_verification *verification,
	const uint8_t *digest, size_t length, const uint8_t *signature, size_t sig_length);
int manifest_verification_set_verification_key (
	const struct signature_verification *verification, const uint8_t *key, size_t length);
int manifest_verification_is_key_valid (const struct signature_verification *verification,
	const uint8_t *key, size_t length);

void manifest_verification_on_manifest_activated (const struct pfm_observer *observer,
	struct manifest *active);

void manifest_verification_on_update_start (const struct firmware_update_observer *observer,
	int *update_allowed);


/**
 * Constant initializer for the signature verification API.
 */
#define	MANIFEST_VERIFICATION_SIGNATURE_VERIFICATION_API_INIT  { \
		.verify_signature = manifest_verification_verify_signature, \
		.set_verification_key = manifest_verification_set_verification_key, \
		.is_key_valid = manifest_verification_is_key_valid \
	}

/**
 * Constant initializer for the manifest event handlers.
 */
#define	MANIFEST_VERIFICATION_PFM_OBSERVER_API_INIT  { \
		.on_pfm_verified = NULL, \
		.on_pfm_activated = \
			(void (*) (const struct pfm_observer*, struct pfm*)) manifest_verification_on_manifest_activated, \
		.on_clear_active = NULL, \
		.on_pfm_activation_request = NULL \
	}

/**
 * Constant initializer for the firmware update event handlers.
 */
#define	MANIFEST_VERIFICATION_FIRMWARE_UPDATE_OBSERVER_API_INIT  { \
		.on_update_start = manifest_verification_on_update_start \
	}


/**
 * Initialize a static instance for manifest signature verification.  This can be a constant
 * instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the verification.
 * @param hash_ptr The hash engine to use for validation.
 * @param sig_verify_ptr The handler to use for key and manifest signature verification.
 * @param manifest_key_ptr Manifest verification key that will be used if no other key is active.
 * This key can also revoke an existing key if it is a higher version.
 * @param manifest_keystore_ptr The keystore that holds the active manifest validation key.
 * @param keystore_key_id The ID of the manifest key in the keystore.
 */
#define	manifest_verification_static_init(state_ptr, hash_ptr, sig_verify_ptr, manifest_key_ptr, \
	manifest_keystore_ptr, keystore_key_id)	{ \
		.base_verify = MANIFEST_VERIFICATION_SIGNATURE_VERIFICATION_API_INIT, \
		.base_observer = MANIFEST_VERIFICATION_PFM_OBSERVER_API_INIT, \
		.base_update = MANIFEST_VERIFICATION_FIRMWARE_UPDATE_OBSERVER_API_INIT, \
		.state = state_ptr, \
		.hash = hash_ptr, \
		.manifest_verify = sig_verify_ptr, \
		.default_key = manifest_key_ptr, \
		.keystore = manifest_keystore_ptr, \
		.key_id = keystore_key_id \
	}


#endif	/* MANIFEST_VERIFICATION_STATIC_H_ */
