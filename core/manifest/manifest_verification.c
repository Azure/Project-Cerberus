// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "manifest_verification.h"
#include "manifest_logging.h"
#include "common/type_cast.h"
#include "common/unused.h"


int manifest_verification_verify_signature (const struct signature_verification *verification,
	const uint8_t *digest, size_t length, const uint8_t *signature, size_t sig_length)
{
	const struct manifest_verification *manifest =
		(const struct manifest_verification*) verification;
	int status;

	if ((verification == NULL) || (digest == NULL) || (length == 0) || (signature == NULL) ||
		(sig_length == 0)) {
		return MANIFEST_VERIFICATION_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&manifest->state->lock);

	if (manifest->state->stored_key.key_data) {
		status = manifest->manifest_verify->set_verification_key (manifest->manifest_verify,
			&manifest->state->stored_key.key->pub_key,
			manifest->state->stored_key.pub_key_length);
		if (status != 0) {
			goto exit;
		}

		status = manifest->manifest_verify->verify_signature (manifest->manifest_verify, digest,
			length, signature, sig_length);
		if ((status == 0) || (status != SIG_VERIFICATION_BAD_SIGNATURE)) {
			/* If verification was successful or verification encountered some error that caused it
			 * to not complete, bail on any further verification. */
			goto exit;
		}
	}

	if (manifest->state->default_valid) {
		status = manifest->manifest_verify->set_verification_key (manifest->manifest_verify,
			&manifest->default_key->key->pub_key, manifest->default_key->pub_key_length);
		if (status != 0) {
			goto exit;
		}

		status = manifest->manifest_verify->verify_signature (manifest->manifest_verify, digest,
			length, signature, sig_length);
	}

exit:
	platform_mutex_unlock (&manifest->state->lock);
	return status;
}

int manifest_verification_set_verification_key (const struct signature_verification *verification,
	const uint8_t *key, size_t length)
{
	UNUSED (verification);
	UNUSED (key);
	UNUSED (length);

	return SIG_VERIFICATION_UNSUPPORTED;
}

int manifest_verification_is_key_valid (const struct signature_verification *verification,
	const uint8_t *key, size_t length)
{
	UNUSED (verification);
	UNUSED (key);
	UNUSED (length);

	return SIG_VERIFICATION_UNSUPPORTED;
}

void manifest_verification_on_manifest_activated (const struct pfm_observer *observer,
	struct manifest *active)
{
	const struct manifest_verification *manifest =
		TO_DERIVED_TYPE (observer, const struct manifest_verification, base_observer);
	uint8_t digest[SHA512_HASH_LENGTH];
	int digest_length;
	uint8_t signature[RSA_MAX_KEY_LENGTH];	// Using RSA should support all known signature lengths.
	int sig_length;
	int status;

	/* Whenever a new manifest is activated, check to see if the stored key should be revoked in
	 * favor of the default manifest key.  Execute the revocation, if appropriate.
	 *
	 * No need for null checks since the observable manifest will ensure valid arguments. */

	platform_mutex_lock (&manifest->state->lock);

	if (manifest->state->stored_key.key_data && manifest->state->default_valid) {
		digest_length = active->get_hash (active, manifest->hash, digest, sizeof (digest));
		if (ROT_IS_ERROR (digest_length)) {
			status = digest_length;
			goto error;
		}

		sig_length = active->get_signature (active, signature, sizeof (signature));
		if (ROT_IS_ERROR (sig_length)) {
			status = sig_length;
			goto error;
		}

		status = manifest->manifest_verify->set_verification_key (manifest->manifest_verify,
			&manifest->default_key->key->pub_key, manifest->default_key->pub_key_length);
		if (status != 0) {
			goto error;
		}

		status = manifest->manifest_verify->verify_signature (manifest->manifest_verify,
			digest, digest_length, signature, sig_length);
		if (status == 0) {
			status = manifest->keystore->save_key (manifest->keystore, manifest->key_id,
				manifest->default_key->key_data, manifest->default_key->key_data_length);

			platform_free ((void*) manifest->state->stored_key.key_data);
			manifest->state->stored_key.key_data = NULL;
			manifest->state->save_failed = (status != 0);
		}

		if ((status != 0) && (status != SIG_VERIFICATION_BAD_SIGNATURE)) {
			/* If the verification or key revocation could not be completed, fail and log the
			 * error. */
			goto error;
		}
	}
	else if (manifest->state->save_failed) {
		status = manifest->keystore->save_key (manifest->keystore, manifest->key_id,
			manifest->default_key->key_data, manifest->default_key->key_data_length);
		if (status == 0) {
			manifest->state->save_failed = false;
		}
		else {
			goto error;
		}
	}

	platform_mutex_unlock (&manifest->state->lock);
	return;

error:
	platform_mutex_unlock (&manifest->state->lock);
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
		MANIFEST_LOGGING_KEY_REVOCATION_FAIL, manifest->key_id, status);
}

void manifest_verification_on_update_start (const struct firmware_update_observer *observer,
	int *update_allowed)
{
	const struct manifest_verification *manifest =
		TO_DERIVED_TYPE (observer, const struct manifest_verification, base_update);
	int status;

	/* Block firmware updates if the active verification key has not been successfully saved to the
	 * keystore.  Otherwise, a firmware update could change the verification key and cause
	 * verification errors for the active manifest. */

	platform_mutex_lock (&manifest->state->lock);

	if (manifest->state->save_failed) {
		 status = manifest->keystore->save_key (manifest->keystore, manifest->key_id,
			manifest->default_key->key_data, manifest->default_key->key_data_length);
		 if (status == 0) {
			 manifest->state->save_failed = false;
		 }
		 else if (*update_allowed == 0) {
			 *update_allowed = status;
		 }
	}

	platform_mutex_unlock (&manifest->state->lock);
}

/**
 * Verify that a key to be used for manifest verification is valid.
 *
 * @param verification The instance to use for key verification.
 * @param key The key to check.
 *
 * @return 0 if the key is valid or an error code.
 */
static int manifest_verification_verify_key (const struct manifest_verification *verification,
	const struct manifest_verification_key *key)
{
	uint8_t key_hash[SHA512_HASH_LENGTH];
	int status;

	/* Check that the key is endorsed by the root key. */
	status = hash_calculate (verification->hash, key->sig_hash, key->key_data,
		key->key_data_length - key->sig_length, key_hash, sizeof (key_hash));
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	status = verification->manifest_verify->verify_signature (verification->manifest_verify,
		key_hash, status, key->signature, key->sig_length);
	if (status != 0) {
		return status;
	}

	/* Ensure the key is compatible with the verification instance. */
	return verification->manifest_verify->is_key_valid (verification->manifest_verify,
		&key->key->pub_key, key->pub_key_length);
}

/**
 * Initialize verification and key management for firmware manifests.
 *
 * @param verification The verification instance to initialize.
 * @param state Variable context for verification.  This must be uninitialized.
 * @param hash The hash engine to use for validation.
 * @param sig_verify The handler to use for key and manifest signature verification.
 * @param root_key The root key used to verify the manifest verification keys.
 * @param root_key_length Length of the root verification key.
 * @param manifest_key Manifest verification key that will be used if no other key is active.  This
 * key can also revoke an existing key if it is a higher version.
 * @param manifest_keystore The keystore that holds the active manifest validation key.
 * @param key_id The ID of the manifest key in the keystore.
 *
 * @return 0 if manifest verification was successfully initialized or an error code.
 */
int manifest_verification_init (struct manifest_verification *verification,
	struct manifest_verification_state *state, struct hash_engine *hash,
	const struct signature_verification *sig_verify, const uint8_t *root_key,
	size_t root_key_length, const struct manifest_verification_key *manifest_key,
	const struct keystore *manifest_keystore, int key_id)
{
	if (verification == NULL) {
		return MANIFEST_VERIFICATION_INVALID_ARGUMENT;
	}

	memset (verification, 0, sizeof (struct manifest_verification));

	verification->base_verify.verify_signature = manifest_verification_verify_signature;
	verification->base_verify.set_verification_key = manifest_verification_set_verification_key;
	verification->base_verify.is_key_valid = manifest_verification_is_key_valid;

	/* PFM, CFM, and PCD observers have the same structure and this module only depends on common
	 * manifest APIs, so save memory by using the same observer instance and handler function. */
	verification->base_observer.on_pfm_activated =
		(void (*) (const struct pfm_observer*, struct pfm*)) manifest_verification_on_manifest_activated;

	verification->base_update.on_update_start = manifest_verification_on_update_start;

	verification->state = state;
	verification->default_key = manifest_key;
	verification->manifest_verify = sig_verify;
	verification->hash = hash;
	verification->keystore = manifest_keystore;
	verification->key_id = key_id;

	return manifest_verification_init_state (verification, root_key, root_key_length);
}

/**
 * Initialize only the variable state for firmware manifest signature verification.  The rest of the
 * verification instance is assumed to have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param verification The verification instance that contains the state to initialize.
 * @param root_key The root key used to verify the manifest verification keys.
 * @param root_key_length Length of the root verification key.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int manifest_verification_init_state (const struct manifest_verification *verification,
	const uint8_t *root_key, size_t root_key_length)
{
	int status;

	if ((verification == NULL) || (root_key == NULL) || (root_key_length == 0)  ||
		(verification->state == NULL) || (verification->hash == NULL) ||
		(verification->manifest_verify == NULL) || (verification->default_key == NULL) ||
		(verification->keystore == NULL)) {
		return MANIFEST_VERIFICATION_INVALID_ARGUMENT;
	}

	memset (verification->state, 0, sizeof (struct manifest_verification_state));

	status = verification->manifest_verify->set_verification_key (verification->manifest_verify,
		root_key, root_key_length);
	if (status != 0) {
		return status;
	}

	status = manifest_verification_verify_key (verification, verification->default_key);
	if (status != 0) {
		return status;
	}

	verification->state->default_valid = true;

	status = verification->keystore->load_key (verification->keystore, verification->key_id,
		(uint8_t**) &verification->state->stored_key.key_data,
		&verification->state->stored_key.key_data_length);
	if ((status != 0) && (status != KEYSTORE_NO_KEY) && (status != KEYSTORE_BAD_KEY)) {
		return status;
	}

	if (status == 0) {
		/* Set up the manifest_verification_key structure for the key loaded from the keystore.
		 * Lengths and hash type are determined from the values set in the default manifest key. */
		verification->state->stored_key.key =
			(struct manifest_verification_key_header*) verification->state->stored_key.key_data;
		verification->state->stored_key.pub_key_length = verification->default_key->pub_key_length;
		verification->state->stored_key.signature = verification->state->stored_key.key_data +
			sizeof (uint32_t) + verification->state->stored_key.pub_key_length;
		verification->state->stored_key.sig_length = verification->default_key->sig_length;
		verification->state->stored_key.sig_hash = verification->default_key->sig_hash;

		if (verification->state->stored_key.key_data_length ==
			verification->default_key->key_data_length) {
			status = manifest_verification_verify_key (verification,
				&verification->state->stored_key);
		}
		else {
			status = MANIFEST_VERIFICATION_INVALID_STORED_KEY;
		}

		if (status != 0) {
			platform_free ((void*) verification->state->stored_key.key_data);

			if ((status == SIG_VERIFICATION_BAD_SIGNATURE) ||
				(status == SIG_VERIFICATION_INVALID_KEY) ||
				(status == MANIFEST_VERIFICATION_INVALID_STORED_KEY)) {
				verification->state->stored_key.key_data = NULL;
			}
			else {
				return status;
			}
		}
	}

	if (!verification->state->stored_key.key_data) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_MANIFEST,
			MANIFEST_LOGGING_NO_STORED_MANIFEST_KEY, verification->key_id, status);

		status = verification->keystore->save_key (verification->keystore, verification->key_id,
			verification->default_key->key_data, verification->default_key->key_data_length);
		if (status != 0) {
			return status;
		}
	}
	else if (verification->state->stored_key.key->id >= verification->default_key->key->id) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_MANIFEST,
			MANIFEST_LOGGING_MANIFEST_KEY_REVOKED, verification->key_id,
			verification->state->stored_key.key->id);

		verification->state->default_valid = false;
	}

	status = platform_mutex_init (&verification->state->lock);
	if (status != 0) {
		platform_free ((void*) verification->state->stored_key.key_data);
		return status;
	}

	return 0;
}

/**
 * Release the resources used for manifest verification.
 *
 * @param verification The verification instance to release.
 */
void manifest_verification_release (const struct manifest_verification *verification)
{
	if (verification) {
		platform_free ((void*) verification->state->stored_key.key_data);
	}
}

/**
 * Get the observer for PFM events.
 *
 * @param verification The verification instance to query.
 *
 * @return The PFM observer or null if the verification instance is not valid.
 */
const struct pfm_observer* manifest_verification_get_pfm_observer (
	const struct manifest_verification *verification)
{
	if (verification) {
		return &verification->base_observer;
	}
	else {
		return NULL;
	}
}

/**
 * Get the observer for CFM events.
 *
 * @param verification The verification instance to query.
 *
 * @return The CFM observer or null if the verification instance is not valid.
 */
const struct cfm_observer* manifest_verification_get_cfm_observer (
	const struct manifest_verification *verification)
{
	if (verification) {
		return (struct cfm_observer*) &verification->base_observer;
	}
	else {
		return NULL;
	}
}

/**
 * Get the observer for PCD events.
 *
 * @param verification The verification instance to query.
 *
 * @return The PCD observer or null if the verification instance is not valid.
 */
const struct pcd_observer* manifest_verification_get_pcd_observer (
	const struct manifest_verification *verification)
{
	if (verification) {
		return (struct pcd_observer*) &verification->base_observer;
	}
	else {
		return NULL;
	}
}
