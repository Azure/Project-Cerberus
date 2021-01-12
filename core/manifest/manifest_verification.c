// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "manifest_verification.h"
#include "manifest_logging.h"
#include "common/type_cast.h"


static int manifest_verification_verify_signature (struct signature_verification *verification,
	const uint8_t *digest, size_t length, const uint8_t *signature, size_t sig_length)
{
	struct manifest_verification *manifest = (struct manifest_verification*) verification;
	int status;

	if (verification == NULL) {
		return MANIFEST_VERIFICATION_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&manifest->lock);

	if (manifest->stored_key) {
		status = manifest->rsa->sig_verify (manifest->rsa, &manifest->stored_key->key, signature,
			sig_length, digest, length);
		if ((status == 0) || (status != RSA_ENGINE_BAD_SIGNATURE)) {
			goto exit;
		}
	}

	if (manifest->default_key) {
		status = manifest->rsa->sig_verify (manifest->rsa, &manifest->default_key->key, signature,
			sig_length, digest, length);
	}

exit:
	platform_mutex_unlock (&manifest->lock);
	return status;
}

static void manifest_verification_on_manifest_activated (struct pfm_observer *observer,
	struct manifest *active)
{
	struct manifest_verification *manifest =
		TO_DERIVED_TYPE (observer, struct manifest_verification, base_observer);
	uint8_t digest[SHA512_HASH_LENGTH];
	int digest_length;
	uint8_t signature[RSA_MAX_KEY_LENGTH];
	int status;

	/* Whenever a new manifest is activated, check to see if the stored key should be revoked in
	 * favor of the default manifest key.  Execute the revocation, if appropriate.
	 *
	 * No need for null checks since the observable manifest will ensure valid arguments. */

	platform_mutex_lock (&manifest->lock);

	if (manifest->stored_key && manifest->default_key) {
		digest_length = active->get_hash (active, manifest->hash, digest, sizeof (digest));
		if (ROT_IS_ERROR (digest_length)) {
			status = digest_length;
			goto error;
		}

		status = active->get_signature (active, signature, sizeof (signature));
		if (ROT_IS_ERROR (status)) {
			goto error;
		}

		status = manifest->rsa->sig_verify (manifest->rsa, &manifest->default_key->key, signature,
			status, digest, digest_length);
		if (status == 0) {
			status = manifest->keystore->save_key (manifest->keystore, manifest->key_id,
				(const uint8_t*) manifest->default_key, sizeof (struct manifest_verification_key));

			platform_free (manifest->stored_key);
			manifest->stored_key = NULL;
			manifest->save_failed = (status != 0);
		}

		if (status != 0) {
			goto error;
		}
	}
	else if (manifest->save_failed) {
		status = manifest->keystore->save_key (manifest->keystore, manifest->key_id,
			(const uint8_t*) manifest->default_key, sizeof (struct manifest_verification_key));
		if (status == 0) {
			manifest->save_failed = false;
		}
		else {
			goto error;
		}
	}

	platform_mutex_unlock (&manifest->lock);
	return;

error:
	platform_mutex_unlock (&manifest->lock);
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
		MANIFEST_LOGGING_KEY_REVOCATION_FAIL, manifest->key_id, status);
}

static void manifest_verification_on_update_start (struct firmware_update_observer *observer,
	int *update_allowed)
{
	struct manifest_verification *manifest =
		TO_DERIVED_TYPE (observer, struct manifest_verification, base_update);
	int status;

	/* Block firmware updates if the active verification key has not been successfully saved to the
	 * keystore.  Otherwise, a firmware update could change the verification key and cause
	 * verification errors for the active manifest. */

	platform_mutex_lock (&manifest->lock);

	if (manifest->save_failed) {
		 status = manifest->keystore->save_key (manifest->keystore, manifest->key_id,
			(const uint8_t*) manifest->default_key, sizeof (struct manifest_verification_key));
		 if (status == 0) {
			 manifest->save_failed = false;
		 }
		 else if (*update_allowed == 0) {
			 *update_allowed = status;
		 }
	}

	platform_mutex_unlock (&manifest->lock);
}

/**
 * Verify that a key to be used for manifest verification is valid.
 *
 * @param key The key to check.
 * @param root_key The key used to sign the manifest key.
 * @param hash The hash engine to use for key validation.
 * @param rsa The RSA engine to use for key signature verification.
 *
 * @return 0 if the key is valid or an error code.
 */
static int manifest_verification_verify_key (const struct manifest_verification_key *key,
	const struct rsa_public_key *root_key, struct hash_engine *hash, struct rsa_engine *rsa)
{
	uint8_t key_hash[SHA256_HASH_LENGTH];
	int status;

	status = hash->calculate_sha256 (hash, (uint8_t*) key, sizeof (*key) - sizeof (key->signature),
		key_hash, sizeof (key_hash));
	if (status != 0) {
		return status;
	}

	return rsa->sig_verify (rsa, root_key, key->signature, root_key->mod_length, key_hash,
		SHA256_HASH_LENGTH);
}

/**
 * Initialize verification and key management for firmware manifests.
 *
 * @param verification The verification instance to initialize.
 * @param hash The hash engine to use for validation.
 * @param rsa The RSA engine to use for signature verification.
 * @param root_key The root key used to verify the manifest verification keys.
 * @param manifest_key Manifest verification key that will be used if no other key is active.  This
 * key can also revoke an existing key if it is a higher version.
 * @param manifest_keystore The keystore that holds the active manifest validation key.
 * @param key_id The ID of the manifest key in the keystore.
 *
 * @return 0 if manifest verification was successfully initialized or an error code.
 */
int manifest_verification_init (struct manifest_verification *verification,
	struct hash_engine *hash, struct rsa_engine *rsa, const struct rsa_public_key *root_key,
	const struct manifest_verification_key *manifest_key, struct keystore *manifest_keystore,
	int key_id)
{
	size_t length;
	int status;

	if ((verification == NULL) || (rsa == NULL) || (root_key == NULL) || (manifest_key == NULL) ||
		(manifest_keystore == NULL) || (hash == NULL)) {
		return MANIFEST_VERIFICATION_INVALID_ARGUMENT;
	}

	memset (verification, 0, sizeof (struct manifest_verification));

	status = manifest_verification_verify_key (manifest_key, root_key, hash, rsa);
	if (status != 0) {
		return status;
	}

	status = manifest_keystore->load_key (manifest_keystore, key_id,
		(uint8_t**) &verification->stored_key, &length);
	if ((status != 0) && (status != KEYSTORE_NO_KEY) && (status != KEYSTORE_BAD_KEY)) {
		return status;
	}

	if (status == 0) {
		if (length == sizeof (struct manifest_verification_key)) {
			status = manifest_verification_verify_key (verification->stored_key, root_key, hash,
				rsa);
		}
		else {
			status = RSA_ENGINE_BAD_SIGNATURE;
		}

		if (status != 0) {
			platform_free (verification->stored_key);
			if (status == RSA_ENGINE_BAD_SIGNATURE) {
				verification->stored_key = NULL;
			}
			else {
				return status;
			}
		}
	}

	if (!verification->stored_key) {
		status = manifest_keystore->save_key (manifest_keystore, key_id,
			(const uint8_t*) manifest_key, sizeof (struct manifest_verification_key));
		if (status != 0) {
			return status;
		}
	}
	else if (verification->stored_key->id >= manifest_key->id) {
		manifest_key = NULL;
	}

	status = platform_mutex_init (&verification->lock);
	if (status != 0) {
		platform_free (verification->stored_key);
		return status;
	}

	verification->default_key = manifest_key;
	verification->rsa = rsa;
	verification->hash = hash;
	verification->keystore = manifest_keystore;
	verification->key_id = key_id;

	verification->base_verify.verify_signature = manifest_verification_verify_signature;

	/* PFM and CFM observers have the same structure and this module only depends on common manifest
	 * APIs, so save memory by using the same observer instance and handler function. */
	verification->base_observer.on_pfm_activated =
		(void (*) (struct pfm_observer*, struct pfm*)) manifest_verification_on_manifest_activated;

	verification->base_update.on_update_start = manifest_verification_on_update_start;

	return 0;
}

/**
 * Release the resources used for manifest verification.
 *
 * @param verification The verification instance to release.
 */
void manifest_verification_release (struct manifest_verification *verification)
{
	if (verification) {
		platform_free (verification->stored_key);
	}
}

/**
 * Get the observer for PFM events.
 *
 * @param verification The verification instance to query.
 *
 * @return The PFM observer or null if the verification instance is not valid.
 */
struct pfm_observer* manifest_verification_get_pfm_observer (
	struct manifest_verification *verification)
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
struct cfm_observer* manifest_verification_get_cfm_observer (
	struct manifest_verification *verification)
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
struct pcd_observer* manifest_verification_get_pcd_observer (
	struct manifest_verification *verification)
{
	if (verification) {
		return (struct pcd_observer*) &verification->base_observer;
	}
	else {
		return NULL;
	}
}
