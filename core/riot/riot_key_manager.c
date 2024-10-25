// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "platform_api.h"
#include "riot_key_manager.h"
#include "riot_logging.h"
#include "common/certificate.h"


/**
 * Free the memory used for CA certificate data.
 *
 * @param cert The certificate data to free.
 */
static void riot_key_manager_free_ca_cert (struct der_cert *cert)
{
	platform_free ((void*) cert->cert);
	cert->cert = NULL;
}

/**
 * Load the certificates from keystore and check if they create a authenticated certificate chain.
 * If the chain is authenticated, update the identity keys using the stored certificates.
 *
 * @param riot The key manager to authenticate.
 *
 * @return 0 if authentication completed without errors or an error code.
 */
static int riot_key_manager_authenticate_stored_certificates (const struct riot_key_manager *riot)
{
	uint8_t *signed_devid;
	size_t devid_length;
	struct x509_ca_certs chain;
	struct x509_certificate cert;
	int status;

	platform_mutex_lock (&riot->state->store_lock);

	/* Load the keys we have in the keystore. */
	status = riot->keystore->load_key (riot->keystore, 0, &signed_devid, &devid_length);
	if (status == 0) {
		status = riot->keystore->load_key (riot->keystore, 1,
			(uint8_t**) &riot->state->root_ca.cert,	&riot->state->root_ca.length);
		if (status == 0) {
			status = riot->keystore->load_key (riot->keystore, 2,
				(uint8_t**) &riot->state->intermediate_ca.cert,
				&riot->state->intermediate_ca.length);
			if ((status != 0) && (status != KEYSTORE_NO_KEY) && (status != KEYSTORE_BAD_KEY)) {
				riot_key_manager_free_ca_cert (&riot->state->root_ca);
				platform_free (signed_devid);

				platform_mutex_unlock (&riot->state->store_lock);

				return status;
			}
		}
		else {
			platform_free (signed_devid);
			if ((status == KEYSTORE_NO_KEY) || (status == KEYSTORE_BAD_KEY)) {
				status = RIOT_KEY_MANAGER_NO_ROOT_CA;
			}

			platform_mutex_unlock (&riot->state->store_lock);

			return status;
		}
	}
	else {
		if ((status == KEYSTORE_NO_KEY) || (status == KEYSTORE_BAD_KEY)) {
			status = RIOT_KEY_MANAGER_NO_SIGNED_DEVICE_ID;
		}

		platform_mutex_unlock (&riot->state->store_lock);

		return status;
	}

	platform_mutex_unlock (&riot->state->store_lock);

	/* Validate that the signed Device ID is valid for the current certificate chain. */
	status = riot->x509->load_certificate (riot->x509, &cert, riot->state->keys.alias_cert,
		riot->state->keys.alias_cert_length);
	if (status != 0) {
		goto auth_load_error;
	}

	status = riot->x509->init_ca_cert_store (riot->x509, &chain);
	if (status != 0) {
		goto auth_free_cert;
	}

	status = riot->x509->add_root_ca (riot->x509, &chain, riot->state->root_ca.cert,
		riot->state->root_ca.length);
	if (status != 0) {
		goto auth_free_store;
	}

	if (riot->state->intermediate_ca.cert) {
		status = riot->x509->add_intermediate_ca (riot->x509, &chain,
			riot->state->intermediate_ca.cert, riot->state->intermediate_ca.length);
		if (status != 0) {
			goto auth_free_store;
		}
	}

	status = riot->x509->add_intermediate_ca (riot->x509, &chain, signed_devid, devid_length);
	if (status != 0) {
		goto auth_free_store;
	}

	status = riot->x509->authenticate (riot->x509, &cert, &chain);
	if (status == 0) {
		platform_mutex_lock (&riot->state->auth_lock);

		if (!riot->state->static_devid) {
			platform_free ((void*) riot->state->keys.devid_cert);
		}
		riot->state->keys.devid_cert = signed_devid;
		riot->state->keys.devid_cert_length = devid_length;
		riot->state->static_devid = false;

		platform_mutex_unlock (&riot->state->auth_lock);

		riot->x509->release_ca_cert_store (riot->x509, &chain);
		riot->x509->release_certificate (riot->x509, &cert);
	}
	else {
		goto auth_free_store;
	}

	return 0;

auth_free_store:
	riot->x509->release_ca_cert_store (riot->x509, &chain);
auth_free_cert:
	riot->x509->release_certificate (riot->x509, &cert);
auth_load_error:
	platform_free (signed_devid);
	riot_key_manager_free_ca_cert (&riot->state->root_ca);
	riot_key_manager_free_ca_cert (&riot->state->intermediate_ca);

	return status;
}

/**
 * Store and authenticate an identity certificate.
 *
 * @param riot The key manager to update.
 * @param id The ID for the certificate to store.
 * @param cert The certificate DER data.
 * @param length The length of the certificate data.
 *
 * @return 0 if the certificate was stored and authentication completed successfully or an error
 * code.
 */
static int riot_key_manager_store_certificate (const struct riot_key_manager *riot, int id,
	const uint8_t *cert, size_t length)
{
	int status;

	if ((riot == NULL) || (cert == NULL) || (length == 0)) {
		return RIOT_KEY_MANAGER_INVALID_ARGUMENT;
	}

	if (riot->state->root_ca.cert) {
		return RIOT_KEY_MANAGER_KEYSTORE_LOCKED;
	}

	platform_mutex_lock (&riot->state->store_lock);
	status = riot->keystore->save_key (riot->keystore, id, cert, length);
	platform_mutex_unlock (&riot->state->store_lock);

	return status;
}

/**
 * Initialize DICE device key management state and load signed certificates from the keystore, if
 * available.
 *
 * @param riot The key manager with state to initialize.
 * @param keys The device keys generated by DICE layer 0.
 * @param static_keys Flag indicating if the keys are stored in static buffers.
 *
 * @return 0 if the manager was successfully initialized or an error code.
 */
static int riot_key_manager_init_cert_state (const struct riot_key_manager *riot,
	const struct riot_keys *keys, bool static_keys)
{
	int status;

	if ((riot == NULL) || (keys == NULL) || (riot->state == NULL) || (riot->keystore == NULL) ||
		(riot->x509 == NULL)) {
		return RIOT_KEY_MANAGER_INVALID_ARGUMENT;
	}

	memset (riot->state, 0, sizeof (*riot->state));

	status = platform_mutex_init (&riot->state->store_lock);
	if (status != 0) {
		return status;
	}

	status = platform_mutex_init (&riot->state->auth_lock);
	if (status != 0) {
		platform_mutex_free (&riot->state->store_lock);

		return status;
	}

	riot->state->static_keys = static_keys;
	riot->state->static_devid = static_keys;
	memcpy (&riot->state->keys, keys, sizeof (riot->state->keys));

	status = riot_key_manager_authenticate_stored_certificates (riot);
	debug_log_create_entry ((status == 0) ? DEBUG_LOG_SEVERITY_INFO : DEBUG_LOG_SEVERITY_WARNING,
		DEBUG_LOG_COMPONENT_RIOT, RIOT_LOGGING_DEVID_AUTH_STATUS, status, 0);

	return 0;
}

/**
 * Initialize RIoT device key management and load signed certificates from the keystore, if
 * available.
 *
 * @param riot The RIoT key manager to initialize.
 * @param state Variable context for the key manager.
 * @param keystore The storage to use for identity certificates.
 * @param keys The device keys generated by DICE layer 0.
 * @param x509 The X.509 engine to use for certificate operations.
 * @param extra_csr Optional list of CSRs (or other binary data) that can be exported by the device.
 * The CSRs in this list will be accessible starting with CSR command index 1, since 0 is for the
 * Device ID CSR.
 * @param csr_count The number of extra CSRs in the list.
 * @param static_keys Flag indicating if the keys are stored in static buffers.
 *
 * @return 0 if the manager was successfully initialized or an error code.
 */
static int riot_key_manager_init_certs (struct riot_key_manager *riot,
	struct riot_key_manager_state *state, const struct keystore *keystore,
	const struct riot_keys *keys, struct x509_engine *x509,	const struct der_cert *const extra_csr,
	size_t csr_count, bool static_keys)
{
	if ((riot == NULL) || (state == NULL) || (keystore == NULL) || (keys == NULL) ||
		(x509 == NULL)) {
		return RIOT_KEY_MANAGER_INVALID_ARGUMENT;
	}

	memset (riot, 0, sizeof (struct riot_key_manager));

	riot->state = state;
	riot->keystore = keystore;
	riot->x509 = x509;
	riot->extra_csr = extra_csr;
	riot->csr_count = csr_count;

	return riot_key_manager_init_cert_state (riot, keys, static_keys);
}

/**
 * Initialize the manager for DICE device identity keys.
 *
 * Keys are provided in dynamically allocated buffers that will be owned by the key manager.
 * Releasing the key manager will also release these key buffers.
 *
 * @param riot The identity key manager to initialize.
 * @param state Variable context for the identity key manager.  This must be uninitialized.
 * @param keystore The storage to use for identity certificates.
 * @param keys The device keys generated by DICE layer 0.  This structure should not be accessed
 * externally after a successful call.  It is best to make this a temporary structure.
 * @param x509 The X.509 engine to use for certificate operations.
 * @param extra_csr Optional list of CSRs (or other binary data) that can be exported by the device.
 * The CSRs in this list will be accessible starting with CSR command index 1, since 0 is for the
 * Device ID CSR.
 * @param csr_count The number of extra CSRs in the list.
 *
 * @return 0 if the manager was successfully initialized or an error code.
 */
int riot_key_manager_init (struct riot_key_manager *riot, struct riot_key_manager_state *state,
	const struct keystore *keystore, const struct riot_keys *keys, struct x509_engine *x509,
	const struct der_cert *const extra_csr, size_t csr_count)
{
	return riot_key_manager_init_certs (riot, state, keystore, keys, x509, extra_csr, csr_count,
		false);
}

/**
 * Initialize the manager for DICE device identity keys.
 *
 * Keys are provided in static buffers.
 *
 * @param riot The identity key manager to initialize.
 * @param state Variable context for the identity key manager.  This must be uninitialized.
 * @param keystore The storage to use for identity certificates.
 * @param keys The device keys generated by DICE layer 0.  This structure should not be accessed
 * externally after a successful call.  It is best to make this a temporary structure.
 * @param x509 The X.509 engine to use for certificate operations.
 * @param extra_csr Optional list of CSRs (or other binary data) that can be exported by the device.
 * The CSRs in this list will be accessible starting with CSR command index 1, since 0 is for the
 * Device ID CSR.
 * @param csr_count The number of extra CSRs in the list.
 *
 * @return 0 if the manager was successfully initialized or an error code.
 */
int riot_key_manager_init_static_keys (struct riot_key_manager *riot,
	struct riot_key_manager_state *state, const struct keystore *keystore,
	const struct riot_keys *keys, struct x509_engine *x509, const struct der_cert *const extra_csr,
	size_t csr_count)
{
	return riot_key_manager_init_certs (riot, state, keystore, keys, x509, extra_csr, csr_count,
		true);
}

/**
 * Initialize only the state fora DICE device identity key manager.  The rest of the manager is
 * assumed to have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * Keys are provided in dynamically allocated buffers that will be owned by the key manager.
 * Releasing the key manager will also release these key buffers.
 *
 * @param riot The key manager that contains the state to initialize.
 * @param keys The device keys generated by DICE layer 0.  This structure should not be accessed
 * externally after a successful call.  It is best to make this a temporary structure.
 *
 * @return 0 if the manager state was successfully initialized or an error code.
 */
int riot_key_manager_init_state (const struct riot_key_manager *riot, const struct riot_keys *keys)
{
	return riot_key_manager_init_cert_state (riot, keys, false);
}

/**
 * Initialize only the state fora DICE device identity key manager.  The rest of the manager is
 * assumed to have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * Keys are provided in static buffers.
 *
 * @param riot The key manager that contains the state to initialize.
 * @param keys The device keys generated by DICE layer 0.  This structure should not be accessed
 * externally after a successful call.  It is best to make this a temporary structure.
 *
 * @return 0 if the manager state was successfully initialized or an error code.
 */
int riot_key_manager_init_state_static_keys (const struct riot_key_manager *riot,
	const struct riot_keys *keys)
{
	return riot_key_manager_init_cert_state (riot, keys, true);
}

/**
 * Release the resources used by a device identity key manager.  The stored device certificates will
 * not be released.
 *
 * @param riot The key manager to initialize.
 */
void riot_key_manager_release (const struct riot_key_manager *riot)
{
	if (riot) {
		if (!riot->state->static_devid) {
			platform_free ((void*) riot->state->keys.devid_cert);
		}
		if (!riot->state->static_keys) {
			platform_free ((void*) riot->state->keys.devid_csr);
			platform_free ((void*) riot->state->keys.alias_key);
			platform_free ((void*) riot->state->keys.alias_cert);
		}

		riot_key_manager_free_ca_cert (&riot->state->root_ca);
		riot_key_manager_free_ca_cert (&riot->state->intermediate_ca);

		platform_mutex_free (&riot->state->store_lock);
		platform_mutex_free (&riot->state->auth_lock);
	}
}

/**
 * Store the signed Device ID certificate.
 *
 * Once an authorized chain has been stored, further attempts to store a signed Device ID
 * certificate will fail.
 *
 * @param riot The key manager to update.
 * @param dev_id The DER encoded data for the signed Device ID X.509 certificate.
 * @param length The length of the certificate DER.
 *
 * @return 0 if the Device ID certificate was successfully stored or an error code.
 */
int riot_key_manager_store_signed_device_id (const struct riot_key_manager *riot,
	const uint8_t *dev_id, size_t length)
{
	return riot_key_manager_store_certificate (riot, 0, dev_id, length);
}

/**
 * Store the Root CA certificate used to authenticate the Device ID.
 *
 * Once an authorized chain has been stored, further attempts to store a Root CA certificate will
 * fail.
 *
 * @param riot The key manager to update.
 * @param dev_id The DER encoded data for the Root CA X.509 certificate.
 * @param length The length of the certificate DER.
 *
 * @return 0 if the Root CA certificate was successfully stored or an error code.
 */
int riot_key_manager_store_root_ca (const struct riot_key_manager *riot, const uint8_t *root_ca,
	size_t length)
{
	return riot_key_manager_store_certificate (riot, 1, root_ca, length);
}

/**
 * Store the Intermediate CA certificate used to sign the Device ID.
 *
 * Once an authorized chain has been stored, further attempts to store a Root CA certificate will
 * fail.
 *
 * @param riot The key manager to update.
 * @param dev_id The DER encoded data for the Intermediate CA X.509 certificate.
 * @param length The length of the certificate DER.
 *
 * @return 0 if the Intermediate CA certificate was successfully stored or an error code.
 */
int riot_key_manager_store_intermediate_ca (const struct riot_key_manager *riot,
	const uint8_t *intr_ca,	size_t length)
{
	return riot_key_manager_store_certificate (riot, 2, intr_ca, length);
}

/**
 * Verify the the stored certificate chain.  If all stored certificates create an authorized chain,
 * the identity certificates exposed by the manager will be updated to match the stored ones.
 *
 * Once the certificate chain has been verified, further attempts to store certificates will fail.
 *
 * Updates to the certificate chain will be blocked until the device identity keys are not in use.
 *
 * @param riot The key manager that will be verified.
 *
 * @return 0 if the chain was successfully verified or an error code.
 */
int riot_key_manager_verify_stored_certs (const struct riot_key_manager *riot)
{
	if (riot == NULL) {
		return RIOT_KEY_MANAGER_INVALID_ARGUMENT;
	}

	return riot_key_manager_authenticate_stored_certificates (riot);
}

/**
 * Erase all stored certificates.  Certificates loaded in memory will not be affected.
 *
 * @param riot The key manager to update.
 *
 * @return 0 if all certificates were successfully erased or an error code.
 */
int riot_key_manager_erase_all_certificates (const struct riot_key_manager *riot)
{
	int status;

	if (riot == NULL) {
		return RIOT_KEY_MANAGER_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&riot->state->store_lock);

	status = riot->keystore->erase_key (riot->keystore, 0);
	if (status != 0) {
		goto exit;
	}

	status = riot->keystore->erase_key (riot->keystore, 1);
	if (status != 0) {
		goto exit;
	}

	status = riot->keystore->erase_key (riot->keystore, 2);

exit:
	platform_mutex_unlock (&riot->state->store_lock);

	return status;
}

/**
 * Get the device identity keys.  Updates to the RIoT keys will be blocked until the caller
 * indicates they are finished using them by calling riot_key_manager_release_riot_keys().
 *
 * @param riot The key manager to query.
 *
 * @return The device keys or null.  If not null, riot_key_manager_release_riot_keys() must be
 * called after the keys are used.
 */
const struct riot_keys* riot_key_manager_get_riot_keys (const struct riot_key_manager *riot)
{
	if (riot) {
		/* Since a lock is being taken, only one external component can access the keys at a time.
		 * If multiple modules ever need to access the keys simultaneously, this lock will need to
		 * only be used to protect a reference count on the keys structure. */
		platform_mutex_lock (&riot->state->auth_lock);

		return &riot->state->keys;
	}
	else {
		return NULL;
	}
}

/**
 * Indicate that the device identity keys are not currently in use.
 *
 * @param riot The key manager to update.
 * @param keys The keys being released.
 */
void riot_key_manager_release_riot_keys (const struct riot_key_manager *riot,
	const struct riot_keys *keys)
{
	if ((riot != NULL) && (keys == &riot->state->keys)) {
		platform_mutex_unlock (&riot->state->auth_lock);
	}
}

/**
 * Get the root CA certificate for identity keys.
 *
 * @param riot The key manager to query.
 *
 * @return The root CA certificate or null if there is no root CA.  The certificate memory is owned
 * by the key manager and must not be freed by the user.
 */
const struct der_cert* riot_key_manager_get_root_ca (const struct riot_key_manager *riot)
{
	if (riot && riot->state->root_ca.cert) {
		return &riot->state->root_ca;
	}
	else {
		return NULL;
	}
}

/**
 * Get the intermediate CA certificate used to sign the Device ID.
 *
 * @param riot The key manager to query.
 *
 * @return The intermediate CA certificate or null if there is no intermediate CA.  The certificate
 * memory is owned by the key manager and must not be freed by the user.
 */
const struct der_cert* riot_key_manager_get_intermediate_ca (const struct riot_key_manager *riot)
{
	if (riot && riot->state->intermediate_ca.cert) {
		return &riot->state->intermediate_ca;
	}
	else {
		return NULL;
	}
}

/**
 * Get the data for a specific CSR provided by the device.
 *
 * @param riot The key manager to query.
 * @param index Index for the requested CSR.  Index 0 will always be the Device ID CSR.
 * @param csr Output for the CSR data.  The CSR memory is owned by the key manager and must not be
 * freed or modified by the user.
 *
 * @return 0 if the CSR data was retrieved successfully or an error code.
 */
int riot_key_manager_get_csr (const struct riot_key_manager *riot, size_t index,
	struct der_cert *csr)
{
	if ((riot == NULL) || (csr == NULL)) {
		return RIOT_KEY_MANAGER_INVALID_ARGUMENT;
	}

	if (index == 0) {
		csr->cert = riot->state->keys.devid_csr;
		csr->length = riot->state->keys.devid_csr_length;
	}
	else if (riot->extra_csr != NULL) {
		if (index <= riot->csr_count) {
			memcpy (csr, &riot->extra_csr[index - 1], sizeof (*csr));
		}
		else {
			return RIOT_KEY_MANAGER_UNKNOWN_CSR;
		}
	}
	else {
		return RIOT_KEY_MANAGER_UNKNOWN_CSR;
	}

	return 0;
}
