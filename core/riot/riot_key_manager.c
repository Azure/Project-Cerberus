// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include "platform.h"
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
 * If the chain is authenticated, update the RIoT keys using the stored certificates.
 *
 * @param riot The RIoT key manager to authenticate.
 *
 * @return 0 if authentication completed without errors or an error code.
 */
static int riot_key_manager_authenticate_stored_certificates (struct riot_key_manager *riot)
{
	uint8_t *signed_devid;
	size_t devid_length;
	struct x509_ca_certs chain;
	struct x509_certificate cert;
	int status;

	platform_mutex_lock (&riot->store_lock);

	/* Load the keys we have in the keystore. */
	status = riot->keystore->load_key (riot->keystore, 0, &signed_devid, &devid_length);
	if (status == 0) {
		status = riot->keystore->load_key (riot->keystore, 1, (uint8_t**) &riot->root_ca.cert,
			&riot->root_ca.length);
		if (status == 0) {
			status = riot->keystore->load_key (riot->keystore, 2,
				(uint8_t**) &riot->intermediate_ca.cert, &riot->intermediate_ca.length);
			if ((status != 0) && (status != KEYSTORE_NO_KEY) && (status != KEYSTORE_BAD_KEY)) {
				riot_key_manager_free_ca_cert (&riot->root_ca);
				platform_free (signed_devid);

				platform_mutex_unlock (&riot->store_lock);
				return status;
			}
		}
		else {
			platform_free (signed_devid);
			if ((status == KEYSTORE_NO_KEY) || (status == KEYSTORE_BAD_KEY)) {
				status = RIOT_KEY_MANAGER_NO_ROOT_CA;
			}

			platform_mutex_unlock (&riot->store_lock);
			return status;
		}
	}
	else {
		if ((status == KEYSTORE_NO_KEY) || (status == KEYSTORE_BAD_KEY)) {
			status = RIOT_KEY_MANAGER_NO_SIGNED_DEVICE_ID;
		}

		platform_mutex_unlock (&riot->store_lock);
		return status;
	}

	platform_mutex_unlock (&riot->store_lock);

	/* Validate that the signed Device ID is valid for the current certificate chain. */
	status = riot->x509->load_certificate (riot->x509, &cert, riot->keys.alias_cert,
		riot->keys.alias_cert_length);
	if (status != 0) {
		goto auth_load_error;
	}

	status = riot->x509->init_ca_cert_store (riot->x509, &chain);
	if (status != 0) {
		goto auth_free_cert;
	}

	status = riot->x509->add_root_ca (riot->x509, &chain, riot->root_ca.cert, riot->root_ca.length);
	if (status != 0) {
		goto auth_free_store;
	}

	if (riot->intermediate_ca.cert) {
		status = riot->x509->add_intermediate_ca (riot->x509, &chain, riot->intermediate_ca.cert,
			riot->intermediate_ca.length);
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
		platform_mutex_lock (&riot->auth_lock);

		if (!riot->static_devid) {
			platform_free ((void*) riot->keys.devid_cert);
		}
		riot->keys.devid_cert = signed_devid;
		riot->keys.devid_cert_length = devid_length;
		riot->static_devid = false;

		platform_mutex_unlock (&riot->auth_lock);

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
	riot_key_manager_free_ca_cert (&riot->root_ca);
	riot_key_manager_free_ca_cert (&riot->intermediate_ca);

	return status;
}

/**
 * Store and authenticate a RIoT certificate.
 *
 * @param riot The RIoT key manager to update.
 * @param id The ID for the certificate to store.
 * @param cert The certificate DER data.
 * @param length The length of the certificate data.
 *
 * @return 0 if the certificate was stored and authentication completed successfully or an error
 * code.
 */
static int riot_key_manager_store_certificate (struct riot_key_manager *riot, int id,
	const uint8_t *cert, size_t length)
{
	int status;

	if ((riot == NULL) || (cert == NULL) || (length == 0)) {
		return RIOT_KEY_MANAGER_INVALID_ARGUMENT;
	}

	if (riot->root_ca.cert) {
		return RIOT_KEY_MANAGER_KEYSTORE_LOCKED;
	}

	platform_mutex_lock (&riot->store_lock);
	status = riot->keystore->save_key (riot->keystore, id, cert, length);
	platform_mutex_unlock (&riot->store_lock);

	return status;
}

/**
 * Initialize RIoT device key management and load signed certificates from the keystore, if
 * available.
 *
 * @param riot The RIoT key manager to initialize.
 * @param keystore The storage to use for RIoT keys.
 * @param keys The device keys generated by RIoT Core.
 * @param x509 The X.509 engine to use for certificate operations.
 * @param static_keys Flag indicating if the keys are stored in static buffers.
 *
 * @return 0 if the manager was successfully initialized or an error code.
 */
static int riot_key_manager_init_certs (struct riot_key_manager *riot, struct keystore *keystore,
	const struct riot_keys *keys, struct x509_engine *x509, bool static_keys)
{
	int status;

	if ((riot == NULL) || (keystore == NULL) || (keys == NULL) || (x509 == NULL)) {
		return RIOT_KEY_MANAGER_INVALID_ARGUMENT;
	}

	memset (riot, 0, sizeof (struct riot_key_manager));

	status = platform_mutex_init (&riot->store_lock);
	if (status != 0) {
		return status;
	}

	status = platform_mutex_init (&riot->auth_lock);
	if (status != 0) {
		platform_mutex_free (&riot->store_lock);
		return status;
	}

	riot->keystore = keystore;
	riot->x509 = x509;
	riot->static_keys = static_keys;
	riot->static_devid = static_keys;
	memcpy (&riot->keys, keys, sizeof (riot->keys));

	status = riot_key_manager_authenticate_stored_certificates (riot);
	debug_log_create_entry ((status == 0) ? DEBUG_LOG_SEVERITY_INFO : DEBUG_LOG_SEVERITY_WARNING,
		DEBUG_LOG_COMPONENT_RIOT, RIOT_LOGGING_DEVID_AUTH_STATUS, status, 0);

	return 0;
}

/**
 * Initialize the manager for RIoT device keys.
 *
 * Keys are provided in dynamically allocated buffers that will be owned by the key manager.
 * Releasing the RIoT key manager will also release these key buffers.
 *
 * @param riot The RIoT key manager to initialize.
 * @param keystore The storage to use for RIoT keys.
 * @param keys The device keys generated by RIoT Core.  This structure should not be accessed
 * externally after a successful call.  It is best to make this a temporary structure.
 * @param x509 The X.509 engine to use for certificate operations.
 *
 * @return 0 if the manager was successfully initialized or an error code.
 */
int riot_key_manager_init (struct riot_key_manager *riot, struct keystore *keystore,
	const struct riot_keys *keys, struct x509_engine *x509)
{
	return riot_key_manager_init_certs (riot, keystore, keys, x509, false);
}

/**
 * Initialize the manager for RIoT device keys.
 *
 * Keys are provided in static buffers.
 *
 * @param riot The RIoT key manager to initialize.
 * @param keystore The storage to use for RIoT keys.
 * @param keys The device keys generated by RIoT Core.  This structure should not be accessed
 * externally after a successful call.  It is best to make this a temporary structure.
 * @param x509 The X.509 engine to use for certificate operations.
 *
 * @return 0 if the manager was successfully initialized or an error code.
 */
int riot_key_manager_init_static (struct riot_key_manager *riot, struct keystore *keystore,
	const struct riot_keys *keys, struct x509_engine *x509)
{
	return riot_key_manager_init_certs (riot, keystore, keys, x509, true);
}

/**
 * Release the resources used by a RIoT key manager.  The RIoT device keys themselves will not be
 * released.
 *
 * @param riot The RIoT key manager to initialize.
 */
void riot_key_manager_release (struct riot_key_manager *riot)
{
	if (riot) {
		if (!riot->static_devid) {
			platform_free ((void*) riot->keys.devid_cert);
		}
		if (!riot->static_keys) {
			platform_free ((void*) riot->keys.devid_csr);
			platform_free ((void*) riot->keys.alias_key);
			platform_free ((void*) riot->keys.alias_cert);
		}

		riot_key_manager_free_ca_cert (&riot->root_ca);
		riot_key_manager_free_ca_cert (&riot->intermediate_ca);

		platform_mutex_free (&riot->store_lock);
		platform_mutex_free (&riot->auth_lock);
	}
}

/**
 * Store the signed Device ID certificate.
 *
 * Once an authorized chain has been stored, further attempts to store a signed Device ID
 * certificate will fail.
 *
 * @param riot The RIoT key manager to update.
 * @param dev_id The DER encoded data for the signed Device ID X.509 certificate.
 * @param length The length of the certificate DER.
 *
 * @return 0 if the Device ID certificate was successfully stored or an error code.
 */
int riot_key_manager_store_signed_device_id (struct riot_key_manager *riot, const uint8_t *dev_id,
	size_t length)
{
	return riot_key_manager_store_certificate (riot, 0, dev_id, length);
}

/**
 * Store the Root CA certificate used to authenticate the Device ID.
 *
 * Once an authorized chain has been stored, further attempts to store a Root CA certificate will
 * fail.
 *
 * @param riot The RIoT key manager to update.
 * @param dev_id The DER encoded data for the Root CA X.509 certificate.
 * @param length The length of the certificate DER.
 *
 * @return 0 if the Root CA certificate was successfully stored or an error code.
 */
int riot_key_manager_store_root_ca (struct riot_key_manager *riot, const uint8_t *root_ca,
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
 * @param riot The RIoT key manager to update.
 * @param dev_id The DER encoded data for the Intermediate CA X.509 certificate.
 * @param length The length of the certificate DER.
 *
 * @return 0 if the Intermediate CA certificate was successfully stored or an error code.
 */
int riot_key_manager_store_intermediate_ca (struct riot_key_manager *riot, const uint8_t *intr_ca,
	size_t length)
{
	return riot_key_manager_store_certificate (riot, 2, intr_ca, length);
}

/**
 * Verify the the stored certificate chain.  If all stored certificates create an authorized chain,
 * the RIoT certificates exposed by the manager will be updated to match the stored ones.
 *
 * Once the certificate chain has been verified, further attempts to store certificates will fail.
 *
 * Updates to the certificate chain will be blocked until the RIoT Core device keys are not in use.
 *
 * @param riot The RIoT key manager that will be verified.
 *
 * @return 0 if the chain was successfully verified or an error code.
 */
int riot_key_manager_verify_stored_certs (struct riot_key_manager *riot)
{
	if (riot == NULL) {
		return RIOT_KEY_MANAGER_INVALID_ARGUMENT;
	}

	return riot_key_manager_authenticate_stored_certificates (riot);
}

 /**
 * Erase all stored certificates.  Certificates loaded in memory will not be affected.
 *
 * @param riot The RIoT key manager to update.
 *
 * @return 0 if all certificates were successfully erased or an error code.
 */
int riot_key_manager_erase_all_certificates (struct riot_key_manager *riot)
{
	int status;

	if (riot == NULL) {
		return RIOT_KEY_MANAGER_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&riot->store_lock);

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
	platform_mutex_unlock (&riot->store_lock);
	return status;
}

/**
 * Get the RIoT Core device keys.  Updates to the RIoT keys will be blocked until the caller
 * indicates they are finished using them by calling riot_key_manager_release_riot_keys().
 *
 * @param riot The RIoT key manager to query.
 *
 * @return The RIoT keys or null.  If not null, riot_key_manager_release_riot_keys() must be
 * called after the keys are used.
 */
const struct riot_keys* riot_key_manager_get_riot_keys (struct riot_key_manager *riot)
{
	if (riot) {
		/* Since a lock is being taken, only one external component can access the keys at a time.
		 * If multiple modules ever need to access the keys simultaneously, this lock will need to
		 * only be used to protect a reference count on the keys structure. */
		platform_mutex_lock (&riot->auth_lock);
		return &riot->keys;
	}
	else {
		return NULL;
	}
}

/**
 * Indicate that the RIoT Core device keys are not currently in use.
 *
 * @param riot The RIoT key manager to update.
 * @param keys The RIoT keys being released.
 */
void riot_key_manager_release_riot_keys (struct riot_key_manager *riot,
	const struct riot_keys *keys)
{
	if ((riot != NULL) && (keys == &riot->keys)) {
		platform_mutex_unlock (&riot->auth_lock);
	}
}

/**
 * Get the root CA certificate for RIoT keys.
 *
 * @param riot The RIoT key manager to query.
 *
 * @return The root CA certificate or null if there is no root CA.  The certificate memory is owned
 * by the RIoT manager and must not be freed by the user.
 */
const struct der_cert* riot_key_manager_get_root_ca (struct riot_key_manager *riot)
{
	if (riot && riot->root_ca.cert) {
		return &riot->root_ca;
	}
	else {
		return NULL;
	}
}

/**
 * Get the intermediate CA certificate used to sign the Device ID.
 *
 * @param riot The RIoT key manager to query.
 *
 * @return The intermediate CA certificate or null if there is no intermediate CA.  The certificate
 * memory is owned by the RIoT manager and must not be freed by the user.
 */
const struct der_cert* riot_key_manager_get_intermediate_ca (struct riot_key_manager *riot)
{
	if (riot && riot->intermediate_ca.cert) {
		return &riot->intermediate_ca;
	}
	else {
		return NULL;
	}
}
