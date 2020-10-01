// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "x509_thread_safe.h"


#ifdef X509_ENABLE_CREATE_CERTIFICATES
static int x509_thread_safe_create_csr (struct x509_engine *engine, const uint8_t *priv_key,
	size_t key_length, const char *name, int type, const char *eku,
	const struct x509_dice_tcbinfo *dice, uint8_t **csr, size_t *csr_length)
{
	struct x509_engine_thread_safe *x509 = (struct x509_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&x509->lock);
	status = x509->engine->create_csr (x509->engine, priv_key, key_length, name, type, eku, dice,
		csr, csr_length);
	platform_mutex_unlock (&x509->lock);

	return status;
}

static int x509_thread_safe_create_self_signed_certificate (struct x509_engine *engine,
	struct x509_certificate *cert, const uint8_t *priv_key, size_t key_length,
	const uint8_t *serial_num, size_t serial_length, const char *name, int type,
	const struct x509_dice_tcbinfo *dice)
{
	struct x509_engine_thread_safe *x509 = (struct x509_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&x509->lock);
	status = x509->engine->create_self_signed_certificate (x509->engine, cert, priv_key, key_length,
		serial_num, serial_length, name, type, dice);
	platform_mutex_unlock (&x509->lock);

	return status;
}

static int x509_thread_safe_create_ca_signed_certificate (struct x509_engine *engine,
	struct x509_certificate *cert, const uint8_t *key, size_t key_length, const uint8_t *serial_num,
	size_t serial_length, const char *name, int type, const uint8_t* ca_priv_key,
	size_t ca_key_length, const struct x509_certificate *ca_cert,
	const struct x509_dice_tcbinfo *dice)
{
	struct x509_engine_thread_safe *x509 = (struct x509_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&x509->lock);
	status = x509->engine->create_ca_signed_certificate (x509->engine, cert, key, key_length,
		serial_num, serial_length, name, type, ca_priv_key, ca_key_length, ca_cert, dice);
	platform_mutex_unlock (&x509->lock);

	return status;
}
#endif

static int x509_thread_safe_load_certificate (struct x509_engine *engine,
	struct x509_certificate *cert, const uint8_t *der, size_t length)
{
	struct x509_engine_thread_safe *x509 = (struct x509_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&x509->lock);
	status = x509->engine->load_certificate (x509->engine, cert, der, length);
	platform_mutex_unlock (&x509->lock);

	return status;
}

static void x509_thread_safe_release_certificate (struct x509_engine *engine,
	struct x509_certificate *cert)
{
	struct x509_engine_thread_safe *x509 = (struct x509_engine_thread_safe*) engine;

	if (engine == NULL) {
		return;
	}

	platform_mutex_lock (&x509->lock);
	x509->engine->release_certificate (x509->engine, cert);
	platform_mutex_unlock (&x509->lock);
}

#ifdef X509_ENABLE_CREATE_CERTIFICATES
static int x509_thread_safe_get_certificate_der (struct x509_engine *engine,
	const struct x509_certificate *cert, uint8_t **der, size_t *length)
{
	struct x509_engine_thread_safe *x509 = (struct x509_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&x509->lock);
	status = x509->engine->get_certificate_der (x509->engine, cert, der, length);
	platform_mutex_unlock (&x509->lock);

	return status;
}
#endif

#ifdef X509_ENABLE_AUTHENTICATION
static int x509_thread_safe_get_certificate_version (struct x509_engine *engine,
	const struct x509_certificate *cert)
{
	struct x509_engine_thread_safe *x509 = (struct x509_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&x509->lock);
	status = x509->engine->get_certificate_version (x509->engine, cert);
	platform_mutex_unlock (&x509->lock);

	return status;
}

static int x509_thread_safe_get_serial_number (struct x509_engine *engine,
	const struct x509_certificate *cert, uint8_t *serial_num, size_t length)
{
	struct x509_engine_thread_safe *x509 = (struct x509_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&x509->lock);
	status = x509->engine->get_serial_number (x509->engine, cert, serial_num, length);
	platform_mutex_unlock (&x509->lock);

	return status;
}

static int x509_thread_safe_get_public_key_type (struct x509_engine *engine,
	const struct x509_certificate *cert)
{
	struct x509_engine_thread_safe *x509 = (struct x509_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&x509->lock);
	status = x509->engine->get_public_key_type (x509->engine, cert);
	platform_mutex_unlock (&x509->lock);

	return status;
}

static int x509_thread_safe_get_public_key_length (struct x509_engine *engine,
	const struct x509_certificate *cert)
{
	struct x509_engine_thread_safe *x509 = (struct x509_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&x509->lock);
	status = x509->engine->get_public_key_length (x509->engine, cert);
	platform_mutex_unlock (&x509->lock);

	return status;
}

static int x509_thread_safe_get_public_key (struct x509_engine *engine,
	const struct x509_certificate *cert, uint8_t **key, size_t *key_length)
{
	struct x509_engine_thread_safe *x509 = (struct x509_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&x509->lock);
	status = x509->engine->get_public_key (x509->engine, cert, key, key_length);
	platform_mutex_unlock (&x509->lock);

	return status;
}

static int x509_thread_safe_init_ca_cert_store (struct x509_engine *engine,
	struct x509_ca_certs *store)
{
	struct x509_engine_thread_safe *x509 = (struct x509_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&x509->lock);
	status = x509->engine->init_ca_cert_store (x509->engine, store);
	platform_mutex_unlock (&x509->lock);

	return status;
}

static void x509_thread_safe_release_ca_cert_store (struct x509_engine *engine,
	struct x509_ca_certs *store)
{
	struct x509_engine_thread_safe *x509 = (struct x509_engine_thread_safe*) engine;

	if (engine == NULL) {
		return;
	}

	platform_mutex_lock (&x509->lock);
	x509->engine->release_ca_cert_store (x509->engine, store);
	platform_mutex_unlock (&x509->lock);
}

static int x509_thread_safe_add_root_ca (struct x509_engine *engine, struct x509_ca_certs *store,
	const uint8_t *der, size_t length)
{
	struct x509_engine_thread_safe *x509 = (struct x509_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&x509->lock);
	status = x509->engine->add_root_ca (x509->engine, store, der, length);
	platform_mutex_unlock (&x509->lock);

	return status;
}

static int x509_thread_safe_add_intermediate_ca (struct x509_engine *engine,
	struct x509_ca_certs *store, const uint8_t *der, size_t length)
{
	struct x509_engine_thread_safe *x509 = (struct x509_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&x509->lock);
	status = x509->engine->add_intermediate_ca (x509->engine, store, der, length);
	platform_mutex_unlock (&x509->lock);

	return status;
}

static int x509_thread_safe_authenticate (struct x509_engine *engine,
	const struct x509_certificate *cert, const struct x509_ca_certs *store)
{
	struct x509_engine_thread_safe *x509 = (struct x509_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&x509->lock);
	status = x509->engine->authenticate (x509->engine, cert, store);
	platform_mutex_unlock (&x509->lock);

	return status;
}
#endif

/**
 * Initialize a thread-safe wrapper for a Base64 engine.
 *
 * @param engine The thread-safe engine to initialize.
 * @param target The target engine that will be used to execute operations.
 *
 * @return 0 if the engine was successfully initialized or an error code.
 */
int x509_thread_safe_init (struct x509_engine_thread_safe *engine, struct x509_engine *target)
{
	if ((engine == NULL) || (target == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine, 0, sizeof (struct x509_engine_thread_safe));

#ifdef X509_ENABLE_CREATE_CERTIFICATES
	engine->base.create_csr = x509_thread_safe_create_csr;
	engine->base.create_self_signed_certificate = x509_thread_safe_create_self_signed_certificate;
	engine->base.create_ca_signed_certificate = x509_thread_safe_create_ca_signed_certificate;
#endif
	engine->base.load_certificate = x509_thread_safe_load_certificate;
	engine->base.release_certificate = x509_thread_safe_release_certificate;
#ifdef X509_ENABLE_CREATE_CERTIFICATES
	engine->base.get_certificate_der = x509_thread_safe_get_certificate_der;
#endif
#ifdef X509_ENABLE_AUTHENTICATION
	engine->base.get_certificate_version = x509_thread_safe_get_certificate_version;
	engine->base.get_serial_number = x509_thread_safe_get_serial_number;
	engine->base.get_public_key_type = x509_thread_safe_get_public_key_type;
	engine->base.get_public_key_length = x509_thread_safe_get_public_key_length;
	engine->base.get_public_key = x509_thread_safe_get_public_key;
	engine->base.init_ca_cert_store = x509_thread_safe_init_ca_cert_store;
	engine->base.release_ca_cert_store = x509_thread_safe_release_ca_cert_store;
	engine->base.add_root_ca = x509_thread_safe_add_root_ca;
	engine->base.add_intermediate_ca = x509_thread_safe_add_intermediate_ca;
	engine->base.authenticate = x509_thread_safe_authenticate;
#endif

	engine->engine = target;

	return platform_mutex_init (&engine->lock);
}

/**
 * Release the resources used for a thread-safe Base64 wrapper.
 *
 * @param engine The thread-safe engine to release.
 */
void x509_thread_safe_release (struct x509_engine_thread_safe *engine)
{
	if (engine != NULL) {
		platform_mutex_free (&engine->lock);
	}
}
