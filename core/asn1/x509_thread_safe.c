// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "x509_thread_safe.h"


#ifdef X509_ENABLE_CREATE_CERTIFICATES
int x509_thread_safe_create_csr (const struct x509_engine *engine, const uint8_t *priv_key,
	size_t key_length, enum hash_type sig_hash, const char *name, int type, const uint8_t *eku,
	size_t eku_length, const struct x509_extension_builder *const *extra_extensions,
	size_t ext_count, uint8_t **csr, size_t *csr_length)
{
	const struct x509_engine_thread_safe *x509 = (const struct x509_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&x509->state->lock);
	status = x509->engine->create_csr (x509->engine, priv_key, key_length, sig_hash, name, type,
		eku, eku_length, extra_extensions, ext_count, csr, csr_length);
	platform_mutex_unlock (&x509->state->lock);

	return status;
}

int x509_thread_safe_create_self_signed_certificate (const struct x509_engine *engine,
	struct x509_certificate *cert, const uint8_t *priv_key, size_t key_length,
	enum hash_type sig_hash, const uint8_t *serial_num, size_t serial_length, const char *name,
	int type, const struct x509_extension_builder *const *extra_extensions, size_t ext_count)
{
	const struct x509_engine_thread_safe *x509 = (const struct x509_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&x509->state->lock);
	status = x509->engine->create_self_signed_certificate (x509->engine, cert, priv_key, key_length,
		sig_hash, serial_num, serial_length, name, type, extra_extensions, ext_count);
	platform_mutex_unlock (&x509->state->lock);

	return status;
}

int x509_thread_safe_create_ca_signed_certificate (const struct x509_engine *engine,
	struct x509_certificate *cert, const uint8_t *key, size_t key_length, const uint8_t *serial_num,
	size_t serial_length, const char *name, int type, const uint8_t *ca_priv_key,
	size_t ca_key_length, enum hash_type sig_hash, const struct x509_certificate *ca_cert,
	const struct x509_extension_builder *const *extra_extensions, size_t ext_count)
{
	const struct x509_engine_thread_safe *x509 = (const struct x509_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&x509->state->lock);
	status = x509->engine->create_ca_signed_certificate (x509->engine, cert, key, key_length,
		serial_num, serial_length, name, type, ca_priv_key, ca_key_length, sig_hash, ca_cert,
		extra_extensions, ext_count);
	platform_mutex_unlock (&x509->state->lock);

	return status;
}
#endif

int x509_thread_safe_load_certificate (const struct x509_engine *engine,
	struct x509_certificate *cert, const uint8_t *der, size_t length)
{
	const struct x509_engine_thread_safe *x509 = (const struct x509_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&x509->state->lock);
	status = x509->engine->load_certificate (x509->engine, cert, der, length);
	platform_mutex_unlock (&x509->state->lock);

	return status;
}

void x509_thread_safe_release_certificate (const struct x509_engine *engine,
	struct x509_certificate *cert)
{
	const struct x509_engine_thread_safe *x509 = (const struct x509_engine_thread_safe*) engine;

	if (engine == NULL) {
		return;
	}

	platform_mutex_lock (&x509->state->lock);
	x509->engine->release_certificate (x509->engine, cert);
	platform_mutex_unlock (&x509->state->lock);
}

#ifdef X509_ENABLE_CREATE_CERTIFICATES
int x509_thread_safe_get_certificate_der (const struct x509_engine *engine,
	const struct x509_certificate *cert, uint8_t **der, size_t *length)
{
	const struct x509_engine_thread_safe *x509 = (const struct x509_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&x509->state->lock);
	status = x509->engine->get_certificate_der (x509->engine, cert, der, length);
	platform_mutex_unlock (&x509->state->lock);

	return status;
}
#endif

#ifdef X509_ENABLE_AUTHENTICATION
int x509_thread_safe_get_certificate_version (const struct x509_engine *engine,
	const struct x509_certificate *cert)
{
	const struct x509_engine_thread_safe *x509 = (const struct x509_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&x509->state->lock);
	status = x509->engine->get_certificate_version (x509->engine, cert);
	platform_mutex_unlock (&x509->state->lock);

	return status;
}

int x509_thread_safe_get_serial_number (const struct x509_engine *engine,
	const struct x509_certificate *cert, uint8_t *serial_num, size_t length)
{
	const struct x509_engine_thread_safe *x509 = (const struct x509_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&x509->state->lock);
	status = x509->engine->get_serial_number (x509->engine, cert, serial_num, length);
	platform_mutex_unlock (&x509->state->lock);

	return status;
}

int x509_thread_safe_get_public_key_type (const struct x509_engine *engine,
	const struct x509_certificate *cert)
{
	const struct x509_engine_thread_safe *x509 = (const struct x509_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&x509->state->lock);
	status = x509->engine->get_public_key_type (x509->engine, cert);
	platform_mutex_unlock (&x509->state->lock);

	return status;
}

int x509_thread_safe_get_public_key_length (const struct x509_engine *engine,
	const struct x509_certificate *cert)
{
	const struct x509_engine_thread_safe *x509 = (const struct x509_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&x509->state->lock);
	status = x509->engine->get_public_key_length (x509->engine, cert);
	platform_mutex_unlock (&x509->state->lock);

	return status;
}

int x509_thread_safe_get_public_key (const struct x509_engine *engine,
	const struct x509_certificate *cert, uint8_t **key, size_t *key_length)
{
	const struct x509_engine_thread_safe *x509 = (const struct x509_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&x509->state->lock);
	status = x509->engine->get_public_key (x509->engine, cert, key, key_length);
	platform_mutex_unlock (&x509->state->lock);

	return status;
}

int x509_thread_safe_init_ca_cert_store (const struct x509_engine *engine,
	struct x509_ca_certs *store)
{
	const struct x509_engine_thread_safe *x509 = (const struct x509_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&x509->state->lock);
	status = x509->engine->init_ca_cert_store (x509->engine, store);
	platform_mutex_unlock (&x509->state->lock);

	return status;
}

void x509_thread_safe_release_ca_cert_store (const struct x509_engine *engine,
	struct x509_ca_certs *store)
{
	const struct x509_engine_thread_safe *x509 = (const struct x509_engine_thread_safe*) engine;

	if (engine == NULL) {
		return;
	}

	platform_mutex_lock (&x509->state->lock);
	x509->engine->release_ca_cert_store (x509->engine, store);
	platform_mutex_unlock (&x509->state->lock);
}

int x509_thread_safe_add_root_ca (const struct x509_engine *engine, struct x509_ca_certs *store,
	const uint8_t *der, size_t length)
{
	const struct x509_engine_thread_safe *x509 = (const struct x509_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&x509->state->lock);
	status = x509->engine->add_root_ca (x509->engine, store, der, length);
	platform_mutex_unlock (&x509->state->lock);

	return status;
}

int x509_thread_safe_add_trusted_ca (const struct x509_engine *engine, struct x509_ca_certs *store,
	const uint8_t *der, size_t length)
{
	const struct x509_engine_thread_safe *x509 = (const struct x509_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&x509->state->lock);
	status = x509->engine->add_trusted_ca (x509->engine, store, der, length);
	platform_mutex_unlock (&x509->state->lock);

	return status;
}

int x509_thread_safe_add_intermediate_ca (const struct x509_engine *engine,
	struct x509_ca_certs *store, const uint8_t *der, size_t length)
{
	const struct x509_engine_thread_safe *x509 = (const struct x509_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&x509->state->lock);
	status = x509->engine->add_intermediate_ca (x509->engine, store, der, length);
	platform_mutex_unlock (&x509->state->lock);

	return status;
}

int x509_thread_safe_authenticate (const struct x509_engine *engine,
	const struct x509_certificate *cert, const struct x509_ca_certs *store)
{
	const struct x509_engine_thread_safe *x509 = (const struct x509_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&x509->state->lock);
	status = x509->engine->authenticate (x509->engine, cert, store);
	platform_mutex_unlock (&x509->state->lock);

	return status;
}
#endif

/**
 * Initialize a thread-safe wrapper for a Base64 engine.
 *
 * @param engine The thread-safe engine to initialize.
 * @param state Variable context for the thread-safe engine  This must be uninitialized.
 * @param target The target engine that will be used to execute operations.
 *
 * @return 0 if the engine was successfully initialized or an error code.
 */
int x509_thread_safe_init (struct x509_engine_thread_safe *engine,
	struct x509_engine_thread_safe_state *state, const struct x509_engine *target)
{
	if ((engine == NULL) || (state == NULL) || (target == NULL)) {
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
	engine->base.add_trusted_ca = x509_thread_safe_add_trusted_ca;
	engine->base.add_intermediate_ca = x509_thread_safe_add_intermediate_ca;
	engine->base.authenticate = x509_thread_safe_authenticate;
#endif

	engine->state = state;
	engine->engine = target;

	return x509_thread_safe_init_state (engine);
}

/**
 * Initialize only the variable state of thread-state X.509 engine wrapper.  The rest of the
 * instance is assumed to already have been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param engine The X.509 engine that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int x509_thread_safe_init_state (const struct x509_engine_thread_safe *engine)
{
	if ((engine == NULL) || (engine->state == NULL) || (engine->engine == NULL)) {
		return X509_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine->state, 0, sizeof (*engine->state));

	return platform_mutex_init (&engine->state->lock);
}

/**
 * Release the resources used for a thread-safe Base64 wrapper.
 *
 * @param engine The thread-safe engine to release.
 */
void x509_thread_safe_release (const struct x509_engine_thread_safe *engine)
{
	if (engine != NULL) {
		platform_mutex_free (&engine->state->lock);
	}
}
