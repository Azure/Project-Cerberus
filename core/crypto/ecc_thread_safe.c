// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "ecc_thread_safe.h"


static int ecc_thread_safe_init_key_pair (struct ecc_engine *engine, const uint8_t *key,
	size_t key_length, struct ecc_private_key *priv_key, struct ecc_public_key *pub_key)
{
	struct ecc_engine_thread_safe *ecc = (struct ecc_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&ecc->lock);
	status = ecc->engine->init_key_pair (ecc->engine, key, key_length, priv_key, pub_key);
	platform_mutex_unlock (&ecc->lock);

	return status;
}

static int ecc_thread_safe_init_public_key (struct ecc_engine *engine, const uint8_t *key,
	size_t key_length, struct ecc_public_key *pub_key)
{
	struct ecc_engine_thread_safe *ecc = (struct ecc_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&ecc->lock);
	status = ecc->engine->init_public_key (ecc->engine, key, key_length, pub_key);
	platform_mutex_unlock (&ecc->lock);

	return status;
}

#ifdef ECC_ENABLE_GENERATE_KEY_PAIR
static int ecc_thread_safe_generate_derived_key_pair (struct ecc_engine *engine,
	const uint8_t *priv, size_t key_length, struct ecc_private_key *priv_key,
	struct ecc_public_key *pub_key)
{
	struct ecc_engine_thread_safe *ecc = (struct ecc_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&ecc->lock);
	status = ecc->engine->generate_derived_key_pair (ecc->engine, priv, key_length, priv_key,
		pub_key);
	platform_mutex_unlock (&ecc->lock);

	return status;
}

static int ecc_thread_safe_generate_key_pair (struct ecc_engine *engine, size_t key_length,
	struct ecc_private_key *priv_key, struct ecc_public_key *pub_key)
{
	struct ecc_engine_thread_safe *ecc = (struct ecc_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&ecc->lock);
	status = ecc->engine->generate_key_pair (ecc->engine, key_length, priv_key, pub_key);
	platform_mutex_unlock (&ecc->lock);

	return status;
}
#endif

static void ecc_thread_safe_release_key_pair (struct ecc_engine *engine,
	struct ecc_private_key *priv_key, struct ecc_public_key *pub_key)
{
	struct ecc_engine_thread_safe *ecc = (struct ecc_engine_thread_safe*) engine;

	if (engine == NULL) {
		return;
	}

	platform_mutex_lock (&ecc->lock);
	ecc->engine->release_key_pair (ecc->engine, priv_key, pub_key);
	platform_mutex_unlock (&ecc->lock);
}

static int ecc_thread_safe_get_signature_max_length (struct ecc_engine *engine,
	struct ecc_private_key *key)
{
	struct ecc_engine_thread_safe *ecc = (struct ecc_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&ecc->lock);
	status = ecc->engine->get_signature_max_length (ecc->engine, key);
	platform_mutex_unlock (&ecc->lock);

	return status;
}

#ifdef ECC_ENABLE_GENERATE_KEY_PAIR
static int ecc_thread_safe_get_private_key_der (struct ecc_engine *engine,
	const struct ecc_private_key *key, uint8_t **der, size_t *length)
{
	struct ecc_engine_thread_safe *ecc = (struct ecc_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&ecc->lock);
	status = ecc->engine->get_private_key_der (ecc->engine, key, der, length);
	platform_mutex_unlock (&ecc->lock);

	return status;
}

static int ecc_thread_safe_get_public_key_der (struct ecc_engine *engine,
	const struct ecc_public_key *key, uint8_t **der, size_t *length)
{
	struct ecc_engine_thread_safe *ecc = (struct ecc_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&ecc->lock);
	status = ecc->engine->get_public_key_der (ecc->engine, key, der, length);
	platform_mutex_unlock (&ecc->lock);

	return status;
}
#endif

static int ecc_thread_safe_sign (struct ecc_engine *engine, struct ecc_private_key *key,
	const uint8_t *digest, size_t length, uint8_t *signature, size_t sig_length)
{
	struct ecc_engine_thread_safe *ecc = (struct ecc_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&ecc->lock);
	status = ecc->engine->sign (ecc->engine, key, digest, length, signature, sig_length);
	platform_mutex_unlock (&ecc->lock);

	return status;
}

static int ecc_thread_safe_verify (struct ecc_engine *engine, struct ecc_public_key *key,
	const uint8_t *digest, size_t length, const uint8_t *signature, size_t sig_length)
{
	struct ecc_engine_thread_safe *ecc = (struct ecc_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&ecc->lock);
	status = ecc->engine->verify (ecc->engine, key, digest, length, signature, sig_length);
	platform_mutex_unlock (&ecc->lock);

	return status;
}

#ifdef ECC_ENABLE_ECDH
static int ecc_thread_safe_get_shared_secret_max_length (struct ecc_engine *engine,
	struct ecc_private_key *key)
{
	struct ecc_engine_thread_safe *ecc = (struct ecc_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&ecc->lock);
	status = ecc->engine->get_shared_secret_max_length (ecc->engine, key);
	platform_mutex_unlock (&ecc->lock);

	return status;
}

static int ecc_thread_safe_compute_shared_secret (struct ecc_engine *engine,
	struct ecc_private_key *priv_key, struct ecc_public_key *pub_key, uint8_t *secret,
	size_t length)
{
	struct ecc_engine_thread_safe *ecc = (struct ecc_engine_thread_safe*) engine;
	int status;

	if (engine == NULL) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&ecc->lock);
	status = ecc->engine->compute_shared_secret (ecc->engine, priv_key, pub_key, secret, length);
	platform_mutex_unlock (&ecc->lock);

	return status;
}
#endif

/**
 * Initialize a thread-safe wrapper for an ECC engine.
 *
 * @param engine The thread-safe engine to initialize.
 * @param target The target engine that will be used to execute operations.
 *
 * @return 0 if the engine was successfully initialized or an error code.
 */
int ecc_thread_safe_init (struct ecc_engine_thread_safe *engine, struct ecc_engine *target)
{
	if ((engine == NULL) || (target == NULL)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine, 0, sizeof (struct ecc_engine_thread_safe));

	engine->base.init_key_pair = ecc_thread_safe_init_key_pair;
	engine->base.init_public_key = ecc_thread_safe_init_public_key;
#ifdef ECC_ENABLE_GENERATE_KEY_PAIR
	engine->base.generate_derived_key_pair = ecc_thread_safe_generate_derived_key_pair;
	engine->base.generate_key_pair = ecc_thread_safe_generate_key_pair;
#endif
	engine->base.release_key_pair = ecc_thread_safe_release_key_pair;
	engine->base.get_signature_max_length = ecc_thread_safe_get_signature_max_length;
#ifdef ECC_ENABLE_GENERATE_KEY_PAIR
	engine->base.get_private_key_der = ecc_thread_safe_get_private_key_der;
	engine->base.get_public_key_der = ecc_thread_safe_get_public_key_der;
#endif
	engine->base.sign = ecc_thread_safe_sign;
	engine->base.verify = ecc_thread_safe_verify;
#ifdef ECC_ENABLE_ECDH
	engine->base.get_shared_secret_max_length = ecc_thread_safe_get_shared_secret_max_length;
	engine->base.compute_shared_secret = ecc_thread_safe_compute_shared_secret;
#endif

	engine->engine = target;

	return platform_mutex_init (&engine->lock);
}

/**
 * Release the resources used for a thread-safe ECC wrapper.
 *
 * @param engine The thread-safe engine to release.
 */
void ecc_thread_safe_release (struct ecc_engine_thread_safe *engine)
{
	if (engine != NULL) {
		platform_mutex_free (&engine->lock);
	}
}
