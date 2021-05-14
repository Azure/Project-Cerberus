// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "rsa_thread_safe.h"


#ifdef RSA_ENABLE_PRIVATE_KEY
static int rsa_thread_safe_generate_key (struct rsa_engine *engine, struct rsa_private_key *key,
	int bits)
{
	struct rsa_engine_thread_safe *rsa = (struct rsa_engine_thread_safe*) engine;
	int status;

	if (rsa == NULL) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&rsa->lock);
	status = rsa->engine->generate_key (rsa->engine, key, bits);
	platform_mutex_unlock (&rsa->lock);

	return status;
}

static int rsa_thread_safe_init_private_key (struct rsa_engine *engine, struct rsa_private_key *key,
	const uint8_t *der, size_t length)
{
	struct rsa_engine_thread_safe *rsa = (struct rsa_engine_thread_safe*) engine;
	int status;

	if (rsa == NULL) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&rsa->lock);
	status = rsa->engine->init_private_key (rsa->engine, key, der, length);
	platform_mutex_unlock (&rsa->lock);

	return status;
}

static void rsa_thread_safe_release_key (struct rsa_engine *engine, struct rsa_private_key *key)
{
	struct rsa_engine_thread_safe *rsa = (struct rsa_engine_thread_safe*) engine;

	if (rsa == NULL) {
		return;
	}

	platform_mutex_lock (&rsa->lock);
	rsa->engine->release_key (rsa->engine, key);
	platform_mutex_unlock (&rsa->lock);
}

static int rsa_thread_safe_get_private_key_der (struct rsa_engine *engine,
	const struct rsa_private_key *key, uint8_t **der, size_t *length)
{
	struct rsa_engine_thread_safe *rsa = (struct rsa_engine_thread_safe*) engine;
	int status;

	if (rsa == NULL) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&rsa->lock);
	status = rsa->engine->get_private_key_der (rsa->engine, key, der, length);
	platform_mutex_unlock (&rsa->lock);

	return status;
}

static int rsa_thread_safe_decrypt (struct rsa_engine *engine, const struct rsa_private_key *key,
	const uint8_t *encrypted, size_t in_length, const uint8_t *label, size_t label_length,
	enum hash_type pad_hash, uint8_t *decrypted, size_t out_length)
{
	struct rsa_engine_thread_safe *rsa = (struct rsa_engine_thread_safe*) engine;
	int status;

	if (rsa == NULL) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&rsa->lock);
	status = rsa->engine->decrypt (rsa->engine, key, encrypted, in_length, label, label_length,
		pad_hash, decrypted, out_length);
	platform_mutex_unlock (&rsa->lock);

	return status;
}
#endif

#ifdef RSA_ENABLE_DER_PUBLIC_KEY
static int rsa_thread_safe_init_public_key (struct rsa_engine *engine, struct rsa_public_key *key,
	const uint8_t *der, size_t length)
{
	struct rsa_engine_thread_safe *rsa = (struct rsa_engine_thread_safe*) engine;
	int status;

	if (rsa == NULL) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&rsa->lock);
	status = rsa->engine->init_public_key (rsa->engine, key, der, length);
	platform_mutex_unlock (&rsa->lock);

	return status;
}

static int rsa_thread_safe_get_public_key_der (struct rsa_engine *engine,
	const struct rsa_private_key *key, uint8_t **der, size_t *length)
{
	struct rsa_engine_thread_safe *rsa = (struct rsa_engine_thread_safe*) engine;
	int status;

	if (rsa == NULL) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&rsa->lock);
	status = rsa->engine->get_public_key_der (rsa->engine, key, der, length);
	platform_mutex_unlock (&rsa->lock);

	return status;
}
#endif

static int rsa_thread_safe_sig_verify (struct rsa_engine *engine, const struct rsa_public_key *key,
	const uint8_t *signature, size_t sig_length, const uint8_t *match, size_t match_length)
{
	struct rsa_engine_thread_safe *rsa = (struct rsa_engine_thread_safe*) engine;
	int status;

	if (rsa == NULL) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&rsa->lock);
	status = rsa->engine->sig_verify (rsa->engine, key, signature, sig_length, match, match_length);
	platform_mutex_unlock (&rsa->lock);

	return status;
}

/**
 * Initialize a thread-safe wrapper for an RSA engine.
 *
 * @param engine The thread-safe engine to initialize.
 * @param target The target engine that will be used to execute operations.
 *
 * @return 0 if the engine was successfully initialized or an error code.
 */
int rsa_thread_safe_init (struct rsa_engine_thread_safe *engine, struct rsa_engine *target)
{
	if ((engine == NULL) || (target == NULL)) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine, 0, sizeof (struct rsa_engine_thread_safe));

#ifdef RSA_ENABLE_PRIVATE_KEY
	engine->base.generate_key = rsa_thread_safe_generate_key;
	engine->base.init_private_key = rsa_thread_safe_init_private_key;
	engine->base.release_key = rsa_thread_safe_release_key;
	engine->base.get_private_key_der = rsa_thread_safe_get_private_key_der;
	engine->base.decrypt = rsa_thread_safe_decrypt;
#endif
#ifdef RSA_ENABLE_DER_PUBLIC_KEY
	engine->base.init_public_key = rsa_thread_safe_init_public_key;
	engine->base.get_public_key_der = rsa_thread_safe_get_public_key_der;
#endif
	engine->base.sig_verify = rsa_thread_safe_sig_verify;

	engine->engine = target;

	return platform_mutex_init (&engine->lock);
}

/**
 * Release the resources used for a thread-safe RSA wrapper.
 *
 * @param engine The thread-safe engine to release.
 */
void rsa_thread_safe_release (struct rsa_engine_thread_safe *engine)
{
	if (engine != NULL) {
		platform_mutex_free (&engine->lock);
	}
}
