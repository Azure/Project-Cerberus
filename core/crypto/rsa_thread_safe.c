// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "rsa_thread_safe.h"


#ifdef RSA_ENABLE_PRIVATE_KEY
int rsa_thread_safe_generate_key (const struct rsa_engine *engine, struct rsa_private_key *key,
	int bits)
{
	const struct rsa_engine_thread_safe *rsa = (const struct rsa_engine_thread_safe*) engine;
	int status;

	if (rsa == NULL) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&rsa->state->lock);
	status = rsa->engine->generate_key (rsa->engine, key, bits);
	platform_mutex_unlock (&rsa->state->lock);

	return status;
}

int rsa_thread_safe_init_private_key (const struct rsa_engine *engine, struct rsa_private_key *key,
	const uint8_t *der, size_t length)
{
	const struct rsa_engine_thread_safe *rsa = (const struct rsa_engine_thread_safe*) engine;
	int status;

	if (rsa == NULL) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&rsa->state->lock);
	status = rsa->engine->init_private_key (rsa->engine, key, der, length);
	platform_mutex_unlock (&rsa->state->lock);

	return status;
}

void rsa_thread_safe_release_key (const struct rsa_engine *engine, struct rsa_private_key *key)
{
	const struct rsa_engine_thread_safe *rsa = (const struct rsa_engine_thread_safe*) engine;

	if (rsa == NULL) {
		return;
	}

	platform_mutex_lock (&rsa->state->lock);
	rsa->engine->release_key (rsa->engine, key);
	platform_mutex_unlock (&rsa->state->lock);
}

int rsa_thread_safe_get_private_key_der (const struct rsa_engine *engine,
	const struct rsa_private_key *key, uint8_t **der, size_t *length)
{
	const struct rsa_engine_thread_safe *rsa = (const struct rsa_engine_thread_safe*) engine;
	int status;

	if (rsa == NULL) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&rsa->state->lock);
	status = rsa->engine->get_private_key_der (rsa->engine, key, der, length);
	platform_mutex_unlock (&rsa->state->lock);

	return status;
}

#ifndef RSA_DISABLE_DECRYPT
int rsa_thread_safe_decrypt (const struct rsa_engine *engine, const struct rsa_private_key *key,
	const uint8_t *encrypted, size_t in_length, const uint8_t *label, size_t label_length,
	enum hash_type pad_hash, uint8_t *decrypted, size_t out_length)
{
	const struct rsa_engine_thread_safe *rsa = (const struct rsa_engine_thread_safe*) engine;
	int status;

	if (rsa == NULL) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&rsa->state->lock);
	status = rsa->engine->decrypt (rsa->engine, key, encrypted, in_length, label, label_length,
		pad_hash, decrypted, out_length);
	platform_mutex_unlock (&rsa->state->lock);

	return status;
}
#endif	// RSA_DISABLE_DECRYPT
#endif	// RSA_ENABLE_PRIVATE_KEY

#ifdef RSA_ENABLE_DER_PUBLIC_KEY
int rsa_thread_safe_init_public_key (const struct rsa_engine *engine, struct rsa_public_key *key,
	const uint8_t *der, size_t length)
{
	const struct rsa_engine_thread_safe *rsa = (const struct rsa_engine_thread_safe*) engine;
	int status;

	if (rsa == NULL) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&rsa->state->lock);
	status = rsa->engine->init_public_key (rsa->engine, key, der, length);
	platform_mutex_unlock (&rsa->state->lock);

	return status;
}

int rsa_thread_safe_get_public_key_der (const struct rsa_engine *engine,
	const struct rsa_private_key *key, uint8_t **der, size_t *length)
{
	const struct rsa_engine_thread_safe *rsa = (const struct rsa_engine_thread_safe*) engine;
	int status;

	if (rsa == NULL) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&rsa->state->lock);
	status = rsa->engine->get_public_key_der (rsa->engine, key, der, length);
	platform_mutex_unlock (&rsa->state->lock);

	return status;
}
#endif

int rsa_thread_safe_sig_verify (const struct rsa_engine *engine, const struct rsa_public_key *key,
	const uint8_t *signature, size_t sig_length, enum hash_type sig_hash, const uint8_t *match,
	size_t match_length)
{
	const struct rsa_engine_thread_safe *rsa = (const struct rsa_engine_thread_safe*) engine;
	int status;

	if (rsa == NULL) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&rsa->state->lock);
	status = rsa->engine->sig_verify (rsa->engine, key, signature, sig_length, sig_hash, match,
		match_length);
	platform_mutex_unlock (&rsa->state->lock);

	return status;
}

/**
 * Initialize a thread-safe wrapper for an RSA engine.
 *
 * @param engine The thread-safe engine to initialize.
 * @param state Variable context for the RSA wrapper.  This must be uninitialized.
 * @param target The target engine that will be used to execute operations.
 *
 * @return 0 if the engine was successfully initialized or an error code.
 */
int rsa_thread_safe_init (struct rsa_engine_thread_safe *engine,
	struct rsa_engine_thread_safe_state *state, const struct rsa_engine *target)
{
	if (engine == NULL) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine, 0, sizeof (struct rsa_engine_thread_safe));

#ifdef RSA_ENABLE_PRIVATE_KEY
	engine->base.generate_key = rsa_thread_safe_generate_key;
	engine->base.init_private_key = rsa_thread_safe_init_private_key;
	engine->base.release_key = rsa_thread_safe_release_key;
	engine->base.get_private_key_der = rsa_thread_safe_get_private_key_der;
#ifndef RSA_DISABLE_DECRYPT
	engine->base.decrypt = rsa_thread_safe_decrypt;
#endif
#endif
#ifdef RSA_ENABLE_DER_PUBLIC_KEY
	engine->base.init_public_key = rsa_thread_safe_init_public_key;
	engine->base.get_public_key_der = rsa_thread_safe_get_public_key_der;
#endif
	engine->base.sig_verify = rsa_thread_safe_sig_verify;

	engine->state = state;
	engine->engine = target;

	return rsa_thread_safe_init_state (engine);
}

/**
 * Initialize only the variable state of a thread-safe wrapper for an RSA engine.  The rest of the
 * instance is assumed to already have been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param engine The RSA engine that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int rsa_thread_safe_init_state (const struct rsa_engine_thread_safe *engine)
{
	if ((engine == NULL) || (engine->state == NULL) || (engine->engine == NULL)) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine->state, 0, sizeof (*engine->state));

	return platform_mutex_init (&engine->state->lock);
}

/**
 * Release the resources used for a thread-safe RSA wrapper.
 *
 * @param engine The thread-safe engine to release.
 */
void rsa_thread_safe_release (const struct rsa_engine_thread_safe *engine)
{
	if (engine != NULL) {
		platform_mutex_free (&engine->state->lock);
	}
}
