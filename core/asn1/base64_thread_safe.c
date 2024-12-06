// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "base64_thread_safe.h"


int base64_thread_safe_encode (const struct base64_engine *engine, const uint8_t *data,
	size_t length, uint8_t *encoded, size_t enc_length)
{
	const struct base64_engine_thread_safe *base64 =
		(const struct base64_engine_thread_safe*) engine;
	int status;

	if (base64 == NULL) {
		return BASE64_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&base64->state->lock);
	status = base64->engine->encode (base64->engine, data, length, encoded, enc_length);
	platform_mutex_unlock (&base64->state->lock);

	return status;
}

/**
 * Initialize a thread-safe wrapper for a Base64 engine.
 *
 * @param engine The thread-safe engine to initialize.
 * @param state Variable context for the thread-safe engine.  This must be uninitialized.
 * @param target The target engine that will be used to execute operations.
 *
 * @return 0 if the engine was successfully initialized or an error code.
 */
int base64_thread_safe_init (struct base64_engine_thread_safe *engine,
	struct base64_engine_thread_safe_state *state, const struct base64_engine *target)
{
	if (engine == NULL) {
		return BASE64_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine, 0, sizeof (struct base64_engine_thread_safe));

	engine->base.encode = base64_thread_safe_encode;

	engine->state = state;
	engine->engine = target;

	return base64_thread_safe_init_state (engine);
}

/**
 * Initialize only the variable state of thread-state Base64 engine wrapper.  The rest of the
 * instance is assumed to already have been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param engine The Base64 engine that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int base64_thread_safe_init_state (const struct base64_engine_thread_safe *engine)
{
	if ((engine == NULL) || (engine->state == NULL) || (engine->engine == NULL)) {
		return BASE64_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine->state, 0, sizeof (*engine->state));

	return platform_mutex_init (&engine->state->lock);
}

/**
 * Release the resources used for a thread-safe Base64 wrapper.
 *
 * @param engine The thread-safe engine to release.
 */
void base64_thread_safe_release (const struct base64_engine_thread_safe *engine)
{
	if (engine != NULL) {
		platform_mutex_free (&engine->state->lock);
	}
}
