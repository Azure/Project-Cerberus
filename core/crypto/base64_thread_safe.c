// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "base64_thread_safe.h"


static int base64_thread_safe_encode (struct base64_engine *engine, const uint8_t *data,
	size_t length, uint8_t *encoded, size_t enc_length)
{
	struct base64_engine_thread_safe *base64 = (struct base64_engine_thread_safe*) engine;
	int status;

	if (base64 == NULL) {
		return BASE64_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&base64->lock);
	status = base64->engine->encode (base64->engine, data, length, encoded, enc_length);
	platform_mutex_unlock (&base64->lock);

	return status;
}

/**
 * Initialize a thread-safe wrapper for a Base64 engine.
 *
 * @param engine The thread-safe engine to initialize.
 * @param target The target engine that will be used to execute operations.
 *
 * @return 0 if the engine was successfully initialized or an error code.
 */
int base64_thread_safe_init (struct base64_engine_thread_safe *engine, struct base64_engine *target)
{
	if ((engine == NULL) || (target == NULL)) {
		return BASE64_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine, 0, sizeof (struct base64_engine_thread_safe));

	engine->base.encode = base64_thread_safe_encode;

	engine->engine = target;

	return platform_mutex_init (&engine->lock);
}

/**
 * Release the resources used for a thread-safe Base64 wrapper.
 *
 * @param engine The thread-safe engine to release.
 */
void base64_thread_safe_release (struct base64_engine_thread_safe *engine)
{
	if (engine != NULL) {
		platform_mutex_free (&engine->lock);
	}
}
