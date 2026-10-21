// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "spdm_persistent_context.h"
#include "common/type_cast.h"
#include "common/unused.h"

int spdm_persistent_context_get_responder_state (
	const struct spdm_persistent_context_interface *context, struct spdm_responder_state **state)
{
	const struct spdm_persistent_context *impl =
		TO_DERIVED_TYPE (context, struct spdm_persistent_context, base);

	if ((context == NULL) || (state == NULL)) {
		return SPDM_PERSISTENT_CONTEXT_INVALID_ARGUMENT;
	}

	*state = &impl->state->responder_state;

	return 0;
}

int spdm_persistent_context_get_secure_session_manager_state (
	const struct spdm_persistent_context_interface *context,
	struct spdm_secure_session_manager_persistent_state **state)
{
	const struct spdm_persistent_context *impl =
		TO_DERIVED_TYPE (context, struct spdm_persistent_context, base);

	if ((context == NULL) || (state == NULL)) {
		return SPDM_PERSISTENT_CONTEXT_INVALID_ARGUMENT;
	}

	*state = &impl->state->ssm_state;

	return 0;
}

void spdm_persistent_context_unlock (const struct spdm_persistent_context_interface *context)
{
	/* No resources to release */
	UNUSED (context);
}

/**
 * Initialize a SPDM persistent context instance. It does not initialize state object. Designated
 * functions must be called to properly initialize runtime and persistent parts of this state.
 *
 * @param context The context to initialize.
 * @param state The internal state for the context.
 *
 * @return 0 if the context was successfully initialized or an error code.
 */
int spdm_persistent_context_init (
	struct spdm_persistent_context *context, struct spdm_persistent_context_state *state)
{
	if ((context == NULL) || (state == NULL)) {
		return SPDM_PERSISTENT_CONTEXT_INVALID_ARGUMENT;
	}

	memset (context, 0, sizeof (struct spdm_persistent_context));
	context->state = state;

	context->base.get_responder_state = spdm_persistent_context_get_responder_state;
	context->base.get_secure_session_manager_state =
		spdm_persistent_context_get_secure_session_manager_state;
	context->base.unlock = spdm_persistent_context_unlock;

	return 0;
}

/**
 * Releases any resources for SPDM persistent context
 *
 * @param context SPDM persistent context
 */
void spdm_persistent_context_release (
	struct spdm_persistent_context *context)
{
	/* No resources to release */
	UNUSED (context);
}
