// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "spdm_persistent_context_no_secure_session.h"
#include "common/type_cast.h"
#include "common/unused.h"

int spdm_persistent_context_no_secure_session_get_responder_state (
	const struct spdm_persistent_context_interface *context, struct spdm_responder_state **state)
{
	const struct spdm_persistent_context_no_secure_session *impl =
		TO_DERIVED_TYPE (context, struct spdm_persistent_context_no_secure_session, base);

	if ((context == NULL) || (state == NULL)) {
		return SPDM_PERSISTENT_CONTEXT_INVALID_ARGUMENT;
	}

	*state = &impl->state->responder_state;

	return 0;
}

int spdm_persistent_context_no_secure_session_get_secure_session_manager_state (
	const struct spdm_persistent_context_interface *context,
	struct spdm_secure_session_manager_persistent_state **state)
{
	UNUSED (context);
	UNUSED (state);

	return SPDM_PERSISTENT_CONTEXT_GET_SESSION_MANAGER_STATE_FAILED;
}

void spdm_persistent_context_no_secure_session_unlock (
	const struct spdm_persistent_context_interface *context)
{
	/* No resources to release */
	UNUSED (context);
}

/**
 * Initialize a SPDM persistent context instance without secure session support. This function
 * does not initialize state struct. State must be initialized using designated functions on
 * SPDM responder side.
 *
 * @param context The context to initialize.
 * @param state The internal state for the context.
 *
 * @return 0 if the context was successfully initialized or an error code.
 */
int spdm_persistent_context_no_secure_session_init (
	struct spdm_persistent_context_no_secure_session *context,
	struct spdm_persistent_context_no_secure_session_state *state)
{
	if ((context == NULL) || (state == NULL)) {
		return SPDM_PERSISTENT_CONTEXT_INVALID_ARGUMENT;
	}

	memset (context, 0, sizeof (*context));
	context->state = state;

	context->base.get_responder_state =
		spdm_persistent_context_no_secure_session_get_responder_state;
	context->base.get_secure_session_manager_state =
		spdm_persistent_context_no_secure_session_get_secure_session_manager_state;
	context->base.unlock = spdm_persistent_context_no_secure_session_unlock;

	return 0;
}

/**
 * Releases any resources for SPDM persistent context
 *
 * @param context SPDM persistent context
 */
void spdm_persistent_context_no_secure_session_release (
	struct spdm_persistent_context_no_secure_session *context)
{
	/* No resources to release */
	UNUSED (context);
}
