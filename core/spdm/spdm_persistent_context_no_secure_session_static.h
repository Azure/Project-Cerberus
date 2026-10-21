// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPDM_PERSISTENT_CONTEXT_NO_SECURE_SESSION_STATIC_H_
#define SPDM_PERSISTENT_CONTEXT_NO_SECURE_SESSION_STATIC_H_

#include "spdm_persistent_context_no_secure_session.h"

int spdm_persistent_context_no_secure_session_get_responder_state (
	const struct spdm_persistent_context_interface *context, struct spdm_responder_state **state);
int spdm_persistent_context_no_secure_session_get_secure_session_manager_state (
	const struct spdm_persistent_context_interface *context,
	struct spdm_secure_session_manager_persistent_state **state);
void spdm_persistent_context_no_secure_session_unlock (
	const struct spdm_persistent_context_interface *context);

/**
 * Constant initializer for the SPDM persistent context interface.
 */
#define SPDM_PERSISTENT_CONTEXT_NO_SECURE_SESSION_API_INIT { \
	.get_responder_state = spdm_persistent_context_no_secure_session_get_responder_state, \
	.get_secure_session_manager_state = spdm_persistent_context_no_secure_session_get_secure_session_manager_state, \
	.unlock = spdm_persistent_context_no_secure_session_unlock, \
}

/**
 * Initialize a static instance of a SPDM persistent context located in DTCM.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Internal state for the context.
 */
#define spdm_persistent_context_no_secure_session_static_init(state_ptr) { \
	.base = SPDM_PERSISTENT_CONTEXT_NO_SECURE_SESSION_API_INIT, \
	.state = state_ptr, \
}


#endif	/* SPDM_PERSISTENT_CONTEXT_NO_SECURE_SESSION_STATIC_H_ */
