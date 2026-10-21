// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPDM_PERSISTENT_CONTEXT_NO_SECURE_SESSION_H_
#define SPDM_PERSISTENT_CONTEXT_NO_SECURE_SESSION_H_

#include "spdm/spdm_persistent_context_interface.h"
#include "spdm/spdm_state.h"

/**
 * Internal state for the SPDM persistent context without secure session support.
 */
struct spdm_persistent_context_no_secure_session_state {
	struct spdm_responder_state responder_state;	/**< SPDM responder state. */
};

/**
 * Implementation of the SPDM persistent context.
 */
struct spdm_persistent_context_no_secure_session {
	struct spdm_persistent_context_interface base;					/**< SPDM persistent context interface */
	struct spdm_persistent_context_no_secure_session_state *state;	/**< Internal state */
};


int spdm_persistent_context_no_secure_session_init (
	struct spdm_persistent_context_no_secure_session *context,
	struct spdm_persistent_context_no_secure_session_state *state);
void spdm_persistent_context_no_secure_session_release (
	struct spdm_persistent_context_no_secure_session *context);


#endif	/* SPDM_PERSISTENT_CONTEXT_NO_SECURE_SESSION_H_ */
