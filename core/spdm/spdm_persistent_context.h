// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPDM_PERSISTENT_CONTEXT_H_
#define SPDM_PERSISTENT_CONTEXT_H_

#include "spdm/spdm_persistent_context_interface.h"
#include "spdm/spdm_secure_session_manager.h"
#include "spdm/spdm_state.h"

/**
 * Internal state for the SPDM persistent context.
 */
struct spdm_persistent_context_state {
	struct spdm_responder_state responder_state;					/**< SPDM responder state. */
	struct spdm_secure_session_manager_persistent_state ssm_state;	/**< SPDM secure session manager persistent state. */
};

/**
 * Implementation of the SPDM persistent context.
 */
struct spdm_persistent_context {
	struct spdm_persistent_context_interface base;	/**< SPDM persistent context interface */
	struct spdm_persistent_context_state *state;	/**< Internal state */
};


int spdm_persistent_context_init (
	struct spdm_persistent_context *context, struct spdm_persistent_context_state *state);
void spdm_persistent_context_release (
	struct spdm_persistent_context *context);


#endif	/* SPDM_PERSISTENT_CONTEXT_H_ */
