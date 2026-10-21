// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AUTHORIZED_EXECUTION_RMA_H_
#define AUTHORIZED_EXECUTION_RMA_H_

#include "common/authorized_execution.h"
#include "rma/device_rma_transition.h"
#include "rma/rma_unlock_token.h"


/**
 * Authorized execution context for transitioning a device to the RMA state.  The details of what
 * this state means are device-specific.
 *
 * This provides an alternate method to authenticate this operation that does not rely on the secure
 * device unlock flow.
 */
struct authorized_execution_rma {
	struct authorized_execution base;			/**< Base API for operation execution. */
	const struct rma_unlock_token *token;		/**< Handler for authenticating RMA tokens. */
	const struct device_rma_transition *rma;	/**< Device handler to apply the RMA configuration. */
};


int authorized_execution_rma_init (struct authorized_execution_rma *execution,
	const struct rma_unlock_token *token, const struct device_rma_transition *rma);
void authorized_execution_rma_release (const struct authorized_execution_rma *execution);


#endif	/* AUTHORIZED_EXECUTION_RMA_H_ */
