// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AUTHORIZED_EXECUTION_RMA_STATIC_H_
#define AUTHORIZED_EXECUTION_RMA_STATIC_H_

#include "authorized_execution_rma.h"


/* Internal functions declared to allow for static initialization. */
int authorized_execution_rma_execute (const struct authorized_execution *execution,
	const uint8_t *data, size_t length, bool *reset_req);
int authorized_execution_rma_validate_data (const struct authorized_execution *execution,
	const uint8_t *data, size_t length);


/**
 * Constant initializer for the execution API.
 */
#define	AUTHORIZED_EXECUTION_RMA_API_INIT	{ \
		.execute = authorized_execution_rma_execute, \
		.validate_data = authorized_execution_rma_validate_data, \
		.get_status_identifiers = authorized_execution_get_status_identifiers, \
	}


/**
 * Static initializer for an authorized execution context for transitioning a device to the RMA
 * state.
 *
 * There is no validation done on the arguments.
 *
 * @param token_ptr Token handler for validating the RMA operation.
 * @param rma_ptr Device handler to transition the device for RMA.
 */
#define	authorized_execution_rma_static_init(token_ptr, rma_ptr) { \
		.base = AUTHORIZED_EXECUTION_RMA_API_INIT, \
		.token = token_ptr, \
		.rma = rma_ptr, \
	}


#endif	/* AUTHORIZED_EXECUTION_RMA_STATIC_H_ */
