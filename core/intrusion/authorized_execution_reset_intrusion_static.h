// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AUTHORIZED_EXECUTION_RESET_INTRUSION_STATIC_H_
#define AUTHORIZED_EXECUTION_RESET_INTRUSION_STATIC_H_

#include "authorized_execution_reset_intrusion.h"


/* Internal functions declared to allow for static initialization. */
int authorized_execution_reset_intrusion_execute (const struct authorized_execution *execution);
void authorized_execution_reset_intrusion_get_status_identifiers (
	const struct authorized_execution *execution, uint8_t *start, uint8_t *error);


/**
 * Constant initializer for the execution API.
 */
#define	AUTHORIZED_EXECUTION_RESET_INTRUSION_API_INIT	{ \
		.execute = authorized_execution_reset_intrusion_execute, \
		.get_status_identifiers = authorized_execution_reset_intrusion_get_status_identifiers, \
	}


/**
 * Static initializer for an authorized execution context to reset the intrusion state.
 *
 * There is no validation done on the arguments.
 *
 * @param intrusion_ptr Intrusion manager that will be used to reset the intrusion state.
 */
#define	authorized_execution_reset_intrusion_static_init(intrusion_ptr) { \
		.base = AUTHORIZED_EXECUTION_RESET_INTRUSION_API_INIT, \
		.intrusion = intrusion_ptr, \
	}


#endif	/* AUTHORIZED_EXECUTION_RESET_INTRUSION_STATIC_H_ */
