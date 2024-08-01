// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AUTHORIZED_EXECUTION_ALLOW_IMPACTFUL_STATIC_H_
#define AUTHORIZED_EXECUTION_ALLOW_IMPACTFUL_STATIC_H_

#include "authorized_execution_allow_impactful.h"


/* Internal functions declared to allow for static initialization. */
int authorized_execution_allow_impactful_execute (const struct authorized_execution *execution,
	bool *reset_req);
void authorized_execution_allow_impactful_get_status_identifiers (
	const struct authorized_execution *execution, uint8_t *start, uint8_t *error);


/**
 * Constant initializer for the execution API.
 */
#define	AUTHORIZED_EXECUTION_ALLOW_IMPACTFUL_API_INIT	{ \
		.execute = authorized_execution_allow_impactful_execute, \
		.get_status_identifiers = authorized_execution_allow_impactful_get_status_identifiers, \
	}


/**
 * Static initializer for an authorized execution context to allow impactful firmware updates.
 *
 * There is no validation done on the arguments.
 *
 * @param impactful_ptr Manager for impactful updates that will be updated with the authorization.
 * @param auth_time_ms_arg The amount of time each impactful authorization will be valid for, in
 * milliseconds.  If this is 0, there is no expiration for the impactful authorization.
 */
#define	authorized_execution_allow_impactful_static_init(impactful_ptr, auth_time_ms_arg) { \
		.base = AUTHORIZED_EXECUTION_ALLOW_IMPACTFUL_API_INIT, \
		.impactful = impactful_ptr, \
		.auth_time_ms = auth_time_ms_arg, \
	}


#endif	/* AUTHORIZED_EXECUTION_ALLOW_IMPACTFUL_STATIC_H_ */
