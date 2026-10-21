// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AUTHORIZED_EXECUTION_ALLOW_IMPACTFUL_H_
#define AUTHORIZED_EXECUTION_ALLOW_IMPACTFUL_H_

#include <stdint.h>
#include "impactful_update_interface.h"
#include "common/authorized_execution.h"


/**
 * Authorized execution context for allowing impactful firmware updates.
 */
struct authorized_execution_allow_impactful {
	struct authorized_execution base;					/**< Base interface for authorized commands. */
	const struct impactful_update_interface *impactful;	/**< Interface for managing impactful updates. */
	uint32_t auth_time_ms;								/**< The amount of time each impactful authorization is valid. */
};


int authorized_execution_allow_impactful_init (
	struct authorized_execution_allow_impactful *execution,
	const struct impactful_update_interface *impactful, uint32_t auth_time_ms);
void authorized_execution_allow_impactful_release (
	const struct authorized_execution_allow_impactful *execution);


#endif	/* AUTHORIZED_EXECUTION_ALLOW_IMPACTFUL_H_ */
