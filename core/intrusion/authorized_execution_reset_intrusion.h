// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AUTHORIZED_EXECUTION_RESET_INTRUSION_H_
#define AUTHORIZED_EXECUTION_RESET_INTRUSION_H_

#include "intrusion_manager.h"
#include "common/authorized_execution.h"


/**
 * Authorized execution context for resetting the intrusion state back to "not intruded".
 */
struct authorized_execution_reset_intrusion {
	struct authorized_execution base;		/**< Base execution API. */
	struct intrusion_manager *intrusion;	/**< Manager for intrusion state. */
};


int authorized_execution_reset_intrusion_init (
	struct authorized_execution_reset_intrusion *execution, struct intrusion_manager *intrusion);
void authorized_execution_reset_intrusion_release (
	const struct authorized_execution_reset_intrusion *execution);


#endif	/* AUTHORIZED_EXECUTION_RESET_INTRUSION_H_ */
