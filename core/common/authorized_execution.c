// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "authorized_execution.h"
#include "cmd_interface/config_reset.h"
#include "common/unused.h"


/* This is a generic implementation of the authorized_execution.get_status_identifiers() API that
 * will provide the generic identifiers in cases where more specific ones are not necessary. */
void authorized_execution_get_status_identifiers (const struct authorized_execution *execution,
	uint8_t *start, uint8_t *error)
{
	UNUSED (execution);

	if (start) {
		*start = CONFIG_RESET_STATUS_AUTHORIZED_OPERATION;
	}

	if (error) {
		*error = CONFIG_RESET_STATUS_AUTHORIZED_OP_FAILED;
	}
}
