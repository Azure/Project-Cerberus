// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "authorized_execution.h"
#include "cmd_interface/config_reset.h"
#include "common/unused.h"


/* This is a implementation of the authorized_execution.validate_data() API that can be used in
 * scenarios where no data validation is necessary. */
int authorized_execution_validate_data (const struct authorized_execution *execution,
	const uint8_t *data, size_t length)
{
	if (execution == NULL) {
		return AUTHORIZED_EXECUTION_INVALID_ARGUMENT;
	}

	/* The command consumes no data, so anything is considered valid. */
	UNUSED (data);
	UNUSED (length);

	return 0;
}

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
