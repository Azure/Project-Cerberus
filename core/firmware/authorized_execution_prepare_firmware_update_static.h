// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AUTHORIZED_EXECUTION_PREPARE_FIRMWARE_UPDATE_STATIC_H_
#define AUTHORIZED_EXECUTION_PREPARE_FIRMWARE_UPDATE_STATIC_H_

#include "authorized_execution_prepare_firmware_update.h"


/* Internal functions declared to allow for static initialization. */
int authorized_execution_prepare_firmware_update_execute (
	const struct authorized_execution *execution, const uint8_t *data, size_t length,
	bool *reset_req);
int authorized_execution_prepare_firmware_update_validate_data (
	const struct authorized_execution *execution, const uint8_t *data, size_t length);
void authorized_execution_prepare_firmware_update_get_status_identifiers (
	const struct authorized_execution *execution, uint8_t *start, uint8_t *error);


/**
 * Constant initializer for the execution API.
 */
#define	AUTHORIZED_EXECUTION_PREPARE_FIRMWARE_UPDATE_API_INIT	{ \
		.execute = authorized_execution_prepare_firmware_update_execute, \
		.validate_data = authorized_execution_prepare_firmware_update_validate_data, \
		.get_status_identifiers = \
			authorized_execution_prepare_firmware_update_get_status_identifiers, \
	}


/**
 * Static initializer for an authorized execution context to prepare the device to receive a
 * firmware update.
 *
 * There is no validation done on the arguments.
 *
 * @param fw_update_ptr Control interface for managing the firmware update.
 * @param prepare_timeout_ms_arg The amount of time to wait for update preparation to complete, in
 * milliseconds.  If this is 0, there is no timeout for the operation.
 */
#define	authorized_execution_prepare_firmware_update_static_init(fw_update_ptr, \
	prepare_timeout_ms_arg) { \
		.base = AUTHORIZED_EXECUTION_PREPARE_FIRMWARE_UPDATE_API_INIT, \
		.fw_update = fw_update_ptr, \
		.timeout_ms = prepare_timeout_ms_arg, \
	}


#endif	/* AUTHORIZED_EXECUTION_PREPARE_FIRMWARE_UPDATE_STATIC_H_ */
