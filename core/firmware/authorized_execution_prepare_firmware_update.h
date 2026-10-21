// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AUTHORIZED_EXECUTION_PREPARE_FIRMWARE_UPDATE_H_
#define AUTHORIZED_EXECUTION_PREPARE_FIRMWARE_UPDATE_H_

#include "common/authorized_execution.h"
#include "firmware/firmware_update_control.h"


/**
 * Authorized execution context for preparing the device to receive a firmware update.  This
 * handling is an alternative to the standard firmware update preparation that adds authorization
 * requirements to the update process.
 */
struct authorized_execution_prepare_firmware_update {
	struct authorized_execution base;					/**< Base API for operation execution. */
	const struct firmware_update_control *fw_update;	/**< Interface for managing the firmware update. */
	uint32_t timeout_ms;								/**< Maximum time to wait for prepare to finish. */
};


int authorized_execution_prepare_firmware_update_init (
	struct authorized_execution_prepare_firmware_update *execution,
	const struct firmware_update_control *fw_update, uint32_t prepare_timeout_ms);
void authorized_execution_prepare_firmware_update_release (
	const struct authorized_execution_prepare_firmware_update *execution);


#endif	/* AUTHORIZED_EXECUTION_PREPARE_FIRMWARE_UPDATE_H_ */
