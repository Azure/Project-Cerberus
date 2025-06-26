// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "firmware_update_handler_no_revocation.h"
#include "common/unused.h"


/**
 * Initialize a handler for firmware update commands.  There are no revocation flows for this
 * handler.
 *
 * @param handler The update handler to initialize.
 * @param state Variable context for the handler.  This must be uninitialized.
 * @param updater The firmware updater that will be used by the handler.
 * @param task The task that will be used to execute firmware update operations.
 * @param running_recovery Flag to indicate that the system has booted the image located in recovery
 * flash.
 *
 * @return 0 if the update handler was successfully initialized or an error code.
 */
int firmware_update_handler_no_revocation_init (
	struct firmware_update_handler_no_revocation *handler,
	struct firmware_update_handler_state *state, const struct firmware_update *updater,
	const struct event_task *task, bool running_recovery)
{
	return firmware_update_handler_no_revocation_init_control_preparation (handler, state, updater,
		task, false, running_recovery, false);
}

/**
 * Initialize a handler for firmware update commands.  There are no revocation flows for this
 * handler.  During initialization, the updater will ensure the recovery image will always match the
 * current active image.
 *
 * @param handler The update handler to initialize.
 * @param state Variable context for the handler.  This must be uninitialized.
 * @param updater The firmware updater that will be used by the handler.
 * @param task The task that will be used to execute firmware update operations.
 * @param recovery_boot Flag to indicate that the system has booted the image located in recovery
 * flash.
 *
 * @return 0 if the update handler was successfully initialized or an error code.
 */
int firmware_update_handler_no_revocation_init_keep_recovery_updated (
	struct firmware_update_handler_no_revocation *handler,
	struct firmware_update_handler_state *state, const struct firmware_update *updater,
	const struct event_task *task, bool running_recovery)
{
	return firmware_update_handler_no_revocation_init_control_preparation (handler, state, updater,
		task, true, running_recovery, false);
}

/**
 * Initialize a handler for firmware update commands.  There are no revocation flows for this
 * handler.
 *
 * Activities taken by the handler during task preparation are parameterized to provide flexibility
 * for different use cases.
 * - The recovery image can optionally be forced to always match the current active image.
 * - During recovery boot scenarios, restoring the active image can optionally be skipped.
 *
 * @param handler The update handler to initialize.
 * @param state Variable context for the handler.  This must be uninitialized.
 * @param updater The firmware updater that will be used by the handler.
 * @param task The task that will be used to execute firmware update operations.
 * @param keep_recovery_updated Flag to indicate the recovery image should always be updated to
 * match the active image.
 * @param running_recovery Flag to indicate that the system has booted the image located in recovery
 * flash.
 * @param skip_active_restore Flag to skip restoring the active boot partition when the device has
 * booted from the recovery flash.  If running_recovery is false, this flag has no effect.
 *
 * @return 0 if the update handler was successfully initialized or an error code.
 */
int firmware_update_handler_no_revocation_init_control_preparation (
	struct firmware_update_handler_no_revocation *handler,
	struct firmware_update_handler_state *state, const struct firmware_update *updater,
	const struct event_task *task, bool keep_recovery_updated, bool running_recovery,
	bool skip_active_restore)
{
	if (handler == NULL) {
		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	memset (handler, 0, sizeof (struct firmware_update_handler_no_revocation));

	handler->base.base_ctrl.start_update = firmware_update_handler_start_update;
	handler->base.base_ctrl.get_status = firmware_update_handler_get_status;
	handler->base.base_ctrl.get_remaining_len = firmware_update_handler_get_remaining_len;
	handler->base.base_ctrl.prepare_staging = firmware_update_handler_prepare_staging;
	handler->base.base_ctrl.set_image_digest = firmware_update_handler_set_image_digest;
	handler->base.base_ctrl.write_staging = firmware_update_handler_write_staging;

	handler->base.base_notify.status_change = firmware_update_handler_status_change;

	handler->base.base_event.prepare = firmware_update_handler_prepare;
	handler->base.base_event.execute = firmware_update_handler_execute;

	handler->base.state = state;
	handler->base.updater = updater;
	handler->base.task = task;
	handler->base.force_recovery_update = keep_recovery_updated;
	handler->base.run_update = firmware_update_run_update_no_revocation;

	return firmware_update_handler_init_state_control_preparation (&handler->base, running_recovery,
		skip_active_restore);
}

/**
 * Release the resources used by a firmware update handler.
 *
 * @param handler The update handler to release.
 */
void firmware_update_handler_no_revocation_release (
	const struct firmware_update_handler_no_revocation *handler)
{
	UNUSED (handler);
}
