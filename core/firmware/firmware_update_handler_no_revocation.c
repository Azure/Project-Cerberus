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
	int status;

	if (handler == NULL) {
		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	status = firmware_update_handler_init (&handler->base, state, updater, task, running_recovery);
	if (status != 0) {
		return status;
	}

	handler->base.run_update = firmware_update_run_update_no_revocation;

	return 0;
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
	int status;

	status = firmware_update_handler_no_revocation_init (handler, state, updater, task,
		running_recovery);
	if (status == 0) {
		handler->base.force_recovery_update = true;
	}

	return status;
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
