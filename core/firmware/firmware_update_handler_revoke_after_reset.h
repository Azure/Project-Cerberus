// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FIRMWARE_UPDATE_HANDLER_REVOKE_AFTER_RESET_H_
#define FIRMWARE_UPDATE_HANDLER_REVOKE_AFTER_RESET_H_

#include "firmware_update_handler.h"


/**
 * Handler for firmware update requests.  Revocation flows and recovery updates will not take place
 * during the normal update flow.  Instead, they will be done during update initialization, after
 * the device has been reset with the updated firmware.
 */
struct firmware_update_handler_revoke_after_reset {
	struct firmware_update_handler base;	/**< Base update handler. */
};


int firmware_update_handler_revoke_after_reset_init (
	struct firmware_update_handler_revoke_after_reset *handler,
	struct firmware_update_handler_state *state, const struct firmware_update *updater,
	const struct event_task *task, bool running_recovery);
int firmware_update_handler_revoke_after_reset_init_keep_recovery_updated (
	struct firmware_update_handler_revoke_after_reset *handler,
	struct firmware_update_handler_state *state, const struct firmware_update *updater,
	const struct event_task *task, bool running_recovery);
int firmware_update_handler_revoke_after_reset_init_control_preparation (
	struct firmware_update_handler_revoke_after_reset *handler,
	struct firmware_update_handler_state *state, const struct firmware_update *updater,
	const struct event_task *task, bool keep_recovery_updated, bool running_recovery,
	bool skip_active_restore);
void firmware_update_handler_revoke_after_reset_release (
	const struct firmware_update_handler_revoke_after_reset *handler);


#endif	/* FIRMWARE_UPDATE_HANDLER_REVOKE_AFTER_RESET_H_ */
