// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FIRMWARE_UPDATE_HANDLER_NO_REVOCATION_H_
#define FIRMWARE_UPDATE_HANDLER_NO_REVOCATION_H_

#include "firmware_update_handler.h"


/**
 * Handler for firmware update requests.  No revocation flows will be executed.
 */
struct firmware_update_handler_no_revocation {
	struct firmware_update_handler base;	/**< Base update handler. */
};


int firmware_update_handler_no_revocation_init (
	struct firmware_update_handler_no_revocation *handler,
	struct firmware_update_handler_state *state, const struct firmware_update *updater,
	const struct event_task *task, bool running_recovery);
int firmware_update_handler_no_revocation_init_keep_recovery_updated (
	struct firmware_update_handler_no_revocation *handler,
	struct firmware_update_handler_state *state, const struct firmware_update *updater,
	const struct event_task *task, bool running_recovery);
int firmware_update_handler_no_revocation_init_control_preparation (
	struct firmware_update_handler_no_revocation *handler,
	struct firmware_update_handler_state *state, const struct firmware_update *updater,
	const struct event_task *task, bool keep_recovery_updated, bool running_recovery,
	bool skip_active_restore);
void firmware_update_handler_no_revocation_release (
	const struct firmware_update_handler_no_revocation *handler);


#endif	/* FIRMWARE_UPDATE_HANDLER_NO_REVOCATION_H_ */
