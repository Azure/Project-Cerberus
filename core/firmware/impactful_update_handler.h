// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef IMPACTFUL_UPDATE_HANDLER_H_
#define IMPACTFUL_UPDATE_HANDLER_H_

#include "firmware_update_handler.h"
#include "impactful_update_interface.h"


/**
 * Handler for firmware updates that may be impactful.  This is a wrapper around a basic firmware
 * update handler to provide additional handling for impactful updates.
 *
 * When registering with an event task instance, both the impactful update handler and the wrapped
 * firmware update handler need to be registered as event handlers for the task.  Both handlers
 * must be registered with the same task instance.
 */
struct impactful_update_handler {
	struct firmware_update_control base_ctrl;			/**< The base control instance. */
	struct event_task_handler base_event;				/**< The task event handler interface. */
	const struct firmware_update_handler *update;		/**< The handler for firmware updates. */
	const struct impactful_update_interface *impactful;	/**< Updater extension for impactful updates. */
};


int impactful_update_handler_init (struct impactful_update_handler *handler,
	const struct firmware_update_handler *update,
	const struct impactful_update_interface *impactful);
void impactful_update_handler_release (const struct impactful_update_handler *handler);


/* This module will be treated as an extension of the impactful updater and use IMPACTFUL_UPDATE_*
 * error codes. */


#endif	/* IMPACTFUL_UPDATE_HANDLER_H_ */
