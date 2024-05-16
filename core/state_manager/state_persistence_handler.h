// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef STATE_PERSISTENCE_HANDLER_H_
#define STATE_PERSISTENCE_HANDLER_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "platform_api.h"
#include "state_manager.h"
#include "system/periodic_task.h"


/**
 * Variable context for the handler for persisting state to flash.
 */
struct state_persistence_handler_state {
	platform_clock next;	/**< Time at which the next execution should run. */
	bool next_valid;		/**< Indicate if the next timeout has been initialized. */
};

/**
 * Handler to persist current state to flash.
 */
struct state_persistence_handler {
	struct periodic_task_handler base;				/**< Base interface for task integration. */
	struct state_persistence_handler_state *state;	/**< Variable context for the handler. */
	struct state_manager **managers;				/**< List of states to persist. */
	size_t manager_count;							/**< Number of state managers in the list. */
	uint32_t period;								/**< Required time between state persistence. */
};


int state_persistence_handler_init (struct state_persistence_handler *handler,
	struct state_persistence_handler_state *state, struct state_manager **managers,
	size_t manager_count, uint32_t period_ms);
int state_persistence_handler_init_state (const struct state_persistence_handler *handler);
void state_persistence_handler_release (const struct state_persistence_handler *handler);


/* This module will be treated as an extension of the state manager module and use STATE_MANAGER_*
 * error codes. */


#endif	/* STATE_PERSISTENCE_HANDLER_H_ */
