// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef STATE_PERSISTENCE_H_
#define STATE_PERSISTENCE_H_

#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#include "state_manager/state_manager.h"


/**
 * Background task for persisting non-volatile state information.
 */
struct state_persistence {
	struct state_manager *state;		/**< The manager for state to persist. */
	TaskHandle_t task;					/**< The persistence background task. */
	SemaphoreHandle_t lock;				/**< Synchronization to protect task deletion. */
	int id;								/**< Instance identifier. */
};


int state_persistence_init (struct state_persistence *persist, struct state_manager *manager,
	int id);
void state_persistence_release (struct state_persistence *persist);


#endif /* STATE_PERSISTENCE_H_ */
