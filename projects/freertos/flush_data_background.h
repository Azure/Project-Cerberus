// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FLUSH_DATA_BACKGROUND_H_
#define FLUSH_DATA_BACKGROUND_H_

#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#include "logging/logging.h"
#include "state_manager/state_manager.h"


/**
 * Background task for flushing log contents to flash and persisting non-volatile state information.
 */
struct flush_data_background {
	const struct logging *logger;			/**< The log instance to flush. */
	TaskHandle_t task;						/**< The log background task. */
	SemaphoreHandle_t lock;					/**< Synchronization to protect task deletion. */
	struct state_manager *system_state;		/**< The manager for system state to persist. */
	struct state_manager *host_state_0;		/**< The manager for host state to persist for port 0. */
	struct state_manager *host_state_1;		/**< The manager for host state to persist for port 1. */
};

int flush_data_background_init (struct flush_data_background *flush_data,
	const struct logging *logger, struct state_manager *system_state,
	struct state_manager *host_state_0, struct state_manager *host_state_1, int priority);
void flush_data_background_release (struct flush_data_background *flush_data);


#endif /* FLUSH_DATA_BACKGROUND_H_ */
