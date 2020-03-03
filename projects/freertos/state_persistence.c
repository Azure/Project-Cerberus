// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "state_persistence.h"
#include "state_manager/state_logging.h"


/**
 * Task function for state persistence.
 *
 * @param persist The persistence context for this task.
 */
static void state_persistence_task (struct state_persistence *persist)
{
	int status;

	while (1) {
		platform_msleep (1000);

		xSemaphoreTake (persist->lock, portMAX_DELAY);
		status = state_manager_store_non_volatile_state (persist->state);
		xSemaphoreGive (persist->lock);

		if (status != 0) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_STATE_MGR,
				STATE_LOGGING_PERSIST_FAIL, persist->id, status);
		}
	}
}

/**
 * Initialize and start a background task to store persistent state information to non-volatile
 * memory.
 *
 * @param persist The persistence task to initialize.
 * @param manager The manager for state to persist.
 * @param id Identifier for the persistance task.
 *
 * @return 0 if the task was initialized successfully or an error code.
 */
int state_persistence_init (struct state_persistence *persist, struct state_manager *manager,
	int id)
{
	int status;

	if ((persist == NULL) || (manager == NULL)) {
		return STATE_MANAGER_INVALID_ARGUMENT;
	}

	memset (persist, 0, sizeof (struct state_persistence));

	persist->state = manager;
	persist->id = id;

	persist->lock = xSemaphoreCreateMutex ();
	if (persist->lock == NULL) {
		return STATE_MANAGER_NO_MEMORY;
	}

	status = xTaskCreate ((TaskFunction_t) state_persistence_task, "Persist", 1 * 256, persist,
		CERBERUS_PRIORITY_NORMAL, &persist->task);
	if (status != pdPASS) {
		vSemaphoreDelete (persist->lock);
		return STATE_MANAGER_NO_MEMORY;
	}

	return 0;
}

/**
 * Stop and release the background persistence task.
 *
 * @param persist The persistence task to release.
 */
void state_persistence_release (struct state_persistence *persist)
{
	if (persist) {
		xSemaphoreTake (persist->lock, portMAX_DELAY);
		vTaskDelete (persist->task);
		vSemaphoreDelete (persist->lock);
	}
}
