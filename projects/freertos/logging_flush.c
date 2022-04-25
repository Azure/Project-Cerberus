// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform.h"
#include "logging_flush.h"


/**
 * Task function for flushing the log.
 *
 * @param flush The management instance for flushing the log.
 */
static void logging_flush_task (struct logging_flush *flush)
{
	while (1) {
		platform_msleep (1000);

		xSemaphoreTake (flush->lock, portMAX_DELAY);
		flush->logger->flush (flush->logger);
		xSemaphoreGive (flush->lock);
	}
}

/**
 * Initialize and start a background task to flush log contents to flash.
 *
 * @param log_task The log flushing task to initialize.
 * @param logger The log instance to flush.
 *
 * @return 0 if the task was initialized successfully or an error code.
 */
int logging_flush_init (struct logging_flush *log_task, const struct logging *logger)
{
	int status;

	if ((log_task == NULL) || (logger == NULL)) {
		return LOGGING_INVALID_ARGUMENT;
	}

	memset (log_task, 0, sizeof (struct logging_flush));

	log_task->logger = logger;

	log_task->lock = xSemaphoreCreateMutex ();
	if (log_task->lock == NULL) {
		return LOGGING_NO_MEMORY;
	}

	status = xTaskCreate ((TaskFunction_t) logging_flush_task, "Log", 1 * 256, log_task,
		CERBERUS_PRIORITY_BACKGROUND, &log_task->task);
	if (status != pdPASS) {
		vSemaphoreDelete (log_task->lock);
		return LOGGING_NO_MEMORY;
	}

	return 0;
}

/**
 * Stop and release the background log flushing task.
 *
 * @param log_task The logging task to release.
 */
void logging_flush_release (struct logging_flush *log_task)
{
	if (log_task) {
		xSemaphoreTake (log_task->lock, portMAX_DELAY);
		vTaskDelete (log_task->task);
		vSemaphoreDelete (log_task->lock);
	}
}
