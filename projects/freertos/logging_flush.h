// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef LOGGING_FLUSH_H_
#define LOGGING_FLUSH_H_

#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#include "logging/logging.h"


/**
 * Background task for flushing log contents to flash.
 */
struct logging_flush {
	const struct logging *logger;		/**< The log instance to flush. */
	TaskHandle_t task;					/**< The log background task. */
	SemaphoreHandle_t lock;				/**< Synchronization to protect task deletion. */
};


int logging_flush_init (struct logging_flush *log_task, const struct logging *logger);
void logging_flush_release (struct logging_flush *log_task);


#endif /* LOGGING_FLUSH_H_ */
