// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FW_UPDATE_TASK_H_
#define FW_UPDATE_TASK_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#include "firmware/firmware_update.h"
#include "firmware/firmware_update_control.h"
#include "cmd_interface/cerberus_protocol.h"
#include "system/system.h"


struct fw_update_task;

/**
 * A update notification implementation for the update task.
 */
struct fw_update_task_notify {
	struct firmware_update_notification base;						/**< The base notification instance. */
	struct fw_update_task *task;									/**< The parent task instance. */
};

/**
 * The task that will run the firmware update.
 */
struct fw_update_task {
	struct firmware_update_control base;							/**< The base control instance. */
	struct fw_update_task_notify notify;							/**< The update notification interface. */
	struct firmware_update *updater;								/**< The firmware updater. */
	struct system *system;											/**< The system manager. */
	int update_status;												/**< The last firmware update status. */
	uint8_t running;												/**< Flag indicating if an update is running. */
	TaskHandle_t task;												/**< The task that will run the update. */
	SemaphoreHandle_t lock;											/**< Mutex for status updates. */
	size_t staging_size;											/**< Size of image to clear in staging area */
	uint8_t staging_buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG];		/**< Buffer of image data to write to staging area. */
	size_t staging_buf_len;											/**< Length of buffer of image data. */
};


int fw_update_task_init (struct fw_update_task *task, struct firmware_update *updater,
	struct system *system);
int fw_update_task_start (struct fw_update_task *task, uint16_t stack_words, bool running_recovery);


#endif /* FW_UPDATE_TASK_H_ */
