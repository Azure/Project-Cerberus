// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "attestation_requester_task.h"


/**
 * Component attestation loop
 *
 * @param data Pointer to attestation requester task instance
 *
 */
static void attestation_requester_task_loop (void *data)
{
	struct attestation_requester_task *task = (struct attestation_requester_task*) data;
	uint32_t duration_ms;

	while (1) {
		attestation_requester_discovery_and_attestation_loop (task->attestation, task->pcr,
			task->authentication_status, task->measurement, task->measurement_version);

		duration_ms = device_manager_get_time_till_next_action (task->device_mgr);
		platform_msleep (duration_ms);
	}
}

/**
 * Initialize and start the task to handle component attestation.
 *
 * @param task The attestation requester task to initialize.
 * @param attestation The attestation requester instance to utilize.
 * @param device_mgr The device manager instance to utilize.
 * @param pcr The PCR manager that will be used to report attestation results.
 * @param measurement The measurement ID for attestation results.
 * @param measurement_version The version associated with the measurement data.
 * @param priority The priority level for running the component attestation task.
 * @param stack_words The size of the component attesation task stack.  The stack size is measured
 * in words.
 * @param authentication_status Pointer to bitmap of component device authentication statuses.  Must
 * be DEVICE_MANAGER_ATTESTATION_STATUS_LEN bytes long.
 *
 * @return Initialization status, 0 if success or an error code.
 */
int attestation_requester_task_init (struct attestation_requester_task *task,
	struct attestation_requester *attestation, struct device_manager *device_mgr,
	struct pcr_store *pcr, uint16_t measurement, uint8_t measurement_version, int priority,
	uint16_t stack_words, uint8_t *authentication_status)
{
	int status;

	if ((task == NULL) || (attestation == NULL) || (device_mgr == NULL) || (pcr == NULL) ||
		(authentication_status == NULL)) {
		return ATTESTATION_INVALID_ARGUMENT;
	}

	memset (task, 0, sizeof (struct attestation_requester_task));

	task->attestation = attestation;
	task->device_mgr = device_mgr;
	task->pcr = pcr;
	task->measurement = measurement;
	task->measurement_version = measurement_version;
	task->authentication_status = authentication_status;

	status = xTaskCreate (attestation_requester_task_loop, "ATTESTATION_REQUESTER", stack_words,
		task, priority, &task->attestation_loop_task);
	if (status != pdPASS) {
		return status;
	}

	return 0;
}

/**
 * Stop and release the attestation requester task.
 *
 * @param task The attestation requester task to release.
 */
void attestation_requester_task_deinit (struct attestation_requester_task *task)
{
	if (task != NULL) {
		vTaskDelete (task->attestation_loop_task);
	}
}
