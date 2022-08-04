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

	while (1) {
		attestation_requester_discovery_and_attestation_loop (task->attestation, task->pcr,
			task->measurement, task->measurement_version);

		attestation_requestor_wait_for_next_action (task->attestation);
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
 *
 * @return Initialization status, 0 if success or an error code.
 */
int attestation_requester_task_init (struct attestation_requester_task *task,
	struct attestation_requester *attestation, struct device_manager *device_mgr,
	struct pcr_store *pcr, uint16_t measurement, uint8_t measurement_version, int priority,
	uint16_t stack_words)
{
	int status;

	if ((task == NULL) || (attestation == NULL) || (device_mgr == NULL) || (pcr == NULL)) {
		return ATTESTATION_INVALID_ARGUMENT;
	}

	memset (task, 0, sizeof (struct attestation_requester_task));

	task->attestation = attestation;
	task->device_mgr = device_mgr;
	task->pcr = pcr;
	task->measurement = measurement;
	task->measurement_version = measurement_version;

	status = xTaskCreate (attestation_requester_task_loop, "AttestRq", stack_words, task, priority,
		&task->attestation_loop_task);
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
