// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "attestation_requester_handler.h"
#include "common/unused.h"


const platform_clock* attestation_requester_handler_get_next_execution (
	const struct periodic_task_handler *handler)
{
	UNUSED (handler);

	return NULL;
}

void attestation_requester_handler_execute (const struct periodic_task_handler *handler)
{
	const struct attestation_requester_handler *task =
		(const struct attestation_requester_handler*) handler;

	attestation_requester_discovery_and_attestation_loop (task->attestation, task->pcr,
			task->measurement, task->measurement_version);

	attestation_requestor_wait_for_next_action (task->attestation);
}

/**
 * Initialize a handler for generating and executing attestation requests to external devices.
 *
 * @param handler The attestation handler to initialize.
 * @param attestation The attestation requester to use for generating requests.
 * @param device_mgr The device manager for the system.
 * @param pcr The PCR manager that will be used to report attestation results.
 * @param measurement The measurement ID for attestation results.
 * @param measurement_version The format version for the data containing attestation results.
 *
 * @return 0 if the handler was successfully initialized or an error code.
 */
int attestation_requester_handler_init (struct attestation_requester_handler *handler,
	const struct attestation_requester *attestation, struct device_manager *device_mgr,
	struct pcr_store *pcr, uint16_t measurement, uint8_t measurement_version)
{
	if ((handler == NULL) || (attestation == NULL) || (device_mgr == NULL) || (pcr == NULL)) {
		return ATTESTATION_INVALID_ARGUMENT;
	}

	memset (handler, 0, sizeof (struct attestation_requester_handler));

	handler->base.get_next_execution = attestation_requester_handler_get_next_execution;
	handler->base.execute = attestation_requester_handler_execute;

	handler->attestation = attestation;
	handler->device_mgr = device_mgr;
	handler->pcr = pcr;
	handler->measurement = measurement;
	handler->measurement_version = measurement_version;

	return 0;
}

/**
 * Release the resources used for generating attestation requests.
 *
 * @param handler The attestation handler to release.
 */
void attestation_requester_handler_release (const struct attestation_requester_handler *handler)
{
	UNUSED (handler);
}
