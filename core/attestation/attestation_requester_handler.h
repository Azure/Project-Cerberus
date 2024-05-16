// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ATTESTATION_REQUESTER_HANDLER_H_
#define ATTESTATION_REQUESTER_HANDLER_H_

#include <stdint.h>
#include "attestation/attestation_requester.h"
#include "attestation/pcr_store.h"
#include "cmd_interface/device_manager.h"
#include "system/periodic_task.h"


/**
 * Handler for executing attestation requests to external components.
 */
struct attestation_requester_handler {
	struct periodic_task_handler base;					/**< Base interface for task integration. */
	const struct attestation_requester *attestation;	/**< Attestation requester instance. */
	struct device_manager *device_mgr;					/**< Device manager instance. */
	struct pcr_store *pcr;								/**< PCR store instance. */
	uint16_t measurement;								/**< PCR ID for the attestation results. */
	uint8_t measurement_version;						/**< Version associated with measurement data. */
};


int attestation_requester_handler_init (struct attestation_requester_handler *handler,
	const struct attestation_requester *attestation, struct device_manager *device_mgr,
	struct pcr_store *pcr, uint16_t measurement, uint8_t measurement_version);
void attestation_requester_handler_release (const struct attestation_requester_handler *handler);


/* This module will be treated as an extension of the attestation requestor and use ATTESTATION_*
 * error codes. */


#endif	/* ATTESTATION_REQUESTER_HANDLER_H_ */
