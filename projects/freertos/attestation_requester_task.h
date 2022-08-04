// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ATTESTATION_REQUESTER_TASK_H_
#define ATTESTATION_REQUESTER_TASK_H_

#include "FreeRTOS.h"
#include "task.h"
#include "attestation/attestation_requester.h"
#include "attestation/pcr_store.h"
#include "cmd_interface/device_manager.h"
#include "crypto/hash.h"


/**
 * Task context for component attestation.
 */
struct attestation_requester_task {
	struct attestation_requester *attestation;  								/**< Attestation requester instance. */
	struct device_manager *device_mgr;											/**< Device manager instance. */
	struct pcr_store *pcr;														/**< PCR store instance. */
	struct pcr_measured_data event_data;										/**< Attestation results event data for PCR entry. */
	uint16_t measurement;														/**< PCR ID for the attestation results. */
	uint8_t measurement_version;												/**< Version associated with measurement data. */
	TaskHandle_t attestation_loop_task;  										/**< Task handle for component attestation loop. */
};


int attestation_requester_task_init (struct attestation_requester_task *task,
	struct attestation_requester *attestation, struct device_manager *device_mgr,
	struct pcr_store *pcr, uint16_t measurement, uint8_t measurement_version, int priority,
	uint16_t stack_words);
void attestation_requester_task_deinit (struct attestation_requester_task *task);


#endif /* ATTESTATION_REQUESTER_TASK_H_ */
