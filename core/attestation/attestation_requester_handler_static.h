// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ATTESTATION_REQUESTER_HANDLER_STATIC_H_
#define ATTESTATION_REQUESTER_HANDLER_STATIC_H_


/* Internal functions declared to allow for static initialization. */
const platform_clock* attestation_requester_handler_get_next_execution (
	const struct periodic_task_handler *handler);
void attestation_requester_handler_execute (const struct periodic_task_handler *handler);


/**
 * Constant initializer for the attestation requester task API.
 */
#define	ATTESTATION_REQUESTER_HANDLER_API_INIT  { \
		.prepare = NULL, \
		.get_next_execution = attestation_requester_handler_get_next_execution, \
		.execute = attestation_requester_handler_execute \
	}


/**
 * Initialize a static instance of a handler for executing attestation requests.  This can be a
 * constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param attestation_ptr The attestation requester to use for generating requests.
 * @param device_mgr_ptr The device manager for the system.
 * @param pcr_ptr The PCR manager that will be used to report attestation results.
 * @param result_meas The measurement ID for attestation results.
 * @param result_meas_version The format version for the data containing attestation results.
 */
#define	attestation_requester_handler_static_init(attestation_ptr, device_mgr_ptr, pcr_ptr, \
	result_meas, result_meas_version)	{ \
		.base = ATTESTATION_REQUESTER_HANDLER_API_INIT, \
		.attestation = attestation_ptr, \
		.device_mgr = device_mgr_ptr, \
		.pcr = pcr_ptr, \
		.measurement = result_meas, \
		.measurement_version = result_meas_version \
	}


#endif /* ATTESTATION_REQUESTER_HANDLER_STATIC_H_ */
