// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ATTESTATION_DISCOVER_MCTP_STATIC_H_
#define ATTESTATION_DISCOVER_MCTP_STATIC_H_

#include "attestation_discover_mctp.h"


/* Internal functions declared to allow for static initialization. */
int attestation_discover_mctp_discover_device (
	const struct attestation_discover *attestation_discover,
	const struct attestation_requester *attestation_requester);
int attestation_discover_mctp_get_device_eid_by_device_num (
	const struct attestation_discover *attestation_discover,
	const struct attestation_requester *attestation, int device_num);
void attestation_requester_on_mctp_set_eid_request (
	const struct mctp_control_protocol_observer *observer);

/**
 * Constant initializer for attestation discover mctp instance API.
 */
#define	ATTESTATION_DISCOVER_MCTP_API_INIT  { \
		.discover_device = attestation_discover_mctp_discover_device, \
		.get_device_eid_by_device_num = attestation_discover_mctp_get_device_eid_by_device_num, \
	}

/**
 * Constant initializer for the MCTP response observer API.
 */
#define	ATTESTATION_DISCOVER_MCTP_RSP_OBSERVER_API_INIT { \
		.on_set_eid_request = attestation_requester_on_mctp_set_eid_request, \
	}


/**
 * Initialize a static instance of attestation discover mctp.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the discover instance.
 * @param transport_ptr SPDM message transport for discovery operations.
 */
#define	attestation_discover_mctp_static_init(state_ptr, transport_ptr)	{ \
		.base = ATTESTATION_DISCOVER_MCTP_API_INIT, \
		.mctp_rsp_observer = ATTESTATION_DISCOVER_MCTP_RSP_OBSERVER_API_INIT, \
		.transport = transport_ptr, \
		.state = state_ptr, \
	}


#endif	/* ATTESTATION_DISCOVER_MCTP_STATIC_H_ */
