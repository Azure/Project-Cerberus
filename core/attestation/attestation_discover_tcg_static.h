// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ATTESTATION_DISCOVER_TCG_STATIC_H_
#define ATTESTATION_DISCOVER_TCG_STATIC_H_


#include "attestation_discover_tcg.h"


/* Internal functions declared to allow for static initialization. */
int attestation_discover_tcg_discover_device (
	const struct attestation_discover *attestation_discover,
	const struct attestation_requester *attestation);
int attestation_discover_tcg_get_device_eid_by_device_num (
	const struct attestation_discover *attestation_discover,
	const struct attestation_requester *attestation, int device_num);

#define	ATTESTATION_DISCOVER_TCG_API_INIT  { \
		.discover_device = attestation_discover_tcg_discover_device, \
		.get_device_eid_by_device_num = attestation_discover_tcg_get_device_eid_by_device_num, \
	}

/**
 * Initialize a static instance of attestation discover tcg.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the discover instance.
 */
#define	attestation_discover_tcg_static_init(state_ptr)	{ \
		.base = ATTESTATION_DISCOVER_TCG_API_INIT, \
		.state = state_ptr, \
	}


#endif	/* ATTESTATION_DISCOVER_TCG_STATIC_H_ */
