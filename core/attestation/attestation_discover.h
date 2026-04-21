// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ATTESTATION_DISCOVER_H_
#define ATTESTATION_DISCOVER_H_

#include <stdbool.h>
#include <stdint.h>
struct attestation_requester;
struct device_manager;


/**
 * Discovery state indicators for the attestation discovery interface.
 */
enum attestation_discovery_state {
	ATTESTATION_DISCOVERY_IDLE = 0,					/**< Idle, waiting for a trigger. */
	ATTESTATION_DISCOVERY_RECEIVED_SET_EID_REQUEST,	/**< Discovery triggered by SET EID request. */
	ATTESTATION_DISCOVERY_TRIGGERED,				/**< Discovery triggered by timer or internal event. */
	ATTESTATION_DISCOVERY_REQUIRED_REFRESH,			/**< Discovery triggered by routing table refresh. */
	ATTESTATION_DISCOVERY_COMPLETE,					/**< Discovery completed, ignore future triggers. */
};


/**
 * Base API for attestation discovery implementation
 */
struct attestation_discover {
	/**
	 * Discover the available devices
	 *
	 * @param attestation_discover The Attestation discover instance to utilize.
	 * @param attestation The Attestation requester instance to utilize.
	 *
	 * @return Discovery status, 0 if success or an error code.
	 */
	int (*discover_device) (const struct attestation_discover *attestation_discover,
		const struct attestation_requester *attestation_requester);

	/**
	 * Get the EID of a device based on its device number. This may be NULL or unsupported for
	 * self-device attestation scenarios where EID is not applicable.
	 *
	 * @param attestation_discover The Attestation discover instance to utilize.
	 * @param attestation The Attestation requester instance to utilize.
	 * @param device_num The device number to query the EID for.
	 *
	 * @return The EID of the device, or a negative error code if the query fails or is unimplemented.
	 */
	int (*get_device_eid_by_device_num) (const struct attestation_discover *attestation_discover,
		const struct attestation_requester *attestation, int device_num);

	/**
	 * TODO:
	 * Add the message transport instance to utilize for discovery operations.
	 * This will be added in a future PR after attestation refactor.
	 */
};


#endif	/* ATTESTATION_DISCOVER_H_ */
