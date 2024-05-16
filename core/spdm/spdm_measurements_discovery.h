// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPDM_MEASUREMENTS_DISCOVERY_H_
#define SPDM_MEASUREMENTS_DISCOVERY_H_

#include "spdm_discovery.h"
#include "spdm_measurements.h"


/**
 * Handler for retrieve SPDM measurement records for device measurements.  The device supports a
 * special measurement block that reports device type information useful for attestation discovery.
 *
 * The device ID measurement block is at a fixed block ID and is discontiguous from the rest of the
 * measurements, which means it needs special handling relative to the other blocks.
 */
struct spdm_measurements_discovery {
	struct spdm_measurements base;						/**< Base measurements API. */
	const struct spdm_discovery_device_id *device_id;	/**< Device type information for attestation discovery. */
};


int spdm_measurements_discovery_init (struct spdm_measurements_discovery *handler,
	struct pcr_store *store, const struct spdm_discovery_device_id *device_id);
void spdm_measurements_discovery_release (const struct spdm_measurements_discovery *handler);


#endif	/* SPDM_MEASUREMENTS_DISCOVERY_H_ */
