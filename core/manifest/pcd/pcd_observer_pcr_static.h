// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PCD_OBSERVER_PCR_STATIC_H_
#define PCD_OBSERVER_PCR_STATIC_H_

#include "pcd_observer_pcr.h"
#include "manifest/manifest_pcr_static.h"


/* Internal functions declared to allow for static initialization. */
void pcd_observer_pcr_on_pcd_activated (const struct pcd_observer *observer,
	const struct pcd *active);
void pcd_observer_pcr_on_clear_active (const struct pcd_observer *observer);


/**
 * Constant initializer for the PCD observer events.
 */
#define	PCD_OBSERVER_PCR_API_INIT  { \
		.on_pcd_verified = NULL, \
		.on_pcd_activated = pcd_observer_pcr_on_pcd_activated, \
		.on_clear_active = pcd_observer_pcr_on_clear_active, \
		.on_pcd_activation_request = NULL, \
	}


/**
 * Initialize a static PCD observer for updating PCR entries.
 *
 * There is no validation done on the arguments.
 *
 * @param hash_ptr The hash engine to use for generating PCR measurements.
 * @param store_ptr The PCR store to update as the PCD changes.
 * @param manifest_measurement_arg The identifier for the manifest measurement in the PCR.
 * @param manifest_id_measurement_arg The identifier for the manifest ID measurement in the PCR.
 * @param platform_id_measurement_arg The identifier for the manifest platform ID measurement in the
 * PCR.
 */
#define	pcd_observer_pcr_static_init(hash_ptr, store_ptr, manifest_measurement_arg, \
	manifest_id_measurement_arg, platform_id_measurement_arg)	{ \
		.base = PCD_OBSERVER_PCR_API_INIT, \
		.pcr = manifest_pcr_static_init (hash_ptr, store_ptr, manifest_measurement_arg, \
			manifest_id_measurement_arg, platform_id_measurement_arg), \
	}


#endif	/* PCD_OBSERVER_PCR_STATIC_H_ */
