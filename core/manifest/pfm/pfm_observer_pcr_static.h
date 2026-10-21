// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PFM_OBSERVER_PCR_STATIC_H_
#define PFM_OBSERVER_PCR_STATIC_H_

#include "pfm_observer_pcr.h"
#include "manifest/manifest_pcr_static.h"


/* Internal functions declared to allow for static initialization. */
void pfm_observer_pcr_on_pfm_activated (const struct pfm_observer *observer,
	const struct pfm *active);
void pfm_observer_pcr_on_clear_active (const struct pfm_observer *observer);


/**
 * Constant initializer for the PFM observer events.
 */
#define	PFM_OBSERVER_PCR_API_INIT  { \
		.on_pfm_verified = NULL, \
		.on_pfm_activated = pfm_observer_pcr_on_pfm_activated, \
		.on_clear_active = pfm_observer_pcr_on_clear_active, \
		.on_pfm_activation_request = NULL, \
	}


/**
 * Initialize a static PFM observer for updating PCR entries.
 *
 * There is no validation done on the arguments.
 *
 * @param hash_ptr The hash engine to use for generating PCR measurements.
 * @param store_ptr The PCR store to update as the PFM changes.
 * @param manifest_measurement_arg The identifier for the manifest measurement in the PCR.
 * @param manifest_id_measurement_arg The identifier for the manifest ID measurement in the PCR.
 * @param platform_id_measurement_arg The identifier for the manifest platform ID measurement in the
 * PCR.
 */
#define	pfm_observer_pcr_static_init(hash_ptr, store_ptr, manifest_measurement_arg, \
	manifest_id_measurement_arg, platform_id_measurement_arg)	{ \
		.base = PFM_OBSERVER_PCR_API_INIT, \
		.pcr = manifest_pcr_static_init (hash_ptr, store_ptr, manifest_measurement_arg, \
			manifest_id_measurement_arg, platform_id_measurement_arg), \
	}


#endif	/* PFM_OBSERVER_PCR_STATIC_H_ */
