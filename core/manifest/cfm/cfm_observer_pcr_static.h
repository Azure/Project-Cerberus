// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CFM_OBSERVER_PCR_STATIC_H_
#define CFM_OBSERVER_PCR_STATIC_H_

#include "cfm_observer_pcr.h"
#include "manifest/manifest_pcr_static.h"


/* Internal functions declared to allow for static initialization. */
void cfm_observer_pcr_on_cfm_activated (const struct cfm_observer *observer,
	const struct cfm *active);
void cfm_observer_pcr_on_clear_active (const struct cfm_observer *observer);


/**
 * Constant initializer for the CFM observer events.
 */
#define	CFM_OBSERVER_PCR_API_INIT  { \
		.on_cfm_verified = NULL, \
		.on_cfm_activated = cfm_observer_pcr_on_cfm_activated, \
		.on_clear_active = cfm_observer_pcr_on_clear_active, \
		.on_cfm_activation_request = NULL, \
	}


/**
 * Initialize a static CFM observer for updating PCR entries.
 *
 * There is no validation done on the arguments.
 *
 * @param hash_ptr The hash engine to use for generating PCR measurements.
 * @param store_ptr The PCR store to update as the CFM changes.
 * @param manifest_measurement_arg The identifier for the manifest measurement in the PCR.
 * @param manifest_id_measurement_arg The identifier for the manifest ID measurement in the PCR.
 * @param platform_id_measurement_arg The identifier for the manifest platform ID measurement in the
 * PCR.
 */
#define	cfm_observer_pcr_static_init(hash_ptr, store_ptr, manifest_measurement_arg, \
	manifest_id_measurement_arg, platform_id_measurement_arg)	{ \
		.base = CFM_OBSERVER_PCR_API_INIT, \
		.pcr = manifest_pcr_static_init (hash_ptr, store_ptr, manifest_measurement_arg, \
			manifest_id_measurement_arg, platform_id_measurement_arg), \
	}


#endif	/* CFM_OBSERVER_PCR_STATIC_H_ */
