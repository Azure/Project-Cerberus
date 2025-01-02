// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MANIFEST_PCR_STATIC_H_
#define MANIFEST_PCR_STATIC_H_

#include "manifest_pcr.h"


/**
 * Statically initialize common manifest PCR management.  This is only intended to be initialized as
 * part of a parent module.
 *
 * There is no validation done on the arguments.
 *
 * @param hash_ptr The hash engine to use for generating PCR measurements.
 * @param store_ptr The PCR store to update as the manifest changes.
 * @param manifest_measurement_arg The identifier for the manifest measurement in the PCR.
 * @param manifest_id_measurement_arge The identifier for the manifest ID measurement in the PCR.
 * @param manifest_platform_id_measurement_arg The identifier for the manifest platform ID
 * measurement in the PCR.
 */
#define	manifest_pcr_static_init(hash_ptr, store_ptr, manifest_measurement_arg, \
	manifest_id_measurement_arg, manifest_platform_id_measurement_arg)	{ \
		.hash = hash_ptr, \
		.store = store_ptr, \
		.manifest_measurement = manifest_measurement_arg, \
		.manifest_id_measurement = manifest_id_measurement_arg, \
		.manifest_platform_id_measurement = manifest_platform_id_measurement_arg, \
	}


#endif	/* MANIFEST_PCR_STATIC_H_ */
