// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_PROCESSOR_OBSERVER_PCR_STATIC_H_
#define HOST_PROCESSOR_OBSERVER_PCR_STATIC_H_

#include "host_processor_observer_pcr.h"


/* Internal functions declared to allow for static initialization. */
void host_processor_observer_pcr_on_bypass_mode (const struct host_processor_observer *observer);
void host_processor_observer_pcr_on_active_mode (const struct host_processor_observer *observer);
void host_processor_observer_pcr_on_recovery (const struct host_processor_observer *observer);

void host_processor_observer_pcr_on_inactive_dirty (const struct host_state_observer *observer,
	const struct host_state_manager *manager);


/**
 * Constant initializer for the host processor observer API.
 */
#define	HOST_PROCESSOR_OBSERVER_PCR_API_INIT	{ \
		.on_soft_reset = NULL, \
		.on_bypass_mode = host_processor_observer_pcr_on_bypass_mode, \
		.on_active_mode = host_processor_observer_pcr_on_active_mode, \
		.on_recovery = host_processor_observer_pcr_on_recovery, \
	}

/**
 * Constant initializer for the host state observer API.
 */
#define	HOST_PROCESSOR_OBSERVER_PCR_STATE_API_INIT	{ \
		.on_active_pfm = NULL, \
		.on_read_only_flash = NULL, \
		.on_inactive_dirty = host_processor_observer_pcr_on_inactive_dirty, \
		.on_active_recovery_image = NULL, \
		.on_pfm_dirty = NULL, \
		.on_run_time_validation = NULL, \
		.on_bypass_mode = NULL, \
		.on_unsupported_flash = NULL, \
	}


/**
 * Initialize a static instance of a PCR manager for host validation state.  This does not
 * initialize the manager state.  This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param hash_ptr The hash engine to use for PCR calculation.
 * @param store_ptr Storage for the PCR that will be managed.
 * @param pcr_arg ID of the PCR entry to manage.
 * @param state_ptr On init, the contents of this memory will seed the PCR value.  Afterward, this
 * will hold the raw value used to generate the PCR entry.  It is recommended this point to a
 * reset-tolerant memory location.
 */
#define	host_processor_observer_pcr_static_init(hash_ptr, store_ptr, pcr_arg, state_ptr)	{ \
		.base = HOST_PROCESSOR_OBSERVER_PCR_API_INIT, \
		.base_state = HOST_PROCESSOR_OBSERVER_PCR_STATE_API_INIT, \
		.hash = hash_ptr, \
		.store = store_ptr, \
		.pcr = pcr_arg, \
		.state = state_ptr, \
	}


#endif	/* HOST_PROCESSOR_OBSERVER_PCR_STATIC_H_ */
