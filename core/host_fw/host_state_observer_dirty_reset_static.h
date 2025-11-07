// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_STATE_OBSERVER_DIRTY_RESET_STATIC_H_
#define HOST_STATE_OBSERVER_DIRTY_RESET_STATIC_H_

#include "host_state_observer_dirty_reset.h"


/* Internal functions declared to allow for static initialization. */
void host_state_observer_dirty_reset_on_inactive_dirty (const struct host_state_observer *observer,
	const struct host_state_manager *manager);


/**
 * Constant initializer for the host state observer API.
 */
#define	HOST_STATE_OBSERVER_DIRTY_RESET_API_INIT	{ \
		.on_active_pfm = NULL, \
		.on_read_only_flash = NULL, \
		.on_inactive_dirty = host_state_observer_dirty_reset_on_inactive_dirty, \
		.on_active_recovery_image = NULL, \
		.on_pfm_dirty = NULL, \
		.on_run_time_validation = NULL, \
		.on_bypass_mode = NULL, \
		.on_unsupported_flash = NULL, \
	}


/**
 * Initialize a static instance of a host state observer to assert the host reset control when the
 * flash is dirty.  This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param control_ptr The interface for host processor control signals.
 */
#define	host_state_observer_dirty_reset_static_init(control_ptr)	{ \
		.base = HOST_STATE_OBSERVER_DIRTY_RESET_API_INIT, \
		.control = control_ptr, \
	}


#endif	/* HOST_STATE_OBSERVER_DIRTY_RESET_STATIC_H_ */
