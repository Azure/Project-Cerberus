// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FIRMWARE_UPDATE_OBSERVER_TDISP_STATIC_H_
#define FIRMWARE_UPDATE_OBSERVER_TDISP_STATIC_H_

#include "firmware_update_observer_tdisp.h"


/* Internal functions declared to allow for static initialization. */
void firmware_update_observer_tdisp_on_prepare_update (
	const struct firmware_update_observer *observer, int *update_allowed);


/**
 * Constant initializer for the firmware update event handlers.
 */
#define	FIRMWARE_UPDATE_OBSERVER_TDISP_API_INIT  { \
		.on_update_start = NULL, \
		.on_prepare_update = firmware_update_observer_tdisp_on_prepare_update, \
		.on_update_applied = NULL, \
	}


/**
 * Initialize a static instance for a firmware update observer used to block firmware updates based
 * on TDISP policy.
 *
 * There is no validation done on the arguments.
 *
 * @param tdisp_ptr The TDISP driver interface that should be used to determine if an update should
 * be allowed.
 * @param tdi_context_ptr The TDI context manager that provides TDI context information.
 * @param max_tdi_context_count_val The maximum number of TDI contexts.
 */
#define	firmware_update_observer_tdisp_static_init(tdisp_ptr, tdi_context_ptr, \
	max_tdi_context_count_val) { \
		.base = FIRMWARE_UPDATE_OBSERVER_TDISP_API_INIT, \
		.tdisp = tdisp_ptr, \
		.tdi_context = tdi_context_ptr, \
		.max_tdi_context_count = max_tdi_context_count_val, \
	}


#endif	/* FIRMWARE_UPDATE_OBSERVER_TDISP_STATIC_H_ */
