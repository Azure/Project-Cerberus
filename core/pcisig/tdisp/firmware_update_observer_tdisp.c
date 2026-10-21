// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "firmware_update_observer_tdisp.h"
#include "common/type_cast.h"
#include "common/unused.h"

void firmware_update_observer_tdisp_on_prepare_update (
	const struct firmware_update_observer *observer, int *update_allowed)
{
	uint32_t function_index;
	uint8_t tdi_state;
	struct tdisp_tdi_context tdi_context;
	int status;
	const struct firmware_update_observer_tdisp *tdisp_observer = TO_DERIVED_TYPE (observer,
		const struct firmware_update_observer_tdisp, base);

	/* Only check if the update is allowed if some other observer has not already disallowed it. */
	if (*update_allowed != 0) {
		return;
	}

	for (function_index = 0; function_index < tdisp_observer->max_tdi_context_count;
		function_index++) {
		status = tdisp_observer->tdisp->get_device_interface_state (tdisp_observer->tdisp,
			function_index,	&tdi_state);
		if (status != 0) {
			continue;
		}

		if ((tdi_state != TDISP_TDI_STATE_RUN) && (tdi_state != TDISP_TDI_STATE_CONFIG_LOCKED)) {
			/* Interfaces not in RUN or LOCKED state cannot block a FW update. */
			continue;
		}

		/* Check whether this TDI permits FW updates. */
		status = tdisp_observer->tdi_context->get_tdi_context (tdisp_observer->tdi_context,
			function_index, TDISP_TDI_CONTEXT_MASK_LOCK_FLAGS, &tdi_context);
		if (status != 0) {
			continue;
		}

		if ((tdi_context.lock_flags & TDISP_LOCK_INTERFACE_FLAGS_NO_FW_UPDATE) != 0) {
			*update_allowed = TDISP_DRIVER_UPDATE_NOT_ALLOWED;

			return;
		}
	}

	return;
}

/**
 * Initialize a firmware update observer used to block firmware updates based on TDISP policy.
 *
 * @param observer The observer to initialize.
 * @param tdisp The TDISP update handler that should be used to determine if an update
 * should be allowed.
 * @param tdi_context The TDI context manager that provides TDI context information.
 * @param max_tdi_context_count The maximum number of TDI contexts.
 *
 * @return 0 if the observer was initialized successfully or an error code.
 */
int firmware_update_observer_tdisp_init (struct firmware_update_observer_tdisp *observer,
	const struct tdisp_driver *tdisp, const struct tdisp_tdi_context_manager *tdi_context,
	uint32_t max_tdi_context_count)
{
	if ((observer == NULL) || (tdisp == NULL) || (tdi_context == NULL)) {
		return TDISP_DRIVER_INVALID_ARGUMENT;
	}

	memset (observer, 0, sizeof (*observer));

	observer->base.on_prepare_update = firmware_update_observer_tdisp_on_prepare_update;

	observer->tdisp = tdisp;
	observer->tdi_context = tdi_context;
	observer->max_tdi_context_count = max_tdi_context_count;

	return 0;
}

/**
 * Release the resources used for an TDISP update observer.
 *
 * @param observer The observer to release.
 */
void firmware_update_observer_tdisp_release (
	const struct firmware_update_observer_tdisp *observer)
{
	UNUSED (observer);
}
