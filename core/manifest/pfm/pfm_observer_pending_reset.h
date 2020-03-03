// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PFM_OBSERVER_PENDING_RESET_H_
#define PFM_OBSERVER_PENDING_RESET_H_

#include "pfm_manager.h"
#include "host_fw/host_control.h"


/**
 * PFM observer to assert the host reset control signal whenever a pending PFM has been verified.
 */
struct pfm_observer_pending_reset {
	struct pfm_observer base;			/**< The base observer interface. */
	struct host_control *control;		/**< The interface for host control signals. */
};


int pfm_observer_pending_reset_init (struct pfm_observer_pending_reset *observer,
	struct host_control *control);
void pfm_observer_pending_reset_release (struct pfm_observer_pending_reset *observer);


#endif /* PFM_OBSERVER_PENDING_RESET_H_ */
