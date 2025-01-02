// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PFM_OBSERVER_PENDING_RESET_STATIC_H_
#define PFM_OBSERVER_PENDING_RESET_STATIC_H_

#include "pfm_observer_pending_reset.h"


/* Internal functions declared to allow for static initialization. */
void pfm_observer_pending_reset_on_pfm_verified (const struct pfm_observer *observer,
	const struct pfm *pending);
void pfm_observer_pending_reset_on_clear_active (const struct pfm_observer *observer);


/**
 * Constant initializer for the PFM observer events.
 */
#define	PFM_OBSERVER_PENDING_RESET_API_INIT  { \
		.on_pfm_verified = pfm_observer_pending_reset_on_pfm_verified, \
		.on_pfm_activated = NULL, \
		.on_clear_active = pfm_observer_pending_reset_on_clear_active, \
		.on_pfm_activation_request = NULL, \
	}


/**
 * Initialize a static PFM observer to assert host reset on pending PFM verification.
 *
 * There is no validation done on the arguments.
 *
 * @param control The interface for host processor control signals.
 */
#define	pfm_observer_pending_reset_static_init(control_ptr)	{ \
		.base = PFM_OBSERVER_PENDING_RESET_API_INIT, \
		.control = control_ptr, \
	}


#endif	/* PFM_OBSERVER_PENDING_RESET_STATIC_H_ */
