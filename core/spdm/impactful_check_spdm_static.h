// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef IMPACTFUL_CHECK_SPDM_STATIC_H_
#define IMPACTFUL_CHECK_SPDM_STATIC_H_

#include "impactful_check_spdm.h"


/* Internal functions declared to allow for static initialization. */
int impactful_check_spdm_is_not_impactful (const struct impactful_check *impactful);
int impactful_check_spdm_is_authorization_allowed (const struct impactful_check *impactful);


/**
 * Constant initializer for the firmware update event handlers.
 */
#define	IMPACTFUL_CHECK_SPDM_API_INIT  { \
		.is_not_impactful = impactful_check_spdm_is_not_impactful, \
		.is_authorization_allowed = impactful_check_spdm_is_authorization_allowed, \
	}


/**
 * Initialize a static instance for an impactful check based on SPDM policy.
 *
 * There is no validation done on the arguments.
 *
 * @param spdm_ptr The SPDM secure session manager interface that should be used to determine if an
 * update is impactful.
 */
#define	impactful_check_spdm_static_init(spdm_ptr) { \
		.base = IMPACTFUL_CHECK_SPDM_API_INIT, \
		.spdm = spdm_ptr, \
	}


#endif	/* IMPACTFUL_CHECK_SPDM_STATIC_H_ */
