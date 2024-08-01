// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef IMPACTFUL_UPDATE_STATIC_H_
#define IMPACTFUL_UPDATE_STATIC_H_

#include "impactful_update.h"


/* Internal functions declared to allow for static initialization. */
int impactful_update_is_update_not_impactful (const struct impactful_update_interface *impactful);
int impactful_update_is_update_allowed (const struct impactful_update_interface *impactful);
int impactful_update_authorize_update (const struct impactful_update_interface *impactful,
	uint32_t allowed_time_ms);
int impactful_update_reset_authorization (const struct impactful_update_interface *impactful);


/**
 * Constant initializer for the impactful update API.
 */
#define	IMPACTFUL_UPDATE_API_INIT  { \
		.is_update_not_impactful = impactful_update_is_update_not_impactful, \
		.is_update_allowed = impactful_update_is_update_allowed, \
		.authorize_update = impactful_update_authorize_update, \
		.reset_authorization = impactful_update_reset_authorization, \
	}


/**
 * Initialize a static instance of an impactful update manager.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the manager.
 * @param check_ptr List of checks to perform when determining whether an update is impactful or
 * not.
 * @param check_count_arg The number of impactful checks in the list.
 */
#define	impactful_update_static_init(state_ptr, check_ptr, check_count_arg)	{ \
		.base = IMPACTFUL_UPDATE_API_INIT, \
		.state = state_ptr, \
		.check = check_ptr, \
		.check_count = check_count_arg, \
	}


#endif	/* IMPACTFUL_UPDATE_STATIC_H_ */
