// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef IMPACTFUL_UPDATE_H_
#define IMPACTFUL_UPDATE_H_

#include <stdbool.h>
#include <stddef.h>
#include "impactful_check.h"
#include "impactful_update_interface.h"
#include "platform_api.h"


/**
 * Variable context for managing impactful firmware updates.
 */
struct impactful_update_state {
	platform_mutex lock;		/**< Lock for synchronization. */
	platform_timer expiration;	/**< Expiration timer for impactful authorization. */
	bool is_authorized;			/**< Flag indicating impactful updates are authorized. */
};

/**
 * Common handler for managing firmware updates that are impactful.
 */
struct impactful_update {
	struct impactful_update_interface base;		/**< Base API for impactful updates. */
	struct impactful_update_state *state;		/**< Variable context for impactful updates. */
	const struct impactful_check *const *check;	/**< List of checks to determine if an update is impactful. */
	size_t check_count;							/**< Number of checks to perform. */
};


int impactful_update_init (struct impactful_update *impactful, struct impactful_update_state *state,
	const struct impactful_check *const *check, size_t check_count);
int impactful_update_init_state (const struct impactful_update *impactful);
void impactful_update_release (const struct impactful_update *impactful);


#endif	/* IMPACTFUL_UPDATE_H_ */
