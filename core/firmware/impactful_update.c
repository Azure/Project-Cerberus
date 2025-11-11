// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "firmware_logging.h"
#include "impactful_update.h"
#include "common/unused.h"


int impactful_update_is_update_not_impactful (const struct impactful_update_interface *impactful)
{
	const struct impactful_update *update = (const struct impactful_update*) impactful;
	size_t i;
	int status;

	if (update == NULL) {
		return IMPACTFUL_UPDATE_INVALID_ARGUMENT;
	}

	for (i = 0; i < update->check_count; i++) {
		status = update->check[i]->is_not_impactful (update->check[i]);
		if (status != 0) {
			break;
		}
	}

	return status;
}

int impactful_update_is_update_allowed (const struct impactful_update_interface *impactful)
{
	const struct impactful_update *update = (const struct impactful_update*) impactful;
	size_t i;
	int status;
	int allowed = 0;

	if (update == NULL) {
		return IMPACTFUL_UPDATE_INVALID_ARGUMENT;
	}

	for (i = 0; i < update->check_count; i++) {
		status = update->check[i]->is_not_impactful (update->check[i]);
		if (status != 0) {
			int auth_allowed;

			/* The check has determined the update will be impactful.  Check to see if the update
			 * can be authorized or not. */
			auth_allowed = update->check[i]->is_authorization_allowed (update->check[i]);
			if (auth_allowed != 0) {
				/* Impactful updates cannot be authorized for this check, so no need to make any
				 * additional checks. */
				debug_log_create_entry (DEBUG_LOG_SEVERITY_WARNING, DEBUG_LOG_COMPONENT_CERBERUS_FW,
					FIRMWARE_LOGGING_IMPACTFUL_BLOCKED, i, auth_allowed);

				return auth_allowed;
			}

			platform_mutex_lock (&update->state->lock);

			if (!update->state->is_authorized) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CERBERUS_FW,
					FIRMWARE_LOGGING_IMPACTFUL_UPDATE_NO_AUTH, i, status);

				allowed = status;
			}

			platform_mutex_unlock (&update->state->lock);

			/* The rest of the checks must be performed to ensure there are no blocking impactful
			 * conditions. */
		}
	}

	return allowed;
}

int impactful_update_authorize_update (const struct impactful_update_interface *impactful,
	uint32_t allowed_time_ms)
{
	const struct impactful_update *update = (const struct impactful_update*) impactful;
	int status;

	if (update == NULL) {
		return IMPACTFUL_UPDATE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&update->state->lock);

	if (allowed_time_ms != 0) {
		status = platform_timer_arm_one_shot (&update->state->expiration, allowed_time_ms);
	}
	else {
		/* No expiration is requested, so cancel any existing expiration timer. */
		status = platform_timer_disarm (&update->state->expiration);
	}

	if (status == 0) {
		/* Only if the expiration timer could be set appropriately will impactful updates be
		 * authorized. */
		update->state->is_authorized = true;
	}

	platform_mutex_unlock (&update->state->lock);

	return status;
}

int impactful_update_reset_authorization (const struct impactful_update_interface *impactful)
{
	const struct impactful_update *update = (const struct impactful_update*) impactful;

	if (update == NULL) {
		return IMPACTFUL_UPDATE_INVALID_ARGUMENT;
	}

	/* This is just for efficiency so the timer doesn't fire unnecessarily, so we don't care about
	 * the status of this call.  If the timer still ends of triggering, it would not change any
	 * state. */
	platform_timer_disarm (&update->state->expiration);

	platform_mutex_lock (&update->state->lock);
	update->state->is_authorized = false;
	platform_mutex_unlock (&update->state->lock);

	return 0;
}

/**
 * Timer callback to force expiration of any active impactful update authorization.
 *
 * @param ctx The impactful update context to update.
 */
static void impactful_update_expired_authorization (void *ctx)
{
	const struct impactful_update_interface *impactful = ctx;

	impactful_update_reset_authorization (impactful);
}

/**
 * Initialize a manager for providing the special handling needed to work with firmware updates that
 * will be impactful to the host system.
 *
 * @param impactful The impactful update manager to initialize.
 * @param state Variable context for the manager.  This must be uninitialized.
 * @param check List of checks to perform when determining whether an update is impactful or not.
 * @param check_count The number of impactful checks in the list.
 *
 * @return 0 if the impactful update manager was initialized successfully or an error code.
 */
int impactful_update_init (struct impactful_update *impactful, struct impactful_update_state *state,
	const struct impactful_check *const *check, size_t check_count)
{
	if ((impactful == NULL) || (state == NULL) || (check == NULL) || (check_count == 0)) {
		return IMPACTFUL_UPDATE_INVALID_ARGUMENT;
	}

	memset (impactful, 0, sizeof (*impactful));

	impactful->base.is_update_not_impactful = impactful_update_is_update_not_impactful;
	impactful->base.is_update_allowed = impactful_update_is_update_allowed;
	impactful->base.authorize_update = impactful_update_authorize_update;
	impactful->base.reset_authorization = impactful_update_reset_authorization;

	impactful->state = state;
	impactful->check = check;
	impactful->check_count = check_count;

	return impactful_update_init_state (impactful);
}

/**
 * Initialize only the variable state for an impactful update manager.  The rest of the manager is
 * assumed to have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param impactful The impactful update manager that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int impactful_update_init_state (const struct impactful_update *impactful)
{
	int status;

	if ((impactful == NULL) || (impactful->state == NULL) || (impactful->check == NULL) ||
		(impactful->check_count == 0)) {
		return IMPACTFUL_UPDATE_INVALID_ARGUMENT;
	}

	memset (impactful->state, 0, sizeof (*impactful->state));

	status = platform_mutex_init (&impactful->state->lock);
	if (status != 0) {
		return status;
	}

	status = platform_timer_create (&impactful->state->expiration,
		impactful_update_expired_authorization, (void*) &impactful->base);
	if (status != 0) {
		platform_mutex_free (&impactful->state->lock);
	}

	return status;
}

/**
 * Release the resources used for managing impactful firmware updates.
 *
 * @param impactful The impactful update manager to release.
 */
void impactful_update_release (const struct impactful_update *impactful)
{
	if (impactful != NULL) {
		platform_timer_delete (&impactful->state->expiration);
		platform_mutex_free (&impactful->state->lock);
	}
}
