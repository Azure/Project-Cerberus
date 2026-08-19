// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "attestation_discover_tcg.h"
#include "attestation_logging.h"
#include "attestation_requester.h"
#include "platform_api.h"
#include "cmd_interface/device_manager.h"
#include "cmd_interface/msg_transport.h"
#include "common/unused.h"
#include "logging/debug_log.h"


/**
 * Get the device EID by device number.
 * @param attestation_discover Attestation discover instance to utilize.
 * @param attestation Attestation requester instance to utilize.
 * @param device_num The device number to query EID for.
 *
 * @return 0 if device EID was queried successfully or an error code otherwise.
 */
int attestation_discover_tcg_get_device_eid_by_device_num (
	const struct attestation_discover *attestation_discover,
	const struct attestation_requester *attestation, int device_num)
{
	/* TCG discovery doesn't support EID lookup by device number.
	 * TCG attestation uses device numbers directly, and self-attested devices
	 * don't have assigned EIDs. This will be removed after attestation refactor.
	 */
	UNUSED (attestation_discover);
	UNUSED (attestation);
	UNUSED (device_num);

	return ATTESTATION_UNSUPPORTED_OPERATION;
}

/**
 * Discover the devices using the TCG approach.
 *
 * @param attestation_discover Attestation discover instance to utilize.
 * @param attestation Attestation requester instance to utilize.
 *
 * @return Completion status, 0 if success or an error code otherwise
 */
int attestation_discover_tcg_discover_device (
	const struct attestation_discover *attestation_discover,
	const struct attestation_requester *attestation)
{
	const struct attestation_discover_tcg *tcg_discover =
		(const struct attestation_discover_tcg*) attestation_discover;

	int device_num;
	int discovery_count = 0;
	int device_state;
	int status = 0;

	if ((attestation_discover == NULL) || (attestation == NULL)) {
		status = ATTESTATION_INVALID_ARGUMENT;
		goto log_failure;
	}

	if ((tcg_discover->state->discovery_state == ATTESTATION_DISCOVERY_IDLE) ||
		(tcg_discover->state->discovery_state == ATTESTATION_DISCOVERY_COMPLETE)) {
		return 0;
	}

	/*
	 * TCG component IDs are statically defined in the PCD and registered into the device
	 * manager at init time with state DEVICE_MANAGER_UNIDENTIFIED. This function transitions
	 * them to NEVER_ATTESTED so attestation can begin after the discovery phase.
	 */
	for (device_num = 0; device_num < attestation->device_mgr->num_devices; ++device_num) {
		if (device_manager_get_discovery_object (attestation->device_mgr, device_num) !=
			attestation_discover) {
			continue;
		}

		device_state = device_manager_get_device_state (attestation->device_mgr, device_num);
		if (ROT_IS_ERROR (device_state)) {
			status = device_state;
			goto failed;
		}

		if (device_state == DEVICE_MANAGER_UNIDENTIFIED) {
			status = device_manager_update_device_state (attestation->device_mgr, device_num,
				DEVICE_MANAGER_NEVER_ATTESTED);
			if (status != 0) {
				goto failed;
			}

			++discovery_count;
		}
	}

	debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_ATTESTATION,
		ATTESTATION_LOGGING_TCG_DISCOVERY_COMPLETE, discovery_count, 0);

	tcg_discover->state->discovery_state = ATTESTATION_DISCOVERY_COMPLETE;

	return 0;

failed:
	device_manager_restart_device_discovery_by_handler (attestation->device_mgr,
		attestation_discover);

log_failure:
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
		ATTESTATION_LOGGING_TCG_DISCOVERY_FAILED, status, 0);

	return status;
}

/**
 * Initialize the attestation discover tcg instance
 *
 * @param discover attestation discover tcg instance to initialize.
 * @param state Variable context for the discover instance. This must be uninitialized.
 *
 * @return Init status, 0 if success or an error code.
 */
int attestation_discover_tcg_init (struct attestation_discover_tcg *discover,
	struct attestation_discover_tcg_state *state)
{
	if ((discover == NULL) || (state == NULL)) {
		return ATTESTATION_INVALID_ARGUMENT;
	}

	memset (discover, 0, sizeof (struct attestation_discover_tcg));
	discover->base.discover_device = attestation_discover_tcg_discover_device;
	discover->base.get_device_eid_by_device_num =
		attestation_discover_tcg_get_device_eid_by_device_num;
	discover->state = state;

	return attestation_discover_tcg_init_state (discover);
}

/**
 * Initialize only the variable state of an attestation discover tcg instance. The rest of the
 * instance is assumed to have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param discover The attestation discover tcg instance that contains the state to initialize.
 *
 * @return Init status, 0 if success or an error code.
 */
int attestation_discover_tcg_init_state (const struct attestation_discover_tcg *discover)
{
	if ((discover == NULL) || (discover->state == NULL)) {
		return ATTESTATION_INVALID_ARGUMENT;
	}

	memset (discover->state, 0, sizeof (struct attestation_discover_tcg_state));
	discover->state->discovery_state = ATTESTATION_DISCOVERY_IDLE;

	return 0;
}

/**
 * Release the resources used for attestation discover tcg.
 *
 * @param discover The attestation discover to release.
 */
void attestation_discover_tcg_release (const struct attestation_discover_tcg *discover)
{
	UNUSED (discover);
}

/**
 * Timer callback to trigger TCG discovery after a boot delay.
 * This is called once after the configured delay to allow the system to stabilize
 * before starting TCG device discovery.
 *
 * @param context TCG discovery timer context containing attestation and discover instances.
 */
void attestation_discover_tcg_timer_callback (
	struct attestation_discover_tcg_timer_context *context)
{
	if (context == NULL) {
		return;
	}

	if ((context->attestation == NULL) || (context->tcg_discover == NULL)) {
		return;
	}

	context->tcg_discover->state->discovery_state = ATTESTATION_DISCOVERY_TRIGGERED;

	debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_ATTESTATION,
		ATTESTATION_LOGGING_TCG_DISCOVERY_TRIGGERED, 0, 0);

	platform_semaphore_post (&context->attestation->state->next_action);
}

/**
 * Initialize and start the TCG discovery delay timer.
 *
 * Sets up the timer context and arms a one-shot timer that will trigger TCG discovery
 * after the specified boot delay.
 *
 * @param timer Platform timer to create and arm.
 * @param context Timer context to initialize with attestation and discover instances.
 * @param attestation Attestation requester instance.
 * @param discover TCG discover instance.
 * @param delay_ms Delay in milliseconds before triggering TCG discovery.
 *
 * @return 0 if success or an error code.
 */
int attestation_discover_tcg_start_timer (platform_timer *timer,
	struct attestation_discover_tcg_timer_context *context,
	const struct attestation_requester *attestation,
	const struct attestation_discover_tcg *discover, uint32_t delay_ms)
{
	int status;

	if ((timer == NULL) || (context == NULL) || (attestation == NULL) || (discover == NULL)) {
		return ATTESTATION_INVALID_ARGUMENT;
	}

	context->attestation = attestation;
	context->tcg_discover = discover;

	status = platform_timer_create (timer, (timer_callback) attestation_discover_tcg_timer_callback,
		context);
	if (status != 0) {
		return status;
	}

	status = platform_timer_arm_one_shot (timer, delay_ms);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_TCG_DISCOVERY_TIMER_FAILED, status, 0);

		return status;
	}

	return 0;
}
