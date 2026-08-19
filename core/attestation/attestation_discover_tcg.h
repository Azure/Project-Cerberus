// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ATTESTATION_DISCOVER_TCG_H_
#define ATTESTATION_DISCOVER_TCG_H_


#include "attestation_discover.h"
#include "attestation_requester.h"
#include "cmd_interface/device_manager.h"

/**
 * Variable context for the TCG discovery. This is held separately so that the discover instance
 * itself can be placed in read-only memory.
 */
struct attestation_discover_tcg_state {
	enum attestation_discovery_state discovery_state;	/**< Current discovery state. */
};

/**
 * Discover the TCG devices.
 */
struct attestation_discover_tcg {
	struct attestation_discover base;				/**< Base attestation discover instance. */
	struct attestation_discover_tcg_state *state;	/**< Variable context for TCG discovery. */
};


int attestation_discover_tcg_init (struct attestation_discover_tcg *discover,
	struct attestation_discover_tcg_state *state);
int attestation_discover_tcg_init_state (const struct attestation_discover_tcg *discover);
void attestation_discover_tcg_release (const struct attestation_discover_tcg *discover);
int attestation_discover_tcg_discover_device (
	const struct attestation_discover *attestation_discover,
	const struct attestation_requester *attestation);
int attestation_discover_tcg_get_device_eid_by_device_num (
	const struct attestation_discover *attestation_discover,
	const struct attestation_requester *attestation, int device_num);

/**
 * Context for the TCG discovery delay timer callback.
 */
struct attestation_discover_tcg_timer_context {
	const struct attestation_requester *attestation;		/**< Attestation requester instance. */
	const struct attestation_discover_tcg *tcg_discover;	/**< TCG discover instance. */
};


void attestation_discover_tcg_timer_callback (
	struct attestation_discover_tcg_timer_context *context);
int attestation_discover_tcg_start_timer (platform_timer *timer,
	struct attestation_discover_tcg_timer_context *context,
	const struct attestation_requester *attestation,
	const struct attestation_discover_tcg *discover, uint32_t delay_ms);


#endif	/* ATTESTATION_DISCOVER_TCG_H_ */
