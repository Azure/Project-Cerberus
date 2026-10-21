// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ATTESTATION_DISCOVER_MCTP_H_
#define ATTESTATION_DISCOVER_MCTP_H_

#include "attestation.h"
#include "attestation_discover.h"
#include "attestation_requester.h"
#include "cmd_interface/device_manager.h"


/**
 * Variable context for the MCTP discovery. This is held separately so that the discover instance
 * itself can be placed in read-only memory.
 */
struct attestation_discover_mctp_state {
	enum attestation_discovery_state discovery_state;	/**< Current discovery state. */
	bool routing_table_dirty;							/**< True if routing table needs to be refreshed, false if up to date. */
};

/**
 * Discover the devices using the MCTP method, it will fetch the available EIDs using
 * MCTP routing table, then do the discovery based on cerberus/spdm protocols.
 */
struct attestation_discover_mctp {
	struct attestation_discover base;							/**< Base attestation discover instance. */
	struct mctp_control_protocol_observer mctp_rsp_observer;	/**< Observer to notifications of a MCTP control protocol response message. */
	const struct msg_transport *transport;						/**< SPDM message transport for discovery operations. */
	struct attestation_discover_mctp_state *state;				/**< Variable context for MCTP discovery. */
};


int attestation_discover_mctp_init (struct attestation_discover_mctp *discover,
	struct attestation_discover_mctp_state *state, const struct msg_transport *transport);
int attestation_discover_mctp_init_state (const struct attestation_discover_mctp *discover);
void attestation_discover_mctp_release (const struct attestation_discover_mctp *discover);

/**
 * Context for the MCTP routing table refresh timer callback.
 */
struct attestation_discover_mctp_refresh_context {
	const struct attestation_requester *attestation;		/**< Attestation requester instance. */
	const struct attestation_discover_mctp *mctp_discover;	/**< MCTP discover instance. */
};


void attestation_discover_mctp_refresh_routing_table (
	struct attestation_discover_mctp_refresh_context *context);
int attestation_discover_mctp_get_device_eid_by_device_num (
	const struct attestation_discover *attestation_discover,
	const struct attestation_requester *attestation, int device_num);
int attestation_discover_mctp_start_timer (platform_timer *timer,
	struct attestation_discover_mctp_refresh_context *context,
	const struct attestation_requester *attestation,
	const struct attestation_discover_mctp *discover, uint32_t timeout_ms);


#endif	/* ATTESTATION_DISCOVER_MCTP_H_ */
