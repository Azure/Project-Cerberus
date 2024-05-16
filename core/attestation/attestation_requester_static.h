// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ATTESTATION_REQUESTER_STATIC_H_
#define ATTESTATION_REQUESTER_STATIC_H_

#include <stdint.h>
#include "attestation_requester.h"


/* Internal functions declared to allow for static initialization. */
void attestation_requester_on_spdm_get_version_response (
	const struct spdm_protocol_observer *observer, const struct cmd_interface_msg *response);
void attestation_requester_on_spdm_get_capabilities_response (
	const struct spdm_protocol_observer *observer, const struct cmd_interface_msg *response);
void attestation_requester_on_spdm_negotiate_algorithms_response (
	const struct spdm_protocol_observer *observer, const struct cmd_interface_msg *response);
void attestation_requester_on_spdm_get_digests_response (
	const struct spdm_protocol_observer *observer, const struct cmd_interface_msg *response);
void attestation_requester_on_spdm_get_certificate_response (
	const struct spdm_protocol_observer *observer, const struct cmd_interface_msg *response);
void attestation_requester_on_spdm_challenge_response (
	const struct spdm_protocol_observer *observer, const struct cmd_interface_msg *response);
void attestation_requester_on_spdm_get_measurements_response (
	const struct spdm_protocol_observer *observer, const struct cmd_interface_msg *response);
void attestation_requester_on_cerberus_get_digest_response (
	const struct cerberus_protocol_observer *observer, const struct cmd_interface_msg *response);
void attestation_requester_on_cerberus_get_certificate_response (
	const struct cerberus_protocol_observer *observer, const struct cmd_interface_msg *response);
void attestation_requester_on_cerberus_challenge_response (
	const struct cerberus_protocol_observer *observer, const struct cmd_interface_msg *response);
void attestation_requester_on_cerberus_device_capabilities_response (
	const struct cerberus_protocol_observer *observer, const struct cmd_interface_msg *response);
void attestation_requester_on_mctp_get_message_type_response (
	const struct mctp_control_protocol_observer *observer,
	const struct cmd_interface_msg *response);
void attestation_requester_on_mctp_set_eid_request (
	const struct mctp_control_protocol_observer *observer);
void attestation_requester_on_mctp_get_routing_table_entries_response (
	const struct mctp_control_protocol_observer *observer,
	const struct cmd_interface_msg *response);


/**
 * Constant initializer for the MCTP response observer API.
 */
#ifdef ATTESTATION_SUPPORT_DEVICE_DISCOVERY
#define	ATTESTATION_REQUESTER_MCTP_RSP_OBSERVER_API_INIT { \
		.on_get_message_type_response = \
			attestation_requester_on_mctp_get_message_type_response, \
		.on_set_eid_request = \
			attestation_requester_on_mctp_set_eid_request, \
		.on_get_routing_table_entries_response = \
			attestation_requester_on_mctp_get_routing_table_entries_response \
	}
#else
#define ATTESTATION_REQUESTER_MCTP_RSP_OBSERVER_API_INIT
#endif

/**
 * Constant initializer for the Cerberus response observer API.
 */
#ifdef ATTESTATION_SUPPORT_CERBERUS_CHALLENGE
#define	ATTESTATION_REQUESTER_CERBERUS_RSP_OBSERVER_API_INIT { \
		.on_get_digest_response = \
			attestation_requester_on_cerberus_get_digest_response, \
		.on_get_certificate_response = \
			attestation_requester_on_cerberus_get_certificate_response, \
		.on_challenge_response = \
			attestation_requester_on_cerberus_challenge_response, \
		.on_device_capabilities = \
			attestation_requester_on_cerberus_device_capabilities_response \
	}
#else
#define ATTESTATION_REQUESTER_CERBERUS_RSP_OBSERVER_API_INIT
#endif

/**
 * Constant initializer for the SPDM response observer API.
 */
#ifdef ATTESTATION_SUPPORT_SPDM
#define	ATTESTATION_REQUESTER_SPDM_RSP_OBSERVER_API_INIT { \
		.on_spdm_get_version_response = \
			attestation_requester_on_spdm_get_version_response, \
		.on_spdm_get_capabilities_response = \
			attestation_requester_on_spdm_get_capabilities_response, \
		.on_spdm_negotiate_algorithms_response = \
			attestation_requester_on_spdm_negotiate_algorithms_response, \
		.on_spdm_get_digests_response = \
			attestation_requester_on_spdm_get_digests_response, \
		.on_spdm_get_certificate_response = \
			attestation_requester_on_spdm_get_certificate_response, \
		.on_spdm_challenge_response = \
			attestation_requester_on_spdm_challenge_response, \
		.on_spdm_get_measurements_response = \
			attestation_requester_on_spdm_get_measurements_response \
	}
#else
#define ATTESTATION_REQUESTER_SPDM_RSP_OBSERVER_API_INIT
#endif

/**
 * Initialize a static attestation requester instance.
 * There is no validation done on the arguments.
 *
 * @param state_ptr The variable context for the attestation requester instance.
 * @param mctp_ptr MCTP interface instance to utilize.
 * @param channel_ptr Command channel instance to utilize.
 * @param primary_hash_ptr The primary hash engine to utilize.
 * @param secondary_hash_ptr The secondary hash engine to utilize for SPDM operations.
 * @param ecc_ptr The ECC engine to utilize.
 * @param rsa_ptr The RSA engine to utilize. Optional, can be set to NULL if not utilized.
 * @param x509_ptr The x509 engine to utilize.
 * @param rng_ptr The RNG engine to utilize.
 * @param riot_ptr RIoT key manager.
 * @param device_mgr_ptr Device manager instance to utilize.
 * @param cfm_manager_ptr CFM manager to utilize.
 */
#define attestation_requester_static_init(state_ptr, mctp_ptr, channel_ptr, primary_hash_ptr, \
	secondary_hash_ptr, ecc_ptr, rsa_ptr, x509_ptr, rng_ptr, riot_ptr, device_mgr_ptr, \
	cfm_manager_ptr) { \
		.mctp = mctp_ptr, \
		.channel = channel_ptr, \
		.primary_hash = primary_hash_ptr, \
		.secondary_hash = secondary_hash_ptr, \
		.ecc = ecc_ptr, \
		.rsa = rsa_ptr, \
		.x509 = x509_ptr, \
		.rng = rng_ptr, \
		.riot = riot_ptr, \
		.device_mgr = device_mgr_ptr, \
		.cfm_manager = cfm_manager_ptr, \
		.state = state_ptr, \
		.mctp_rsp_observer = ATTESTATION_REQUESTER_MCTP_RSP_OBSERVER_API_INIT, \
		.cerberus_rsp_observer = ATTESTATION_REQUESTER_CERBERUS_RSP_OBSERVER_API_INIT, \
		.spdm_rsp_observer = ATTESTATION_REQUESTER_SPDM_RSP_OBSERVER_API_INIT, \
	}


#endif	/* ATTESTATION_REQUESTER_STATIC_H_ */
