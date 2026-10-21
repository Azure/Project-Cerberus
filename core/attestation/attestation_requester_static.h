// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ATTESTATION_REQUESTER_STATIC_H_
#define ATTESTATION_REQUESTER_STATIC_H_

#include <stdint.h>
#include "attestation_requester.h"


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
 * @param discover_interfaces_ptr Array of attestation discover interfaces.
 * @param interfaces_count_val Number of entries in the discover interfaces array.
 * @param mctp_control_ptr Message transport MCTP control instance to utilize.
 * @param spdm_transport_ptr Message transport SPDM instance to utilize.
 */
#define attestation_requester_static_init(state_ptr, mctp_ptr, channel_ptr, primary_hash_ptr, \
	secondary_hash_ptr, ecc_ptr, rsa_ptr, x509_ptr, rng_ptr, riot_ptr, device_mgr_ptr, \
	cfm_manager_ptr, discover_interfaces_ptr, interfaces_count_val, mctp_control_ptr, \
	spdm_transport_ptr) { \
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
		.discover_interfaces = discover_interfaces_ptr, \
		.interfaces_count = interfaces_count_val, \
		.mctp_control = mctp_control_ptr, \
		.spdm_transport = spdm_transport_ptr, \
	}


#endif	/* ATTESTATION_REQUESTER_STATIC_H_ */
