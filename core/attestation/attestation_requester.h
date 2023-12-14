// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ATTESTATION_REQUESTER_H_
#define ATTESTATION_REQUESTER_H_

#include <stdint.h>
#include "asn1/x509.h"
#include "crypto/hash.h"
#include "crypto/ecc.h"
#include "crypto/rsa.h"
#include "crypto/rng.h"
#include "cmd_interface/cerberus_protocol_observer.h"
#include "cmd_interface/device_manager.h"
#include "manifest/cfm/cfm_manager.h"
#include "manifest/cfm/cfm_observer.h"
#include "mctp/mctp_base_protocol.h"
#include "mctp/mctp_control_protocol_observer.h"
#include "spdm/spdm_protocol_observer.h"
#include "riot/riot_key_manager.h"
#include "attestation.h"
#include "pcr_store.h"


/**
 * Attestation requester request transaction state
 */
enum attestation_requester_request_state {
	ATTESTATION_REQUESTER_REQUEST_IDLE = 0,						/**< Start of a transaction or no response received yet */
	ATTESTATION_REQUESTER_REQUEST_SUCCESSFUL,					/**< Successful response received */
	ATTESTATION_REQUESTER_REQUEST_RSP_FAIL,						/**< Failed response received */
};

/**
 * Context related to a attestation or discovery transaction
 */
struct attestation_requester_transaction_state {
	uint8_t msg_buffer[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN];		/**< Buffer to be used for request generation and response processing. */
	size_t msg_buffer_len;										/**< Length of data in message buffer */
	enum attestation_requester_request_state request_status;	/**< Response processing status. */
	enum attestation_protocol protocol;							/**< Attestation protocol utilized with this device. */
	uint32_t sleep_duration_ms;									/**< Duration in milliseconds to sleep while waiting for response. */
	uint16_t device_version_set;								/**< Version set selected for device. */
	uint8_t *cert_buffer;										/**< A temporary dynamically allocated buffer for aggregating and verifying certificate chain. */
	uint8_t requested_command;									/**< Command awaiting response for. */
	uint8_t measurement_operation_requested;					/**< Measurement operation requested from device. */
	uint8_t slot_num;											/**< Slot number selected for device currently being attested. */
	uint8_t num_certs;											/**< Number of certificates in certificate chain. */
	uint8_t respond_if_ready_token;								/**< Token to pass to responder in RESPOND_IF_READY requests. */
	size_t cert_buffer_len;										/**< Length of cert_buffer contents. */
	size_t cert_total_len;										/**< Total certificate chain length to read back from device. */
	size_t alias_signature_len;									/**< Length of a signature component signed by device alias key. */
	enum hash_type transcript_hash_type;						/**< Cryptographic hashing algorithm utilized in attestation transcript hashing. */
	enum hash_type measurement_hash_type;						/**< Cryptographic hashing algorithm utilized in measurement hashing. */
	bool hash_finish;											/**< Transcript hashing completed. */
	bool challenge_supported;									/**< Challenge command supported. */
	bool raw_bitstream_requested;								/**< Requested raw measurement data from device. */
	bool device_discovery;										/**< Performing device discovery. */
	bool cert_supported;										/**< Certificate command supported. */
};

/**
 * Variable context associated with an attestation requester
 */
struct attestation_requester_state {
	struct attestation_requester_transaction_state txn;			/**< Current transaction context. */
	struct spdm_protocol_mctp_header *spdm_mctp;				/**< MCTP header for SPDM requests. */
	uint8_t *spdm_msg_buffer;									/**< Buffer for building SPDM requests. */
	bool get_routing_table;										/**< Flag indicating that MCTP routing table should be updated. */
	bool mctp_bridge_wait;										/**< Flag indicating Cerberus is waiting on MCTP bridge to start discovery flow */
	platform_semaphore next_action;								/**< Semaphore used to indicate attestation requester has a pending action. */
};

/**
 * Module that performs attestation against component devices using both Cerberus and SPDM protocol
 * over MCTP
 */
struct attestation_requester {
#ifdef ATTESTATION_SUPPORT_CERBERUS_CHALLENGE
	struct cerberus_protocol_observer cerberus_rsp_observer;	/**< Observer to notifications of a Cerberus protocol response message. */
#endif
#ifdef ATTESTATION_SUPPORT_SPDM
	struct spdm_protocol_observer spdm_rsp_observer;			/**< Observer to notifications of a SPDM protocol response message. */
#endif
#ifdef ATTESTATION_SUPPORT_DEVICE_DISCOVERY
	struct mctp_control_protocol_observer mctp_rsp_observer;	/**< Observer to notifications of a MCTP control protocol response message. */
#endif
	struct cfm_observer cfm_observer; 							/**< Observer to CFM notifications. */
	struct attestation_requester_state *state;					/**< Variable context for the attestation requester. */
	const struct cmd_channel *channel;							/**< Channel for communicating with BMC. */
	struct mctp_interface *mctp;								/**< MCTP interface to utilize for communication with BMC. */
	struct hash_engine *primary_hash;							/**< The hashing engine for attestation authentication operations. */
	struct hash_engine *secondary_hash;							/**< Secondary hash engine for SPDM attestation. Instance provided needs to be capable of running simultaneously with primary hash instance. */
	struct ecc_engine *ecc;										/**< The ECC engine for attestation authentication operations. */
	struct rsa_engine *rsa;										/**< The RSA engine for attestation authentication operations. */
	struct x509_engine *x509;									/**< The X509 engine for attestation authentication operations. */
	struct rng_engine *rng;										/**< The RNG engine for attestation authentication operations. */
	struct riot_key_manager *riot;								/**< RIoT key manager. */
	struct device_manager *device_mgr;							/**< Device manager instance to utilize. */
	struct cfm_manager *cfm_manager;							/**< CFM manager instance */
};


int attestation_requester_init (struct attestation_requester *attestation,
	struct attestation_requester_state *state, struct mctp_interface *mctp,
	const struct cmd_channel *channel, struct hash_engine *primary_hash,
	struct hash_engine *secondary_hash, struct ecc_engine *ecc, struct rsa_engine *rsa,
	struct x509_engine *x509, struct rng_engine *rng, struct riot_key_manager *riot,
	struct device_manager *device_mgr, struct cfm_manager *cfm_manager);
int attestation_requester_init_state (const struct attestation_requester *attestation);
void attestation_requester_deinit (const struct attestation_requester *ctrl);

int attestation_requester_attest_device (const struct attestation_requester *attestation,
	uint8_t eid);

#ifdef ATTESTATION_SUPPORT_DEVICE_DISCOVERY
int attestation_requester_discover_device (const struct attestation_requester *attestation,
	uint8_t eid);

int attestation_requester_get_mctp_routing_table (const struct attestation_requester *attestation);
#endif

void attestation_requester_discovery_and_attestation_loop (
	const struct attestation_requester *attestation, struct pcr_store *pcr, uint16_t measurement,
	uint8_t measurement_version);

int attestation_requestor_mctp_bridge_was_reset (const struct attestation_requester *attestation);

void attestation_requester_refresh_routing_table (const struct attestation_requester *attestation);

void attestation_requestor_wait_for_next_action (const struct attestation_requester *attestation);


#endif /* ATTESTATION_REQUESTER_H_ */
