// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <string.h>
#include "common/type_cast.h"
#include "common/unused.h"
#include "crypto/asn1.h"
#include "logging/debug_log.h"
#include "cmd_interface/cerberus_protocol_required_commands.h"
#include "cmd_interface/cerberus_protocol_master_commands.h"
#include "cmd_interface/cerberus_protocol.h"
#include "manifest/cfm/cfm_manager.h"
#include "mctp/mctp_interface.h"
#include "mctp/mctp_control_protocol.h"
#include "mctp/mctp_control_protocol_commands.h"
#include "spdm/spdm_commands.h"
#include "spdm/spdm_measurements.h"
#include "spdm/spdm_protocol.h"
#include "attestation_logging.h"
#include "attestation.h"
#include "pcr_store.h"
#include "attestation_requester.h"


// Context strings used in SPDM signatures
#define SPDM_CHALLENGE_SIGNATURE_CONTEXT_STR "responder-challenge_auth signing"
#define SPDM_GET_MEASUREMENTS_SIGNATURE_CONTEXT_STR "responder-measurements signing"

/**
 * Check to see if response received is for pending Cerberus request
 *
 * @param attestation Attestation requester instance to utilize
 * @param command Command expected
 */
#define attestation_requester_check_cerberus_unexpected_rsp(attestation, command) \
	((attestation->state->protocol != ATTESTATION_PROTOCOL_CERBERUS) || \
	(attestation->state->requested_command != command))

/**
 * Check to see if response received is for pending SDPM request
 *
 * @param attestation Attestation requester instance to utilize
 * @param command Command expected
 */
#define attestation_requester_check_spdm_unexpected_rsp(attestation, command) \
	((attestation->state->protocol < ATTESTATION_PROTOCOL_DMTF_SPDM_1_1) || \
	(attestation->state->requested_command != command))


#if defined (ATTESTATION_SUPPORT_SPDM) || defined (ATTESTATION_SUPPORT_CERBERUS_CHALLENGE)
/**
 * Function to send Cerberus protocol or SPDM request and wait for a response. This function
 * assumes a pregenerated request is in attestation_requester's msg_buffer.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param request_len Length of request to send.
 * @param dest_addr SMBus address of destination device.
 * @param dest_eid MCTP EID of destination device.
 * @param crypto_timeout Flag indicating whether to use the crypto timeout with device.
 * @param command Requested command to send out.
 *
 * @return 0 if successful or error code otherwise
 */
static int attestation_requester_send_request_and_get_response (
	const struct attestation_requester *attestation, size_t request_len, uint8_t dest_addr,
	uint8_t dest_eid, bool crypto_timeout, uint8_t command)
{
	uint32_t timeout_ms;
	bool rsp_ready = false;
	int status;

	attestation->state->request_status = ATTESTATION_REQUESTER_REQUEST_IDLE;
	attestation->state->requested_command = command;

	if (crypto_timeout) {
		timeout_ms = device_manager_get_reponse_timeout_by_eid (attestation->device_mgr, dest_eid);
	}
	else {
		timeout_ms = device_manager_get_crypto_timeout_by_eid (attestation->device_mgr, dest_eid);
	}

	while (!rsp_ready) {
		/* Send request and await response. mctp_interface_issue_request will block till a response
		 * is received or timeout period elapses. If response is received, the notification
		 * callbacks will process response and update the request_status.
		 */
		status = mctp_interface_issue_request (attestation->mctp, attestation->channel, dest_addr,
			dest_eid, attestation->state->msg_buffer, request_len, attestation->state->msg_buffer,
			sizeof (attestation->state->msg_buffer), timeout_ms);
		if (status != 0) {
			return status;
		}

		if (attestation->state->request_status != ATTESTATION_REQUESTER_REQUEST_SUCCESSFUL) {
			return ATTESTATION_REQUEST_FAILED;
		}

		/* If SPDM, responder might send a ResponseNotReady error. The ResponseNotReady notification
		 * will set sleep_duration_ms to a non-zero value based on the error response as per the
		 * SPDM DSP0274 spec. First, sleep for the duration requested until response is ready, then
		 * send a RESPOND_IF_READY request to retrieve response to original request.
		 */

		// TODO: Check for an upper limit to number of retries
		if (attestation->state->sleep_duration_ms != 0) {
			platform_msleep (attestation->state->sleep_duration_ms);
			attestation->state->sleep_duration_ms = 0;

			request_len = spdm_generate_respond_if_ready_request (attestation->state->msg_buffer,
				sizeof (attestation->state->msg_buffer), attestation->state->requested_command,
				attestation->state->respond_if_ready_token, attestation->state->protocol);
			if (ROT_IS_ERROR ((int) request_len)) {
				return request_len;
			}
		}
		else {
			rsp_ready = true;
		}
	}

	return 0;
}

/**
 * Check if digest matches an allowable digest for the device.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param allowable_digests Allowable digests container to utilize.
 * @param digest Buffer populated with digest to verify. If set to NULL, msg_buffer will be used for
 *  the verification.
 * @param digest_type Type of digest in digest buffer.
 *
 * @return Completion status, 0 if success or an error code otherwise
 */
static int attestation_requester_verify_digest_in_allowable_list (
	const struct attestation_requester *attestation, struct cfm_digests *allowable_digests,
	uint8_t *digest, enum hash_type digest_type)
{
	size_t offset = 0;
	size_t digest_len;
	size_t i_digest;
	int status;

	if (digest == NULL) {
		digest = attestation->state->msg_buffer;
	}

	if (allowable_digests->hash_type != digest_type) {
		status = ATTESTATION_CFM_INVALID_ATTESTATION;
	}
	else {
		digest_len = hash_get_hash_len (digest_type);

		for (i_digest = 0; i_digest < allowable_digests->digest_count; ++i_digest) {
			status = memcmp (digest, &allowable_digests->digests[offset], digest_len);
			if (status == 0) {
				break;
			}
			else {
				offset += digest_len;
				status = ATTESTATION_CFM_ATTESTATION_RULE_FAIL;
			}
		}
	}

	return status;
}

/**
 * Check if PMR digest received in msg_buffer matches an allowable PMR digest for the device from
 * 	the active CFM.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param active_cfm Active CFM to utilize.
 * @param component_type SHA256 digest of component type of device.
 * @param eid EID of device to attest.
 * @param pmr_id ID of PMR to verify.
 *
 * @return Completion status, 0 if success, CFM_PMR_DIGEST_NOT_FOUND if PMR has no entry in CFM, or
 * 	an error code otherwise
 */
static int attestation_requester_verify_pmr (const struct attestation_requester *attestation,
	struct cfm *active_cfm, const uint8_t *component_type, uint8_t eid, uint8_t pmr_id)
{
	struct cfm_pmr_digest pmr_digest;
	int status;

	status = active_cfm->get_component_pmr_digest (active_cfm, component_type, pmr_id, &pmr_digest);
	if (status == 0) {
		status = attestation_requester_verify_digest_in_allowable_list (attestation,
			&pmr_digest.digests, NULL, attestation->state->measurement_hash_type);

		active_cfm->free_component_pmr_digest (active_cfm, &pmr_digest);
	}

	if ((status != 0) && (status != CFM_PMR_DIGEST_NOT_FOUND)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_DEVICE_FAILED_ATTESTATION,
			((eid << 16) | (attestation->state->protocol << 8) |
				attestation->state->requested_command),
			status);
	}

	return status;
}
#endif

/**
 * Function to send SPDM request and wait for a response. This function assumes a pregenerated
 * request is in attestation_requester's msg_buffer. If request is not part of device discovery,
 * the request is added to the transcript hash.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param request_len Length of request to send.
 * @param dest_addr SMBus address of destination device.
 * @param dest_eid MCTP EID of destination device.
 * @param crypto_timeout Flag indicating whether to use the crypto timeout with device.
 * @param command Requested command to send out.
 *
 * @return 0 if successful or error code otherwise
 */
#ifdef ATTESTATION_SUPPORT_SPDM
static int attestation_requester_send_spdm_request_and_get_response (
	const struct attestation_requester *attestation, size_t request_len, uint8_t dest_addr,
	uint8_t dest_eid, bool crypto_timeout, uint8_t command)
{
	int status;

	if (!attestation->state->device_discovery) {
		status = attestation->secondary_hash->update (attestation->secondary_hash,
			attestation->state->msg_buffer + 1, request_len - 1);
		if (ROT_IS_ERROR (status)) {
			return status;
		}
	}

	return attestation_requester_send_request_and_get_response (attestation, request_len, dest_addr,
		dest_eid, crypto_timeout, command);
}

/**
 * Update current hash operation with a new block of data, then update transaction status.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param hash Hashing engine to utilize.
 * @param buffer Buffer with block of data to utilize.
 * @param buffer_len Length of buffer.
 *
 * @return 0 if completed successfully, or an error code
 */
static int attestation_requester_update_response_hash (
	const struct attestation_requester *attestation, struct hash_engine *hash, uint8_t *buffer,
	size_t buffer_len)
{
	int status;

	/* If performing device discovery, Get Measurements is not required to provide a signed response
	 * thus transcript hashing is not necessary. */
	if (!attestation->state->device_discovery) {
		status = hash->update (hash, buffer, buffer_len);
		if (status != 0) {
			attestation->state->request_status = ATTESTATION_REQUESTER_REQUEST_RSP_FAIL;
			return status;
		}
	}

	attestation->state->request_status = ATTESTATION_REQUESTER_REQUEST_SUCCESSFUL;

	return 0;
}
#endif

#if defined(ATTESTATION_SUPPORT_SPDM) || defined(ATTESTATION_SUPPORT_CERBERUS_CHALLENGE)
/**
 * Verify certificate chain received from device and if successful store alias key.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param eid EID of device that sent certificate chain.
 * @param active_cfm Active CFM to utilize.
 * @param component_type SHA256 digest of component type of device.
 *
 * @return 0 if completed successfully, or an error code
 */
static int attestation_requester_verify_and_load_leaf_key (
	const struct attestation_requester *attestation, uint8_t eid, struct cfm *active_cfm,
	const uint8_t *component_type)
{
	uint8_t digest[HASH_MAX_HASH_LEN];
	struct x509_ca_certs certs_chain;
	struct x509_certificate cert;
	struct cfm_root_ca_digests root_ca_digests;
	const struct der_cert *root_ca = riot_key_manager_get_root_ca (attestation->riot);
	uint8_t *leaf_key;
	size_t leaf_key_len;
	int leaf_key_type;
	size_t cert_chain_overhead = 0;
	size_t cert_offset = 0;
	size_t transcript_hash_len = hash_get_hash_len (attestation->state->transcript_hash_type);
	size_t cert_len;
	int status;

	if (attestation->state->protocol >= ATTESTATION_PROTOCOL_DMTF_SPDM_1_1) {
		cert_chain_overhead = sizeof (struct spdm_certificate_chain) + transcript_hash_len;
		cert_offset = cert_chain_overhead;
	}

	status = attestation->x509->init_ca_cert_store (attestation->x509, &certs_chain);
	if (status != 0) {
		goto release_cert_buffer;
	}

	status = asn1_get_der_item_len (&attestation->state->cert_buffer[cert_offset],
		attestation->state->cert_buffer_len - cert_offset);
	if (ROT_IS_ERROR (status)) {
		goto release_cert_store;
	}

	cert_len = (size_t) status;

	/*
	 *	1) If CFM has an alternate allowed root CA, make sure root CA provided by device matches
	 *	2) If CFM has no alternate root CA, and requester has no provisioned root CA, then just use
 	 *		device's root CA provided. The requester with no root CA will ultimately fail
 	 *		attestation but device's attestation can succeed, useful for testing.
	 *	3) If CFM has no alternate root CA, but requester has a provisioned root CA, use the
	 * 		requester's root CA then skip over root CA provided by device. */
	status = active_cfm->get_root_ca_digest (active_cfm, component_type, &root_ca_digests);
	if (status == 0) {
		status = hash_calculate (attestation->primary_hash, root_ca_digests.digests.hash_type,
			&attestation->state->cert_buffer[cert_offset], cert_len, digest, sizeof (digest));
		if (ROT_IS_ERROR (status)) {
			goto release_cert_store;
		}

		status = attestation_requester_verify_digest_in_allowable_list (attestation,
			&root_ca_digests.digests, digest, root_ca_digests.digests.hash_type);
		if (status != 0) {
			goto release_cert_store;
		}
	}
	else if (status != CFM_ROOT_CA_NOT_FOUND) {
		goto release_cert_store;
	}

	if ((status == 0) || (root_ca == NULL)) {
		status = attestation->x509->add_root_ca (attestation->x509, &certs_chain,
			&attestation->state->cert_buffer[cert_offset],
			attestation->state->cert_buffer_len - cert_offset);
		if (status != 0) {
			goto release_cert_store;
		}
	}
	else {
		status = attestation->x509->add_root_ca (attestation->x509, &certs_chain, root_ca->cert,
			root_ca->length);
		if (status != 0) {
			goto release_cert_store;
		}
	}

	cert_offset += cert_len;
	status = asn1_get_der_item_len (&attestation->state->cert_buffer[cert_offset],
		attestation->state->cert_buffer_len - cert_offset);
	if (ROT_IS_ERROR (status)) {
		goto release_cert_store;
	}

	cert_len = (size_t) status;

	while ((cert_offset < attestation->state->cert_buffer_len) &&
		((attestation->state->cert_buffer_len - cert_offset) > cert_len)) {
		status = attestation->x509->add_intermediate_ca (attestation->x509, &certs_chain,
			&attestation->state->cert_buffer[cert_offset],
			attestation->state->cert_buffer_len - cert_offset);
		if (status != 0) {
			goto release_cert_store;
		}

		cert_offset += cert_len;
		status = asn1_get_der_item_len (&attestation->state->cert_buffer[cert_offset],
			attestation->state->cert_buffer_len - cert_offset);
		if (ROT_IS_ERROR (status)) {
			goto release_cert_store;
		}

		cert_len = (size_t) status;
	}

	status = attestation->x509->load_certificate (attestation->x509, &cert,
		&attestation->state->cert_buffer[cert_offset],
		attestation->state->cert_buffer_len - cert_offset);
	if (status != 0) {
		goto release_cert_store;
	}

	status = attestation->x509->authenticate (attestation->x509, &cert, &certs_chain);
	if (status != 0) {
		goto release_leaf_cert;
	}

	status = hash_calculate (attestation->primary_hash, attestation->state->transcript_hash_type,
		&attestation->state->cert_buffer[cert_chain_overhead],
		attestation->state->cert_buffer_len - cert_chain_overhead, digest, sizeof (digest));
	if (ROT_IS_ERROR (status)) {
		goto release_leaf_cert;
	}

	status = device_manager_compare_cert_chain_digest (attestation->device_mgr, eid, digest,
		transcript_hash_len);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_CERT_CHAIN_COMPUTED_DIGEST_MISMATCH,
			(eid << 8) | attestation->state->slot_num, status);

		goto release_leaf_cert;
	}

	leaf_key_type = attestation->x509->get_public_key_type (attestation->x509, &cert);
	if (ROT_IS_ERROR (leaf_key_type)) {
		status = leaf_key_type;
		goto release_leaf_cert;
	}

	status = attestation->x509->get_public_key (attestation->x509, &cert, &leaf_key, &leaf_key_len);
	if (status != 0) {
		goto release_leaf_cert;
	}

	status = device_manager_update_alias_key (attestation->device_mgr, eid, leaf_key, leaf_key_len,
		leaf_key_type);
	platform_free (leaf_key);

release_leaf_cert:
	attestation->x509->release_certificate (attestation->x509, &cert);

release_cert_store:
	attestation->x509->release_ca_cert_store (attestation->x509, &certs_chain);

release_cert_buffer:
	platform_free (attestation->state->cert_buffer);
	attestation->state->cert_buffer_len = 0;

	return status;
}

/**
 * Finalize current hash operation, then verify provided signature using cached alias key of
 * target device using provided EID.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param hash Hashing engine to utilize.
 * @param eid EID of target device.
 * @param signature Buffer with signature sent by target device to verify.
 * @param signature_len Length of signature.
 * @param spdm_context Context string to utilize. Can be set to NULL if not used.
 */
static void attestation_requester_verify_signature (const struct attestation_requester *attestation,
	struct hash_engine *hash, uint8_t eid, uint8_t *signature, size_t signature_len,
	char *spdm_context)
{
	uint8_t digest[HASH_MAX_HASH_LEN];
	const struct device_manager_key *alias_key;
	size_t transcript_hash_len = hash_get_hash_len (attestation->state->transcript_hash_type);
	int status;

	status = hash->finish (hash, digest, sizeof (digest));
	if (status != 0) {
		goto fail;
	}

	attestation->state->hash_finish = true;

#ifdef ATTESTATION_SUPPORT_SPDM
	if (attestation->state->protocol >= ATTESTATION_PROTOCOL_DMTF_SPDM_1_2) {
		status = spdm_format_signature_digest (hash, attestation->state->transcript_hash_type,
			attestation->state->protocol, spdm_context, digest);
		if (status != 0) {
			goto fail;
		}
	}
#endif

	alias_key = device_manager_get_alias_key (attestation->device_mgr, eid);
	if (alias_key == NULL) {
		status = ATTESTATION_ALIAS_KEY_LOAD_FAIL;
		goto fail;
	}

	if (alias_key->key_type == X509_PUBLIC_KEY_ECC) {
		struct ecc_public_key ecc_key;

		status = attestation->ecc->init_public_key (attestation->ecc, alias_key->key,
			alias_key->key_len, &ecc_key);
		if (status != 0) {
			goto fail;
		}

		status = attestation->ecc->verify (attestation->ecc, &ecc_key, digest, transcript_hash_len,
			signature, signature_len);

		attestation->ecc->release_key_pair (attestation->ecc, NULL, &ecc_key);
	}
#ifdef ATTESTATION_SUPPORT_RSA_CHALLENGE
	else if ((alias_key->key_type == X509_PUBLIC_KEY_RSA) && (attestation->rsa != NULL)) {
		struct rsa_public_key rsa_key;

		status = attestation->rsa->init_public_key (attestation->rsa, &rsa_key, alias_key->key,
			alias_key->key_len);
		if (status != 0) {
			goto fail;
		}

		status = attestation->rsa->sig_verify (attestation->rsa, &rsa_key, signature, signature_len,
			digest, transcript_hash_len);
	}
#endif
	else {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_ALIAS_KEY_TYPE_UNSUPPORTED, eid, alias_key->key_type);

		goto fail;
	}

	if (status == 0) {
		attestation->state->request_status = ATTESTATION_REQUESTER_REQUEST_SUCCESSFUL;

		return;
	}

fail:
	attestation->state->request_status = ATTESTATION_REQUESTER_REQUEST_RSP_FAIL;
}
#endif

#ifdef ATTESTATION_SUPPORT_SPDM
/**
 * SPDM get version response observer function. The Get Version request/response interaction
 * determines the highest SPDM version both devices support, and then subsequent transactions with
 * the device uses the determined version.
 */
void attestation_requester_on_spdm_get_version_response (
	struct spdm_protocol_observer *observer, const struct cmd_interface_msg *response)
{
	struct attestation_requester *attestation =
		TO_DERIVED_TYPE (observer, struct attestation_requester, spdm_rsp_observer);
	struct spdm_get_version_response *rsp = (struct spdm_get_version_response*) response->data;
	struct spdm_version_num_entry *version_table = spdm_get_version_resp_version_table (rsp);
	uint8_t minor_version = SPDM_MIN_MINOR_VERSION;
	bool found = false;
	int i_version;

	if (attestation_requester_check_spdm_unexpected_rsp (attestation, SPDM_REQUEST_GET_VERSION)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_RESPONSE_RECEIVED, response->source_eid,
			((attestation->state->protocol << 24) | (attestation->state->requested_command << 16) |
				(ATTESTATION_PROTOCOL_DMTF_SPDM_1_1 << 8) |	SPDM_REQUEST_GET_VERSION));
		goto fail;
	}

	for (i_version = 0; i_version < rsp->version_num_entry_count; ++i_version, ++version_table) {
		if ((version_table->major_version != SPDM_MAJOR_VERSION) || (version_table->alpha > 0)) {
			continue;
		}

		if ((version_table->minor_version >= minor_version) &&
			(version_table->minor_version <= SPDM_MAX_MINOR_VERSION)) {
			minor_version = version_table->minor_version;
			found = true;
		}
	}

	if (found) {
		attestation->state->protocol = (enum attestation_protocol) minor_version;

		attestation_requester_update_response_hash (attestation, attestation->secondary_hash,
			spdm_get_spdm_rsp_payload (rsp), spdm_get_version_resp_length (rsp) - 1);

		return;
	}

	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
		ATTESTATION_LOGGING_DEVICE_NOT_INTEROPERABLE, response->source_eid, 0);

fail:
	attestation->state->request_status = ATTESTATION_REQUESTER_REQUEST_RSP_FAIL;
}

/**
 * SPDM get capabilities response observer function. The Get Capabilities request/response
 * interaction allows both devices to know the level of support for non-required SPDM commands in
 * the other device, as well as timeout and message size capabilities.
 */
void attestation_requester_on_spdm_get_capabilities_response (
	struct spdm_protocol_observer *observer, const struct cmd_interface_msg *response)
{
	struct attestation_requester *attestation =
		TO_DERIVED_TYPE (observer, struct attestation_requester, spdm_rsp_observer);
	struct spdm_get_capabilities *rsp = (struct spdm_get_capabilities*) response->data;
	struct device_manager_full_capabilities capabilities;
	size_t capabilities_len;
	uint8_t ct_exponent;
	int device_num;
	int status;

	if (attestation_requester_check_spdm_unexpected_rsp (attestation,
		SPDM_REQUEST_GET_CAPABILITIES)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_RESPONSE_RECEIVED, response->source_eid,
			((attestation->state->protocol << 24) | (attestation->state->requested_command << 16) |
				(ATTESTATION_PROTOCOL_DMTF_SPDM_1_1 << 8) |	SPDM_REQUEST_GET_CAPABILITIES));
		goto fail;
	}

	/* Device is assumed to either support, or eventually support after a FW update, minimum
	 * capabilities needed to complete attestation since it is included in CFM. If device does not,
	 * attestation will fail but will continue to retry until an expected FW adds required support. */

	if (rsp->base_capabilities.flags.cert_cap == 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_GET_CERT_NOT_SUPPORTED, response->source_eid,
			*((uint32_t*) &rsp->base_capabilities.flags));
		goto fail;
	}

	if (rsp->base_capabilities.flags.meas_cap != SPDM_MEASUREMENT_RSP_CAP_MEASUREMENTS_WITH_SIG) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_MEASUREMENT_CAP_NOT_SUPPORTED, response->source_eid,
			*((uint32_t*) &rsp->base_capabilities.flags));
		goto fail;
	}

	attestation->state->challenge_supported = rsp->base_capabilities.flags.chal_cap;

	capabilities_len =
		(attestation->state->protocol >= ATTESTATION_PROTOCOL_DMTF_SPDM_1_2) ?
		sizeof (struct spdm_get_capabilities) : sizeof (struct spdm_get_capabilities_1_1);

	if (!attestation->state->device_discovery) {
		device_num = device_manager_get_device_num (attestation->device_mgr, response->source_eid);
		if (ROT_IS_ERROR (device_num)) {
			goto fail;
		}

		status = device_manager_get_device_capabilities (attestation->device_mgr, device_num,
			&capabilities);
		if (status != 0) {
			goto fail;
		}

		/* Limit maximum cryptographic timeout period of responder to prevent overflows. This
		 * assumes 25.5 seconds is plenty of time, so if a device responds with a timeout longer
		 * than that, we will fail attestation at 25.5s even if device thinks it has more time to
		 * respond. */
		ct_exponent = (rsp->base_capabilities.ct_exponent > 24) ? 24 :
			rsp->base_capabilities.ct_exponent;

		capabilities.max_timeout = device_manager_set_timeout_ms (SPDM_MAX_RESPONSE_TIMEOUT_MS);
		capabilities.max_sig = device_manager_set_crypto_timeout_ms (
			spdm_capabilities_rsp_ct_to_ms (ct_exponent));

		if (rsp->base_capabilities.header.spdm_minor_version > 1) {
			capabilities.request.max_message_size = rsp->data_transfer_size;
		}

		status = device_manager_update_device_capabilities (attestation->device_mgr, device_num,
			&capabilities);
		if (status != 0) {
			goto fail;
		}
	}

	attestation_requester_update_response_hash (attestation, attestation->secondary_hash,
		spdm_get_spdm_rsp_payload (rsp), capabilities_len - 1);

	return;

fail:
	attestation->state->request_status = ATTESTATION_REQUESTER_REQUEST_RSP_FAIL;
}

/**
 * SPDM negotiate algorithms response observer function. The Negotiate Algorithms request/response
 * interaction allows both devices to select common hashing and asymmetric cryptographic algorithms
 * to utilize in subsequent SPDM interactions.
 */
void attestation_requester_on_spdm_negotiate_algorithms_response (
	struct spdm_protocol_observer *observer, const struct cmd_interface_msg *response)
{
	struct attestation_requester *attestation =
		TO_DERIVED_TYPE (observer, struct attestation_requester, spdm_rsp_observer);
	struct spdm_negotiate_algorithms_response *rsp =
		(struct spdm_negotiate_algorithms_response*) response->data;

	if (attestation_requester_check_spdm_unexpected_rsp (attestation,
		SPDM_REQUEST_NEGOTIATE_ALGORITHMS)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_RESPONSE_RECEIVED, response->source_eid,
			((attestation->state->protocol << 24) | (attestation->state->requested_command << 16) |
				(ATTESTATION_PROTOCOL_DMTF_SPDM_1_1 << 8) |	SPDM_REQUEST_NEGOTIATE_ALGORITHMS));
		goto fail;
	}

	// Currently, only SPDM measurement blocks following the DMTF format are supported
	if (rsp->measurement_specification != SPDM_MEASUREMENT_SPEC_DMTF) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_MEASUREMENT_SPEC_UNSUPPORTED, response->source_eid,
			rsp->measurement_specification);
		goto fail;
	}

	if ((rsp->base_asym_sel != SPDM_TPM_ALG_ECDSA_ECC_NIST_P256)
#if ECC_MAX_KEY_LENGTH >= 384
		&& (rsp->base_asym_sel != SPDM_TPM_ALG_ECDSA_ECC_NIST_P384)
#endif
#if ECC_MAX_KEY_LENGTH >= 521
		&& (rsp->base_asym_sel != SPDM_TPM_ALG_ECDSA_ECC_NIST_P521)
#endif
		) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_BASE_ASYM_KEY_SIG_ALG_UNSUPPORTED, response->source_eid,
			rsp->base_asym_sel);
		goto fail;
	}

	if ((rsp->base_hash_sel != SPDM_TPM_ALG_SHA_256)
#ifdef HASH_ENABLE_SHA384
		&& (rsp->base_hash_sel != SPDM_TPM_ALG_SHA_384)
#endif
#ifdef HASH_ENABLE_SHA512
		&& (rsp->base_hash_sel != SPDM_TPM_ALG_SHA_512)
#endif
		) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_HASHING_ALGORITHM_UNSUPPORTED, response->source_eid,
			rsp->base_hash_sel);
		goto fail;
	}

	if (((rsp->base_hash_sel == SPDM_TPM_ALG_SHA_256) &&
			(attestation->state->transcript_hash_type != HASH_TYPE_SHA256)) ||
		((rsp->base_hash_sel == SPDM_TPM_ALG_SHA_384) &&
			(attestation->state->transcript_hash_type != HASH_TYPE_SHA384)) ||
		((rsp->base_hash_sel == SPDM_TPM_ALG_SHA_512) &&
			(attestation->state->transcript_hash_type != HASH_TYPE_SHA512))) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_HASH_ALGO_IN_RSP, response->source_eid,
			rsp->base_hash_sel);
		goto fail;
	}

	if ((rsp->measurement_hash_algo != SPDM_TPM_ALG_SHA_256) &&
		(rsp->measurement_hash_algo != SPDM_TPM_ALG_SHA_384) &&
		(rsp->measurement_hash_algo != SPDM_TPM_ALG_SHA_512)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_HASHING_MEAS_ALGORITHM_UNSUPPORTED, response->source_eid,
			rsp->measurement_hash_algo);
		goto fail;
	}

	if (((rsp->measurement_hash_algo == SPDM_TPM_ALG_SHA_256) &&
			(attestation->state->measurement_hash_type != HASH_TYPE_SHA256)) ||
		((rsp->measurement_hash_algo == SPDM_TPM_ALG_SHA_384) &&
			(attestation->state->measurement_hash_type != HASH_TYPE_SHA384)) ||
		((rsp->measurement_hash_algo == SPDM_TPM_ALG_SHA_512) &&
			(attestation->state->measurement_hash_type != HASH_TYPE_SHA512))) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_MEAS_HASH_ALGO_IN_RSP, response->source_eid,
			rsp->measurement_hash_algo);
		goto fail;
	}

	attestation_requester_update_response_hash (attestation, attestation->secondary_hash,
		spdm_get_spdm_rsp_payload (rsp), rsp->length);

	return;

fail:
	attestation->state->request_status = ATTESTATION_REQUESTER_REQUEST_RSP_FAIL;
}

/**
 * SPDM get digests response observer function. The Get Digests request/response interaction allows
 * the requester to retrieve certificate chain digests from the responder. The digests will then be
 * compared to the requesters certificate chain cache for the device being attested, and in case of
 * a mismatch, the requester will fetch new certificate chain from device.
 */
void attestation_requester_on_spdm_get_digests_response (
	struct spdm_protocol_observer *observer, const struct cmd_interface_msg *response)
{
	struct attestation_requester *attestation =
		TO_DERIVED_TYPE (observer, struct attestation_requester, spdm_rsp_observer);
	struct spdm_get_digests_response *rsp = (struct spdm_get_digests_response*) response->data;
	size_t transcript_hash_len;
	size_t rsp_len;
	uint8_t *digest;
	int status;

	if (attestation_requester_check_spdm_unexpected_rsp (attestation, SPDM_REQUEST_GET_DIGESTS)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_RESPONSE_RECEIVED, response->source_eid,
			((attestation->state->protocol << 24) | (attestation->state->requested_command << 16) |
				(ATTESTATION_PROTOCOL_DMTF_SPDM_1_1 << 8) |	SPDM_REQUEST_GET_DIGESTS));
		goto fail;
	}

	transcript_hash_len = hash_get_hash_len (attestation->state->transcript_hash_type);

	rsp_len = spdm_get_digests_resp_length (rsp, transcript_hash_len);
	digest = spdm_get_digests_resp_digest (rsp, attestation->state->slot_num, transcript_hash_len);

	if (response->length != rsp_len) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_RSP_LEN,
			(response->source_eid << 8) | SPDM_RESPONSE_GET_DIGESTS,
			((uint16_t) rsp_len) << 16 | ((uint16_t) response->length));
		goto fail;
	};

	if ((rsp->slot_mask & (1 << attestation->state->slot_num)) == 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_SLOT_NUMBER_EMPTY, response->source_eid,
			(attestation->state->slot_num << 8) | rsp->slot_mask);
		goto fail;
	}
	else {
		attestation->state->cached_cert_valid = false;

		status = device_manager_compare_cert_chain_digest (attestation->device_mgr,
			response->source_eid, digest, transcript_hash_len);
		if ((status == DEVICE_MGR_DIGEST_MISMATCH) || (status == DEVICE_MGR_DIGEST_LEN_MISMATCH)) {
			status = device_manager_update_cert_chain_digest (attestation->device_mgr,
				response->source_eid, attestation->state->slot_num, digest, transcript_hash_len);
			if (status != 0) {
				goto fail;
			}
		}
		else if (status == 0) {
			attestation->state->cached_cert_valid = true;
		}
		else {
			goto fail;
		}
	}

	attestation_requester_update_response_hash (attestation, attestation->secondary_hash,
		spdm_get_spdm_rsp_payload (rsp), rsp_len - 1);

	return;

fail:
	attestation->state->request_status = ATTESTATION_REQUESTER_REQUEST_RSP_FAIL;
}

/**
 * SPDM get certificate response observer function. The Get Certificate request/response interaction
 * is used for the requester to retrieve certificate chain to be used for attestation from
 * responder.
 */
void attestation_requester_on_spdm_get_certificate_response (
	struct spdm_protocol_observer *observer, const struct cmd_interface_msg *response)
{
	struct attestation_requester *attestation =
		TO_DERIVED_TYPE (observer, struct attestation_requester, spdm_rsp_observer);
	struct spdm_get_certificate_response *rsp =
		(struct spdm_get_certificate_response*) response->data;
	int status;

	if (attestation_requester_check_spdm_unexpected_rsp (attestation,
		SPDM_REQUEST_GET_CERTIFICATE)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_RESPONSE_RECEIVED, response->source_eid,
			((attestation->state->protocol << 24) | (attestation->state->requested_command << 16) |
				(ATTESTATION_PROTOCOL_DMTF_SPDM_1_1 << 8) |	SPDM_REQUEST_GET_CERTIFICATE));
		goto fail;
	}

	if (rsp->slot_num != attestation->state->slot_num) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_SLOT_NUM_IN_RSP, response->source_eid,
			(attestation->state->slot_num << 8) | rsp->slot_num);

		goto fail;
	}
	else {
		/* If first response in a Get Certificate transaction, allocate buffer to hold entire
		 * certificate chain */
		if (attestation->state->cert_buffer_len == 0) {
			attestation->state->cert_total_len = rsp->portion_len + rsp->remainder_len;
			attestation->state->cert_buffer = platform_malloc (attestation->state->cert_total_len);
			if (attestation->state->cert_buffer == NULL) {
				goto fail;
			}
		}

		if ((rsp->portion_len + attestation->state->cert_buffer_len) >
			attestation->state->cert_total_len) {
			if (attestation->state->cert_buffer != NULL) {
				platform_free (attestation->state->cert_buffer);
			}

			goto fail;
		}

		memcpy (
			&attestation->state->cert_buffer[attestation->state->cert_buffer_len],
			spdm_get_certificate_resp_cert_chain (rsp), rsp->portion_len);
		attestation->state->cert_buffer_len += rsp->portion_len;

		status = attestation_requester_update_response_hash (attestation,
			attestation->secondary_hash, spdm_get_spdm_rsp_payload (rsp),
			spdm_get_certificate_resp_length (rsp) - 1);
		if (status != 0) {
			platform_free (attestation->state->cert_buffer);
			attestation->state->cert_buffer_len = 0;
		}

		return;
	}

fail:
	attestation->state->request_status = ATTESTATION_REQUESTER_REQUEST_RSP_FAIL;
}

/**
 * SPDM challenge response observer function. The Challenge request/response interaction allows the
 * requester to authenticate the responder through the challenge-response protocol by validating the
 * transcript signature and comparing the measurement summary hash to CFM contents.
 */
void attestation_requester_on_spdm_challenge_response (
	struct spdm_protocol_observer *observer, const struct cmd_interface_msg *response)
{
	struct attestation_requester *attestation =
		TO_DERIVED_TYPE (observer, struct attestation_requester, spdm_rsp_observer);
	struct spdm_challenge_response *rsp = (struct spdm_challenge_response*) response->data;
	size_t transcript_hash_len = hash_get_hash_len (attestation->state->transcript_hash_type);
	size_t measurement_hash_len = hash_get_hash_len (attestation->state->measurement_hash_type);
	int status;

	if (attestation_requester_check_spdm_unexpected_rsp (attestation, SPDM_REQUEST_CHALLENGE)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_RESPONSE_RECEIVED, response->source_eid,
			((attestation->state->protocol << 24) | (attestation->state->requested_command << 16) |
				(ATTESTATION_PROTOCOL_DMTF_SPDM_1_1 << 8) |	SPDM_REQUEST_CHALLENGE));
		goto fail;
	}

	if (rsp->slot_num != attestation->state->slot_num) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_SLOT_NUM_IN_RSP, response->source_eid,
			(attestation->state->slot_num << 8) | rsp->slot_num);
		goto fail;
	}

	if (rsp->basic_mutual_auth_req) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_TARGET_REQ_UNSUPPORTED_MUTUAL_AUTH, response->source_eid, 0);
		goto fail;
	}

	if ((rsp->slot_mask & (1 << attestation->state->slot_num)) == 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_SLOT_NUMBER_EMPTY, response->source_eid,
			(attestation->state->slot_num << 8) | rsp->slot_mask);
		goto fail;
	}

	if (response->length <=
			spdm_get_challenge_resp_length (rsp, transcript_hash_len, measurement_hash_len)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_RSP_LEN,
			(response->source_eid << 8) | SPDM_RESPONSE_CHALLENGE,
			(((uint16_t) (spdm_get_challenge_resp_length (rsp, transcript_hash_len,
				measurement_hash_len))) << 16) |
			((uint16_t) response->length));
		goto fail;
	}

	status = device_manager_compare_cert_chain_digest (attestation->device_mgr,
		response->source_eid, spdm_get_challenge_resp_cert_chain_hash (rsp), transcript_hash_len);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_CERT_CHAIN_DIGEST_MISMATCH, response->source_eid,
			rsp->slot_num);
		goto fail;
	}

	status = attestation_requester_update_response_hash (attestation, attestation->secondary_hash,
		spdm_get_spdm_rsp_payload (rsp),
		spdm_get_challenge_resp_length (rsp, transcript_hash_len, measurement_hash_len) - 1);
	if (status == 0) {
		attestation_requester_verify_signature (attestation, attestation->secondary_hash,
			response->source_eid,
			spdm_get_challenge_resp_signature (rsp, transcript_hash_len, measurement_hash_len),
			spdm_get_challenge_resp_signature_length (rsp, transcript_hash_len, response->length,
				measurement_hash_len),
			SPDM_CHALLENGE_SIGNATURE_CONTEXT_STR);

		if (attestation->state->request_status != ATTESTATION_REQUESTER_REQUEST_RSP_FAIL) {
			// msg_buffer is sized to hold maximum response lengths
			memcpy (attestation->state->msg_buffer,
				spdm_get_challenge_resp_measurement_summary_hash (rsp, transcript_hash_len),
				measurement_hash_len);
			attestation->state->msg_buffer_len = measurement_hash_len;
		}
	}

	return;

fail:
	attestation->state->request_status = ATTESTATION_REQUESTER_REQUEST_RSP_FAIL;
}

/**
 * SPDM get measurements response observer function. The Get Measurements request/response
 * interaction allows the requester to retrieve measurement blocks from the responder, then
 * authenticate the responder through validating the transcript signature and comparing the
 * measurement blocks to CFM contents.
 */
void attestation_requester_on_spdm_get_measurements_response (
	struct spdm_protocol_observer *observer, const struct cmd_interface_msg *response)
{
	struct attestation_requester *attestation =
		TO_DERIVED_TYPE (observer, struct attestation_requester, spdm_rsp_observer);
	struct spdm_get_measurements_response *rsp =
		(struct spdm_get_measurements_response*) response->data;
	struct spdm_measurements_block_header *block;
	size_t measurement_hash_len = hash_get_hash_len (attestation->state->measurement_hash_type);
	size_t offset;
	uint8_t number_of_blocks = 1;
	uint8_t i_block;
	int status;

	if (attestation_requester_check_spdm_unexpected_rsp (attestation,
		SPDM_REQUEST_GET_MEASUREMENTS)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_RESPONSE_RECEIVED, response->source_eid,
			((attestation->state->protocol << 24) | (attestation->state->requested_command << 16) |
				(ATTESTATION_PROTOCOL_DMTF_SPDM_1_1 << 8) |	SPDM_REQUEST_GET_MEASUREMENTS));
		goto fail;
	}

	// If Get Measurement request was not for all blocks, then only one block should be in response
	if ((attestation->state->measurement_operation_requested !=
			SPDM_MEASUREMENT_OPERATION_GET_ALL_BLOCKS) &&
		!attestation->state->device_discovery && (rsp->number_of_blocks != 1)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_NUM_MEASUREMENT_BLOCKS, response->source_eid,
			(1 << 8) | rsp->number_of_blocks);
		goto fail;
	}

	if (!attestation->state->device_discovery) {
		number_of_blocks = rsp->number_of_blocks;

		if (rsp->slot_id != attestation->state->slot_num) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
				ATTESTATION_LOGGING_UNEXPECTED_SLOT_NUM_IN_RSP, response->source_eid,
				(attestation->state->slot_num << 8) | rsp->slot_id);
			goto fail;
		}

		status = attestation_requester_update_response_hash (attestation,
			attestation->secondary_hash, spdm_get_spdm_rsp_payload (rsp),
			spdm_get_measurements_resp_length (rsp) - 1);
		if (status != 0) {
			goto fail;
		}

		attestation_requester_verify_signature (attestation, attestation->secondary_hash,
			response->source_eid, spdm_get_measurements_resp_signature (rsp),
			spdm_get_measurements_resp_signature_length (rsp, response->length),
			SPDM_GET_MEASUREMENTS_SIGNATURE_CONTEXT_STR);
		if (attestation->state->request_status == ATTESTATION_REQUESTER_REQUEST_RSP_FAIL) {
			return;
		}
	}
	else {
		attestation->state->request_status = ATTESTATION_REQUESTER_REQUEST_SUCCESSFUL;

		if (attestation->state->measurement_operation_requested ==
				SPDM_MEASUREMENT_OPERATION_GET_NUM_BLOCKS) {
			attestation->state->msg_buffer_len = 1;
			attestation->state->msg_buffer[0] = rsp->num_measurement_indices;

			return;
		}
	}

	attestation->state->msg_buffer_len = 0;

	offset = sizeof (struct spdm_get_measurements_response);

	for (i_block = 0; i_block < number_of_blocks; ++i_block) {
		block = (struct spdm_measurements_block_header*) &response->data[offset];
		offset += sizeof (struct spdm_measurements_block_header);

		// If a specific block was requested, make sure response only includes that block
		if ((attestation->state->measurement_operation_requested !=
				SPDM_MEASUREMENT_OPERATION_GET_ALL_BLOCKS) &&
			(block->index != attestation->state->measurement_operation_requested)) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
				ATTESTATION_LOGGING_UNEXPECTED_NUM_MEASUREMENT_BLOCKS, response->source_eid,
				(1 << 16) | (attestation->state->measurement_operation_requested << 8) |
					block->index);
			goto fail;
		}

		// If block was requested in digest form and response was in raw form, hash response
		if (!attestation->state->raw_bitstream_requested &&	block->dmtf.raw_bit_stream) {
			if (attestation->state->protocol >= ATTESTATION_PROTOCOL_DMTF_SPDM_1_2) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_WARNING, DEBUG_LOG_COMPONENT_ATTESTATION,
					ATTESTATION_LOGGING_UNEXPECTED_MEASUREMENT_BLOCK_RAW, response->source_eid,
					(attestation->state->measurement_operation_requested << 8) | block->index);
			}

			status = hash_calculate (attestation->primary_hash,
				attestation->state->measurement_hash_type, &response->data[offset],
				block->dmtf.measurement_size,
				&attestation->state->msg_buffer[attestation->state->msg_buffer_len],
				sizeof (attestation->state->msg_buffer) - attestation->state->msg_buffer_len);
			if (ROT_IS_ERROR (status)) {
				goto fail;
			}

			attestation->state->msg_buffer_len += measurement_hash_len;
		}
		// If block was requested in raw form and response was in digest form, fail
		else if (attestation->state->raw_bitstream_requested && !block->dmtf.raw_bit_stream) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
				ATTESTATION_LOGGING_UNEXPECTED_MEASUREMENT_BLOCK_DIGEST,
				response->source_eid, block->index);
			goto fail;
		}
		else {
			if ((block->dmtf.measurement_size + attestation->state->msg_buffer_len) >
				sizeof (attestation->state->msg_buffer)) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
					ATTESTATION_LOGGING_MEASUREMENT_DATA_TOO_LARGE,
					(response->source_eid << 8) | block->index,
					block->dmtf.measurement_size + attestation->state->msg_buffer_len);
				goto fail;
			}

			memcpy (&attestation->state->msg_buffer[attestation->state->msg_buffer_len],
				&response->data[offset], block->dmtf.measurement_size);
			attestation->state->msg_buffer_len += block->dmtf.measurement_size;
		}

		offset += block->dmtf.measurement_size;
	}

	return;

fail:
	attestation->state->request_status = ATTESTATION_REQUESTER_REQUEST_RSP_FAIL;
}

/**
 * SPDM ResponseNotReady error observer function. If original request command code allows
 * ResponseNotReady, wait for RDT duration then issue RESPOND_IF_READY request.
 */
void attestation_requester_on_spdm_response_not_ready (
	struct spdm_protocol_observer *observer, const struct cmd_interface_msg *response)
{
	struct attestation_requester *attestation =
		TO_DERIVED_TYPE (observer, struct attestation_requester, spdm_rsp_observer);
	struct spdm_error_response *rsp = (struct spdm_error_response*) response->data;
	struct spdm_error_response_not_ready *rsp_not_ready =
		(struct spdm_error_response_not_ready*) spdm_get_spdm_error_rsp_optional_data (rsp);
	uint8_t rdt_exponent;

	if (attestation->state->protocol < ATTESTATION_PROTOCOL_DMTF_SPDM_1_1) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_RESPONSE_RECEIVED, response->source_eid,
			((attestation->state->protocol << 24) | (attestation->state->requested_command << 16) |
				(ATTESTATION_PROTOCOL_DMTF_SPDM_1_1 << 8) |	SPDM_RESPONSE_ERROR));
		goto fail;
	}

	// DSP0274 SPDM spec indicates these commands cannot respond with ResponseNotReady
	if ((attestation->state->requested_command == SPDM_REQUEST_GET_VERSION) ||
		(attestation->state->requested_command == SPDM_REQUEST_GET_CAPABILITIES) ||
		(attestation->state->requested_command == SPDM_REQUEST_NEGOTIATE_ALGORITHMS)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_ILLEGAL_RSP_NOT_READY, response->source_eid,
			attestation->state->requested_command);
		goto fail;
	}

	if (rsp_not_ready->request_code != attestation->state->requested_command) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_RQ_CODE_IN_RSP, response->source_eid,
			(attestation->state->requested_command << 8) | rsp_not_ready->request_code);
		goto fail;
	}

	// TODO: Get maximum permitted sleep duration from PCD

	/* If the requested sleep duration is too large to store, then cap it at the maximum sleep
	 * duration that can fit in sleep_duration_ms, which is roughly 25 days. If for some reason
	 * responder requests a duration larger than that, then responder can respond to the
	 * RESPOND_IF_READY request with another ResponseNotReady. */
	if (rsp_not_ready->rdt_exponent > 41) {
		rdt_exponent = 41;
	}
	else {
		rdt_exponent = rsp_not_ready->rdt_exponent;
	}

	attestation->state->sleep_duration_ms = 1 + ((1 << rdt_exponent) / 1000);
	attestation->state->respond_if_ready_token = rsp_not_ready->token;
	attestation->state->request_status = ATTESTATION_REQUESTER_REQUEST_SUCCESSFUL;

	return;

fail:
	attestation->state->request_status = ATTESTATION_REQUESTER_REQUEST_RSP_FAIL;
}
#endif

#ifdef ATTESTATION_SUPPORT_CERBERUS_CHALLENGE
/**
 * Cerberus Challenge get digest response observer function. The Get Digests request/response
 * interaction allows the requester to retrieve certificate chain digests from the responder. The
 * digests will then be compared to the requesters certificate chain cache for the device being
 * attested, and in case of a mismatch, the requester will fetch new certificate chain from device.
 */
void attestation_requester_on_cerberus_get_digest_response (
	struct cerberus_protocol_observer *observer, const struct cmd_interface_msg *response)
{
	struct attestation_requester *attestation =
		TO_DERIVED_TYPE (observer, struct attestation_requester, cerberus_rsp_observer);
	struct cerberus_protocol_get_certificate_digest_response *rsp =
		(struct cerberus_protocol_get_certificate_digest_response*) response->data;
	uint8_t digest[SHA256_HASH_LENGTH];
	int status;

	if (attestation_requester_check_cerberus_unexpected_rsp (attestation,
		CERBERUS_PROTOCOL_GET_DIGEST)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_RESPONSE_RECEIVED, response->source_eid,
			((attestation->state->protocol << 24) | (attestation->state->requested_command << 16) |
				(ATTESTATION_PROTOCOL_CERBERUS << 8) | CERBERUS_PROTOCOL_GET_DIGEST));
		goto fail;
	}

	status = attestation->primary_hash->calculate_sha256 (attestation->primary_hash,
		cerberus_protocol_certificate_digests (rsp), (SHA256_HASH_LENGTH * rsp->num_digests),
		digest, sizeof (digest));
	if (status != 0) {
		goto fail;
	}

	attestation->state->cached_cert_valid = false;

	status = device_manager_compare_cert_chain_digest (attestation->device_mgr,
		response->source_eid, digest, SHA256_HASH_LENGTH);
	if ((status == DEVICE_MGR_DIGEST_MISMATCH) || (status == DEVICE_MGR_DIGEST_LEN_MISMATCH)) {
		status = device_manager_update_cert_chain_digest (attestation->device_mgr,
			response->source_eid, attestation->state->slot_num, digest,	SHA256_HASH_LENGTH);
		if (status == 0) {
			attestation->state->request_status = ATTESTATION_REQUESTER_REQUEST_SUCCESSFUL;
			attestation->state->num_certs = rsp->num_digests;
			return;
		}
		else {
			goto fail;
		}
	}
	else if (status == 0) {
		attestation->state->request_status = ATTESTATION_REQUESTER_REQUEST_SUCCESSFUL;
		attestation->state->cached_cert_valid = true;

		return;
	}

fail:
	attestation->state->request_status = ATTESTATION_REQUESTER_REQUEST_RSP_FAIL;
}

/**
 * Cerberus Challenge get certificate response observer function. The Get Certificate
 * request/response interaction is used for the requester to retrieve certificate chain to be used
 * for attestation from responder.
 */
void attestation_requester_on_cerberus_get_certificate_response (
	struct cerberus_protocol_observer *observer, const struct cmd_interface_msg *response)
{
	struct attestation_requester *attestation =
		TO_DERIVED_TYPE (observer, struct attestation_requester, cerberus_rsp_observer);
	struct cerberus_protocol_get_certificate_response *rsp =
		(struct cerberus_protocol_get_certificate_response*) response->data;
	size_t cert_portion_len;

	if (attestation_requester_check_cerberus_unexpected_rsp (attestation,
		CERBERUS_PROTOCOL_GET_CERTIFICATE)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_RESPONSE_RECEIVED, response->source_eid,
			((attestation->state->protocol << 24) | (attestation->state->requested_command << 16) |
				(ATTESTATION_PROTOCOL_CERBERUS << 8) | CERBERUS_PROTOCOL_GET_CERTIFICATE));
		goto fail;
	}

	if (rsp->slot_num != attestation->state->slot_num) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_SLOT_NUM_IN_RSP, response->source_eid,
			(attestation->state->slot_num << 8) | rsp->slot_num);
		goto fail;
	}
	else {
		if (attestation->state->cert_buffer_len == 0) {
			attestation->state->cert_buffer =
				platform_malloc (CERBERUS_PROTOCOL_MAX_CERT_CHAIN_LEN);
			if (attestation->state->cert_buffer == NULL) {
				goto fail;
			}
		}

		cert_portion_len =
			cerberus_protocol_get_certificate_response_cert_length (response->length);

		if ((attestation->state->cert_buffer_len + cert_portion_len) >
			CERBERUS_PROTOCOL_MAX_CERT_CHAIN_LEN) {
			goto fail;
		}

		memcpy (
			&attestation->state->cert_buffer[attestation->state->cert_buffer_len],
			cerberus_protocol_certificate (rsp), cert_portion_len);
		attestation->state->cert_buffer_len += cert_portion_len;

		attestation->state->request_status = ATTESTATION_REQUESTER_REQUEST_SUCCESSFUL;

		return;
	}

fail:
	attestation->state->request_status = ATTESTATION_REQUESTER_REQUEST_RSP_FAIL;
}

/**
 * Cerberus Challenge challenge response observer function. The Challenge request/response
 * interaction allows the requester to authenticate the responder by validating the response
 * signature and comparing the device PMR0 to CFM contents.
 */
void attestation_requester_on_cerberus_challenge_response (
	struct cerberus_protocol_observer *observer, const struct cmd_interface_msg *response)
{
	struct attestation_requester *attestation =
		TO_DERIVED_TYPE (observer, struct attestation_requester, cerberus_rsp_observer);
	struct cerberus_protocol_challenge_response *rsp =
		(struct cerberus_protocol_challenge_response*) response->data;
	int status;

	if (attestation_requester_check_cerberus_unexpected_rsp (attestation,
		CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_RESPONSE_RECEIVED, response->source_eid,
			((attestation->state->protocol << 24) | (attestation->state->requested_command << 16) |
				(ATTESTATION_PROTOCOL_CERBERUS << 8) | CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE));
		goto fail;
	}

	if (rsp->challenge.slot_num != attestation->state->slot_num) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_SLOT_NUM_IN_RSP, response->source_eid,
			(attestation->state->slot_num << 8) | rsp->challenge.slot_num);
	}
	else if (rsp->challenge.digests_size != SHA256_HASH_LENGTH) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_HASH_LEN_IN_RSP, response->source_eid,
			(rsp->challenge.digests_size << 8) | SHA256_HASH_LENGTH);
	}
	else if ((rsp->challenge.min_protocol_version > CERBERUS_PROTOCOL_PROTOCOL_VERSION) ||
		(rsp->challenge.max_protocol_version < CERBERUS_PROTOCOL_PROTOCOL_VERSION)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_CERBERUS_PROTOCOL_VER_UNSUPPORTED, response->source_eid,
			(rsp->challenge.max_protocol_version << 16) |
				(rsp->challenge.min_protocol_version << 8) | CERBERUS_PROTOCOL_PROTOCOL_VERSION);
	}
	else {
		status = attestation_requester_update_response_hash (attestation, attestation->primary_hash,
			response->data + 1,	cerberus_protocol_challenge_response_length (rsp) - 1);
		if (status == 0) {
			attestation_requester_verify_signature (attestation, attestation->primary_hash,
				response->source_eid, cerberus_protocol_challenge_get_signature (rsp),
				cerberus_protocol_challenge_get_signature_len (rsp, response->length), NULL);
		}

		if (attestation->state->request_status != ATTESTATION_REQUESTER_REQUEST_RSP_FAIL) {
			memcpy (attestation->state->msg_buffer, cerberus_protocol_challenge_get_pmr (rsp),
				SHA256_HASH_LENGTH);
			attestation->state->msg_buffer_len = SHA256_HASH_LENGTH;
		}

		return;
	}

fail:
	attestation->state->request_status = ATTESTATION_REQUESTER_REQUEST_RSP_FAIL;
}

/**
 * Cerberus Challenge get capabilities response observer function. The Get Capabilities
 * request/response interaction allows both devices to determine device functionalities, including
 * timeout and message size capabilities.
 */
void attestation_requester_on_cerberus_device_capabilities_response (
	struct cerberus_protocol_observer *observer, const struct cmd_interface_msg *response)
{
	struct attestation_requester *attestation =
		TO_DERIVED_TYPE (observer, struct attestation_requester, cerberus_rsp_observer);

	if (attestation_requester_check_cerberus_unexpected_rsp (attestation,
		CERBERUS_PROTOCOL_GET_DEVICE_CAPABILITIES)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_RESPONSE_RECEIVED, response->source_eid,
			((attestation->state->protocol << 24) | (attestation->state->requested_command << 16) |
				(ATTESTATION_PROTOCOL_CERBERUS << 8) | CERBERUS_PROTOCOL_GET_DEVICE_CAPABILITIES));
		attestation->state->request_status = ATTESTATION_REQUESTER_REQUEST_RSP_FAIL;
	}
	else {
		attestation->state->request_status = ATTESTATION_REQUESTER_REQUEST_SUCCESSFUL;
	}
}
#endif

#ifdef ATTESTATION_SUPPORT_DEVICE_DISCOVERY
/**
 * MCTP control protocol get message type response observer function. The Get Message Type
 * request/response interaction allows requester to determine MCTP message types supported by
 * responder. This function is used during device discovery to determine SPDM and Cerberus Challenge
 * support.
 */
void attestation_requester_on_mctp_get_message_type_response (
	struct mctp_control_protocol_observer *observer, const struct cmd_interface_msg *response)
{
	struct attestation_requester *attestation =
		TO_DERIVED_TYPE (observer, struct attestation_requester, mctp_rsp_observer);

	if ((attestation->state->requested_command != MCTP_CONTROL_PROTOCOL_GET_MESSAGE_TYPE)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_RESPONSE_RECEIVED, response->source_eid,
			((attestation->state->protocol << 24) | (attestation->state->requested_command << 16) |
				(255 << 8) | MCTP_CONTROL_PROTOCOL_GET_MESSAGE_TYPE));
		attestation->state->request_status = ATTESTATION_REQUESTER_REQUEST_RSP_FAIL;
	}
	else {
		attestation->state->request_status = ATTESTATION_REQUESTER_REQUEST_SUCCESSFUL;
	}

	// msg_buffer is sized to hold maximum response lengths
	memcpy (attestation->state->msg_buffer, response->data, response->length);
	attestation->state->msg_buffer_len = response->length;
}

/**
 * MCTP control protocol set EID request observer function. Incoming set EID requests are monitored
 * since they are used by the MCTP bridge to alert device of routing table updates.
 */
void attestation_requester_on_mctp_set_eid_request (
	struct mctp_control_protocol_observer *observer)
{
	struct attestation_requester *attestation =
		TO_DERIVED_TYPE (observer, struct attestation_requester, mctp_rsp_observer);

	attestation->state->get_routing_table = true;
}

/**
 * MCTP control protocol get routing table entries response observer function. The Get Routing Table
 * Entries request/response interaction is used by the requester to fetch routing table from MCTP
 * bridge.
 */
void attestation_requester_on_mctp_get_routing_table_entries_response (
	struct mctp_control_protocol_observer *observer, const struct cmd_interface_msg *response)
{
	struct attestation_requester *attestation =
		TO_DERIVED_TYPE (observer, struct attestation_requester, mctp_rsp_observer);

	if ((attestation->state->requested_command !=
		MCTP_CONTROL_PROTOCOL_GET_ROUTING_TABLE_ENTRIES)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_RESPONSE_RECEIVED, response->source_eid,
			((attestation->state->protocol << 24) | (attestation->state->requested_command << 16) |
				(255 << 8) | MCTP_CONTROL_PROTOCOL_GET_MESSAGE_TYPE));
		attestation->state->request_status = ATTESTATION_REQUESTER_REQUEST_RSP_FAIL;
	}
	else {
		attestation->state->request_status = ATTESTATION_REQUESTER_REQUEST_SUCCESSFUL;
	}

	// msg_buffer is sized to hold maximum response lengths
	memcpy (attestation->state->msg_buffer, response->data, response->length);
	attestation->state->msg_buffer_len = response->length;
}

/**
 * CFM activation request observer function. CFM activation requests are used to communicate to
 * device that component attestation states should be reset.
 */
void attestation_requester_on_cfm_activation_request (struct cfm_observer *observer)
{
	struct attestation_requester *attestation =
		TO_DERIVED_TYPE (observer, struct attestation_requester, cfm_observer);

	device_manager_reset_authenticated_devices (attestation->device_mgr);
}
#endif

/**
 * Initialize an attestation requester instance.
 *
 * @param attestation Attestation requester instance to initialize.
 * @param state Variable context for the attestation requester to utilize.
 * @param mctp MCTP interface instance to utilize.
 * @param channel Command channel instance to utilize.
 * @param primary_hash The primary hash engine to utilize.
 * @param secondary_hash The secondary hash engine to utilize for SPDM operations.
 * @param ecc The ECC engine to utilize.
 * @param rsa The RSA engine to utilize. Optional, can be set to NULL if not utilized.
 * @param x509 The x509 engine to utilize.
 * @param rng The RNG engine to utilize.
 * @param riot RIoT key manager.
 * @param device_mgr Device manager instance to utilize.
 * @param cfm_manager CFM manager to utilize.
 *
 * @return Initialization status, 0 if success or an error code.
 */
int attestation_requester_init (struct attestation_requester *attestation,
	struct attestation_requester_state *state, struct mctp_interface *mctp,
	struct cmd_channel *channel, struct hash_engine *primary_hash,
	struct hash_engine *secondary_hash, struct ecc_engine *ecc, struct rsa_engine *rsa,
	struct x509_engine *x509, struct rng_engine *rng, struct riot_key_manager *riot,
	struct device_manager *device_mgr, struct cfm_manager *cfm_manager)
{
	if ((attestation == NULL) || (state == NULL) || (mctp == NULL) || (channel == NULL) ||
		(primary_hash == NULL) || (ecc == NULL) || (x509 == NULL) || (rng == NULL) ||
		(riot == NULL) || (device_mgr == NULL) || (cfm_manager == NULL)) {
		return ATTESTATION_INVALID_ARGUMENT;
	}

	memset (attestation, 0, sizeof (struct attestation_requester));

	attestation->state = state;

	attestation->mctp = mctp;
	attestation->channel = channel;
	attestation->primary_hash = primary_hash;
	attestation->secondary_hash = secondary_hash;
	attestation->ecc = ecc;
	attestation->rsa = rsa;
	attestation->x509 = x509;
	attestation->rng = rng;
	attestation->riot = riot;
	attestation->device_mgr = device_mgr;
	attestation->cfm_manager = cfm_manager;

#ifdef ATTESTATION_SUPPORT_SPDM
	attestation->spdm_rsp_observer.on_spdm_get_version_response =
		attestation_requester_on_spdm_get_version_response;
	attestation->spdm_rsp_observer.on_spdm_get_capabilities_response =
		attestation_requester_on_spdm_get_capabilities_response;
	attestation->spdm_rsp_observer.on_spdm_negotiate_algorithms_response =
		attestation_requester_on_spdm_negotiate_algorithms_response;
	attestation->spdm_rsp_observer.on_spdm_get_digests_response =
		attestation_requester_on_spdm_get_digests_response;
	attestation->spdm_rsp_observer.on_spdm_get_certificate_response =
		attestation_requester_on_spdm_get_certificate_response;
	attestation->spdm_rsp_observer.on_spdm_challenge_response =
		attestation_requester_on_spdm_challenge_response;
	attestation->spdm_rsp_observer.on_spdm_get_measurements_response =
		attestation_requester_on_spdm_get_measurements_response;
	attestation->spdm_rsp_observer.on_spdm_response_not_ready =
		attestation_requester_on_spdm_response_not_ready;
#endif

#ifdef ATTESTATION_SUPPORT_CERBERUS_CHALLENGE
	attestation->cerberus_rsp_observer.on_get_digest_response =
		attestation_requester_on_cerberus_get_digest_response;
	attestation->cerberus_rsp_observer.on_get_certificate_response =
		attestation_requester_on_cerberus_get_certificate_response;
	attestation->cerberus_rsp_observer.on_challenge_response =
		attestation_requester_on_cerberus_challenge_response;
	attestation->cerberus_rsp_observer.on_device_capabilities =
		attestation_requester_on_cerberus_device_capabilities_response;
#endif

#ifdef ATTESTATION_SUPPORT_DEVICE_DISCOVERY
	attestation->mctp_rsp_observer.on_get_message_type_response =
		attestation_requester_on_mctp_get_message_type_response;
	attestation->mctp_rsp_observer.on_set_eid_request =
		attestation_requester_on_mctp_set_eid_request;
	attestation->mctp_rsp_observer.on_get_routing_table_entries_response =
		attestation_requester_on_mctp_get_routing_table_entries_response;

	attestation->cfm_observer.on_cfm_activation_request =
		attestation_requester_on_cfm_activation_request;
#endif

	return attestation_requester_init_state (attestation);
}

/**
 * Initialize only the variable state for an attestation responder instance.  The rest of the
 * instance is assumed to have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param attestation Attestation requester instance that contains state to initialize.
 *
 * @return Initialization status, 0 if success or an error code.
 */
int attestation_requester_init_state (const struct attestation_requester *attestation)
{
	if (attestation == NULL) {
		return ATTESTATION_INVALID_ARGUMENT;
	}

	memset (attestation->state, 0, sizeof (struct attestation_requester_state));

	return 0;
}

/**
 * Release an attestation requester instance.
 *
 * @param attestation Attestation requester instance to release.
 */
void attestation_requester_deinit (const struct attestation_requester *attestation)
{
	UNUSED (attestation);
}

#ifdef ATTESTATION_SUPPORT_CERBERUS_CHALLENGE
/**
 * Perform an attestation cycle on a provided device using Cerberus Protocol.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param eid EID of device to attest.
 * @param device_addr Slave address of device.
 * @param active_cfm Active CFM to utilize.
 * @param component_type SHA256 digest of component type of device.
 *
 * @return Completion status, 0 if success or an error code otherwise.
 */
static int attestation_requester_attest_device_cerberus_protocol (
	const struct attestation_requester *attestation, uint8_t eid, int device_addr,
	struct cfm *active_cfm, const uint8_t *component_type)
{
	uint8_t i_cert;	int challenge_rq_len;
	int status;

	attestation->state->protocol = ATTESTATION_PROTOCOL_CERBERUS;

	// TODO Get Cerberus Protocol version using the MCTP control Get VDM Support command

	status = cerberus_protocol_generate_get_device_capabilities_request (attestation->device_mgr,
		attestation->state->msg_buffer, sizeof (attestation->state->msg_buffer));
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	status = attestation_requester_send_request_and_get_response (attestation, status, device_addr,
		eid, false, CERBERUS_PROTOCOL_GET_DEVICE_CAPABILITIES);
	if (status != 0) {
		return status;
	}

	status = cerberus_protocol_generate_get_certificate_digest_request (
		attestation->state->slot_num, ATTESTATION_ECDHE_KEY_EXCHANGE,
		attestation->state->msg_buffer, sizeof (attestation->state->msg_buffer));
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	status = attestation_requester_send_request_and_get_response (attestation, status, device_addr,
		eid, true, CERBERUS_PROTOCOL_GET_DIGEST);
	if (status != 0) {
		return status;
	}

	// If certificate chain digest retrieved does not match cached certificate, refresh chain
	if (!attestation->state->cached_cert_valid) {
		attestation->state->cert_buffer_len = 0;

		for (i_cert = 0; i_cert < attestation->state->num_certs; ++i_cert) {
			status = cerberus_protocol_generate_get_certificate_request (
				attestation->state->slot_num, i_cert, attestation->state->msg_buffer,
				sizeof (attestation->state->msg_buffer), 0, 0);
			if (ROT_IS_ERROR (status)) {
				return status;
			}

			status = attestation_requester_send_request_and_get_response (attestation, status,
				device_addr, eid, false, CERBERUS_PROTOCOL_GET_CERTIFICATE);
			if (status != 0) {
				return status;
			}
		}

		status = attestation_requester_verify_and_load_leaf_key (attestation, eid, active_cfm,
			component_type);
		if (status != 0) {
			return status;
		}

		attestation->state->cached_cert_valid = true;
	}

	status = attestation->primary_hash->start_sha256 (attestation->primary_hash);
	if (status != 0) {
		return status;
	}

	challenge_rq_len = cerberus_protocol_generate_challenge_request (attestation->rng, eid,
		attestation->state->slot_num, attestation->state->msg_buffer,
		sizeof (attestation->state->msg_buffer));
	if (ROT_IS_ERROR (challenge_rq_len)) {
		status = challenge_rq_len;
		goto hash_cancel;
	}

	status = attestation->primary_hash->update (attestation->primary_hash,
		attestation->state->msg_buffer + 1, challenge_rq_len - 1);
	if (ROT_IS_ERROR (status)) {
		goto hash_cancel;
	}

	status = attestation_requester_send_request_and_get_response (attestation, challenge_rq_len,
		device_addr, eid, true, CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE);
	if (status != 0) {
		goto hash_cancel;
	}

	status = attestation_requester_verify_pmr (attestation, active_cfm, component_type, eid, 0);
	if (status == 0) {
		status = device_manager_update_device_state_by_eid (attestation->device_mgr, eid,
			DEVICE_MANAGER_AUTHENTICATED);
	}

	/* TODO Implement additional Cerberus Challenge Protocol attestation flows
	 *	1) PMR(n) attestation using the Get PMR command
	 *	2) PMR measurement attestation using the Get Log and Get PMR commands
	 *	3) PMR measurement data attestation using the Get Attestation Data, Get Log, and Get PMR
	 *		commands
	 *	4) Manifest IDs attestation using the Get Config IDs command */

hash_cancel:
	if (!attestation->state->hash_finish) {
		attestation->primary_hash->cancel (attestation->primary_hash);
	}

	return status;
}
#endif

#ifdef ATTESTATION_SUPPORT_SPDM
/**
 * Get SPDM device version and capabilities, and perform algorithms negotiation. Since the VCA
 * commands are included in SPDM Challenges and Measurement (for SPDM v1.2+) signatures, this
 * command is run before every challenge and get measurement (SPDM v1.2+) transaction if signatures
 * are requested in response.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param eid EID of device to utilize.
 * @param device_addr Slave address of device
 *
 * @return Completion status, 0 if success or an error code otherwise
 */
static int attestation_requester_setup_spdm_device (const struct attestation_requester *attestation,
	uint8_t eid, int device_addr)
{
	uint32_t base_asym_algo = SPDM_TPM_ALG_ECDSA_ECC_NIST_P256;
	uint32_t base_hash_algo;
	int rq_len;
	int status;

	rq_len = spdm_generate_get_version_request (attestation->state->msg_buffer,
		sizeof (attestation->state->msg_buffer));
	if (ROT_IS_ERROR (rq_len)) {
		return rq_len;
	}

	status = attestation_requester_send_spdm_request_and_get_response (attestation, rq_len,
		device_addr, eid, false, SPDM_REQUEST_GET_VERSION);
	if (status != 0) {
		return status;
	}

	rq_len = spdm_generate_get_capabilities_request (attestation->state->msg_buffer,
		sizeof (attestation->state->msg_buffer), attestation->state->protocol);
	if (ROT_IS_ERROR (rq_len)) {
		return rq_len;
	}

	status = attestation_requester_send_spdm_request_and_get_response (attestation, rq_len,
		device_addr, eid, false, SPDM_REQUEST_GET_CAPABILITIES);
	if (status != 0) {
		return status;
	}

	// Only show support for hashing algorithm that CFM selects for attestation with this device
	switch (attestation->state->transcript_hash_type) {
		case HASH_TYPE_SHA256:
			base_hash_algo = SPDM_TPM_ALG_SHA_256;
			break;

#ifdef HASH_ENABLE_SHA384
		case HASH_TYPE_SHA384:
			base_hash_algo = SPDM_TPM_ALG_SHA_384;
			break;
#endif

#ifdef HASH_ENABLE_SHA512
		case HASH_TYPE_SHA512:
			base_hash_algo = SPDM_TPM_ALG_SHA_512;
			break;
#endif

		default:
			return ATTESTATION_UNSUPPORTED_ALGORITHM;
	}

	if (attestation->state->transcript_hash_type != attestation->state->measurement_hash_type) {
		switch (attestation->state->measurement_hash_type) {
			case HASH_TYPE_SHA256:
				base_hash_algo |= SPDM_TPM_ALG_SHA_256;
				break;

#ifdef HASH_ENABLE_SHA384
			case HASH_TYPE_SHA384:
				base_hash_algo |= SPDM_TPM_ALG_SHA_384;
				break;
#endif

#ifdef HASH_ENABLE_SHA512
			case HASH_TYPE_SHA512:
				base_hash_algo |= SPDM_TPM_ALG_SHA_512;
				break;
#endif

			default:
				return ATTESTATION_UNSUPPORTED_ALGORITHM;
		}
	}

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
	base_asym_algo |= SPDM_TPM_ALG_ECDSA_ECC_NIST_P384;
#endif
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
	base_asym_algo |= SPDM_TPM_ALG_ECDSA_ECC_NIST_P521;
#endif

	rq_len = spdm_generate_negotiate_algorithms_request (attestation->state->msg_buffer,
		sizeof (attestation->state->msg_buffer), base_asym_algo, base_hash_algo,
		attestation->state->protocol);
	if (ROT_IS_ERROR (rq_len)) {
		return rq_len;
	}

	status = attestation_requester_send_spdm_request_and_get_response (attestation, rq_len,
		device_addr, eid, false, SPDM_REQUEST_NEGOTIATE_ALGORITHMS);
	if (status != 0) {
		return status;
	}

	return 0;
}

/**
 * Generate and send SPDM get measurements request, then wait for response.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param eid EID of device being attested.
 * @param device_addr Slave address of device.
 * @param measurement_operation Measurement operation requested.
 * @param raw_bitstream_requested Flag indicating whether to request raw form of measurement blocks.
 *
 * @return Completion status, 0 if success or an error code otherwise
 */
static int attestation_requester_send_and_receive_spdm_get_measurements (
	const struct attestation_requester *attestation, uint8_t eid, int device_addr,
	uint8_t measurement_operation, bool raw_bitstream_requested)
{
	uint8_t nonce[SPDM_NONCE_LEN];
	int rq_len;
	int status;

	if (!attestation->state->device_discovery) {
		if (!attestation->state->hash_finish) {
			attestation->secondary_hash->cancel (attestation->secondary_hash);
		}

		attestation->state->hash_finish = true;

		status = hash_start_new_hash (attestation->secondary_hash,
			attestation->state->transcript_hash_type);
		if (status != 0) {
			return status;
		}

		attestation->state->hash_finish = false;
	}

	/* In 1.2+, every Get Measurement transaction with a signature requested in response requires a
	 * a transcript that includes VDM. */
	if ((attestation->state->protocol > ATTESTATION_PROTOCOL_DMTF_SPDM_1_1) ||
		attestation->state->device_discovery) {
		status = attestation_requester_setup_spdm_device (attestation, eid, device_addr);
		if (status != 0) {
			return status;
		}
	}

	// No signature or nonce needed when getting device ID measurement block in device discovery
	if (!attestation->state->device_discovery) {
		status = attestation->rng->generate_random_buffer (attestation->rng, SPDM_NONCE_LEN, nonce);
		if (status != 0) {
			return status;
		}

		rq_len = spdm_generate_get_measurements_request (attestation->state->msg_buffer,
			sizeof (attestation->state->msg_buffer), attestation->state->slot_num,
			measurement_operation, true, raw_bitstream_requested, nonce,
			attestation->state->protocol);
		if (ROT_IS_ERROR (rq_len)) {
			return rq_len;
		}
	}
	else {
		/* SPDM 1.1.x requires all measurement blocks to be contiguous.  This means that device
		 * might not be able to support the dedicated 0xEF block and be compliant, so instead
		 * device IDs are placed in the last measurement block on the device.  Cerberus will first
		 * get the number of measurement blocks, then update measurement_operation to the index of
		 * the last measurement block on the device.  Starting from SPDM 1.2.x, measurement blocks
		 * no longer have the contiguity requirement so instead use index 0xEF which is dedicated to
		 * device IDs. */
		if (attestation->state->protocol == ATTESTATION_PROTOCOL_DMTF_SPDM_1_1) {
			rq_len = spdm_generate_get_measurements_request (attestation->state->msg_buffer,
				sizeof (attestation->state->msg_buffer), attestation->state->slot_num,
				SPDM_MEASUREMENT_OPERATION_GET_NUM_BLOCKS, false, raw_bitstream_requested, NULL,
				attestation->state->protocol);
			if (ROT_IS_ERROR (rq_len)) {
				return rq_len;
			}

			attestation->state->raw_bitstream_requested = raw_bitstream_requested;
			attestation->state->measurement_operation_requested =
				SPDM_MEASUREMENT_OPERATION_GET_NUM_BLOCKS;

			status = attestation_requester_send_spdm_request_and_get_response (attestation, rq_len,
				device_addr, eid, true, SPDM_REQUEST_GET_MEASUREMENTS);
			if (status != 0) {
				return status;
			}

			measurement_operation = attestation->state->msg_buffer[0];
		}

		rq_len = spdm_generate_get_measurements_request (attestation->state->msg_buffer,
			sizeof (attestation->state->msg_buffer), attestation->state->slot_num,
			measurement_operation, false, raw_bitstream_requested, NULL,
			attestation->state->protocol);
		if (ROT_IS_ERROR (rq_len)) {
			return rq_len;
		}
	}

	attestation->state->raw_bitstream_requested = raw_bitstream_requested;
	attestation->state->measurement_operation_requested = measurement_operation;

	return attestation_requester_send_spdm_request_and_get_response (attestation, rq_len,
		device_addr, eid, true, SPDM_REQUEST_GET_MEASUREMENTS);
}

/**
 * If PMR0 digest checking is in CFM for device being attested using SPDM, get all measurement
 * blocks from device then combine into single digest and compare with allowable PMR0 digests.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param eid EID of device being attested.
 * @param device_addr Slave address of device.
 * @param active_cfm Active CFM to utilize.
 * @param component_type SHA256 digest of component type of device.
 *
 * @return Completion status, 0 if success, CFM_PMR_DIGEST_NOT_FOUND if no PMR0 digest checking
 * 	defined in CFM for this device, or an error code otherwise
 */
static int attestation_requester_get_and_verify_all_spdm_measurement_blocks (
	const struct attestation_requester *attestation, uint8_t eid, int device_addr,
	struct cfm *active_cfm, const uint8_t *component_type)
{
	uint8_t digest[HASH_MAX_HASH_LEN];
	struct cfm_pmr_digest pmr_digest;
	int status;

	status = active_cfm->get_component_pmr_digest (active_cfm, component_type, 0, &pmr_digest);
	if (status != 0) {
		return status;
	}

	status = attestation_requester_send_and_receive_spdm_get_measurements (attestation, eid,
		device_addr, SPDM_MEASUREMENT_OPERATION_GET_ALL_BLOCKS, false);
	if (status != 0) {
		goto free_pmr_digest;
	}

	status = hash_calculate (attestation->primary_hash, attestation->state->measurement_hash_type,
		attestation->state->msg_buffer, attestation->state->msg_buffer_len,	digest,
		sizeof (digest));
	if (ROT_IS_ERROR (status)) {
		goto free_pmr_digest;
	}

	status = attestation_requester_verify_digest_in_allowable_list (attestation,
		&pmr_digest.digests, digest, attestation->state->measurement_hash_type);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_DEVICE_FAILED_ATTESTATION,
			((attestation->state->protocol << 16) |
				(attestation->state->requested_command << 8) | eid),
			status);
	}

free_pmr_digest:
	active_cfm->free_component_pmr_digest (active_cfm, &pmr_digest);

	return status;
}

/**
 * For each measurement block with corresponding measurement entry in CFM, get measurement block
 * digest using SPDM and compare to allowable values.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param eid EID of device being attested.
 * @param device_addr Slave address of device.
 * @param active_cfm Active CFM to utilize.
 * @param component_type SHA256 digest of component type of device.
 *
 * @return Completion status, 0 if success or no measurement entries in CFM, or an error code
 * 	otherwise
 */
static int attestation_requester_get_and_verify_spdm_measurement_blocks_in_cfm (
	const struct attestation_requester *attestation, uint8_t eid, int device_addr,
	struct cfm *active_cfm, const uint8_t *component_type)
{
	struct cfm_measurement measurement;
	bool first = true;
	int status = 0;

	while (status == 0) {
		status = active_cfm->get_next_measurement (active_cfm, component_type, &measurement, first);
		if (status == 0) {
			status = attestation_requester_send_and_receive_spdm_get_measurements (attestation, eid,
				device_addr, measurement.measurement_id + 1, false);
			if (status == 0) {
				status = attestation_requester_verify_digest_in_allowable_list (attestation,
					&measurement.digests, NULL, attestation->state->measurement_hash_type);
				if (status != 0) {
					debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR,
						DEBUG_LOG_COMPONENT_ATTESTATION,
						ATTESTATION_LOGGING_DEVICE_FAILED_ATTESTATION,
						((attestation->state->protocol << 16) |
							(attestation->state->requested_command << 8) | eid),
						status);
				}
			}

			active_cfm->free_measurement (active_cfm, &measurement);
			first = false;
		}
	}

	if (status == CFM_MEASUREMENT_NOT_FOUND) {
		return 0;
	}

	return status;
}

/**
 * Perform check requested on data compared to expected data.
 *
 * @param check Checking method requested.
 * @param actual Actual data to utilize.
 * @param expected Expected data to utilize.
 * @param length Length of both actual and expected data.
 * @param bitmask Buffer with bitmask to use during comparison. Can be set to NULL if not needed.
 *
 * @return 0 if data matches or 1 otherwise
 */
static int attestation_requester_compare_data (enum cfm_check check, const uint8_t *actual,
	const uint8_t *expected, size_t length, const uint8_t *bitmask)
{
	uint8_t actual_value;
	uint8_t expected_value;
	int i_data;
	int result;

	// TODO: use multi-byte storage format from CFM
	// Assumes multi-byte data is in little endian
	for (i_data = length - 1; i_data >= 0; --i_data) {
		actual_value = actual[i_data];
		expected_value = expected[i_data];

		if (bitmask != NULL) {
			actual_value &= bitmask[i_data];
			expected_value &= bitmask[i_data];
		}

		result = actual_value - expected_value;

		if (result != 0) {
			break;
		}
	}

	if (result == 0) {
		if ((check == CFM_CHECK_EQUAL) || (check == CFM_CHECK_LESS_THAN_OR_EQUAL) ||
			(check == CFM_CHECK_GREATER_THAN_OR_EQUAL)) {
			return 0;
		}
	}
	else if (result > 0) {
		if ((check == CFM_CHECK_GREATER_THAN) || (check == CFM_CHECK_GREATER_THAN_OR_EQUAL) ||
			(check == CFM_CHECK_NOT_EQUAL)) {
			return 0;
		}
	}
	else {
		if ((check == CFM_CHECK_LESS_THAN) || (check == CFM_CHECK_LESS_THAN_OR_EQUAL) ||
			(check == CFM_CHECK_NOT_EQUAL)) {
			return 0;
		}
	}

	return 1;
}

/**
 * Check if data in msg_buffer matches all checks in allowable data list.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param allowable_data List of allowable data checks to utilize.
 *
 * @return Completion status, 0 if success or an error code otherwise
 */
static int attestation_requester_verify_data_in_allowable_list (
	const struct attestation_requester *attestation, struct cfm_allowable_data *allowable_data,
	size_t num_allowable_data)
{
	size_t i_allowable_data;
	size_t i_data;
	size_t offset;
	int status = ATTESTATION_CFM_INVALID_ATTESTATION;

	for (i_allowable_data = 0; i_allowable_data < num_allowable_data;
		++i_allowable_data, ++allowable_data) {
		if ((allowable_data->data_len != attestation->state->msg_buffer_len) ||
			((allowable_data->data_count != 1) && (allowable_data->check != CFM_CHECK_EQUAL) &&
				(allowable_data->check != CFM_CHECK_NOT_EQUAL))) {
			return ATTESTATION_CFM_INVALID_ATTESTATION;
		}

		for (i_data = 0, offset = 0; i_data < allowable_data->data_count; ++i_data,
			offset += allowable_data->data_len) {
			status = attestation_requester_compare_data (allowable_data->check,
				attestation->state->msg_buffer, &allowable_data->allowable_data[offset],
				allowable_data->data_len, allowable_data->bitmask);
			if (status == 0) {
				//For the equal check, at least one comparison must succeed
				if (allowable_data->check == CFM_CHECK_EQUAL) {
					break;
				}
			}
			else {
				status = ATTESTATION_CFM_ATTESTATION_RULE_FAIL;

				//Except for the equal check, all comparisons must succeed
				if (allowable_data->check != CFM_CHECK_EQUAL) {
					break;
				}
			}
		}
	}

	return status;
}

/**
 * For each measurement block with corresponding measurement data entry in CFM, get raw measurement
 * block using SPDM and compare to allowable values.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param eid EID of device being attested.
 * @param device_addr Slave address of device.
 * @param active_cfm Active CFM to utilize.
 * @param component_type SHA256 digest of component type of device.
 *
 * @return Completion status, 0 if success or no measurement entries in CFM, or an error code
 * 	otherwise
 */
static int attestation_requester_get_and_verify_raw_spdm_measurement_blocks_in_cfm (
	const struct attestation_requester *attestation, uint8_t eid, int device_addr,
	struct cfm *active_cfm, const uint8_t *component_type)
{
	struct cfm_measurement_data data;
	bool first = true;
	int status = 0;

	while (status == 0) {
		status = active_cfm->get_next_measurement_data (active_cfm, component_type, &data, first);
		if (status == 0) {
			status = attestation_requester_send_and_receive_spdm_get_measurements (attestation, eid,
				device_addr, data.measurement_id + 1, true);
			if (status == 0) {
				status = attestation_requester_verify_data_in_allowable_list (attestation,
					data.check, data.check_count);
				if (status != 0) {
					debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR,
						DEBUG_LOG_COMPONENT_ATTESTATION,
						ATTESTATION_LOGGING_DEVICE_FAILED_ATTESTATION,
						((attestation->state->protocol << 16) |
							(attestation->state->requested_command << 8) | eid),
						status);
				}
			}

			active_cfm->free_measurement_data (active_cfm, &data);
			first = false;
		}
	}

	if (status == CFM_MEASUREMENT_DATA_NOT_FOUND) {
		return 0;
	}

	return status;
}

/**
 * Perform an attestation cycle on a provided device using SPDM.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param eid EID of device to attest.
 * @param device_addr Slave address of device.
 * @param active_cfm Active CFM to utilize.
 * @param component_type SHA256 digest of component type of device.
 *
 * @return Completion status, 0 if success or an error code otherwise
 */
static int attestation_requester_attest_device_spdm (
	const struct attestation_requester *attestation, uint8_t eid, int device_addr,
	struct cfm *active_cfm, const uint8_t *component_type)
{
	uint8_t nonce[SPDM_NONCE_LEN];
	int rq_len;
	int status;

	status = hash_start_new_hash (attestation->secondary_hash,
		attestation->state->transcript_hash_type);
	if (status != 0) {
		return status;
	}

	// Start off assuming 1.1 then update based on response from device to the Get Version request
	attestation->state->protocol = ATTESTATION_PROTOCOL_DMTF_SPDM_1_1;

	status = attestation_requester_setup_spdm_device (attestation, eid, device_addr);
	if (status != 0) {
		goto hash_cancel;
	}

	rq_len = spdm_generate_get_digests_request (attestation->state->msg_buffer,
		sizeof (attestation->state->msg_buffer), attestation->state->protocol);
	if (ROT_IS_ERROR (rq_len)) {
		status = rq_len;
		goto hash_cancel;
	}

	status = attestation->secondary_hash->update (attestation->secondary_hash,
		attestation->state->msg_buffer + 1, rq_len - 1);
	if (ROT_IS_ERROR (status)) {
		goto hash_cancel;
	}

	status = attestation_requester_send_request_and_get_response (attestation, rq_len, device_addr,
		eid, true, SPDM_REQUEST_GET_DIGESTS);
	if (status != 0) {
		goto hash_cancel;
	}

	// If certificate chain digest retrieved does not match cached certificate, refresh chain
	if (!attestation->state->cached_cert_valid) {
		attestation->state->cert_buffer_len = 0;
		attestation->state->cert_total_len = SPDM_GET_CERTIFICATE_MAX_CERT_BUFFER;

		 while ((attestation->state->cert_total_len - attestation->state->cert_buffer_len) > 0) {
			rq_len = spdm_generate_get_certificate_request (attestation->state->msg_buffer,
				sizeof (attestation->state->msg_buffer), attestation->state->slot_num,
				attestation->state->cert_buffer_len,
				attestation->state->cert_total_len - attestation->state->cert_buffer_len,
				attestation->state->protocol);
			if (ROT_IS_ERROR (rq_len)) {
				status = rq_len;
				goto hash_cancel;
			}

			status = attestation->secondary_hash->update (attestation->secondary_hash,
				attestation->state->msg_buffer + 1, rq_len - 1);
			if (ROT_IS_ERROR (status)) {
				goto hash_cancel;
			}

			status = attestation_requester_send_request_and_get_response (attestation, rq_len,
				device_addr, eid, false, SPDM_REQUEST_GET_CERTIFICATE);
			if (status != 0) {
				goto hash_cancel;
			}
		}

		status = attestation_requester_verify_and_load_leaf_key (attestation, eid, active_cfm,
			component_type);
		if (status != 0) {
			goto hash_cancel;
		}

		attestation->state->cached_cert_valid = true;
	}

	/* Perform PMR0 check. If device supports Challenge command, then use that. Otherwise, get all
	 * measurement blocks which make up PMR0 using the Get Measurement command */
	if (attestation->state->challenge_supported) {
		status = attestation->rng->generate_random_buffer (attestation->rng, SPDM_NONCE_LEN, nonce);
		if (status != 0) {
			goto hash_cancel;
		}

		rq_len = spdm_generate_challenge_request (attestation->state->msg_buffer,
			sizeof (attestation->state->msg_buffer), attestation->state->slot_num,
			SPDM_MEASUREMENT_SUMMARY_HASH_ALL, nonce, attestation->state->protocol);
		if (ROT_IS_ERROR (rq_len)) {
			status = rq_len;
			goto hash_cancel;
		}

		status = attestation->secondary_hash->update (attestation->secondary_hash,
			attestation->state->msg_buffer + 1, rq_len - 1);
		if (ROT_IS_ERROR (status)) {
			goto hash_cancel;
		}

		status = attestation_requester_send_request_and_get_response (attestation, rq_len,
			device_addr, eid, true, SPDM_REQUEST_CHALLENGE);
		if (status != 0) {
			goto hash_cancel;
		}

		status = attestation_requester_verify_pmr (attestation, active_cfm, component_type, eid, 0);
		if ((status != 0) && (status != CFM_PMR_DIGEST_NOT_FOUND)) {
			goto hash_cancel;
		}
	}
	else {
		status = attestation_requester_get_and_verify_all_spdm_measurement_blocks (attestation, eid,
			device_addr, active_cfm, component_type);
		if ((status != 0) && (status != CFM_PMR_DIGEST_NOT_FOUND)) {
			goto hash_cancel;
		}
	}

	/* If PMR0 entry exists in CFM, then by getting here device has valid PMR0. Since PMR0 includes
	 * all measurement blocks, we dont have to check rest of the attestation rules. */
	if (status == CFM_PMR_DIGEST_NOT_FOUND) {
		status = attestation_requester_get_and_verify_spdm_measurement_blocks_in_cfm (attestation,
			eid, device_addr, active_cfm, component_type);
		if (status != 0) {
			goto hash_cancel;
		}

		status = attestation_requester_get_and_verify_raw_spdm_measurement_blocks_in_cfm (
			attestation, eid, device_addr, active_cfm, component_type);
		if (status != 0) {
			goto hash_cancel;
		}
	}

	status = device_manager_update_device_state_by_eid (attestation->device_mgr, eid,
		DEVICE_MANAGER_AUTHENTICATED);

hash_cancel:
	if (!attestation->state->hash_finish) {
		attestation->secondary_hash->cancel (attestation->secondary_hash);
	}

	return status;
}
#endif

/**
 * Perform an attestation cycle on a provided device using requested protocol.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param eid EID of device to attest.
 * @param hash_type Hashing algorithm to utilize.
 *
 * @return Completion status, 0 if success or an error code otherwise
 */
int attestation_requester_attest_device (const struct attestation_requester *attestation,
	uint8_t eid, enum hash_type hash_type)
{
	struct cfm_component_device component_device;
	struct cfm *active_cfm;
	const uint8_t *component_type;
	enum cfm_attestation_type attestation_protocol;
	int device_addr;
	int status;

	if (attestation == NULL) {
		return ATTESTATION_INVALID_ARGUMENT;
	}

	if (attestation->state->get_routing_table) {
		return ATTESTATION_REFRESH_ROUTING_TABLE;
	}

	status = attestation_requester_init_state (attestation);
	if (status != 0) {
		return status;
	}

	device_addr = device_manager_get_device_addr_by_eid (attestation->device_mgr, eid);
	if (ROT_IS_ERROR (device_addr)) {
		return device_addr;
	}

	component_type = device_manager_get_component_type_digest (attestation->device_mgr, eid);
	if (component_type == NULL) {
		return ATTESTATION_COMPONENT_TYPE_NOT_SET;
	}

	active_cfm = attestation->cfm_manager->get_active_cfm (attestation->cfm_manager);
	if (active_cfm == NULL) {
		return ATTESTATION_NO_CFM;
	}

	status = active_cfm->get_component_device (active_cfm, component_type, &component_device);
	if (status != 0) {
		goto free_cfm;
	}

	attestation->state->slot_num = component_device.cert_slot;

	// TODO: Use hash lengths from CFM
	attestation->state->transcript_hash_type = hash_type;
	attestation->state->measurement_hash_type = hash_type;

	attestation_protocol = component_device.attestation_protocol;

	active_cfm->free_component_device (active_cfm, &component_device);

	status = device_manager_update_device_state_by_eid (attestation->device_mgr, eid,
		DEVICE_MANAGER_READY_FOR_ATTESTATION);
	if (status != 0) {
		goto free_cfm;
	}

	switch (attestation_protocol) {
#ifdef ATTESTATION_SUPPORT_CERBERUS_CHALLENGE
		case CFM_ATTESTATION_CERBERUS_PROTOCOL:
			status = attestation_requester_attest_device_cerberus_protocol (attestation, eid,
				device_addr, active_cfm, component_type);

			break;
#endif

#ifdef ATTESTATION_SUPPORT_SPDM
		case CFM_ATTESTATION_DMTF_SPDM:
			if (attestation->secondary_hash == NULL) {
				status = ATTESTATION_UNSUPPORTED_OPERATION;
			}
			else {
				status = attestation_requester_attest_device_spdm (attestation, eid, device_addr,
					active_cfm, component_type);
			}

			break;
#endif

		default:
			status = ATTESTATION_UNSUPPORTED_PROTOCOL;
	}


free_cfm:
	attestation->cfm_manager->free_cfm (attestation->cfm_manager, active_cfm);

	return status;
}

#ifdef ATTESTATION_SUPPORT_DEVICE_DISCOVERY
#ifdef ATTESTATION_SUPPORT_CERBERUS_CHALLENGE
/**
 * Perform discovery on a provided device using the Cerberus protocol.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param eid EID of device to discover.
 *
 * @return Completion status, 0 if success or an error code otherwise
 */
static int attestation_requester_discover_device_cerberus_protocol (
	const struct attestation_requester *attestation, uint8_t eid)
{
	// TODO: Implement Cerberus protocol device discovery
	return 0;
}
#endif

#ifdef ATTESTATION_SUPPORT_SPDM
/**
 * Perform discovery on a provided device using the SPDM protocol.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param eid EID of device to discover.
 * @param device_addr Slave address of device.
 *
 * @return Completion status, 0 if success or an error code otherwise
 */
static int attestation_requester_discover_device_spdm_protocol (
	const struct attestation_requester *attestation, uint8_t eid, uint8_t device_addr)
{
	struct spdm_measurements_device_id_block *block =
		(struct spdm_measurements_device_id_block *) attestation->state->msg_buffer;
	struct spdm_measurements_device_id_descriptor *descriptor;
	uint16_t pci_vid = 0;
	uint16_t pci_device_id = 0;
	uint16_t pci_sub_vid = 0;
	uint16_t pci_sub_id = 0;
	uint16_t *id;
	size_t offset = sizeof (struct spdm_measurements_device_id_block);
	uint8_t found = 0;
	int i_descriptor;
	int device_num;
	int status;

	attestation->state->protocol = ATTESTATION_PROTOCOL_DMTF_SPDM_1_1;
	attestation->state->transcript_hash_type = HASH_TYPE_SHA256;
	attestation->state->measurement_hash_type = HASH_TYPE_SHA256;

	status = attestation_requester_send_and_receive_spdm_get_measurements (attestation, eid,
		device_addr, SPDM_MEASUREMENT_OPERATION_GET_DEVICE_ID, true);
	if (status != 0) {
		return status;
	}

	if (block->completion_code != SPDM_MEASUREMENTS_DEVICE_ID_BLOCK_CC_SUCCESS) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_GET_DEVICE_ID_FAILED,
			((eid << 8) | attestation->state->requested_command), block->completion_code);

		return ATTESTATION_GET_DEVICE_ID_FAIL;
	}

	// Only PCI descriptors are supported, so ensure the 4 PCI descriptors are included in response
	if ((block->descriptor_count < 4) ||
		(block->device_id_len <
			((sizeof (struct spdm_measurements_device_id_descriptor) + sizeof (uint16_t)) * 4))) {
		return 0;
	}

	for (i_descriptor = 0; i_descriptor < block->descriptor_count; ++i_descriptor) {
		descriptor =
			(struct spdm_measurements_device_id_descriptor*) &attestation->state->msg_buffer[offset];

		offset += sizeof (struct spdm_measurements_device_id_descriptor);
		id = (uint16_t*) &attestation->state->msg_buffer[offset];
		offset += descriptor->descriptor_len;

		if (descriptor->descriptor_len != sizeof (uint16_t)) {
			continue;
		}

		switch (descriptor->descriptor_type) {
			case SPDM_MEASUREMENTS_DEVICE_ID_PCI_VID:
				pci_vid = *id;
				found |= 1;
				break;

			case SPDM_MEASUREMENTS_DEVICE_ID_PCI_DEVICE_ID:
				pci_device_id = *id;
				found |= (1 << 1);
				break;

			case SPDM_MEASUREMENTS_DEVICE_ID_PCI_SUBSYSTEM_VID:
				pci_sub_vid = *id;
				found |= (1 << 2);
				break;

			case SPDM_MEASUREMENTS_DEVICE_ID_PCI_SUBSYSTEM_ID:
				pci_sub_id = *id;
				found |= (1 << 3);
				break;

			default:
				continue;
		}
	}

	if (found == 0x0F) {
		device_num = device_manager_get_device_num_by_device_ids (attestation->device_mgr, pci_vid,
			pci_device_id, pci_sub_vid, pci_sub_id);
		if (ROT_IS_ERROR (device_num)) {
			return 0;
		}

		status = device_manager_update_device_state (attestation->device_mgr, device_num,
			DEVICE_MANAGER_READY_FOR_ATTESTATION);
		if (status != 0) {
			return status;
		}

		return device_manager_update_device_eid (attestation->device_mgr, device_num, eid);
	}

	return 0;
}
#endif

/**
 * Perform discovery on a provided device.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param eid EID of device to discover.
 *
 * @return Completion status, 0 if success or an error code otherwise
 */
int attestation_requester_discover_device (const struct attestation_requester *attestation,
	uint8_t eid)
{
	struct mctp_control_get_message_type_response *msg_type_rsp;
	uint8_t *msg_type;
	uint8_t i_type;
	int device_addr;
	int status;

	if (attestation == NULL) {
		return ATTESTATION_INVALID_ARGUMENT;
	}

	if (attestation->state->get_routing_table) {
		return ATTESTATION_REFRESH_ROUTING_TABLE;
	}

	status = attestation_requester_init_state (attestation);
	if (status != 0) {
		return status;
	}

	device_addr = device_manager_get_device_addr (attestation->device_mgr,
		DEVICE_MANAGER_MCTP_BRIDGE_DEVICE_NUM);
	if (ROT_IS_ERROR (device_addr)) {
		return device_addr;
	}

	attestation->state->device_discovery = true;

	status = mctp_control_protocol_generate_get_message_type_support_request (
		attestation->state->msg_buffer, sizeof (attestation->state->msg_buffer));
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	status = attestation_requester_send_request_and_get_response (attestation, status, device_addr,
		eid, false, MCTP_CONTROL_PROTOCOL_GET_MESSAGE_TYPE);
	if (status != 0) {
		return status;
	}

	msg_type_rsp = (struct mctp_control_get_message_type_response*) attestation->state->msg_buffer;

	for (i_type = 0; i_type < msg_type_rsp->message_type_count; ++i_type) {
		msg_type = attestation->state->msg_buffer +
			sizeof (struct mctp_control_get_message_type_response) + i_type;

		switch (*msg_type) {
#ifdef ATTESTATION_SUPPORT_CERBERUS_CHALLENGE
			case MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF:
				status = attestation_requester_discover_device_cerberus_protocol (attestation, eid);
				goto done;
#endif

#ifdef ATTESTATION_SUPPORT_SPDM
			case MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM:
				status = attestation_requester_discover_device_spdm_protocol (attestation, eid,
					device_addr);
				goto done;
#endif

			default:
				continue;
		}
	}

done:
	if (status != 0) {
		return device_manager_unidentified_device_timed_out (attestation->device_mgr, eid);
	}

	return device_manager_remove_unidentified_device (attestation->device_mgr, eid);
}

/**
 * Check to see if routing table should be retrieved from the MCTP bridge, and fetch it if so.
 *
 * @param attestation Attestation requester instance to utilize.
 *
 * @return Completion status, 0 if success or an error code otherwise
 */
int attestation_requester_get_mctp_routing_table (const struct attestation_requester *attestation)
{
	struct mctp_control_get_routing_table_entries_response *routing_table_rsp;
	struct mctp_control_routing_table_entry *entry;
	uint8_t entry_handle = 0;
	uint8_t i_entry;
	uint8_t i_eid;
	int bridge_addr;
	int bridge_eid;
	int self_eid;
	int status;

	if (attestation == NULL) {
		return ATTESTATION_INVALID_ARGUMENT;
	}

	if (!attestation->state->get_routing_table) {
		return 0;
	}

	device_manager_clear_unidentified_devices (attestation->device_mgr);

	bridge_addr = device_manager_get_device_addr (attestation->device_mgr,
		DEVICE_MANAGER_MCTP_BRIDGE_DEVICE_NUM);
	if (ROT_IS_ERROR (bridge_addr)) {
		return bridge_addr;
	}

	bridge_eid = device_manager_get_device_eid (attestation->device_mgr,
		DEVICE_MANAGER_MCTP_BRIDGE_DEVICE_NUM);
	if (ROT_IS_ERROR (bridge_eid)) {
		return bridge_eid;
	}

	self_eid = device_manager_get_device_eid (attestation->device_mgr,
		DEVICE_MANAGER_SELF_DEVICE_NUM);
	if (ROT_IS_ERROR (self_eid)) {
		return self_eid;
	}

	while (entry_handle != 0xFF) {
		status = mctp_control_protocol_generate_get_routing_table_entries_request (entry_handle,
			attestation->state->msg_buffer, sizeof (attestation->state->msg_buffer));
		if (ROT_IS_ERROR (status)) {
			return status;
		}

		status = attestation_requester_send_request_and_get_response (attestation, status,
			bridge_addr, bridge_eid, false, MCTP_CONTROL_PROTOCOL_GET_ROUTING_TABLE_ENTRIES);
		if (status != 0) {
			return status;
		}

		routing_table_rsp =
			(struct mctp_control_get_routing_table_entries_response*) attestation->state->msg_buffer;
		entry = mctp_control_get_routing_table_entries_response_get_entries (routing_table_rsp);

		for (i_entry = 0; i_entry < routing_table_rsp->num_entries; ++i_entry, ++entry) {
			if (entry->starting_eid == self_eid) {
				continue;
			}

			for (i_eid = 0; i_eid < entry->eid_range_size; ++i_eid) {
				status = device_manager_add_unidentified_device (attestation->device_mgr,
					entry->starting_eid + i_eid);
				if (status != 0) {
					return status;
				}
			}
		}

		entry_handle = routing_table_rsp->next_entry_handle;
	}

	attestation->state->get_routing_table = 0;

	return 0;
}
#endif

/**
 * Check to see if routing table should be retrieved from the MCTP bridge, and fetch it if so.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param pcr PCR store instance to utilize.
 * @param attestation_status Attestation status bitmap. Must be
 * 	DEVICE_MANAGER_ATTESTATION_STATUS_LEN bytes long.
 * @param measurement The measurement ID for attestation results.
 * @param measurement_version The version associated with the measurement data.
 */
void attestation_requester_discovery_and_attestation_loop (
	struct attestation_requester *attestation, struct pcr_store *pcr, uint8_t *attestation_status,
	uint16_t measurement, uint8_t measurement_version)
{
	int eid = 0;
	int status;

	if ((attestation == NULL) || (pcr == NULL) || (attestation_status == NULL)) {
		return;
	}

#ifdef ATTESTATION_SUPPORT_DEVICE_DISCOVERY
	while (eid != DEVICE_MGR_NO_DEVICES_AVAILABLE) {
		eid = device_manager_get_eid_of_next_device_to_discover (attestation->device_mgr);
		if (!ROT_IS_ERROR (eid)) {
			status = attestation_requester_discover_device (attestation, eid);
			if (status == ATTESTATION_REFRESH_ROUTING_TABLE) {
				goto get_routing_table;
			}
		}
	}
#endif

	eid = 0;

	while (eid != DEVICE_MGR_NO_DEVICES_AVAILABLE) {
		eid = device_manager_get_eid_of_next_device_to_attest (attestation->device_mgr);
		if (!ROT_IS_ERROR (eid)) {
			status = attestation_requester_attest_device (attestation, eid,	HASH_TYPE_SHA256);
			if (status == ATTESTATION_REFRESH_ROUTING_TABLE) {
				goto get_routing_table;
			}
		}
	}

	status = device_manager_get_attestation_status (attestation->device_mgr, attestation_status);
	if (status == 0) {
		pcr_store_update_versioned_buffer (pcr, attestation->primary_hash, measurement,
			attestation_status, DEVICE_MANAGER_ATTESTATION_STATUS_LEN, true, measurement_version);
	}

	return;

get_routing_table:
#ifdef ATTESTATION_SUPPORT_DEVICE_DISCOVERY
	attestation_requester_get_mctp_routing_table (attestation);
#endif

	return;
}
