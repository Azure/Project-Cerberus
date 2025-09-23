// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <string.h>
#include "attestation.h"
#include "attestation_logging.h"
#include "attestation_requester.h"
#include "pcr_store.h"
#include "asn1/asn1_util.h"
#include "asn1/ecc_der_util.h"
#include "cmd_interface/cerberus_protocol.h"
#include "cmd_interface/cerberus_protocol_master_commands.h"
#include "cmd_interface/cerberus_protocol_required_commands.h"
#include "common/buffer_util.h"
#include "common/common_math.h"
#include "common/type_cast.h"
#include "common/unused.h"
#include "logging/debug_log.h"
#include "manifest/cfm/cfm_manager.h"
#include "mctp/cmd_interface_protocol_mctp.h"
#include "mctp/mctp_control_protocol.h"
#include "mctp/mctp_control_protocol_commands.h"
#include "mctp/mctp_interface.h"
#include "spdm/spdm_commands.h"
#include "spdm/spdm_discovery.h"
#include "spdm/spdm_measurements.h"
#include "spdm/spdm_protocol.h"


// Context strings used in SPDM signatures
#define SPDM_CHALLENGE_SIGNATURE_CONTEXT_STR "responder-challenge_auth signing"
#define SPDM_GET_MEASUREMENTS_SIGNATURE_CONTEXT_STR "responder-measurements signing"

/**
 * Maximum length for an SPDM message.
 */
#define	ATTESTATION_REQUESTER_MAX_SPDM_REQUEST      \
	(MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - sizeof (struct spdm_protocol_mctp_header))

/**
 * Check to see if response received is for pending Cerberus request
 *
 * @param attestation Attestation requester instance to utilize
 * @param command Command expected
 */
#define attestation_requester_check_cerberus_unexpected_rsp(attestation, command) \
	((attestation->state->txn.protocol != ATTESTATION_PROTOCOL_CERBERUS) || \
	(attestation->state->txn.requested_command != command))

/**
 * Check to see if response received is for pending SDPM request
 *
 * @param attestation Attestation requester instance to utilize
 * @param command Command expected
 */
#define attestation_requester_check_spdm_unexpected_rsp(attestation, command) \
	((attestation->state->txn.protocol != ATTESTATION_PROTOCOL_DMTF_SPDM) || \
	(attestation->state->txn.requested_command != command))

/**
 * Check to see if device version set found
 *
 * @param attestation Attestation requester instance to utilize
 */
#define attestation_requester_is_version_set_selected(attestation) \
	(attestation->state->txn.device_version_set != 0)

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
 * @param mctp_ctrl_cmd Flag indicating whether request is from MCTP control protocol.
 * @param command Requested command to send out.
 *
 * @return 0 if successful or error code otherwise
 */
static int attestation_requester_send_request_and_get_response (
	const struct attestation_requester *attestation, size_t request_len, uint8_t dest_addr,
	uint8_t dest_eid, bool crypto_timeout, bool mctp_ctrl_cmd, uint8_t command)
{
	uint32_t timeout_ms;
	uint32_t max_rsp_not_ready_timeout_ms;
	uint8_t max_rsp_not_ready_retries;
	bool rsp_ready = false;
	int device_state;
	int status;

	attestation->state->txn.request_status = ATTESTATION_REQUESTER_REQUEST_IDLE;
	attestation->state->txn.requested_command = command;

	if (mctp_ctrl_cmd) {
		timeout_ms = device_manager_get_mctp_ctrl_timeout (attestation->device_mgr);
	}
	else {
		if (crypto_timeout) {
			timeout_ms = device_manager_get_crypto_timeout_by_eid (attestation->device_mgr,
				dest_eid);
		}
		else {
			timeout_ms = device_manager_get_reponse_timeout_by_eid (attestation->device_mgr,
				dest_eid);
		}
	}

	status = device_manager_get_rsp_not_ready_limits (attestation->device_mgr,
		&max_rsp_not_ready_timeout_ms, &max_rsp_not_ready_retries);
	if (status != 0) {
		return status;
	}

	while (!rsp_ready) {
		/* Send request and await response. mctp_interface_issue_request will block till a response
		 * is received or timeout period elapses. If response is received, the notification
		 * callbacks will process response and update the request_status. */
		status = mctp_interface_issue_request (attestation->mctp, attestation->channel, dest_addr,
			dest_eid, attestation->state->txn.msg_buffer, request_len,
			attestation->state->txn.msg_buffer, sizeof (attestation->state->txn.msg_buffer),
			timeout_ms);
		if (status != 0) {
			if (status == MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT) {
				device_state = device_manager_get_device_state_by_eid (attestation->device_mgr,
					dest_eid);

				if (device_state == DEVICE_MANAGER_AUTHENTICATED) {
					device_manager_update_device_state_by_eid (attestation->device_mgr, dest_eid,
						DEVICE_MANAGER_AUTHENTICATED_WITH_TIMEOUT);
				}
				else if (device_state == DEVICE_MANAGER_AUTHENTICATED_WITHOUT_CERTS) {
					device_manager_update_device_state_by_eid (attestation->device_mgr, dest_eid,
						DEVICE_MANAGER_AUTHENTICATED_WITHOUT_CERTS_WITH_TIMEOUT);
				}
				else {
					device_manager_update_device_state_by_eid (attestation->device_mgr, dest_eid,
						DEVICE_MANAGER_ATTESTATION_INTERRUPTED);
				}
			}
			else if ((status == MCTP_BASE_PROTOCOL_ERROR_RESPONSE) ||
				(status == MCTP_BASE_PROTOCOL_FAIL_RESPONSE)) {
				device_manager_update_device_state_by_eid (attestation->device_mgr, dest_eid,
					DEVICE_MANAGER_ATTESTATION_INVALID_RESPONSE);
			}

			return status;
		}

		if (attestation->state->txn.request_status != ATTESTATION_REQUESTER_REQUEST_SUCCESSFUL) {
			device_manager_update_device_state_by_eid (attestation->device_mgr, dest_eid,
				DEVICE_MANAGER_ATTESTATION_INVALID_RESPONSE);

			return ATTESTATION_REQUEST_FAILED;
		}

		/* If SPDM, responder might send a ResponseNotReady error. The ResponseNotReady notification
		 * will set sleep_duration_ms to a non-zero value based on the error response as per the
		 * SPDM DSP0274 spec. First, sleep for the duration requested until response is ready, then
		 * send a RESPOND_IF_READY request to retrieve response to original request. */
		if (attestation->state->txn.sleep_duration_ms != 0) {
			if (max_rsp_not_ready_retries == 0) {
				device_manager_update_device_state_by_eid (attestation->device_mgr, dest_eid,
					DEVICE_MANAGER_ATTESTATION_INVALID_RESPONSE);

				return ATTESTATION_TOO_MANY_RETRIES_REQUESTED;
			}

			--max_rsp_not_ready_retries;

			attestation->state->txn.sleep_duration_ms =
				min (max_rsp_not_ready_timeout_ms, attestation->state->txn.sleep_duration_ms);
			platform_msleep (attestation->state->txn.sleep_duration_ms);
			attestation->state->txn.sleep_duration_ms = 0;

			request_len =
				spdm_generate_respond_if_ready_request (attestation->state->spdm_msg_buffer,
				ATTESTATION_REQUESTER_MAX_SPDM_REQUEST, attestation->state->txn.requested_command,
				attestation->state->txn.respond_if_ready_token,
				attestation->state->txn.spdm_minor_version);
			if (ROT_IS_ERROR ((int) request_len)) {
				return request_len;
			}

			spdm_populate_mctp_header (attestation->state->spdm_mctp);
			request_len += sizeof (struct spdm_protocol_mctp_header);
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
		digest = attestation->state->txn.msg_buffer;
	}

	if (allowable_digests->hash_type != digest_type) {
		status = ATTESTATION_CFM_INVALID_ATTESTATION;
	}
	else {
		digest_len = hash_get_hash_length (digest_type);

		for (i_digest = 0; i_digest < allowable_digests->digest_count; ++i_digest) {
			status = buffer_compare (digest, &allowable_digests->digests[offset], digest_len);
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
 * @param component_id The component ID of the device.
 * @param eid EID of device to attest.
 * @param pmr_id ID of PMR to verify.
 *
 * @return Completion status, 0 if success, CFM_PMR_DIGEST_NOT_FOUND if PMR has no entry in CFM, or
 * 	an error code otherwise
 */
static int attestation_requester_verify_pmr (const struct attestation_requester *attestation,
	const struct cfm *active_cfm, uint32_t component_id, uint8_t eid, uint8_t pmr_id)
{
	struct cfm_pmr_digest pmr_digest;
	int status;

	status = active_cfm->get_component_pmr_digest (active_cfm, component_id, pmr_id, &pmr_digest);
	if (status == 0) {
		status = attestation_requester_verify_digest_in_allowable_list (attestation,
			&pmr_digest.digests, NULL, attestation->state->txn.transcript_hash_type);

		if (status != 0) {
			device_manager_update_device_state_by_eid (attestation->device_mgr, eid,
				DEVICE_MANAGER_ATTESTATION_MEASUREMENT_MISMATCH);
		}

		active_cfm->free_component_pmr_digest (active_cfm, &pmr_digest);
	}

	return status;
}
#endif

#if defined (ATTESTATION_SUPPORT_SPDM) || defined (ATTESTATION_SUPPORT_CERBERUS_CHALLENGE)
/**
 * Update the cached certificate chain digest for a device.
 *
 * @param attestation Attestation requester processing the received digest.
 * @param device_eid EID of the device reporting the digest.
 * @param digest Reported digest of the certificate chain.
 * @param digest_length Length of the cert chain digest.
 *
 * @return 0 if the cert chain digest was updated successfully or an error code.
 */
static int attestation_requester_update_cert_chain_digest (
	const struct attestation_requester *attestation, uint8_t device_eid, const uint8_t *digest,
	size_t digest_length)
{
	const struct device_manager_key *alias_key;
	int status;

	alias_key = device_manager_get_alias_key (attestation->device_mgr, device_eid);
	if (alias_key == NULL) {
		status = device_manager_update_cert_chain_digest (attestation->device_mgr, device_eid,
			attestation->state->txn.slot_num, digest, digest_length);
	}
	else {
		status = device_manager_compare_cert_chain_digest (attestation->device_mgr, device_eid,
			digest, digest_length);
		if ((status == DEVICE_MGR_DIGEST_MISMATCH) || (status == DEVICE_MGR_DIGEST_LEN_MISMATCH)) {
			status = device_manager_clear_alias_key (attestation->device_mgr, device_eid);
			if (status != 0) {
				return status;
			}

			status = device_manager_update_cert_chain_digest (attestation->device_mgr, device_eid,
				attestation->state->txn.slot_num, digest, digest_length);
		}
	}

	return status;
}

/**
 * Verify that the root certificate is trusted.  If so, load it into the certificate store for cert
 * chain authentication.
 *
 * @param attestation Attestation requester validating the root CA.
 * @param eid EID of the device that provided the certificate.
 * @param active_cfm Active CFM being used for attestation.
 * @param component_id The component ID of the device being attested.
 * @param root_ca Certificate data for the root CA to verify.
 * @param root_ca_length Length of the root CA certificate data.
 * @param header_data Additional header data that needs to be included in the certificate chain
 * hash.  Set to null if there is no header data.
 * @param header_length Length of the additional certificate chain header.
 * @param certs_chain CA certificate storage that will be initialized and updated with the validated
 * root CA.
 *
 * @return 0 if the root cert is trusted or an error code.
 */
static int attestation_requester_verify_and_load_root_cert (
	const struct attestation_requester *attestation, uint8_t eid, const struct cfm *active_cfm,
	uint32_t component_id, const uint8_t *root_ca, size_t root_ca_length,
	const uint8_t *header_data, size_t header_length, struct x509_ca_certs *certs_chain)
{
	uint8_t digest[HASH_MAX_HASH_LEN];
	struct cfm_root_ca_digests root_ca_digests;
	const struct der_cert *local_root_ca = riot_key_manager_get_root_ca (attestation->riot);
	bool cfm_root_ca = false;
	int status;

	/* 1) If CFM has an alternate allowed root CA, make sure root CA provided by device matches
	 * 2) If CFM has no alternate root CA, and requester has no provisioned root CA, then just use
	 *    device's root CA provided. The requester with no root CA will ultimately fail
	 *    attestation but device's attestation can succeed, useful for testing.
	 * 3) If CFM has no alternate root CA, but requester has a provisioned root CA, use the
	 *    requester's root CA then skip over root CA provided by device. */
	status = active_cfm->get_root_ca_digest (active_cfm, component_id, &root_ca_digests);
	if (status == 0) {
		status = hash_calculate (attestation->primary_hash, root_ca_digests.digests.hash_type,
			root_ca, root_ca_length, digest, sizeof (digest));
		if (ROT_IS_ERROR (status)) {
			active_cfm->free_root_ca_digest (active_cfm, &root_ca_digests);

			return status;
		}

		status = attestation_requester_verify_digest_in_allowable_list (attestation,
			&root_ca_digests.digests, digest, root_ca_digests.digests.hash_type);
		if (status != 0) {
			device_manager_update_device_state_by_eid (attestation->device_mgr, eid,
				DEVICE_MANAGER_ATTESTATION_UNTRUSTED_CERTS);

			active_cfm->free_root_ca_digest (active_cfm, &root_ca_digests);

			return status;
		}

		active_cfm->free_root_ca_digest (active_cfm, &root_ca_digests);
		cfm_root_ca = true;
	}
	else if (status != CFM_ROOT_CA_NOT_FOUND) {
		return status;
	}

	status = attestation->x509->init_ca_cert_store (attestation->x509, certs_chain);
	if (status != 0) {
		return status;
	}

	if (cfm_root_ca || (local_root_ca == NULL)) {
		status = attestation->x509->add_root_ca (attestation->x509, certs_chain, root_ca,
			root_ca_length);
	}
	else {
		status = attestation->x509->add_root_ca (attestation->x509, certs_chain,
			local_root_ca->cert, local_root_ca->length);
	}

	if (status != 0) {
		goto release_cert_store;
	}

	/* Begin hashing the received certificate chain, starting with the certificate header and root
	 * certificate. */
	status = hash_start_new_hash (attestation->primary_hash,
		attestation->state->txn.transcript_hash_type);
	if (status != 0) {
		goto release_cert_store;
	}

	if (header_data != NULL) {
		status = attestation->primary_hash->update (attestation->primary_hash, header_data,
			header_length);
		if (status != 0) {
			goto cancel_hash;
		}
	}

	status = attestation->primary_hash->update (attestation->primary_hash, root_ca, root_ca_length);
	if (status != 0) {
		goto cancel_hash;
	}

	return 0;

cancel_hash:
	attestation->primary_hash->cancel (attestation->primary_hash);

release_cert_store:
	attestation->x509->release_ca_cert_store (attestation->x509, certs_chain);

	return status;
}

/**
 * Verify that a received certificate is trusted.  The trust anchor for this certificate must
 * already be present in the certificate store.  If the certificate is valid and is a CA, the
 * certificate store will be updated to make this certificate the new trust anchor for future certs.
 *
 * In error scenarios, the active hash for the current certificate chain will be cancelled and all
 * allocated certificate components will be released.
 *
 * For CA certs, the provided cert store will be valid upon successful return and the certificate
 * instance will always be released.
 * For leaf certs, the provided certificate instance will contain the parsed cert upon successful
 * return and the cert store will always be released.
 *
 * @param attestation Attestation requester validating the certificate.
 * @param eid EID of the device that provided the certificate.
 * @param cert_data Certificate data for the to verify.
 * @param cert_length Length of the certificate data.
 * @param is_leaf Flag to indicate if this is the last cert in the chain or if it's expected to be a
 * CA certificate.
 * @param cert Certificate container to use for parsing the received certificate.  This must not
 * currently be in use for a different certificate.  This will only contain a certificate upon
 * successfully verification of the leaf certificate.  In all other cases, this instance will be
 * empty.
 * @param certs_chain CA certificate storage that will be used to verify the received cert.  This
 * will be updated with the new trust anchor for CA certificates.  If verifying the leaf cert, this
 * instance will always be released upon return.
 *
 * @return 0 if the certificate was parsed and validated successfully or an error code.
 */
static int attestation_requester_verify_and_load_certificate (
	const struct attestation_requester *attestation, uint8_t eid, const uint8_t *cert_data,
	size_t cert_length, bool is_leaf, struct x509_certificate *cert,
	struct x509_ca_certs *certs_chain)
{
	int status;

	status = attestation->primary_hash->update (attestation->primary_hash, cert_data, cert_length);
	if (status != 0) {
		goto release_cert_store;
	}

	/* Authenticate the received certificate against the trusted CA already in the certificate
	 * store. */
	status = attestation->x509->load_certificate (attestation->x509, cert, cert_data, cert_length);
	if (status != 0) {
		goto release_cert_store;
	}

	status = attestation->x509->authenticate (attestation->x509, cert, certs_chain);
	if (status != 0) {
		device_manager_update_device_state_by_eid (attestation->device_mgr, eid,
			DEVICE_MANAGER_ATTESTATION_UNTRUSTED_CERTS);

		goto release_cert;
	}

	if (!is_leaf) {
		/* If this is not the last certificate in the chain, initialize a new certificate store to
		 * use for authenticating the next cert. */
		attestation->x509->release_certificate (attestation->x509, cert);
		attestation->x509->release_ca_cert_store (attestation->x509, certs_chain);

		status = attestation->x509->init_ca_cert_store (attestation->x509, certs_chain);
		if (status != 0) {
			goto cancel_hash;
		}

		status = attestation->x509->add_trusted_ca (attestation->x509, certs_chain, cert_data,
			cert_length);
		if (status != 0) {
			goto release_cert_store;
		}
	}
	else {
		/* If this is the last cert, release the cert store since it won't be needed anymore. */
		attestation->x509->release_ca_cert_store (attestation->x509, certs_chain);
	}

	return 0;

release_cert:
	attestation->x509->release_certificate (attestation->x509, cert);

release_cert_store:
	attestation->x509->release_ca_cert_store (attestation->x509, certs_chain);

cancel_hash:
	attestation->primary_hash->cancel (attestation->primary_hash);

	return status;
}

/**
 * Parse the alias key from a leaf certificate and set the alias key for the device.  This will only
 * happen if the certificate chain digest matches the expected digest.
 *
 * Upon returning from this call, in all cases, the certificate chain hash will be finished and the
 * leaf certificate instance will be released.
 *
 * @param attestation The attestation requester processing a received alias certificate.
 * @param eid EID of the device associated with the key.
 * @param digest_length Length of the certificate chain digest.
 * @param cert Certificate for the alias key.  This must have already been authenticated.  Upon
 * returning from this call, this instance will always be released.
 *
 * @return 0 if the alias key was updated successfully or an error code.
 */
static int attestation_requester_update_alias_key (const struct attestation_requester *attestation,
	uint8_t eid, size_t digest_length, struct x509_certificate *cert)
{
	uint8_t digest[HASH_MAX_HASH_LEN];
	int leaf_key_type;
	uint8_t *leaf_key;
	size_t leaf_key_len;
	int status;

	status = attestation->primary_hash->finish (attestation->primary_hash, digest, sizeof (digest));
	if (ROT_IS_ERROR (status)) {
		attestation->primary_hash->cancel (attestation->primary_hash);

		goto release_leaf_cert;
	}

	status = device_manager_compare_cert_chain_digest (attestation->device_mgr, eid, digest,
		digest_length);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_CERT_CHAIN_COMPUTED_DIGEST_MISMATCH,
			(eid << 8) | attestation->state->txn.slot_num, status);

		device_manager_update_device_state_by_eid (attestation->device_mgr, eid,
			DEVICE_MANAGER_ATTESTATION_UNTRUSTED_CERTS);

		goto release_leaf_cert;
	}

	leaf_key_type = attestation->x509->get_public_key_type (attestation->x509, cert);
	if (ROT_IS_ERROR (leaf_key_type)) {
		status = leaf_key_type;
		goto release_leaf_cert;
	}

	status = attestation->x509->get_public_key (attestation->x509, cert, &leaf_key, &leaf_key_len);
	if (status != 0) {
		goto release_leaf_cert;
	}

	status = device_manager_update_alias_key (attestation->device_mgr, eid, leaf_key, leaf_key_len,
		leaf_key_type);

	platform_free (leaf_key);

release_leaf_cert:
	attestation->x509->release_certificate (attestation->x509, cert);

	return status;
}

/**
 * Verify provided ECDSA signature using cached alias key of target device.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param signature Buffer with signature sent by target device to verify.
 * @param signature_len Length of signature.
 * @param digest Hash to be verified against the signature.
 * @param transcript_hash_len Length of the digest.
 * @param alias_key Key used to verify the signature.
 *
 * @return 0 if completed successfully, or an error code
 */
static int attestation_requester_verify_ecdsa_signature (
	const struct attestation_requester *attestation, uint8_t *signature, size_t signature_len,
	uint8_t *digest, size_t transcript_hash_len, const struct device_manager_key *alias_key)
{
	struct ecc_public_key ecc_key;
	int signature_der_len;
	uint8_t signature_der[ECC_DER_ECDSA_MAX_LENGTH];
	int status;

	// SPDM signatures are not DER encoded, encode before processing
	if (attestation->state->txn.protocol != ATTESTATION_PROTOCOL_CERBERUS) {
		signature_der_len = ecc_der_encode_ecdsa_signature (signature,
			&signature[attestation->state->txn.alias_signature_len],
			attestation->state->txn.alias_signature_len, signature_der, sizeof (signature_der));
		if (ROT_IS_ERROR (signature_der_len)) {
			return signature_der_len;
		}
	}
	else {
		memcpy (signature_der, signature, signature_len);
		signature_der_len = signature_len;
	}

	status = attestation->ecc->init_public_key (attestation->ecc, alias_key->key,
		alias_key->key_len, &ecc_key);
	if (status != 0) {
		return status;
	}

	status = attestation->ecc->verify (attestation->ecc, &ecc_key, digest, transcript_hash_len,
		signature_der, signature_der_len);

	attestation->ecc->release_key_pair (attestation->ecc, NULL, &ecc_key);

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
 *
 * @return 0 if completed successfully, or an error code
 */
static int attestation_requester_verify_signature (const struct attestation_requester *attestation,
	const struct hash_engine *hash, uint8_t eid, uint8_t *signature, size_t signature_len,
	char *spdm_context)
{
	uint8_t digest[HASH_MAX_HASH_LEN];
	const struct device_manager_key *alias_key;
	size_t transcript_hash_len =
		hash_get_hash_length (attestation->state->txn.transcript_hash_type);
	int status;

	/* TODO:  This signature verification flow does not use the ECDSA APIs so is not compatible with
	 * FIPS.  Updating this flow to use the ECDSA implementation is more complicated, so this is
	 * deferred until necessary or this piece gets refactored to make the migration easier.
	 *
	 * The same is true for RSASSA, if that's supported. */

	status = hash->finish (hash, digest, sizeof (digest));
	if (status != 0) {
		return status;
	}

	attestation->state->txn.hash_finish = true;

	// Skip signature verification for SPDM protocol when cert is not supported.
	if ((attestation->state->txn.protocol != ATTESTATION_PROTOCOL_CERBERUS) &&
		!attestation->state->txn.cert_supported) {
		return 0;
	}

#ifdef ATTESTATION_SUPPORT_SPDM
	if ((attestation->state->txn.protocol != ATTESTATION_PROTOCOL_CERBERUS) &&
		(attestation->state->txn.spdm_minor_version >= ATTESTATION_PROTOCOL_DMTF_SPDM_1_2)) {
		status = spdm_format_signature_digest (hash, attestation->state->txn.transcript_hash_type,
			attestation->state->txn.spdm_minor_version, spdm_context, digest);
		if (status != 0) {
			return status;
		}
	}
#endif

	alias_key = device_manager_get_alias_key (attestation->device_mgr, eid);
	if (alias_key == NULL) {
		return ATTESTATION_ALIAS_KEY_LOAD_FAIL;
	}

	if (alias_key->key_type == X509_PUBLIC_KEY_ECC) {
		status = attestation_requester_verify_ecdsa_signature (attestation, signature,
			signature_len, digest, transcript_hash_len, alias_key);

		/* The endianess of the signature is not clearly declared in the SPDM 1.0 and 1.1
		 * specification. It's not possible to programmatically identify the endianess used.
		 * To cover the case where the signature fails due to the endianess,
		 * this code swaps the signature endianess, and retries the verification. */
		if ((status == ECC_ENGINE_BAD_SIGNATURE) &&
			(attestation->state->txn.spdm_minor_version < ATTESTATION_PROTOCOL_DMTF_SPDM_1_2) &&
			(attestation->state->txn.protocol != ATTESTATION_PROTOCOL_CERBERUS)) {
			buffer_reverse (signature, signature_len / 2);
			buffer_reverse (signature + (signature_len / 2), signature_len / 2);

			status = attestation_requester_verify_ecdsa_signature (attestation, signature,
				signature_len, digest, transcript_hash_len, alias_key);
		}
	}
#ifdef ATTESTATION_SUPPORT_RSA_CHALLENGE
	else if ((alias_key->key_type == X509_PUBLIC_KEY_RSA) && (attestation->rsa != NULL)) {
		struct rsa_public_key rsa_key;

		status = attestation->rsa->init_public_key (attestation->rsa, &rsa_key, alias_key->key,
			alias_key->key_len);
		if (status != 0) {
			return status;
		}

		status = attestation->rsa->sig_verify (attestation->rsa, &rsa_key, signature, signature_len,
			HASH_TYPE_SHA256, digest, transcript_hash_len);
	}
#endif
	else {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_ALIAS_KEY_TYPE_UNSUPPORTED, eid, alias_key->key_type);

		return ATTESTATION_UNSUPPORTED_ALGORITHM;
	}

	return status;
}
#endif

#ifdef ATTESTATION_SUPPORT_SPDM
/**
 * SPDM get version response post processing function.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param device_eid EID of device to utilize.
 *
 * @return Completion status, 0 if success or an error code otherwise
 */
static int attestation_requester_get_version_rsp_post_processing (
	const struct attestation_requester *attestation, uint8_t device_eid)
{
	struct spdm_get_version_response *rsp =
		(struct spdm_get_version_response*) attestation->state->txn.msg_buffer;
	struct spdm_version_num_entry *version_table = spdm_get_version_resp_version_table (rsp);
	uint8_t minor_version = SPDM_MIN_MINOR_VERSION;
	bool found = false;
	int i_version;

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
		attestation->state->txn.spdm_minor_version =
			(enum attestation_spdm_minor_version) minor_version;
		attestation->state->txn.protocol =
			(enum attestation_protocol) ATTESTATION_PROTOCOL_DMTF_SPDM;

		return 0;
	}

	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
		ATTESTATION_LOGGING_DEVICE_NOT_INTEROPERABLE, device_eid, 0);

	return ATTESTATION_DEVICE_NOT_INTEROPERABLE;
}

/**
 * SPDM get capabilities response post processing function.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param device_eid EID of device to utilize.
 *
 * @return Completion status, 0 if success or an error code otherwise
 */
static int attestation_requester_get_capabilities_rsp_post_processing (
	const struct attestation_requester *attestation, uint8_t device_eid)
{
	struct spdm_get_capabilities *rsp =
		(struct spdm_get_capabilities*) attestation->state->txn.msg_buffer;
	struct device_manager_full_capabilities capabilities;
	uint8_t ct_exponent;
	int device_num;
	int status;

	/* Device is assumed to either support, or eventually support after a FW update, minimum
	 * capabilities needed to complete attestation since it is included in CFM. If device does not,
	 * attestation will fail but will continue to retry until an expected FW adds required
	 * support. */

	attestation->state->txn.cert_supported = rsp->base_capabilities.flags.cert_cap;

	if (!rsp->base_capabilities.flags.meas_cap) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_MEASUREMENT_CAP_NOT_SUPPORTED, device_eid,
			*((uint32_t*) &rsp->base_capabilities.flags));

		return ATTESTATION_GET_MEAS_NOT_SUPPORTED_BY_DEVICE;
	}

	if (attestation->state->txn.cert_supported) {
		if (rsp->base_capabilities.flags.meas_cap !=
			SPDM_MEASUREMENT_RSP_CAP_MEASUREMENTS_WITH_SIG) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
				ATTESTATION_LOGGING_GET_MEASUREMENT_CAP_MISMATCH_ERROR, device_eid,
				*((uint32_t*) &rsp->base_capabilities.flags));

			return ATTESTATION_GET_MEAS_CAP_MISMATCH_BY_DEVICE;
		}
	}
	else {
		if (rsp->base_capabilities.flags.meas_cap !=
			SPDM_MEASUREMENT_RSP_CAP_MEASUREMENTS_WITHOUT_SIG) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
				ATTESTATION_LOGGING_GET_MEASUREMENT_CAP_MISMATCH_ERROR, device_eid,
				*((uint32_t*) &rsp->base_capabilities.flags));

			return ATTESTATION_GET_MEAS_CAP_MISMATCH_BY_DEVICE;
		}

		if (rsp->base_capabilities.flags.chal_cap) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
				ATTESTATION_LOGGING_CHALLENGE_CAP_MISMATCH_ERROR, device_eid,
				*((uint32_t*) &rsp->base_capabilities.flags));

			return ATTESTATION_CHAL_CAP_MISMATCH_BY_DEVICE;
		}
	}

	attestation->state->txn.challenge_supported = rsp->base_capabilities.flags.chal_cap;

	if (attestation->state->txn.device_discovery) {
		return 0;
	}

	device_num = device_manager_get_device_num (attestation->device_mgr, device_eid);
	if (ROT_IS_ERROR (device_num)) {
		return device_num;
	}

	status = device_manager_get_device_capabilities (attestation->device_mgr, device_num,
		&capabilities);
	if (status != 0) {
		return status;
	}

	/* Limit maximum cryptographic timeout period of responder to prevent overflows. This
	 * assumes 25.5 seconds is plenty of time, so if a device responds with a timeout longer
	 * than that, we will fail attestation at 25.5s even if device thinks it has more time to
	 * respond. */
	ct_exponent = (rsp->base_capabilities.ct_exponent > 24) ? 24 :
			rsp->base_capabilities.ct_exponent;

	capabilities.max_timeout = device_manager_set_timeout_ms (SPDM_MAX_RESPONSE_TIMEOUT_MS);
	capabilities.max_sig =
		device_manager_set_crypto_timeout_ms (spdm_capabilities_rsp_ct_to_ms (ct_exponent));

	if (rsp->base_capabilities.header.spdm_minor_version > 1) {
		capabilities.request.max_message_size = rsp->data_transfer_size;
	}
	else {
		capabilities.request.max_message_size = SPDM_1_0_AND_1_1_MAX_RESPONSE_LEN;
	}

	return device_manager_update_device_capabilities (attestation->device_mgr, device_num,
		&capabilities);
}

/**
 * SPDM negotiate algorithms response post processing function.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param device_eid EID of device to utilize.
 *
 * @return Completion status, 0 if success or an error code otherwise
 */
static int attestation_requester_negotiate_algorithms_rsp_post_processing (
	const struct attestation_requester *attestation, uint8_t device_eid)
{
	struct spdm_negotiate_algorithms_response *rsp =
		(struct spdm_negotiate_algorithms_response*) attestation->state->txn.msg_buffer;

	// Currently, only SPDM measurement blocks following the DMTF format are supported
	if (rsp->measurement_specification != SPDM_MEASUREMENT_SPEC_DMTF) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_MEASUREMENT_SPEC_UNSUPPORTED, device_eid,
			rsp->measurement_specification);

		return ATTESTATION_UNSUPPORTED_MEASUREMENT_SPEC;
	}

	if (attestation->state->txn.cert_supported) {
		if (rsp->base_asym_sel == SPDM_TPM_ALG_ECDSA_ECC_NIST_P256) {
			attestation->state->txn.alias_signature_len = ECC_KEY_LENGTH_256;
		}
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
		else if (rsp->base_asym_sel == SPDM_TPM_ALG_ECDSA_ECC_NIST_P384) {
			attestation->state->txn.alias_signature_len = ECC_KEY_LENGTH_384;
		}
#endif
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
		else if (rsp->base_asym_sel == SPDM_TPM_ALG_ECDSA_ECC_NIST_P521) {
			attestation->state->txn.alias_signature_len = ECC_KEY_LENGTH_521;
		}
#endif
		else {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
				ATTESTATION_LOGGING_BASE_ASYM_KEY_SIG_ALG_UNSUPPORTED, device_eid,
				rsp->base_asym_sel);

			return ATTESTATION_UNSUPPORTED_ALGORITHM;
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
				ATTESTATION_LOGGING_HASHING_ALGORITHM_UNSUPPORTED, device_eid, rsp->base_hash_sel);

			return ATTESTATION_UNSUPPORTED_ALGORITHM;
		}
	}
	else {
		/* DSP0274 SPDM spec indicates base_asym_sel and base_hash_sel shall be 0 if they are not
		 * supported by the device. */
		if (rsp->base_asym_sel != 0) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
				ATTESTATION_LOGGING_BASE_ASYM_KEY_SIG_ALG_UNSUPPORTED, device_eid,
				rsp->base_asym_sel);

			return ATTESTATION_UNSUPPORTED_ALGORITHM;
		}

		if (rsp->base_hash_sel != 0) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
				ATTESTATION_LOGGING_HASHING_ALGORITHM_UNSUPPORTED, device_eid, rsp->base_hash_sel);

			return ATTESTATION_UNSUPPORTED_ALGORITHM;
		}
	}

	if ((rsp->measurement_hash_algo != SPDM_MEAS_RSP_TPM_ALG_SHA_256) &&
		(rsp->measurement_hash_algo != SPDM_MEAS_RSP_TPM_ALG_SHA_384) &&
		(rsp->measurement_hash_algo != SPDM_MEAS_RSP_TPM_ALG_SHA_512)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_HASHING_MEAS_ALGORITHM_UNSUPPORTED, device_eid,
			rsp->measurement_hash_algo);

		return ATTESTATION_UNSUPPORTED_ALGORITHM;
	}

	if (!attestation->state->txn.device_discovery) {
		if (attestation->state->txn.cert_supported) {
			if (((rsp->base_hash_sel == SPDM_TPM_ALG_SHA_256) &&
				(attestation->state->txn.transcript_hash_type != HASH_TYPE_SHA256)) ||
				((rsp->base_hash_sel == SPDM_TPM_ALG_SHA_384) &&
				(attestation->state->txn.transcript_hash_type != HASH_TYPE_SHA384)) ||
				((rsp->base_hash_sel == SPDM_TPM_ALG_SHA_512) &&
				(attestation->state->txn.transcript_hash_type != HASH_TYPE_SHA512))) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
					ATTESTATION_LOGGING_UNEXPECTED_HASH_ALGO_IN_RSP, device_eid,
					rsp->base_hash_sel);

				return ATTESTATION_UNEXPECTED_ALG_IN_RESPONSE;
			}
		}

		if (((rsp->measurement_hash_algo == SPDM_MEAS_RSP_TPM_ALG_SHA_256) &&
			(attestation->state->txn.measurement_hash_type != HASH_TYPE_SHA256)) ||
			((rsp->measurement_hash_algo == SPDM_MEAS_RSP_TPM_ALG_SHA_384) &&
			(attestation->state->txn.measurement_hash_type != HASH_TYPE_SHA384)) ||
			((rsp->measurement_hash_algo == SPDM_MEAS_RSP_TPM_ALG_SHA_512) &&
			(attestation->state->txn.measurement_hash_type != HASH_TYPE_SHA512))) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
				ATTESTATION_LOGGING_UNEXPECTED_MEAS_HASH_ALGO_IN_RSP, device_eid,
				rsp->measurement_hash_algo);

			return ATTESTATION_UNEXPECTED_ALG_IN_RESPONSE;
		}
	}

	return 0;
}

/**
 * SPDM get digests response post processing function.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param device_eid EID of device to utilize.
 *
 * @return Completion status, 0 if success or an error code otherwise
 */
static int attestation_requester_get_digests_rsp_post_processing (
	const struct attestation_requester *attestation, uint8_t device_eid)
{
	struct spdm_get_digests_response *rsp =
		(struct spdm_get_digests_response*) attestation->state->txn.msg_buffer;
	size_t transcript_hash_len;
	size_t rsp_len;
	uint8_t *digest;
	int status;

	transcript_hash_len = hash_get_hash_length (attestation->state->txn.transcript_hash_type);

	rsp_len = spdm_get_digests_resp_length (rsp, transcript_hash_len);

	if (attestation->state->txn.msg_buffer_len != rsp_len) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_RSP_LEN, (device_eid << 8) | SPDM_RESPONSE_GET_DIGESTS,
			((uint16_t) rsp_len) << 16 | ((uint16_t) device_eid));

		return ATTESTATION_BAD_LENGTH;
	}

	if ((rsp->slot_mask & (1 << attestation->state->txn.slot_num)) == 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_SLOT_NUMBER_EMPTY, device_eid,
			(attestation->state->txn.slot_num << 8) | rsp->slot_mask);

		status = ATTESTATION_REQUESTED_SLOT_NUM_EMPTY;
	}
	else {
		digest = spdm_get_digests_resp_digest (rsp, attestation->state->txn.slot_num,
			transcript_hash_len);

		status = attestation_requester_update_cert_chain_digest (attestation, device_eid, digest,
			transcript_hash_len);
	}

	return status;
}

/**
 * SPDM get certificate response post processing function.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param device_eid EID of device to utilize.
 *
 * @return Completion status, 0 if success or an error code otherwise
 */
static int attestation_requester_get_certificate_rsp_post_processing (
	const struct attestation_requester *attestation, uint8_t device_eid)
{
	struct spdm_get_certificate_response *rsp =
		(struct spdm_get_certificate_response*) attestation->state->txn.msg_buffer;

	if (rsp->slot_num != attestation->state->txn.slot_num) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_SLOT_NUM_IN_RSP, device_eid,
			(attestation->state->txn.slot_num << 8) | rsp->slot_num);

		return ATTESTATION_UNEXPECTED_SLOT_NUM;
	}

	return 0;
}

/**
 * SPDM challenge response post processing function.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param eid EID of device to utilize.
 *
 * @return Completion status, 0 if success or an error code otherwise
 */
static int attestation_requester_spdm_challenge_rsp_post_processing (
	const struct attestation_requester *attestation, uint8_t device_eid)
{
	struct spdm_challenge_response *rsp =
		(struct spdm_challenge_response*) attestation->state->txn.msg_buffer;
	size_t transcript_hash_len =
		hash_get_hash_length (attestation->state->txn.transcript_hash_type);
	int status;

	if (rsp->slot_num != attestation->state->txn.slot_num) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_SLOT_NUM_IN_RSP, device_eid,
			(attestation->state->txn.slot_num << 8) | rsp->slot_num);

		return ATTESTATION_UNEXPECTED_SLOT_NUM;
	}

	if (rsp->basic_mutual_auth_req) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_TARGET_REQ_UNSUPPORTED_MUTUAL_AUTH, device_eid, 0);

		return ATTESTATION_UNSUPPORTED_OPERATION;
	}

	if ((rsp->slot_mask & (1 << attestation->state->txn.slot_num)) == 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_SLOT_NUMBER_EMPTY, device_eid,
			(attestation->state->txn.slot_num << 8) | rsp->slot_mask);

		return ATTESTATION_REQUESTED_SLOT_NUM_EMPTY;
	}

	if (attestation->state->txn.msg_buffer_len <=
		spdm_get_challenge_resp_length (rsp, transcript_hash_len, transcript_hash_len)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_RSP_LEN, (device_eid << 8) | SPDM_RESPONSE_CHALLENGE,
			(((uint16_t) (spdm_get_challenge_resp_length (rsp, transcript_hash_len,
				transcript_hash_len))) << 16) |
					((uint16_t) attestation->state->txn.msg_buffer_len));

		return ATTESTATION_BAD_LENGTH;
	}

	status = device_manager_compare_cert_chain_digest (attestation->device_mgr, device_eid,
		spdm_get_challenge_resp_cert_chain_hash (rsp), transcript_hash_len);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_CERT_CHAIN_DIGEST_MISMATCH, device_eid, rsp->slot_num);
	}

	return status;
}

/**
 * SPDM get measurements response post processing function.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param eid EID of device to utilize.
 *
 * @return Completion status, 0 if success or an error code otherwise
 */
static int attestation_requester_spdm_get_measurements_rsp_post_processing (
	const struct attestation_requester *attestation, uint8_t device_eid)
{
	struct spdm_get_measurements_response *rsp =
		(struct spdm_get_measurements_response*) attestation->state->txn.msg_buffer;

	// If Get Measurement request was not for all blocks, then only one block should be in response
	if ((attestation->state->txn.measurement_operation_requested !=
		SPDM_MEASUREMENT_OPERATION_GET_ALL_BLOCKS) &&
		!attestation->state->txn.device_discovery && (rsp->number_of_blocks != 1)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_NUM_MEASUREMENT_BLOCKS, device_eid,
			(1 << 8) | rsp->number_of_blocks);

		return ATTESTATION_UNEXPECTED_NUM_MEAS_BLOCKS;
	}

	if (rsp->slot_id != attestation->state->txn.slot_num) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_SLOT_NUM_IN_RSP, device_eid,
			(attestation->state->txn.slot_num << 8) | rsp->slot_id);

		return ATTESTATION_UNEXPECTED_SLOT_NUM;
	}

	if (attestation->state->txn.measurement_operation_requested ==
		SPDM_MEASUREMENT_OPERATION_GET_NUM_BLOCKS) {
		attestation->state->txn.msg_buffer[0] = rsp->num_measurement_indices;
		attestation->state->txn.msg_buffer_len = 1;
	}

	return 0;
}

/**
 * Send MCTP message transport request command and get response for MCTP control.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param transport The Message transport instance used to send the messages.
 * @param request Request to process.
 * @param response The response container received.
 * @param dest_eid EID of destination device.
 * @param timeout_ms Timeout period in milliseconds to wait for response to be received.
 * @param command Requested command to send out.
 *
 * @return Initialization status, 0 if success or an error code.
 */
static int attestation_requester_send_mctp_control_msg_transport_request_and_get_response (
	const struct attestation_requester *attestation, const struct msg_transport *transport,
	struct cmd_interface_msg *request, struct cmd_interface_msg *response, uint8_t dest_eid,
	uint32_t timeout_ms, uint8_t command)
{
	struct mctp_control_protocol_resp_header *resp_header;
	int device_state;
	int status;

	attestation->state->txn.request_status = ATTESTATION_REQUESTER_REQUEST_IDLE;
	attestation->state->txn.requested_command = command;

	status = transport->send_request_message (transport, request, timeout_ms, response);
	if (status != 0) {
		if (status == MSG_TRANSPORT_REQUEST_TIMEOUT) {
			device_state = device_manager_get_device_state_by_eid (attestation->device_mgr,
				dest_eid);

			if (device_state == DEVICE_MANAGER_AUTHENTICATED) {
				device_manager_update_device_state_by_eid (attestation->device_mgr, dest_eid,
					DEVICE_MANAGER_AUTHENTICATED_WITH_TIMEOUT);
			}
			else if (device_state == DEVICE_MANAGER_AUTHENTICATED_WITHOUT_CERTS) {
				device_manager_update_device_state_by_eid (attestation->device_mgr, dest_eid,
					DEVICE_MANAGER_AUTHENTICATED_WITHOUT_CERTS_WITH_TIMEOUT);
			}
			else {
				device_manager_update_device_state_by_eid (attestation->device_mgr, dest_eid,
					DEVICE_MANAGER_ATTESTATION_INTERRUPTED);
			}
		}
		else if (status == MSG_TRANSPORT_UNEXPECTED_RESPONSE) {
			device_manager_update_device_state_by_eid (attestation->device_mgr, dest_eid,
				DEVICE_MANAGER_ATTESTATION_INVALID_RESPONSE);
		}

		return status;
	}

	resp_header = (struct mctp_control_protocol_resp_header*) response->payload;
	if ((resp_header->completion_code != MCTP_CONTROL_PROTOCOL_SUCCESS) ||
		(attestation->state->txn.requested_command != resp_header->header.command_code)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_RESPONSE_RECEIVED, response->source_eid,
			((attestation->state->txn.protocol << 24) |
						(attestation->state->txn.requested_command << 16)) | (255 << 8) |
				resp_header->header.command_code);
		device_manager_update_device_state_by_eid (attestation->device_mgr, dest_eid,
			DEVICE_MANAGER_ATTESTATION_INVALID_RESPONSE);

		return ATTESTATION_REQUEST_FAILED;
	}

	return status;
}

/**
 * Function to send SPDM request and wait for a response.  This function assumes a pregenerated
 * request is in attestation_requester's spdm_msg_buffer.  If request is not part of device
 * discovery, the request is added to the transcript hash.
 *
 * The MCTP header will be added to the message before sending the request.
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
static int attestation_requester_send_spdm_request_and_get_response (
	const struct attestation_requester *attestation, size_t request_len, uint8_t dest_addr,
	uint8_t dest_eid, bool crypto_timeout, uint8_t command)
{
	struct spdm_challenge_response *challenge_rsp =
		(struct spdm_challenge_response*) attestation->state->txn.msg_buffer;
	struct spdm_get_measurements_response *get_meas_rsp =
		(struct spdm_get_measurements_response*) attestation->state->txn.msg_buffer;
	size_t transcript_hash_len =
		hash_get_hash_length (attestation->state->txn.transcript_hash_type);
	size_t rsp_to_hash_len;
	int status;

	/* If performing device discovery, Get Measurements is not required to provide a signed response
	 * thus transcript hashing is not necessary. */
	if (!attestation->state->txn.device_discovery) {
		// Transcript hashing should not include the MCTP message header.
		status = attestation->secondary_hash->update (attestation->secondary_hash,
			attestation->state->spdm_msg_buffer, request_len);
		if (ROT_IS_ERROR (status)) {
			return status;
		}
	}

	spdm_populate_mctp_header (attestation->state->spdm_mctp);
	request_len += 1;

	status = attestation_requester_send_request_and_get_response (attestation, request_len,
		dest_addr, dest_eid, crypto_timeout, false, command);
	if (status != 0) {
		return status;
	}

	rsp_to_hash_len = attestation->state->txn.msg_buffer_len;

	switch (command) {
		case SPDM_REQUEST_GET_VERSION:
			status = attestation_requester_get_version_rsp_post_processing (attestation, dest_eid);

			if (status != 0) {
				device_manager_update_device_state_by_eid (attestation->device_mgr, dest_eid,
					DEVICE_MANAGER_ATTESTATION_INVALID_VERSION);
			}
			break;

		case SPDM_REQUEST_GET_CAPABILITIES:
			status = attestation_requester_get_capabilities_rsp_post_processing (attestation,
				dest_eid);

			if (status != 0) {
				device_manager_update_device_state_by_eid (attestation->device_mgr, dest_eid,
					DEVICE_MANAGER_ATTESTATION_INVALID_CAPS);
			}
			break;

		case SPDM_REQUEST_NEGOTIATE_ALGORITHMS:
			status = attestation_requester_negotiate_algorithms_rsp_post_processing (attestation,
				dest_eid);

			if (status != 0) {
				device_manager_update_device_state_by_eid (attestation->device_mgr, dest_eid,
					DEVICE_MANAGER_ATTESTATION_INVALID_ALGORITHM);
			}
			break;

		case SPDM_REQUEST_GET_DIGESTS:
			status = attestation_requester_get_digests_rsp_post_processing (attestation, dest_eid);

			if (status != 0) {
				device_manager_update_device_state_by_eid (attestation->device_mgr, dest_eid,
					DEVICE_MANAGER_ATTESTATION_INVALID_DIGESTS);
			}
			break;

		case SPDM_REQUEST_GET_CERTIFICATE:
			status = attestation_requester_get_certificate_rsp_post_processing (attestation,
				dest_eid);

			if (status != 0) {
				device_manager_update_device_state_by_eid (attestation->device_mgr, dest_eid,
					DEVICE_MANAGER_ATTESTATION_INVALID_CERTS);
			}
			break;

		case SPDM_REQUEST_CHALLENGE:
			status = attestation_requester_spdm_challenge_rsp_post_processing (attestation,
				dest_eid);

			if (status != 0) {
				device_manager_update_device_state_by_eid (attestation->device_mgr, dest_eid,
					DEVICE_MANAGER_ATTESTATION_INVALID_CHALLENGE);
			}

			rsp_to_hash_len = spdm_get_challenge_resp_length (challenge_rsp, transcript_hash_len,
				transcript_hash_len);

			break;

		case SPDM_REQUEST_GET_MEASUREMENTS:
			status = attestation_requester_spdm_get_measurements_rsp_post_processing (attestation,
				dest_eid);

			if (status != 0) {
				device_manager_update_device_state_by_eid (attestation->device_mgr, dest_eid,
					DEVICE_MANAGER_ATTESTATION_INVALID_MEASUREMENT);
			}

			rsp_to_hash_len = spdm_get_measurements_resp_length (get_meas_rsp);

			break;
	}

	if (status != 0) {
		return status;
	}

	if (attestation->state->txn.device_discovery) {
		return 0;
	}

	return attestation->secondary_hash->update (attestation->secondary_hash,
		attestation->state->txn.msg_buffer, rsp_to_hash_len);
}
#endif

#ifdef ATTESTATION_SUPPORT_SPDM
/**
 * Copy received response to internal buffer.
 *
 * @param observer The observer instance being notified.
 * @param response The response container received.
 * @param command Incoming command.
 */
static void attestation_requester_copy_spdm_response (const struct spdm_protocol_observer *observer,
	const struct cmd_interface_msg *response, uint8_t command)
{
	const struct attestation_requester *attestation =
		TO_DERIVED_TYPE (observer, const struct attestation_requester, spdm_rsp_observer);

	if (attestation_requester_check_spdm_unexpected_rsp (attestation, command)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_RESPONSE_RECEIVED, response->source_eid,
			((attestation->state->txn.protocol << 24) |
						(attestation->state->txn.requested_command << 16) |
						(ATTESTATION_PROTOCOL_DMTF_SPDM << 8) |	command));

		attestation->state->txn.request_status = ATTESTATION_REQUESTER_REQUEST_RSP_FAIL;

		return;
	}

	memcpy (attestation->state->txn.msg_buffer, response->payload, response->payload_length);
	attestation->state->txn.msg_buffer_len = response->payload_length;
	attestation->state->txn.request_status = ATTESTATION_REQUESTER_REQUEST_SUCCESSFUL;
}

/**
 * SPDM get version response observer function. The Get Version request/response interaction
 * determines the highest SPDM version both devices support, and then subsequent transactions with
 * the device uses the determined version.
 */
void attestation_requester_on_spdm_get_version_response (
	const struct spdm_protocol_observer *observer, const struct cmd_interface_msg *response)
{
	attestation_requester_copy_spdm_response (observer, response, SPDM_REQUEST_GET_VERSION);
}

/**
 * SPDM get capabilities response observer function. The Get Capabilities request/response
 * interaction allows both devices to know the level of support for non-required SPDM commands in
 * the other device, as well as timeout and message size capabilities.
 */
void attestation_requester_on_spdm_get_capabilities_response (
	const struct spdm_protocol_observer *observer, const struct cmd_interface_msg *response)
{
	attestation_requester_copy_spdm_response (observer, response, SPDM_REQUEST_GET_CAPABILITIES);
}

/**
 * SPDM negotiate algorithms response observer function. The Negotiate Algorithms request/response
 * interaction allows both devices to select common hashing and asymmetric cryptographic algorithms
 * to utilize in subsequent SPDM interactions.
 */
void attestation_requester_on_spdm_negotiate_algorithms_response (
	const struct spdm_protocol_observer *observer, const struct cmd_interface_msg *response)
{
	attestation_requester_copy_spdm_response (observer, response,
		SPDM_REQUEST_NEGOTIATE_ALGORITHMS);
}

/**
 * SPDM get digests response observer function. The Get Digests request/response interaction allows
 * the requester to retrieve certificate chain digests from the responder. The digests will then be
 * compared to the requesters certificate chain cache for the device being attested, and in case of
 * a mismatch, the requester will fetch new certificate chain from device.
 */
void attestation_requester_on_spdm_get_digests_response (
	const struct spdm_protocol_observer *observer, const struct cmd_interface_msg *response)
{
	attestation_requester_copy_spdm_response (observer, response, SPDM_REQUEST_GET_DIGESTS);
}

/**
 * SPDM get certificate response observer function. The Get Certificate request/response interaction
 * is used for the requester to retrieve certificate chain to be used for attestation from
 * responder.
 */
void attestation_requester_on_spdm_get_certificate_response (
	const struct spdm_protocol_observer *observer, const struct cmd_interface_msg *response)
{
	attestation_requester_copy_spdm_response (observer, response, SPDM_REQUEST_GET_CERTIFICATE);
}

/**
 * SPDM challenge response observer function. The Challenge request/response interaction allows the
 * requester to authenticate the responder through the challenge-response protocol by validating the
 * transcript signature and comparing the measurement summary hash to CFM contents.
 */
void attestation_requester_on_spdm_challenge_response (
	const struct spdm_protocol_observer *observer, const struct cmd_interface_msg *response)
{
	attestation_requester_copy_spdm_response (observer, response, SPDM_REQUEST_CHALLENGE);
}

/**
 * SPDM get measurements response observer function. The Get Measurements request/response
 * interaction allows the requester to retrieve measurement blocks from the responder, then
 * authenticate the responder through validating the transcript signature and comparing the
 * measurement blocks to CFM contents.
 */
void attestation_requester_on_spdm_get_measurements_response (
	const struct spdm_protocol_observer *observer, const struct cmd_interface_msg *response)
{
	attestation_requester_copy_spdm_response (observer, response, SPDM_REQUEST_GET_MEASUREMENTS);
}

/**
 * SPDM ResponseNotReady error observer function. If original request command code allows
 * ResponseNotReady, wait for RDT duration then issue RESPOND_IF_READY request.
 */
void attestation_requester_on_spdm_response_not_ready (
	const struct spdm_protocol_observer *observer, const struct cmd_interface_msg *response)
{
	const struct attestation_requester *attestation =
		TO_DERIVED_TYPE (observer, const struct attestation_requester, spdm_rsp_observer);
	struct spdm_error_response *rsp = (struct spdm_error_response*) response->payload;
	struct spdm_error_response_not_ready *rsp_not_ready =
		(struct spdm_error_response_not_ready*) spdm_get_spdm_error_rsp_optional_data (rsp);
	uint8_t rdt_exponent;

	if (attestation->state->txn.protocol != ATTESTATION_PROTOCOL_DMTF_SPDM) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_RESPONSE_RECEIVED, response->source_eid,
			((attestation->state->txn.protocol << 24) |
						(attestation->state->txn.requested_command << 16) |
						(ATTESTATION_PROTOCOL_DMTF_SPDM << 8) |	SPDM_RESPONSE_ERROR));
		goto fail;
	}

	// DSP0274 SPDM spec indicates these commands cannot respond with ResponseNotReady
	if ((attestation->state->txn.requested_command == SPDM_REQUEST_GET_VERSION) ||
		(attestation->state->txn.requested_command == SPDM_REQUEST_GET_CAPABILITIES) ||
		(attestation->state->txn.requested_command == SPDM_REQUEST_NEGOTIATE_ALGORITHMS)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_ILLEGAL_RSP_NOT_READY, response->source_eid,
			attestation->state->txn.requested_command);
		goto fail;
	}

	if (rsp_not_ready->request_code != attestation->state->txn.requested_command) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_RQ_CODE_IN_RSP, response->source_eid,
			(attestation->state->txn.requested_command << 8) | rsp_not_ready->request_code);
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

	attestation->state->txn.sleep_duration_ms = 1 + ((1 << rdt_exponent) / 1000);
	attestation->state->txn.respond_if_ready_token = rsp_not_ready->token;
	attestation->state->txn.request_status = ATTESTATION_REQUESTER_REQUEST_SUCCESSFUL;

	return;

fail:
	attestation->state->txn.request_status = ATTESTATION_REQUESTER_REQUEST_RSP_FAIL;
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
	const struct cerberus_protocol_observer *observer, const struct cmd_interface_msg *response)
{
	const struct attestation_requester *attestation =
		TO_DERIVED_TYPE (observer, const struct attestation_requester, cerberus_rsp_observer);
	struct cerberus_protocol_get_certificate_digest_response *rsp =
		(struct cerberus_protocol_get_certificate_digest_response*) response->payload;

	if (attestation_requester_check_cerberus_unexpected_rsp (attestation,
		CERBERUS_PROTOCOL_GET_DIGEST)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_RESPONSE_RECEIVED, response->source_eid,
			((attestation->state->txn.protocol << 24) |
						(attestation->state->txn.requested_command << 16) |
						(ATTESTATION_PROTOCOL_CERBERUS << 8) | CERBERUS_PROTOCOL_GET_DIGEST));
		attestation->state->txn.request_status = ATTESTATION_REQUESTER_REQUEST_RSP_FAIL;

		return;
	}

	memcpy (attestation->state->txn.msg_buffer, cerberus_protocol_certificate_digests (rsp),
		SHA256_HASH_LENGTH * rsp->num_digests);
	attestation->state->txn.msg_buffer_len = SHA256_HASH_LENGTH * rsp->num_digests;
	attestation->state->txn.request_status = ATTESTATION_REQUESTER_REQUEST_SUCCESSFUL;

	return;
}

/**
 * Cerberus Challenge get certificate response observer function. The Get Certificate
 * request/response interaction is used for the requester to retrieve certificate chain to be used
 * for attestation from responder.
 */
void attestation_requester_on_cerberus_get_certificate_response (
	const struct cerberus_protocol_observer *observer, const struct cmd_interface_msg *response)
{
	const struct attestation_requester *attestation =
		TO_DERIVED_TYPE (observer, const struct attestation_requester, cerberus_rsp_observer);
	struct cerberus_protocol_get_certificate_response *rsp =
		(struct cerberus_protocol_get_certificate_response*) response->payload;
	size_t cert_portion_len;

	if (attestation_requester_check_cerberus_unexpected_rsp (attestation,
		CERBERUS_PROTOCOL_GET_CERTIFICATE)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_RESPONSE_RECEIVED, response->source_eid,
			((attestation->state->txn.protocol << 24) |
						(attestation->state->txn.requested_command << 16) |
						(ATTESTATION_PROTOCOL_CERBERUS << 8) | CERBERUS_PROTOCOL_GET_CERTIFICATE));
		goto fail;
	}

	if (rsp->slot_num != attestation->state->txn.slot_num) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_SLOT_NUM_IN_RSP, response->source_eid,
			(attestation->state->txn.slot_num << 8) | rsp->slot_num);
		goto fail;
	}

	cert_portion_len =
		cerberus_protocol_get_certificate_response_cert_length (response->payload_length);

	/* TODO:  Is there a better error that could be reported here? */
	if (cert_portion_len > sizeof (attestation->state->txn.msg_buffer)) {
		goto fail;
	}

	memcpy (attestation->state->txn.msg_buffer, cerberus_protocol_certificate (rsp),
		cert_portion_len);
	attestation->state->txn.msg_buffer_len = cert_portion_len;
	attestation->state->txn.request_status = ATTESTATION_REQUESTER_REQUEST_SUCCESSFUL;

	return;

fail:
	attestation->state->txn.request_status = ATTESTATION_REQUESTER_REQUEST_RSP_FAIL;
}

/**
 * Cerberus Challenge challenge response observer function. The Challenge request/response
 * interaction allows the requester to authenticate the responder by validating the response
 * signature and comparing the device PMR0 to CFM contents.
 */
void attestation_requester_on_cerberus_challenge_response (
	const struct cerberus_protocol_observer *observer, const struct cmd_interface_msg *response)
{
	const struct attestation_requester *attestation =
		TO_DERIVED_TYPE (observer, const struct attestation_requester, cerberus_rsp_observer);
	struct cerberus_protocol_challenge_response *rsp =
		(struct cerberus_protocol_challenge_response*) response->payload;

	if (attestation_requester_check_cerberus_unexpected_rsp (attestation,
		CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_RESPONSE_RECEIVED, response->source_eid,
			((attestation->state->txn.protocol << 24) |
						(attestation->state->txn.requested_command << 16) |
						(ATTESTATION_PROTOCOL_CERBERUS <<
						8) | CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE));
		goto fail;
	}

	if (rsp->challenge.slot_num != attestation->state->txn.slot_num) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_SLOT_NUM_IN_RSP, response->source_eid,
			(attestation->state->txn.slot_num << 8) | rsp->challenge.slot_num);
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
					(rsp->challenge.min_protocol_version <<
					8) | CERBERUS_PROTOCOL_PROTOCOL_VERSION);
	}
	else {
		memcpy (attestation->state->txn.msg_buffer, response->payload, response->payload_length);
		attestation->state->txn.msg_buffer_len = response->payload_length;
		attestation->state->txn.request_status = ATTESTATION_REQUESTER_REQUEST_SUCCESSFUL;

		return;
	}

fail:
	attestation->state->txn.request_status = ATTESTATION_REQUESTER_REQUEST_RSP_FAIL;
}

/**
 * Cerberus Challenge get capabilities response observer function. The Get Capabilities
 * request/response interaction allows both devices to determine device functionalities, including
 * timeout and message size capabilities.
 */
void attestation_requester_on_cerberus_device_capabilities_response (
	const struct cerberus_protocol_observer *observer, const struct cmd_interface_msg *response)
{
	const struct attestation_requester *attestation =
		TO_DERIVED_TYPE (observer, const struct attestation_requester, cerberus_rsp_observer);

	if (attestation_requester_check_cerberus_unexpected_rsp (attestation,
		CERBERUS_PROTOCOL_GET_DEVICE_CAPABILITIES)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_RESPONSE_RECEIVED, response->source_eid,
			((attestation->state->txn.protocol << 24) |
						(attestation->state->txn.requested_command << 16) |
						(ATTESTATION_PROTOCOL_CERBERUS <<
						8) | CERBERUS_PROTOCOL_GET_DEVICE_CAPABILITIES));
		attestation->state->txn.request_status = ATTESTATION_REQUESTER_REQUEST_RSP_FAIL;
	}
	else {
		attestation->state->txn.request_status = ATTESTATION_REQUESTER_REQUEST_SUCCESSFUL;
	}
}
#endif

#ifdef ATTESTATION_SUPPORT_DEVICE_DISCOVERY
/**
 * MCTP control protocol set EID request observer function. Incoming set EID requests are monitored
 * since they are used by the MCTP bridge to alert device of routing table updates.
 */
void attestation_requester_on_mctp_set_eid_request (
	const struct mctp_control_protocol_observer *observer)
{
	const struct attestation_requester *attestation =
		TO_DERIVED_TYPE (observer, const struct attestation_requester, mctp_rsp_observer);

	attestation->state->get_routing_table = true;
	attestation->state->mctp_bridge_wait = false;

	platform_semaphore_post (&attestation->state->next_action);
}

/**
 * MCTP control protocol get routing table entries response observer function. The Get Routing Table
 * Entries request/response interaction is used by the requester to fetch routing table from MCTP
 * bridge.
 */
void attestation_requester_on_mctp_get_routing_table_entries_response (
	const struct mctp_control_protocol_observer *observer, const struct cmd_interface_msg *response)
{
	const struct attestation_requester *attestation =
		TO_DERIVED_TYPE (observer, const struct attestation_requester, mctp_rsp_observer);

	if ((attestation->state->txn.requested_command !=
		MCTP_CONTROL_PROTOCOL_GET_ROUTING_TABLE_ENTRIES)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_UNEXPECTED_RESPONSE_RECEIVED, response->source_eid,
			((attestation->state->txn.protocol << 24) |
						(attestation->state->txn.requested_command << 16) |
						(255 << 8) | MCTP_CONTROL_PROTOCOL_GET_MESSAGE_TYPE));
		attestation->state->txn.request_status = ATTESTATION_REQUESTER_REQUEST_RSP_FAIL;
	}
	else {
		attestation->state->txn.request_status = ATTESTATION_REQUESTER_REQUEST_SUCCESSFUL;
	}

	// msg_buffer is sized to hold maximum response lengths
	memcpy (attestation->state->txn.msg_buffer, response->payload, response->payload_length);
	attestation->state->txn.msg_buffer_len = response->payload_length;
}

/**
 * CFM activation request observer function. CFM activation requests are used to communicate to
 * device that component attestation states should be reset.
 */
void attestation_requester_on_cfm_activation_request (const struct cfm_observer *observer)
{
	const struct attestation_requester *attestation =
		TO_DERIVED_TYPE (observer, const struct attestation_requester, cfm_observer);

	device_manager_reset_authenticated_devices (attestation->device_mgr);

	platform_semaphore_post (&attestation->state->next_action);
}
#endif

/**
 * Initialize an attestation requester instance.
 *
 * @param attestation Attestation requester instance to initialize.
 * @param state Variable context for the attestation requester to utilize.
 * @param mctp MCTP interface instance to utilize.
 * @param channel Command channel instance to utilize.
 * @param primary_hash The hash engine to utilize for most attestation hashing operations.  This
 * must be a dedicated hash engine that is not shared with any other component.
 * @param secondary_hash The hash engine to utilize for SPDM transcript hashes.  This must be a
 * dedicated hash engine that is not not shared with any other component.
 * @param ecc The ECC engine to utilize.
 * @param rsa The RSA engine to utilize. Optional, can be set to NULL if not utilized.
 * @param x509 The x509 engine to utilize.
 * @param rng The RNG engine to utilize.
 * @param riot RIoT key manager.
 * @param device_mgr Device manager instance to utilize.
 * @param cfm_manager CFM manager to utilize.
 * @param mctp_control MCTP Control msg transport instance to utilize.
 *
 * @return Initialization status, 0 if success or an error code.
 */
int attestation_requester_init (struct attestation_requester *attestation,
	struct attestation_requester_state *state, const struct mctp_interface *mctp,
	const struct cmd_channel *channel, const struct hash_engine *primary_hash,
	const struct hash_engine *secondary_hash, const struct ecc_engine *ecc,
	const struct rsa_engine *rsa, const struct x509_engine *x509, const struct rng_engine *rng,
	const struct riot_key_manager *riot, struct device_manager *device_mgr,
	const struct cfm_manager *cfm_manager, const struct msg_transport *mctp_control)
{
	if ((attestation == NULL) || (state == NULL) || (mctp == NULL) || (channel == NULL) ||
		(primary_hash == NULL) || (ecc == NULL) || (x509 == NULL) || (rng == NULL) ||
		(riot == NULL) || (device_mgr == NULL) || (cfm_manager == NULL) || (mctp_control == NULL)) {
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
	attestation->mctp_control = mctp_control;

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

	/* Set up buffer pointers for generating SPDM requests. */
	attestation->state->spdm_mctp =
		(struct spdm_protocol_mctp_header*) attestation->state->txn.msg_buffer;
	attestation->state->spdm_msg_buffer =
		&attestation->state->txn.msg_buffer[sizeof (struct spdm_protocol_mctp_header)];

	attestation->state->mctp_bridge_wait = true;

	return platform_semaphore_init (&attestation->state->next_action);
}

/**
 * Release an attestation requester instance.
 *
 * @param attestation Attestation requester instance to release.
 */
void attestation_requester_deinit (const struct attestation_requester *attestation)
{
	if (attestation != NULL) {
		platform_semaphore_free (&attestation->state->next_action);
	}
}

#ifdef ATTESTATION_SUPPORT_CERBERUS_CHALLENGE
/**
 * Retrieve and verify the certificate chain from the device using Cerberus challenge protocol.  If
 * the certs are valid, store the alias key of the device.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param device_addr Physical address of the device to query for certificates.
 * @param eid EID of the device to query for certificates.
 * @param active_cfm Active CFM to utilize.
 * @param component_id The component ID of the device.
 *
 * @return 0 if completed successfully, or an error code
 */
static int attestation_requester_verify_and_load_leaf_key_cerberus (
	const struct attestation_requester *attestation, uint8_t device_addr, uint8_t eid,
	const struct cfm *active_cfm, uint32_t component_id)
{
	struct x509_ca_certs certs_chain;
	struct x509_certificate cert;
	size_t transcript_hash_len =
		hash_get_hash_length (attestation->state->txn.transcript_hash_type);
	size_t cert_idx;
	int status;

	/* TODO:  Cert chain digest calculation seems like it might be wrong for Cerberus now relative
	 * to how GET_DIGESTS is handled. */
	for (cert_idx = 0; cert_idx < attestation->state->txn.num_certs; ++cert_idx) {
		status =
			cerberus_protocol_generate_get_certificate_request (attestation->state->txn.slot_num,
			cert_idx, attestation->state->txn.msg_buffer,
			sizeof (attestation->state->txn.msg_buffer), 0, 0);
		if (ROT_IS_ERROR (status)) {
			attestation->primary_hash->cancel (attestation->primary_hash);

			return status;
		}

		status = attestation_requester_send_request_and_get_response (attestation, status,
			device_addr, eid, false, false, CERBERUS_PROTOCOL_GET_CERTIFICATE);
		if (status != 0) {
			attestation->primary_hash->cancel (attestation->primary_hash);

			return status;
		}

		if (cert_idx == 0) {
			/* Handle the Root CA. */
			status = attestation_requester_verify_and_load_root_cert (attestation, eid, active_cfm,
				component_id, attestation->state->txn.msg_buffer,
				attestation->state->txn.msg_buffer_len, NULL, 0, &certs_chain);
		}
		else {
			/* Handle any other cert. */
			status = attestation_requester_verify_and_load_certificate (attestation, eid,
				attestation->state->txn.msg_buffer, attestation->state->txn.msg_buffer_len,
				((cert_idx + 1) == attestation->state->txn.num_certs), &cert, &certs_chain);
		}

		if (status != 0) {
			return status;
		}
	}

	return attestation_requester_update_alias_key (attestation, eid, transcript_hash_len, &cert);
}

/**
 * Perform an attestation cycle on a provided device using Cerberus Protocol.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param eid EID of device to attest.
 * @param device_addr Slave address of device.
 * @param active_cfm Active CFM to utilize.
 * @param component_id The component ID of the device.
 *
 * @return Completion status, 0 if success or an error code otherwise.
 */
static int attestation_requester_attest_device_cerberus_protocol (
	const struct attestation_requester *attestation, uint8_t eid, int device_addr,
	const struct cfm *active_cfm, uint32_t component_id)
{
	struct cerberus_protocol_challenge *challenge_rq =
		(struct cerberus_protocol_challenge*) attestation->state->txn.msg_buffer;
	struct cerberus_protocol_challenge_response *challenge_rsp =
		(struct cerberus_protocol_challenge_response*) attestation->state->txn.msg_buffer;
	const struct device_manager_key *alias_key;
	uint8_t digest[SHA256_HASH_LENGTH];
	int challenge_rq_len;
	int status;

	attestation->state->txn.protocol = ATTESTATION_PROTOCOL_CERBERUS;

	// TODO Get Cerberus Protocol version using the MCTP control Get VDM Support command

	status = cerberus_protocol_generate_get_device_capabilities_request (attestation->device_mgr,
		attestation->state->txn.msg_buffer, sizeof (attestation->state->txn.msg_buffer));
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	status = attestation_requester_send_request_and_get_response (attestation, status, device_addr,
		eid, false, false, CERBERUS_PROTOCOL_GET_DEVICE_CAPABILITIES);
	if (status != 0) {
		return status;
	}

	status =
		cerberus_protocol_generate_get_certificate_digest_request (attestation->state->txn.slot_num,
		ATTESTATION_ECDHE_KEY_EXCHANGE, attestation->state->txn.msg_buffer,
		sizeof (attestation->state->txn.msg_buffer));
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	status = attestation_requester_send_request_and_get_response (attestation, status, device_addr,
		eid, true, false, CERBERUS_PROTOCOL_GET_DIGEST);
	if (status != 0) {
		return status;
	}

	status = attestation->primary_hash->calculate_sha256 (attestation->primary_hash,
		attestation->state->txn.msg_buffer, attestation->state->txn.msg_buffer_len, digest,
		sizeof (digest));
	if (status != 0) {
		return status;
	}

	status = attestation_requester_update_cert_chain_digest (attestation, eid, digest,
		SHA256_HASH_LENGTH);
	if (status != 0) {
		return status;
	}

	attestation->state->txn.num_certs = attestation->state->txn.msg_buffer_len / SHA256_HASH_LENGTH;
	alias_key = device_manager_get_alias_key (attestation->device_mgr, eid);

	// If certificate chain digest retrieved does not match cached certificate, refresh chain
	if (alias_key == NULL) {
		status = attestation_requester_verify_and_load_leaf_key_cerberus (attestation, device_addr,
			eid, active_cfm, component_id);
		if (status != 0) {
			goto clear_cert_chain;
		}
	}

	status = attestation->primary_hash->start_sha256 (attestation->primary_hash);
	if (status != 0) {
		return status;
	}

	challenge_rq_len = cerberus_protocol_generate_challenge_request (attestation->rng, eid,
		attestation->state->txn.slot_num, attestation->state->txn.msg_buffer,
		sizeof (attestation->state->txn.msg_buffer));
	if (ROT_IS_ERROR (challenge_rq_len)) {
		status = challenge_rq_len;
		goto hash_cancel;
	}

	status = attestation->primary_hash->update (attestation->primary_hash,
		(uint8_t*) &challenge_rq->challenge, sizeof (struct attestation_challenge));
	if (ROT_IS_ERROR (status)) {
		goto hash_cancel;
	}

	status = attestation_requester_send_request_and_get_response (attestation, challenge_rq_len,
		device_addr, eid, true, false, CERBERUS_PROTOCOL_ATTESTATION_CHALLENGE);
	if (status != 0) {
		goto hash_cancel;
	}

	status = attestation->primary_hash->update (attestation->primary_hash,
		(uint8_t*) &challenge_rsp->challenge,
		sizeof (struct attestation_response) + challenge_rsp->challenge.digests_size);
	if (status != 0) {
		goto hash_cancel;
	}

	status = attestation_requester_verify_signature (attestation, attestation->primary_hash, eid,
		cerberus_protocol_challenge_get_signature (challenge_rsp),
		cerberus_protocol_challenge_get_signature_len (challenge_rsp,
		attestation->state->txn.msg_buffer_len), NULL);
	if (status != 0) {
		goto hash_cancel;
	}

	memmove (attestation->state->txn.msg_buffer,
		cerberus_protocol_challenge_get_pmr (challenge_rsp), SHA256_HASH_LENGTH);
	attestation->state->txn.msg_buffer_len = SHA256_HASH_LENGTH;

	status = attestation_requester_verify_pmr (attestation, active_cfm, component_id, eid, 0);

	/* TODO Implement additional Cerberus Challenge Protocol attestation flows
	 *	1) PMR(n) attestation using the Get PMR command
	 *	2) PMR measurement attestation using the Get Log and Get PMR commands
	 *	3) PMR measurement data attestation using the Get Attestation Data, Get Log, and Get PMR
	 *		commands
	 *	4) Manifest IDs attestation using the Get Config IDs command */

hash_cancel:
	if (!attestation->state->txn.hash_finish) {
		attestation->primary_hash->cancel (attestation->primary_hash);
	}

	return status;

clear_cert_chain:
	device_manager_clear_alias_key (attestation->device_mgr, eid);
	device_manager_clear_cert_chain_digest (attestation->device_mgr, eid);

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

	rq_len = spdm_generate_get_version_request (attestation->state->spdm_msg_buffer,
		ATTESTATION_REQUESTER_MAX_SPDM_REQUEST);
	if (ROT_IS_ERROR (rq_len)) {
		return rq_len;
	}

	status = attestation_requester_send_spdm_request_and_get_response (attestation, rq_len,
		device_addr, eid, false, SPDM_REQUEST_GET_VERSION);
	if (status != 0) {
		return status;
	}

	rq_len = spdm_generate_get_capabilities_request (attestation->state->spdm_msg_buffer,
		ATTESTATION_REQUESTER_MAX_SPDM_REQUEST, attestation->state->txn.spdm_minor_version);
	if (ROT_IS_ERROR (rq_len)) {
		return rq_len;
	}

	status = attestation_requester_send_spdm_request_and_get_response (attestation, rq_len,
		device_addr, eid, false, SPDM_REQUEST_GET_CAPABILITIES);
	if (status != 0) {
		return status;
	}

	/* If doing device discovery, show support for all hashing algorithms.  Otherwise, only show
	 * support for hashing algorithm that CFM selects for attestation with this device. */
	if (attestation->state->txn.device_discovery) {
		base_hash_algo = SPDM_TPM_ALG_SHA_256;
#ifdef HASH_ENABLE_SHA384
		base_hash_algo |= SPDM_TPM_ALG_SHA_384;
#endif
#ifdef HASH_ENABLE_SHA512
		base_hash_algo |= SPDM_TPM_ALG_SHA_512;
#endif
	}
	else {
		switch (attestation->state->txn.transcript_hash_type) {
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

		if (attestation->state->txn.transcript_hash_type !=
			attestation->state->txn.measurement_hash_type) {
			switch (attestation->state->txn.measurement_hash_type) {
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
	}

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
	base_asym_algo |= SPDM_TPM_ALG_ECDSA_ECC_NIST_P384;
#endif
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
	base_asym_algo |= SPDM_TPM_ALG_ECDSA_ECC_NIST_P521;
#endif

	rq_len = spdm_generate_negotiate_algorithms_request (attestation->state->spdm_msg_buffer,
		ATTESTATION_REQUESTER_MAX_SPDM_REQUEST, base_asym_algo, base_hash_algo,
		attestation->state->txn.spdm_minor_version);
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
 * SPDM get measurements response processing function.  For Get Measurements responses outside of
 *  device discovery, validating the transcript signature.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param eid EID of device to utilize.
 *
 * @return Completion status, 0 if success or an error code otherwise
 */
static int attestation_requester_spdm_process_get_measurements_response (
	const struct attestation_requester *attestation, uint8_t device_eid)
{
	struct spdm_get_measurements_response *rsp =
		(struct spdm_get_measurements_response*) attestation->state->txn.msg_buffer;
	struct spdm_measurements_measurement_block *block;
	size_t offset = sizeof (struct spdm_get_measurements_response);
	size_t measurement_size;
	uint8_t number_of_blocks = rsp->number_of_blocks;
	uint8_t i_block;
	int status;

	if (attestation->state->txn.measurement_operation_requested ==
		SPDM_MEASUREMENT_OPERATION_GET_NUM_BLOCKS) {
		return 0;
	}

	if (!attestation->state->txn.device_discovery) {
		status = attestation_requester_verify_signature (attestation, attestation->secondary_hash,
			device_eid, spdm_get_measurements_resp_signature (rsp),
			spdm_get_measurements_resp_signature_length (rsp,
			attestation->state->txn.msg_buffer_len), SPDM_GET_MEASUREMENTS_SIGNATURE_CONTEXT_STR);
		if (status != 0) {
			return status;
		}
	}

	attestation->state->txn.msg_buffer_len = 0;

	for (i_block = 0; i_block < number_of_blocks; ++i_block) {
		block =
			(struct spdm_measurements_measurement_block*) &attestation->state->txn.msg_buffer[offset];
		offset += sizeof (struct spdm_measurements_measurement_block);

		// If a specific block was requested, make sure response only includes that block
		if ((attestation->state->txn.measurement_operation_requested !=
			SPDM_MEASUREMENT_OPERATION_GET_ALL_BLOCKS) &&
			(block->index != attestation->state->txn.measurement_operation_requested)) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
				ATTESTATION_LOGGING_UNEXPECTED_NUM_MEASUREMENT_BLOCKS, device_eid,
				(1 << 16) | (attestation->state->txn.measurement_operation_requested << 8) |
					block->index);

			return ATTESTATION_GET_MEAS_OPERATION_UNEXPECTED;
		}

		// If block was requested in digest form and response is in raw form, fail
		if (!attestation->state->txn.raw_bitstream_requested &&	block->dmtf.raw_bit_stream) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
				ATTESTATION_LOGGING_UNEXPECTED_MEASUREMENT_BLOCK_RAW, device_eid,
				(attestation->state->txn.measurement_operation_requested << 8) | block->index);

			return ATTESTATION_GET_MEAS_RSP_NOT_DIGEST;
		}
		// If block was requested in raw form and response was in digest form, fail
		else if (attestation->state->txn.raw_bitstream_requested && !block->dmtf.raw_bit_stream) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
				ATTESTATION_LOGGING_UNEXPECTED_MEASUREMENT_BLOCK_DIGEST, device_eid, block->index);

			return ATTESTATION_GET_MEAS_RSP_NOT_RAW;
		}
		else {
			if ((block->dmtf.measurement_value_size + attestation->state->txn.msg_buffer_len) >
				sizeof (attestation->state->txn.msg_buffer)) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
					ATTESTATION_LOGGING_MEASUREMENT_DATA_TOO_LARGE,
					(device_eid << 8) | block->index,
					block->dmtf.measurement_value_size + attestation->state->txn.msg_buffer_len);

				return ATTESTATION_GET_MEAS_BLOCKS_TOO_LARGE;
			}

			measurement_size = block->dmtf.measurement_value_size;
			memmove (&attestation->state->txn.msg_buffer[attestation->state->txn.msg_buffer_len],
				&attestation->state->txn.msg_buffer[offset], measurement_size);
			attestation->state->txn.msg_buffer_len += measurement_size;
		}

		offset += measurement_size;
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

	if (!attestation->state->txn.device_discovery) {
		if (!attestation->state->txn.hash_finish) {
			attestation->secondary_hash->cancel (attestation->secondary_hash);
		}

		attestation->state->txn.hash_finish = true;

		status = hash_start_new_hash (attestation->secondary_hash,
			attestation->state->txn.transcript_hash_type);
		if (status != 0) {
			return status;
		}

		attestation->state->txn.hash_finish = false;
	}

	/* In 1.2+, every Get Measurement transaction with a signature requested in response requires a
	 * a transcript that includes VDM. */
	if (((attestation->state->txn.protocol != ATTESTATION_PROTOCOL_CERBERUS) &&
		(attestation->state->txn.spdm_minor_version > ATTESTATION_PROTOCOL_DMTF_SPDM_1_1)) ||
		attestation->state->txn.device_discovery) {
		status = attestation_requester_setup_spdm_device (attestation, eid, device_addr);
		if (status != 0) {
			return status;
		}
	}

	// No signature or nonce needed when getting device ID measurement block in device discovery
	if (!attestation->state->txn.device_discovery) {
		if (attestation->state->txn.cert_supported) {
			status = attestation->rng->generate_random_buffer (attestation->rng, SPDM_NONCE_LEN,
				nonce);
			if (status != 0) {
				return status;
			}
		}

		rq_len = spdm_generate_get_measurements_request (attestation->state->spdm_msg_buffer,
			ATTESTATION_REQUESTER_MAX_SPDM_REQUEST, attestation->state->txn.slot_num,
			measurement_operation, attestation->state->txn.cert_supported ? true : false,
			raw_bitstream_requested, attestation->state->txn.cert_supported ? nonce : NULL,
			attestation->state->txn.spdm_minor_version);
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
		if ((attestation->state->txn.protocol != ATTESTATION_PROTOCOL_CERBERUS) &&
			(attestation->state->txn.spdm_minor_version <= ATTESTATION_PROTOCOL_DMTF_SPDM_1_1)) {
			rq_len = spdm_generate_get_measurements_request (attestation->state->spdm_msg_buffer,
				ATTESTATION_REQUESTER_MAX_SPDM_REQUEST, attestation->state->txn.slot_num,
				SPDM_MEASUREMENT_OPERATION_GET_NUM_BLOCKS, false, raw_bitstream_requested, NULL,
				attestation->state->txn.spdm_minor_version);
			if (ROT_IS_ERROR (rq_len)) {
				return rq_len;
			}

			attestation->state->txn.raw_bitstream_requested = raw_bitstream_requested;
			attestation->state->txn.measurement_operation_requested =
				SPDM_MEASUREMENT_OPERATION_GET_NUM_BLOCKS;

			status = attestation_requester_send_spdm_request_and_get_response (attestation, rq_len,
				device_addr, eid, true, SPDM_REQUEST_GET_MEASUREMENTS);
			if (status != 0) {
				return status;
			}

			status =
				attestation_requester_spdm_process_get_measurements_response (attestation, eid);
			if (status != 0) {
				device_manager_update_device_state_by_eid (attestation->device_mgr, eid,
					DEVICE_MANAGER_ATTESTATION_INVALID_MEASUREMENT);

				return status;
			}

			measurement_operation = attestation->state->txn.msg_buffer[0];
		}

		rq_len = spdm_generate_get_measurements_request (attestation->state->spdm_msg_buffer,
			ATTESTATION_REQUESTER_MAX_SPDM_REQUEST, attestation->state->txn.slot_num,
			measurement_operation, false, raw_bitstream_requested, NULL,
			attestation->state->txn.spdm_minor_version);
		if (ROT_IS_ERROR (rq_len)) {
			return rq_len;
		}
	}

	attestation->state->txn.raw_bitstream_requested = raw_bitstream_requested;
	attestation->state->txn.measurement_operation_requested = measurement_operation;

	status = attestation_requester_send_spdm_request_and_get_response (attestation, rq_len,
		device_addr, eid, true, SPDM_REQUEST_GET_MEASUREMENTS);
	if (status != 0) {
		return status;
	}

	status = attestation_requester_spdm_process_get_measurements_response (attestation, eid);
	if (status != 0) {
		device_manager_update_device_state_by_eid (attestation->device_mgr, eid,
			DEVICE_MANAGER_ATTESTATION_INVALID_MEASUREMENT);
	}

	return status;
}

/**
 * If PMR0 digest checking is in CFM for device being attested using SPDM, get all measurement
 * blocks from device then combine into single digest and compare with allowable PMR0 digests.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param eid EID of device being attested.
 * @param device_addr Slave address of device.
 * @param active_cfm Active CFM to utilize.
 * @param component_id The component ID of the device.
 *
 * @return Completion status, 0 if success, CFM_PMR_DIGEST_NOT_FOUND if no PMR0 digest checking
 * 	defined in CFM for this device, or an error code otherwise
 */
static int attestation_requester_get_and_verify_all_spdm_measurement_blocks (
	const struct attestation_requester *attestation, uint8_t eid, int device_addr,
	const struct cfm *active_cfm, uint32_t component_id)
{
	uint8_t digest[HASH_MAX_HASH_LEN];
	struct cfm_pmr_digest pmr_digest;
	int status;

	status = active_cfm->get_component_pmr_digest (active_cfm, component_id, 0, &pmr_digest);
	if (status != 0) {
		return status;
	}

	status = attestation_requester_send_and_receive_spdm_get_measurements (attestation, eid,
		device_addr, SPDM_MEASUREMENT_OPERATION_GET_ALL_BLOCKS, false);
	if (status != 0) {
		goto free_pmr_digest;
	}

	// TODO: If device responds with raw blocks, hash them here instead of reporting error

	status = hash_calculate (attestation->primary_hash,
		attestation->state->txn.measurement_hash_type, attestation->state->txn.msg_buffer,
		attestation->state->txn.msg_buffer_len, digest, sizeof (digest));
	if (ROT_IS_ERROR (status)) {
		goto free_pmr_digest;
	}

	status = attestation_requester_verify_digest_in_allowable_list (attestation,
		&pmr_digest.digests, digest, attestation->state->txn.measurement_hash_type);

	if (status != 0) {
		device_manager_update_device_state_by_eid (attestation->device_mgr, eid,
			DEVICE_MANAGER_ATTESTATION_MEASUREMENT_MISMATCH);
	}

free_pmr_digest:
	active_cfm->free_component_pmr_digest (active_cfm, &pmr_digest);

	return status;
}

/**
 * Get corresponding the SPDM measurement block for a measurement entry from the CFM, then compare
 * to allowable values.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param measurement CFM measurement entry.
 * @param eid EID of device being attested.
 * @param device_addr Slave address of device.
 *
 * @return Completion status, 0 if success or an error code	otherwise
 */
static int attestation_requester_get_and_verify_spdm_measurement_block (
	const struct attestation_requester *attestation, struct cfm_measurement_digest *measurement,
	uint8_t eid, int device_addr)
{
	size_t i_allowable_digests;
	int status = 0;

	status = attestation_requester_send_and_receive_spdm_get_measurements (attestation, eid,
		device_addr, measurement->measurement_id, false);
	if (status != 0) {
		return status;
	}

	for (i_allowable_digests = 0; i_allowable_digests < measurement->allowable_digests_count;
		++i_allowable_digests) {
		/* If device version set selected, and allowable digest has a non-zero version set which
		 * does not match that of device, then digest not permitted for this device in its current
		 * state.  If there are no allowable digests with matching version sets to device, then
		 * measurement comparison is not applicable to device in its current state and will be
		 * skipped without failing attestation. */
		if (attestation_requester_is_version_set_selected (attestation) &&
			(measurement->allowable_digests[i_allowable_digests].version_set != 0) &&
			(measurement->allowable_digests[i_allowable_digests].version_set !=
			attestation->state->txn.device_version_set)) {
			continue;
		}

		/* If device version set not selected, then this should be a measurement used for version
		 * set selection with only allowable digests unique to a single version set. */
		if (!attestation_requester_is_version_set_selected (attestation) &&
			(measurement->allowable_digests[i_allowable_digests].version_set == 0)) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
				ATTESTATION_LOGGING_CFM_VERSION_SET_SELECTOR_INVALID,
				((eid << 16) | (measurement->pmr_id << 8) | (measurement->measurement_id)),
				i_allowable_digests);

			return ATTESTATION_CFM_VERSION_SET_SELECTOR_INVALID;
		}

		status = attestation_requester_verify_digest_in_allowable_list (attestation,
			&measurement->allowable_digests[i_allowable_digests].digests, NULL,
			attestation->state->txn.measurement_hash_type);
		if (status == 0) {
			// If device version set still not selected, then set it
			if (!attestation_requester_is_version_set_selected (attestation)) {
				attestation->state->txn.device_version_set =
					measurement->allowable_digests[i_allowable_digests].version_set;
			}

			break;
		}
	}

	// If device version set not selected, then report error
	if (!attestation_requester_is_version_set_selected (attestation)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_VERSION_SET_SELECTION_FAILED,
			((eid << 16) | (measurement->pmr_id << 8) | (measurement->measurement_id)), status);

		if (status == 0) {
			return ATTESTATION_FAILED_TO_SELECT_VERSION_SET;
		}
	}

	return status;
}

/**
 * Perform check requested on data compared to expected data.
 *
 * @param check Checking method requested.
 * @param actual Actual data to utilize.
 * @param actual_length Length of actual data.
 * @param expected Expected data to utilize.
 * @param expected_length Length of expected data.
 * @param bitmask Buffer with bitmask to use during comparison. Can be set to NULL if not needed.
 * @param big_endian Bool flag indicating if multi-byte data values are in big endian.
 *
 * @return 0 if data matches or 1 otherwise
 */
static int attestation_requester_compare_data (enum cfm_check check, const uint8_t *actual,
	size_t actual_length, const uint8_t *expected, size_t expected_length, const uint8_t *bitmask,
	bool big_endian)
{
	uint8_t actual_value;
	uint8_t expected_value;
	size_t i_comp;
	size_t i_data;
	int direction;
	int result;

	if (expected_length != actual_length) {
		return 1;
	}

	if (big_endian) {
		i_data = 0;
		direction = 1;
	}
	else {
		// If data is in little endian, reverse loop traversal.
		i_data = actual_length - 1;
		direction = -1;
	}

	for (i_comp = 0; i_comp < actual_length; ++i_comp, i_data += direction) {
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
 * Check if data in msg_buffer matches all checks in allowable data list from CFM entry.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param check List of allowable data checks to utilize.
 * @param num_check Number of allowable data checks.
 * @param pmr_id PMR ID for CFM measurement data entry.
 * @param measurement_id Measurement ID for CFM measurement data entry.
 * @param eid EID of device being attested.
 *
 * @return Completion status, 0 if success or an error code otherwise
 */
static int attestation_requester_verify_data_in_allowable_list (
	const struct attestation_requester *attestation, struct cfm_allowable_data *check,
	size_t num_check, uint8_t pmr_id, uint8_t measurement_id, uint8_t eid)
{
	size_t i_checks_in_version_set = 0;
	size_t i_check;
	size_t i_data;
	int status = ATTESTATION_CFM_INVALID_ATTESTATION;

	for (i_check = 0; i_check < num_check; ++i_check, ++check) {
		for (i_data = 0; i_data < check->data_count; ++i_data) {
			/* If device version set selected, and allowable data entry has a non-zero version set
			 * which does not match that of device, then data not permitted for this device in its
			 * current state. */
			if (attestation_requester_is_version_set_selected (attestation) &&
				(check->allowable_data[i_data].version_set != 0) &&
				(check->allowable_data[i_data].version_set !=
				attestation->state->txn.device_version_set)) {
				continue;
			}

			/* If device version set not selected, then this should be a measurement data used for
			 * version set selection with only allowable data entries unique to a single version
			 * set. */
			if (!attestation_requester_is_version_set_selected (attestation) &&
				(check->allowable_data[i_data].version_set == 0)) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
					ATTESTATION_LOGGING_CFM_VERSION_SET_SELECTOR_INVALID,
					((eid << 16) | (pmr_id << 8) | (measurement_id)), i_data);

				return ATTESTATION_CFM_VERSION_SET_SELECTOR_INVALID;
			}

			/* For a single version set, only a single allowable data entry is permitted unless a
			 * "equal" or "not equal" check. */
			if ((i_checks_in_version_set != 0) && (check->check != CFM_CHECK_EQUAL) &&
				(check->check != CFM_CHECK_NOT_EQUAL)) {
				return ATTESTATION_CFM_INVALID_ATTESTATION;
			}

			++i_checks_in_version_set;

			if ((check->bitmask != NULL) &&
				(check->bitmask_length < attestation->state->txn.msg_buffer_len)) {
				return ATTESTATION_BITMASK_TOO_SMALL;
			}

			status = attestation_requester_compare_data (check->check,
				attestation->state->txn.msg_buffer, attestation->state->txn.msg_buffer_len,
				check->allowable_data[i_data].data, check->allowable_data[i_data].data_len,
				check->bitmask, check->big_endian);
			if (status == 0) {
				// If device version set still not selected, then set it
				if (!attestation_requester_is_version_set_selected (attestation)) {
					attestation->state->txn.device_version_set =
						check->allowable_data[i_data].version_set;
				}

				//For the equal check, at least one comparison must succeed
				if (check->check == CFM_CHECK_EQUAL) {
					break;
				}
			}
			else {
				status = ATTESTATION_CFM_ATTESTATION_RULE_FAIL;

				//Except for the equal check, all comparisons must succeed
				if (check->check != CFM_CHECK_EQUAL) {
					break;
				}
			}
		}
	}

	/* If there are no allowable data entries with matching version sets to device, then measurement
	 * data comparison is not applicable to device in its current state and will be skipped without
	 * failing attestation. */
	if (i_checks_in_version_set == 0) {
		return 0;
	}

	return status;
}

/**
 * Get corresponding the SPDM measurement block for a measurement data entry from the CFM, then
 * compare to allowable values.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param measurement CFM measurement data entry.
 * @param eid EID of device being attested.
 * @param device_addr Slave address of device.
 *
 * @return Completion status, 0 if success or an error code	otherwise
 */
static int attestation_requester_get_and_verify_spdm_measurement_data_block (
	const struct attestation_requester *attestation, struct cfm_measurement_data *data, uint8_t eid,
	int device_addr)
{
	int status;

	status = attestation_requester_send_and_receive_spdm_get_measurements (attestation, eid,
		device_addr, data->measurement_id, true);
	if (status != 0) {
		return status;
	}

	status = attestation_requester_verify_data_in_allowable_list (attestation, data->data_checks,
		data->data_checks_count, data->pmr_id, data->measurement_id, eid);

	// If device version set not selected, then report error
	if (!attestation_requester_is_version_set_selected (attestation)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_VERSION_SET_SELECTION_FAILED,
			((eid << 16) | (data->pmr_id << 8) | (data->measurement_id)), status);

		if (status == 0) {
			return ATTESTATION_FAILED_TO_SELECT_VERSION_SET;
		}
	}

	return status;
}

/**
 * For each measurement or measurement data entry in CFM, get corresponding SPDM measurement block
 * and compare to allowable values.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param eid EID of device being attested.
 * @param device_addr Slave address of device.
 * @param active_cfm Active CFM to utilize.
 * @param component_id The component ID of the device.
 *
 * @return Completion status, 0 if success or no measurement entries in CFM, or an error code
 * 	otherwise
 */
static int attestation_requester_get_and_verify_cfm_contents (
	const struct attestation_requester *attestation, uint8_t eid, int device_addr,
	const struct cfm *active_cfm, uint32_t component_id)
{
	struct cfm_measurement_container container;
	bool first = true;
	int status = 0;

	while (status == 0) {
		status = active_cfm->get_next_measurement_or_measurement_data (active_cfm, component_id,
			&container, first);
		if (status == 0) {
			if (container.measurement_type == CFM_MEASUREMENT_TYPE_DIGEST) {
				status = attestation_requester_get_and_verify_spdm_measurement_block (attestation,
					&container.measurement.digest, eid, device_addr);
			}
			else {
				status =
					attestation_requester_get_and_verify_spdm_measurement_data_block (attestation,
					&container.measurement.data, eid, device_addr);
			}

			first = false;
		}
	}

	active_cfm->free_measurement_container (active_cfm, &container);

	if (status == CFM_ENTRY_NOT_FOUND) {
		return 0;
	}

	if (status != 0) {
		device_manager_update_device_state_by_eid (attestation->device_mgr, eid,
			DEVICE_MANAGER_ATTESTATION_MEASUREMENT_MISMATCH);
	}

	return status;
}

/**
 * Process incoming SPDM challenge response.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param eid EID of device to utilize.
 *
 * @return Completion status, 0 if success or an error code otherwise
 */
static int attestation_requester_spdm_process_challenge_response (
	const struct attestation_requester *attestation, uint8_t device_eid)
{
	struct spdm_challenge_response *rsp =
		(struct spdm_challenge_response*) attestation->state->txn.msg_buffer;
	size_t transcript_hash_len =
		hash_get_hash_length (attestation->state->txn.transcript_hash_type);
	int status;

	status = attestation_requester_verify_signature (attestation, attestation->secondary_hash,
		device_eid,
		spdm_get_challenge_resp_signature (rsp, transcript_hash_len, transcript_hash_len),
		spdm_get_challenge_resp_signature_length (rsp, transcript_hash_len,
		attestation->state->txn.msg_buffer_len, transcript_hash_len),
		SPDM_CHALLENGE_SIGNATURE_CONTEXT_STR);
	if (status != 0) {
		return status;
	}

	// msg_buffer is sized to hold maximum response lengths
	memmove (attestation->state->txn.msg_buffer,
		spdm_get_challenge_resp_measurement_summary_hash (rsp, transcript_hash_len),
		transcript_hash_len);
	attestation->state->txn.msg_buffer_len = transcript_hash_len;

	return 0;
}

/**
 * Retrieve a specified portion of the complete certificate chain data.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param eid EID of device that sent certificate chain.
 * @param device_addr Slave address of device.
 * @param offset Offset within the certificate chain of the requested data.
 * @param length Total length of data to retrieve.
 * @param portion_data Output for the received certificate chain data.
 *
 * @return 0 if completed successfully, or an error code
 */
static int attestation_requester_retrieve_spdm_certificate_chain_portion (
	const struct attestation_requester *attestation, uint8_t eid, int device_addr, uint32_t offset,
	size_t length, uint8_t **portion_data)
{
	struct spdm_get_certificate_response *rsp =
		(struct spdm_get_certificate_response*) attestation->state->txn.msg_buffer;
	uint8_t *cert_buffer = NULL;
	size_t rx_data = 0;
	uint16_t read_len;
	size_t max_len;
	int rq_len;
	int status;

	/* Assume that no single certificate will be larger than the the total size of the message
	 * buffer. */
	if (length > sizeof (attestation->state->txn.msg_buffer)) {
		device_manager_update_device_state_by_eid (attestation->device_mgr, eid,
			DEVICE_MANAGER_ATTESTATION_INVALID_CERTS);

		return ATTESTATION_BUFFER_OVERRUN;
	}

	max_len = device_manager_get_max_message_len_by_eid (attestation->device_mgr, eid) -
		sizeof (struct spdm_get_certificate_response);

	read_len = (length > max_len) ? max_len : length;

	while (length > 0) {
		rq_len = spdm_generate_get_certificate_request (attestation->state->spdm_msg_buffer,
			ATTESTATION_REQUESTER_MAX_SPDM_REQUEST, attestation->state->txn.slot_num,
			offset + rx_data, read_len, attestation->state->txn.spdm_minor_version);
		if (ROT_IS_ERROR (rq_len)) {
			status = rq_len;
			goto exit;
		}

		status = attestation_requester_send_spdm_request_and_get_response (attestation, rq_len,
			device_addr, eid, true, SPDM_REQUEST_GET_CERTIFICATE);
		if (status != 0) {
			goto exit;
		}

		/* if portion_len is 0, or portion_len is greater than length, then the response is invalid */
		if ((rsp->portion_len == 0) || (rsp->portion_len > length)) {
			device_manager_update_device_state_by_eid (attestation->device_mgr, eid,
				DEVICE_MANAGER_ATTESTATION_INVALID_CERTS);

			status = ATTESTATION_INVALID_CERT_CHAIN;
			goto exit;
		}

		if (cert_buffer == NULL) {
			/* If all the requested data did not get returned in a single request, allocate a memory
			 * buffer to accumulate the data. */
			if (rsp->portion_len < length) {
				cert_buffer = platform_malloc (length);
				if (cert_buffer == NULL) {
					return ATTESTATION_NO_MEMORY;
				}
			}
		}

		/* Handle the response data, copying as necessary.  Extra data beyond what was requested
		 * will be discarded. */
		if (cert_buffer != NULL) {
			rx_data += buffer_copy (spdm_get_certificate_resp_cert_chain (rsp), rsp->portion_len,
				NULL, &length, &cert_buffer[rx_data]);
			if (length < read_len) {
				read_len = length;
			}
		}
		else {
			/* All the requested data is in the message buffer. */
			*portion_data = spdm_get_certificate_resp_cert_chain (rsp);
			length = 0;
		}
	}

	if (cert_buffer != NULL) {
		/* It is guaranteed that the message buffer is large enough for the accumulated data based
		 * on the length check made before requesting the data. */
		memcpy (attestation->state->txn.msg_buffer, cert_buffer, rx_data);
		*portion_data = attestation->state->txn.msg_buffer;
	}

exit:
	if (cert_buffer != NULL) {
		platform_free (cert_buffer);
	}

	return status;
}

/**
 * Retrieve a single certificate from an SPDM certificate chain.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param dest_addr SMBus address of destination device.
 * @param dest_eid MCTP EID of destination device.
 * @param offset Offset within the certificate chain for the requested certificate.
 * @param cert_data Output for the retrieved certificate data.
 * @param cert_len Output for the total length of the certificate that it retrieved from response.
 *
 * @return 0 if completed successfully, or an error code
 */
static int attestation_requester_retrieve_individual_spdm_certificate (
	const struct attestation_requester *attestation, uint8_t dest_addr, uint8_t dest_eid,
	uint32_t offset, uint8_t **cert_data, size_t *cert_len)
{
	uint8_t *portion_data;
	size_t portion_size;
	uint8_t cert_header[ATTESTATION_REQUESTER_CERT_ASN1_HEADER_LEN];
	int status;

	/* First determine the size of the next certificate at the specified offset by retrieving just
	 * the ASN.1 header of the X.509 certificate. */
	portion_size = ATTESTATION_REQUESTER_CERT_ASN1_HEADER_LEN;

	status = attestation_requester_retrieve_spdm_certificate_chain_portion (attestation, dest_eid,
		dest_addr, offset, portion_size, &portion_data);
	if (status != 0) {
		return status;
	}

	memcpy (cert_header, portion_data, portion_size);

	status = asn1_get_der_item_len (portion_data, portion_size);
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	/* Assume that no single certificate will be larger than the the total size of the message
	 * buffer. */
	if ((size_t) (status + sizeof (struct spdm_get_certificate_response)) >
		sizeof (attestation->state->txn.msg_buffer)) {
		device_manager_update_device_state_by_eid (attestation->device_mgr, dest_eid,
			DEVICE_MANAGER_ATTESTATION_INVALID_CERTS);

		return ATTESTATION_CERT_TOO_LARGE;
	}

	/* Then issue a request to retrieve the rest of the certificate. As specified in SPDM spec,
	 * offset must be monotonic after the first request for a particular certificate chain. */
	if ((size_t) status < portion_size) {
		portion_size = 0;
	}
	else {
		offset += portion_size;
		portion_size = status - portion_size;

		status = attestation_requester_retrieve_spdm_certificate_chain_portion (attestation,
			dest_eid, dest_addr, offset, portion_size, &portion_data);
		if (status != 0) {
			return status;
		}

		memmove (portion_data + ATTESTATION_REQUESTER_CERT_ASN1_HEADER_LEN, portion_data,
			portion_size);
		memcpy (portion_data, cert_header, ATTESTATION_REQUESTER_CERT_ASN1_HEADER_LEN);
	}

	*cert_data = portion_data;
	*cert_len = portion_size + ATTESTATION_REQUESTER_CERT_ASN1_HEADER_LEN;

	return 0;
}

/**
 * Retrieve and verify the certificate chain from the device using SPDM protocol.  If the certs are
 * valid, store the alias key of the device.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param eid EID of device that sent certificate chain.
 * @param active_cfm Active CFM to utilize.
 * @param component_id The component ID of the device.
 *
 * @return 0 if completed successfully, or an error code
 */
static int attestation_requester_verify_and_load_leaf_key_spdm (
	const struct attestation_requester *attestation, uint8_t dest_addr, uint8_t eid,
	const struct cfm *active_cfm, uint32_t component_id)
{
	struct x509_ca_certs certs_chain;
	struct x509_certificate cert;
	uint8_t cert_chain_header[sizeof (struct spdm_certificate_chain) + HASH_MAX_HASH_LEN];
	struct spdm_certificate_chain *spdm_cert_chain;
	size_t transcript_hash_len =
		hash_get_hash_length (attestation->state->txn.transcript_hash_type);
	size_t cert_offset = 0;
	uint8_t *cert_data;
	size_t cert_len;
	int status;

	/* Determine the length of the SPDM certificate header and request just the header data. */
	cert_len = sizeof (struct spdm_certificate_chain) + transcript_hash_len;

	status = attestation_requester_retrieve_spdm_certificate_chain_portion (attestation, eid,
		dest_addr, cert_offset, cert_len, &cert_data);
	if (status != 0) {
		return status;
	}

	memcpy (cert_chain_header, cert_data, cert_len);
	spdm_cert_chain = (struct spdm_certificate_chain*) cert_chain_header;

	/* Get root CA certificate. */
	cert_offset = cert_len;

	status = attestation_requester_retrieve_individual_spdm_certificate (attestation, dest_addr,
		eid, cert_offset, &cert_data, &cert_len);
	if (status != 0) {
		return status;
	}

	status = attestation_requester_verify_and_load_root_cert (attestation, eid, active_cfm,
		component_id, cert_data, cert_len, cert_chain_header, cert_offset, &certs_chain);
	if (status != 0) {
		return status;
	}

	cert_offset += cert_len;

	while (cert_offset < spdm_cert_chain->length) {
		/* Retrieve, hash, and validate each certificate in the chain. */
		status = attestation_requester_retrieve_individual_spdm_certificate (attestation, dest_addr,
			eid, cert_offset, &cert_data, &cert_len);
		if (status != 0) {
			attestation->primary_hash->cancel (attestation->primary_hash);
			attestation->x509->release_ca_cert_store (attestation->x509, &certs_chain);

			return status;
		}

		cert_offset += cert_len;

		status = attestation_requester_verify_and_load_certificate (attestation, eid, cert_data,
			cert_len, (cert_offset >= spdm_cert_chain->length), &cert, &certs_chain);
		if (status != 0) {
			return status;
		}
	}

	return attestation_requester_update_alias_key (attestation, eid, transcript_hash_len, &cert);
}

/**
 * Perform an attestation cycle on a provided device using SPDM.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param eid EID of device to attest.
 * @param device_addr Slave address of device.
 * @param active_cfm Active CFM to utilize.
 * @param component_id The component ID of the device.
 *
 * @return Completion status, 0 if success or an error code otherwise
 */
static int attestation_requester_attest_device_spdm (
	const struct attestation_requester *attestation, uint8_t eid, int device_addr,
	const struct cfm *active_cfm, uint32_t component_id)
{
	const struct device_manager_key *alias_key;
	uint8_t nonce[SPDM_NONCE_LEN];
	int rq_len;
	int status;

	if (!hash_is_alg_supported (attestation->state->txn.transcript_hash_type) ||
		!hash_is_alg_supported (attestation->state->txn.measurement_hash_type)) {
		return ATTESTATION_UNSUPPORTED_ALGORITHM;
	}

	status = hash_start_new_hash (attestation->secondary_hash,
		attestation->state->txn.transcript_hash_type);
	if (status != 0) {
		return status;
	}

	// Start off assuming 1.0 then update based on response from device to the Get Version request
	attestation->state->txn.protocol = ATTESTATION_PROTOCOL_DMTF_SPDM;
	attestation->state->txn.spdm_minor_version = ATTESTATION_PROTOCOL_DMTF_SPDM_1_0;

	status = attestation_requester_setup_spdm_device (attestation, eid, device_addr);
	if (status != 0) {
		goto hash_cancel;
	}

	if (attestation->state->txn.cert_supported) {
		rq_len = spdm_generate_get_digests_request (attestation->state->spdm_msg_buffer,
			ATTESTATION_REQUESTER_MAX_SPDM_REQUEST, attestation->state->txn.spdm_minor_version);
		if (ROT_IS_ERROR (rq_len)) {
			status = rq_len;
			goto hash_cancel;
		}

		status = attestation_requester_send_spdm_request_and_get_response (attestation, rq_len,
			device_addr, eid, true, SPDM_REQUEST_GET_DIGESTS);
		if (status != 0) {
			goto hash_cancel;
		}

		// If certificate chain digest retrieved does not match cached certificate, refresh chain
		alias_key = device_manager_get_alias_key (attestation->device_mgr, eid);
		if (alias_key == NULL) {
			status = attestation_requester_verify_and_load_leaf_key_spdm (attestation, device_addr,
				eid, active_cfm, component_id);
			if (status != 0) {
				goto clear_cert_chain;
			}
		}
	}

	/* Perform PMR0 check. If device supports Challenge command, then use that. Otherwise, get all
	 * measurement blocks which make up PMR0 using the Get Measurement command */
	if (attestation->state->txn.challenge_supported) {
		status = attestation->rng->generate_random_buffer (attestation->rng, SPDM_NONCE_LEN, nonce);
		if (status != 0) {
			goto hash_cancel;
		}

		rq_len = spdm_generate_challenge_request (attestation->state->spdm_msg_buffer,
			ATTESTATION_REQUESTER_MAX_SPDM_REQUEST, attestation->state->txn.slot_num,
			SPDM_MEASUREMENT_SUMMARY_HASH_ALL, nonce, attestation->state->txn.spdm_minor_version);
		if (ROT_IS_ERROR (rq_len)) {
			status = rq_len;
			goto hash_cancel;
		}

		status = attestation_requester_send_spdm_request_and_get_response (attestation, rq_len,
			device_addr, eid, true, SPDM_REQUEST_CHALLENGE);
		if (status != 0) {
			goto hash_cancel;
		}

		status = attestation_requester_spdm_process_challenge_response (attestation, eid);
		if (status != 0) {
			goto hash_cancel;
		}

		status = attestation_requester_verify_pmr (attestation, active_cfm, component_id, eid, 0);
		if ((status != 0) && (status != CFM_PMR_DIGEST_NOT_FOUND)) {
			goto hash_cancel;
		}
	}
	else {
		status = attestation_requester_get_and_verify_all_spdm_measurement_blocks (attestation, eid,
			device_addr, active_cfm, component_id);
		if ((status != 0) && (status != CFM_PMR_DIGEST_NOT_FOUND)) {
			goto hash_cancel;
		}
	}

	/* If PMR0 entry exists in CFM, then by getting here device has valid PMR0. Since PMR0 includes
	 * all measurement blocks, we dont have to check rest of the attestation rules. */
	if (status == CFM_PMR_DIGEST_NOT_FOUND) {
		status = attestation_requester_get_and_verify_cfm_contents (attestation, eid, device_addr,
			active_cfm, component_id);
		if (status != 0) {
			goto hash_cancel;
		}
	}

hash_cancel:
	if (!attestation->state->txn.hash_finish) {
		attestation->secondary_hash->cancel (attestation->secondary_hash);
	}

	return status;

clear_cert_chain:
	device_manager_clear_alias_key (attestation->device_mgr, eid);
	device_manager_clear_cert_chain_digest (attestation->device_mgr, eid);

	if (!attestation->state->txn.hash_finish) {
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
 *
 * @return Completion status, 0 if success or an error code otherwise
 */
int attestation_requester_attest_device (const struct attestation_requester *attestation,
	uint8_t eid)
{
	struct cfm_component_device component_device;
	const struct cfm *active_cfm;
	uint32_t component_id;
	enum cfm_attestation_type attestation_protocol;
	int device_addr;
	int device_state;
	int status;

	if (attestation == NULL) {
		return ATTESTATION_INVALID_ARGUMENT;
	}

	if (attestation->state->get_routing_table) {
		return ATTESTATION_REFRESH_ROUTING_TABLE;
	}

	memset (&attestation->state->txn, 0, sizeof (struct attestation_requester_transaction_state));

	device_addr = device_manager_get_device_addr_by_eid (attestation->device_mgr, eid);
	if (ROT_IS_ERROR (device_addr)) {
		return device_addr;
	}

	status = device_manager_get_component_id (attestation->device_mgr, eid, &component_id);
	if (status != 0) {
		return status;
	}

	active_cfm = attestation->cfm_manager->get_active_cfm (attestation->cfm_manager);
	if (active_cfm == NULL) {
		status = device_manager_update_device_state_by_eid (attestation->device_mgr, eid,
			DEVICE_MANAGER_ATTESTATION_INVALID_CFM);
		if (status != 0) {
			return status;
		}

		return ATTESTATION_NO_CFM;
	}

	status = active_cfm->get_component_device (active_cfm, component_id, &component_device);
	if (status != 0) {
		device_manager_update_device_state_by_eid (attestation->device_mgr, eid,
			DEVICE_MANAGER_ATTESTATION_INVALID_CFM);

		goto free_cfm;
	}

	attestation->state->txn.slot_num = component_device.cert_slot;
	attestation->state->txn.transcript_hash_type = component_device.transcript_hash_type;
	attestation->state->txn.measurement_hash_type = component_device.measurement_hash_type;

	attestation_protocol = component_device.attestation_protocol;

	active_cfm->free_component_device (active_cfm, &component_device);

	/* update previous attestation state in device manager attestation event */
	device_manager_update_attestation_summary_prev_state_by_eid (attestation->device_mgr, eid);

	device_state = device_manager_get_device_state_by_eid (attestation->device_mgr, eid);

	if (!(device_state == DEVICE_MANAGER_AUTHENTICATED) ||
		(device_state == DEVICE_MANAGER_AUTHENTICATED_WITHOUT_CERTS)) {
		status = device_manager_update_device_state_by_eid (attestation->device_mgr, eid,
			DEVICE_MANAGER_READY_FOR_ATTESTATION);
		if (status != 0) {
			goto free_cfm;
		}
	}

	switch (attestation_protocol) {
#ifdef ATTESTATION_SUPPORT_CERBERUS_CHALLENGE
		case CFM_ATTESTATION_CERBERUS_PROTOCOL:
			status = attestation_requester_attest_device_cerberus_protocol (attestation, eid,
				device_addr, active_cfm, component_id);

			break;
#endif

#ifdef ATTESTATION_SUPPORT_SPDM
		case CFM_ATTESTATION_DMTF_SPDM:
			if (attestation->secondary_hash == NULL) {
				status = ATTESTATION_UNSUPPORTED_OPERATION;
			}
			else {
				status = attestation_requester_attest_device_spdm (attestation, eid, device_addr,
					active_cfm, component_id);
			}

			break;
#endif

		default:
			status = ATTESTATION_UNSUPPORTED_PROTOCOL;
	}

free_cfm:
	attestation->cfm_manager->free_cfm (attestation->cfm_manager, active_cfm);

	if (status == 0) {
		if (attestation_protocol == CFM_ATTESTATION_DMTF_SPDM) {
			device_manager_update_device_state_by_eid (attestation->device_mgr, eid,
				attestation->state->txn.cert_supported ?
					DEVICE_MANAGER_AUTHENTICATED : DEVICE_MANAGER_AUTHENTICATED_WITHOUT_CERTS);
		}
		else {
			device_manager_update_device_state_by_eid (attestation->device_mgr, eid,
				DEVICE_MANAGER_AUTHENTICATED);
		}
	}
	else {
		device_state = device_manager_get_device_state_by_eid (attestation->device_mgr, eid);

		if ((device_state == DEVICE_MANAGER_NEVER_ATTESTED) ||
			(device_state == DEVICE_MANAGER_READY_FOR_ATTESTATION)) {
			device_manager_update_device_state_by_eid (attestation->device_mgr, eid,
				DEVICE_MANAGER_ATTESTATION_FAILED);
		}
	}

	device_manager_update_attestation_summary_event_counters_by_eid (attestation->device_mgr, eid);

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
	UNUSED (attestation);
	UNUSED (eid);

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
	const struct attestation_requester *attestation, uint8_t eid)
{
	struct spdm_discovery_device_id_block *block =
		(struct spdm_discovery_device_id_block*) attestation->state->txn.msg_buffer;
	struct spdm_discovery_device_id_descriptor *descriptor;
	uint16_t pci_vid = 0;
	uint16_t pci_device_id = 0;
	uint16_t pci_sub_vid = 0;
	uint16_t pci_sub_id = 0;
	uint16_t *id;
	size_t offset = sizeof (struct spdm_discovery_device_id_block);
	uint8_t found = 0;
	int device_addr;
	int device_num;
	int i_descriptor;
	int status;

	attestation->state->txn.protocol = ATTESTATION_PROTOCOL_DMTF_SPDM;
	attestation->state->txn.spdm_minor_version = ATTESTATION_PROTOCOL_DMTF_SPDM_1_0;
	attestation->state->txn.transcript_hash_type = HASH_TYPE_SHA256;
	attestation->state->txn.measurement_hash_type = HASH_TYPE_SHA256;

	device_addr = device_manager_get_device_addr (attestation->device_mgr,
		DEVICE_MANAGER_MCTP_BRIDGE_DEVICE_NUM);
	if (ROT_IS_ERROR (device_addr)) {
		return device_addr;
	}

	status = attestation_requester_send_and_receive_spdm_get_measurements (attestation, eid,
		device_addr, SPDM_MEASUREMENT_OPERATION_GET_DEVICE_ID, true);
	if (status != 0) {
		return status;
	}

	if (block->completion_code != SPDM_DISCOVERY_DEVICE_ID_BLOCK_CC_SUCCESS) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_GET_DEVICE_ID_FAILED,
			((eid << 8) | attestation->state->txn.spdm_minor_version), block->completion_code);

		return ATTESTATION_GET_DEVICE_ID_FAIL;
	}

	// Only PCI descriptors are supported, so ensure the 4 PCI descriptors are included in response
	if ((block->descriptor_count < 4) ||
		(block->device_id_len <
		((sizeof (struct spdm_discovery_device_id_descriptor) + sizeof (uint16_t)) * 4))) {
		return 0;
	}

	for (i_descriptor = 0; i_descriptor < block->descriptor_count; ++i_descriptor) {
		descriptor =
			(struct spdm_discovery_device_id_descriptor*) &attestation->state->txn.msg_buffer[offset];

		offset += sizeof (struct spdm_discovery_device_id_descriptor);
		id = (uint16_t*) &attestation->state->txn.msg_buffer[offset];
		offset += descriptor->descriptor_len;

		if (descriptor->descriptor_len != sizeof (uint16_t)) {
			continue;
		}

		switch (descriptor->descriptor_type) {
			case SPDM_DISCOVERY_DEVICE_ID_PCI_VID:
				pci_vid = *id;
				found |= 1;
				break;

			case SPDM_DISCOVERY_DEVICE_ID_PCI_DEVICE_ID:
				pci_device_id = *id;
				found |= (1 << 1);
				break;

			case SPDM_DISCOVERY_DEVICE_ID_PCI_SUBSYSTEM_VID:
				pci_sub_vid = *id;
				found |= (1 << 2);
				break;

			case SPDM_DISCOVERY_DEVICE_ID_PCI_SUBSYSTEM_ID:
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
			DEVICE_MANAGER_NEVER_ATTESTED);
		if (status != 0) {
			return status;
		}

		return device_manager_update_device_eid (attestation->device_mgr, device_num, eid);
	}

	return 0;
}
#endif

/**
 * Get Message Type support to a provided device using MCTP control message transport.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param eid EID of device to discover.
 * @param request Request to process.
 * @param response The response container received.
 *
 * @return Completion status, 0 if success or an error code otherwise
 */
static int attestation_requester_get_message_type (const struct attestation_requester *attestation,
	uint8_t eid, struct cmd_interface_msg *request, struct cmd_interface_msg *response)
{
	uint32_t timeout_ms;
	int request_len;
	int status;

	timeout_ms = device_manager_get_mctp_ctrl_timeout (attestation->device_mgr);

	status = msg_transport_create_empty_request (attestation->mctp_control,
		attestation->state->txn.msg_buffer, sizeof (attestation->state->txn.msg_buffer), eid,
		request);
	if (status != 0) {
		return status;
	}

	request_len = mctp_control_protocol_generate_get_message_type_support_request (request->payload,
		request->payload_length);
	if (ROT_IS_ERROR (request_len)) {
		return request_len;
	}

	//Update the payload length and request length after request message is ready
	cmd_interface_msg_set_message_payload_length (request, request_len);

	status = msg_transport_create_empty_response (attestation->state->txn.msg_buffer,
		sizeof (attestation->state->txn.msg_buffer), response);
	if (status != 0) {
		return status;
	}

	status =
		attestation_requester_send_mctp_control_msg_transport_request_and_get_response (attestation,
		attestation->mctp_control, request, response, eid, timeout_ms,
		MCTP_CONTROL_PROTOCOL_GET_MESSAGE_TYPE);
	if (status != 0) {
		return status;
	}

	status = mctp_control_protocol_process_get_message_type_support_response (response);
	if (status != 0) {
		return status;
	}

	return status;
}

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
	struct mctp_control_get_message_type_response *msg_type_rsp = NULL;
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	uint8_t i_type;
	uint8_t *msg_type;
	size_t msg_type_rsp_len = sizeof (struct mctp_control_get_message_type_response);
	int status;

	if (attestation == NULL) {
		return ATTESTATION_INVALID_ARGUMENT;
	}

	if (attestation->state->get_routing_table) {
		return ATTESTATION_REFRESH_ROUTING_TABLE;
	}

	memset (&attestation->state->txn, 0, sizeof (struct attestation_requester_transaction_state));
	attestation->state->txn.device_discovery = true;

	status = attestation_requester_get_message_type (attestation, eid, &request, &response);
	if (status != 0) {
		goto done;
	}

	msg_type_rsp = (struct mctp_control_get_message_type_response*) response.payload;
	for (i_type = 0; i_type < msg_type_rsp->message_type_count; ++i_type) {
		msg_type = &response.payload[msg_type_rsp_len] + i_type;

		switch (*msg_type) {
#ifdef ATTESTATION_SUPPORT_CERBERUS_CHALLENGE
			case MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF:
				status = attestation_requester_discover_device_cerberus_protocol (attestation, eid);
				goto done;
#endif

#ifdef ATTESTATION_SUPPORT_SPDM
			case MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM:
				status = attestation_requester_discover_device_spdm_protocol (attestation, eid);
				goto done;
#endif

			default:
				continue;
		}
	}

done:
	if (status != 0) {
		device_manager_unidentified_device_timed_out (attestation->device_mgr, eid);

		return status;
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
	struct mctp_base_protocol_message_header *header;
	struct mctp_control_get_routing_table_entries_response *routing_table_rsp;
	struct mctp_control_routing_table_entry *entry;
	uint8_t entry_handle = 0;
	uint8_t i_entry;
	uint8_t i_eid;
	int bridge_addr;
	int bridge_eid;
	int request_len;
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

	while (entry_handle != 0xFF) {
		/* TODO: Populating MCTP base header would be removed after the transition to msg_transport. */
		header = (struct mctp_base_protocol_message_header*) attestation->state->txn.msg_buffer;
		header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
		header->integrity_check = 0;
		request_len = sizeof (struct mctp_base_protocol_message_header);

		status = mctp_control_protocol_generate_get_routing_table_entries_request (entry_handle,
			&attestation->state->txn.msg_buffer[request_len],
			(sizeof (attestation->state->txn.msg_buffer) - request_len));
		if (ROT_IS_ERROR (status)) {
			return status;
		}
		request_len += status;

		status = attestation_requester_send_request_and_get_response (attestation, request_len,
			bridge_addr, bridge_eid, false, true, MCTP_CONTROL_PROTOCOL_GET_ROUTING_TABLE_ENTRIES);
		if (status != 0) {
			return status;
		}

		routing_table_rsp =
			(struct mctp_control_get_routing_table_entries_response*) attestation->state->txn.
			msg_buffer;
		entry = mctp_control_get_routing_table_entries_response_get_entries (routing_table_rsp);

		for (i_entry = 0; i_entry < routing_table_rsp->num_entries; ++i_entry, ++entry) {
			if (device_manager_is_device_unattestable (attestation->device_mgr,
				entry->starting_eid)) {
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

	status = device_manager_restart_device_discovery (attestation->device_mgr);
	if (status != 0) {
		return status;
	}

	attestation->state->get_routing_table = false;
	attestation->state->mctp_bridge_wait = false;

	return 0;
}
#endif

/**
 * Check to see if routing table should be retrieved from the MCTP bridge, and fetch it if so.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param pcr PCR store instance to utilize.
 * @param measurement The measurement ID for attestation results.
 * @param measurement_version The version associated with the measurement data.
 */
void attestation_requester_discovery_and_attestation_loop (
	const struct attestation_requester *attestation, struct pcr_store *pcr, uint16_t measurement,
	uint8_t measurement_version)
{
	const uint8_t *attestation_status;
	int eid = 0;
	int status;

	if ((attestation == NULL) || (pcr == NULL)) {
		return;
	}

#ifdef ATTESTATION_SUPPORT_DEVICE_DISCOVERY
	while (eid != DEVICE_MGR_NO_DEVICES_AVAILABLE) {
		eid = device_manager_get_eid_of_next_device_to_discover (attestation->device_mgr);
		if (!ROT_IS_ERROR (eid)) {
			status = attestation_requester_discover_device (attestation, eid);
			if (status != 0) {
				if (status == ATTESTATION_REFRESH_ROUTING_TABLE) {
					goto get_routing_table;
				}

				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
					ATTESTATION_LOGGING_DEVICE_FAILED_DISCOVERY,
					attestation->state->txn.requested_command, status);
			}
		}
		else if (eid != DEVICE_MGR_NO_DEVICES_AVAILABLE) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
				ATTESTATION_LOGGING_NEXT_DEVICE_DISCOVERY_ERROR, eid, 0);
		}
	}
#endif

	eid = 0;

	while (eid != DEVICE_MGR_NO_DEVICES_AVAILABLE) {
		eid = device_manager_get_eid_of_next_device_to_attest (attestation->device_mgr);
		if (!ROT_IS_ERROR (eid)) {
			status = attestation_requester_attest_device (attestation, eid);
			if (status != 0) {
				if (status == ATTESTATION_REFRESH_ROUTING_TABLE) {
					goto get_routing_table;
				}

				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
					ATTESTATION_LOGGING_DEVICE_FAILED_ATTESTATION,
					((eid << 16) | (attestation->state->txn.protocol << 8) |
							attestation->state->txn.requested_command), status);
			}
		}
		else if (eid != DEVICE_MGR_NO_DEVICES_AVAILABLE) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
				ATTESTATION_LOGGING_NEXT_DEVICE_ATTESTATION_ERROR, eid, 0);
		}
	}

	status = device_manager_get_attestation_status (attestation->device_mgr, &attestation_status);
	if (!ROT_IS_ERROR (status)) {
		status = pcr_store_update_versioned_buffer (pcr, attestation->primary_hash, measurement,
			attestation_status, status, true, measurement_version);
		if (status != 0) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
				ATTESTATION_LOGGING_PCR_UPDATE_ERROR, measurement, status);
		}
	}
	else {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_GET_ATTESTATION_STATUS_ERROR, status, 0);
	}

get_routing_table:
#ifdef ATTESTATION_SUPPORT_DEVICE_DISCOVERY
	status = attestation_requester_get_mctp_routing_table (attestation);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_GET_MCTP_ROUTING_TABLE_ERROR, status, 0);
	}
#endif

	return;
}

/**
 * On an MCTP bridge reset event, this function should be called to indicate that the attestation
 * requester needs to refresh the routing table and rediscover any remote devices.
 *
 * @param attestation Attestation requester instance to utilize.
 *
 * @return Completion status, 0 if success or an error code otherwise
 */
int attestation_requestor_mctp_bridge_was_reset (const struct attestation_requester *attestation)
{
	if (attestation == NULL) {
		return ATTESTATION_INVALID_ARGUMENT;
	}

	attestation->state->mctp_bridge_wait = true;

	return 0;
}

/**
 * Indicate that MCTP routing table should be queried from the MCTP bridge.
 * attestation_requestor_mctp_bridge_was_reset must be called prior to sending this request.  Even
 * then, MCTP bridge will not be queried for its routing table if routing table has already been
 * refreshed due to processing of a set EID request from the MCTP bridge.
 *
 * @param attestation Attestation requester instance to utilize.
 */
void attestation_requester_refresh_routing_table (const struct attestation_requester *attestation)
{
	if (attestation == NULL) {
		return;
	}

	if (attestation->state->mctp_bridge_wait) {
		attestation->state->get_routing_table = true;

		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_BRIDGE_RESET_TRIGGERED_ROUTING_TABLE_SYNC, 0, 0);

		platform_semaphore_post (&attestation->state->next_action);
	}
}

/**
 * This call will block until the attestation requester has a pending action to perform.
 *
 * @param attestation Attestation requester instance to utilize.
 */
void attestation_requestor_wait_for_next_action (const struct attestation_requester *attestation)
{
	uint32_t duration_ms;

	if (attestation == NULL) {
		return;
	}

	duration_ms = device_manager_get_time_till_next_action (attestation->device_mgr);

	if (duration_ms != 0) {
		platform_semaphore_wait (&attestation->state->next_action, duration_ms);
	}
}
