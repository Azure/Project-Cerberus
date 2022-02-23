// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "common/certificate.h"
#include "common/common_math.h"
#include "host_fw/host_processor.h"
#include "firmware/firmware_update_control.h"
#include "i2c/i2c_slave_common.h"
#include "logging/debug_log.h"
#include "logging/logging_flash.h"
#include "manifest/manifest_cmd_interface.h"
#include "manifest/pfm/pfm_manager.h"
#include "attestation/attestation.h"
#include "attestation_cmd_interface.h"
#include "cerberus_protocol.h"
#include "cmd_authorization.h"
#include "cmd_background.h"
#include "cmd_interface.h"
#include "session_manager.h"
#include "recovery/recovery_image.h"
#include "cerberus_protocol_required_commands.h"
#include "cerberus_protocol_master_commands.h"
#include "cerberus_protocol_optional_commands.h"


/**
 * Get PFM interface for a specified PFM location.
 *
 * @param pfm_mgr PFM manager for the requested port.
 * @param region The PFM region to query. 0 for active, 1 for pending.
 * @param pfm Output for the PFM.
 *
 * @return 0 if the operation was successful or an error code.
 */
static int cerberus_protocol_get_curr_pfm (struct pfm_manager *pfm_mgr, uint8_t region,
	struct pfm **pfm)
{
	if (pfm_mgr == NULL) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	if (region == 0) {
		*pfm = pfm_mgr->get_active_pfm (pfm_mgr);
	}
	else if (region == 1) {
		*pfm = pfm_mgr->get_pending_pfm (pfm_mgr);
	}
	else {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	return 0;
}

/**
 * Get the recovery image command interface for a specified recovery image.
 *
 * @param recovery_0 The recovery image command interface instance for port 0.
 * @param recovery_1 The recovery image command interface instance for port 1.
 * @param port The port to query.
 *
 * @return The recovery image command interface or null.
 */
struct recovery_image_cmd_interface* cerberus_protocol_get_recovery_image_cmd_interface (
	struct recovery_image_cmd_interface *recovery_0,
	struct recovery_image_cmd_interface *recovery_1, uint8_t port)
{
	if (port == 0) {
		return recovery_0;
	}
	else if (port == 1) {
		return recovery_1;
	}

	return NULL;
}

/**
 * Get recovery image manager instance for a specified port.
 *
 * @param recovery_manager_0 Recovery image manager instance for port 0.
 * @param recovery_manager_1 Recovery image manager instance for port 1.
 * @param port The recovery image port to query.
 *
 * @return The recovery image manager instance if a valid manager was found or null.
 */
struct recovery_image_manager* cerberus_protocol_get_recovery_image_manager (
	struct recovery_image_manager *recovery_manager_0,
	struct recovery_image_manager *recovery_manager_1, uint8_t port)
{
	if (port == 0) {
		return recovery_manager_0;
	}
	else if (port == 1) {
		return recovery_manager_1;
	}

	return NULL;
}

/**
 * Process FW update init request
 *
 * @param control Firmware update control instance to utilize
 * @param request FW update request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_fw_update_init (struct firmware_update_control *control,
	struct cmd_interface_msg *request)
{
	struct cerberus_protocol_prepare_fw_update *rq =
		(struct cerberus_protocol_prepare_fw_update*) request->data;

	if (request->length != sizeof (struct cerberus_protocol_prepare_fw_update)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	request->length = 0;
	return control->prepare_staging (control, rq->total_size);
}

/**
 * Process FW update request
 *
 * @param control Firmware update control instance to utilize
 * @param request FW update request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_fw_update (struct firmware_update_control *control,
	struct cmd_interface_msg *request)
{
	struct cerberus_protocol_fw_update *rq = (struct cerberus_protocol_fw_update*) request->data;
	int status;

	if (request->length < sizeof (struct cerberus_protocol_fw_update)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	status = control->write_staging (control, &rq->payload,
		cerberus_protocol_fw_update_length (request));

	request->length = 0;
	return status;
}

/**
 * Process FW update start request
 *
 * @param control Firmware update control instance to utilize
 * @param request FW update start request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_fw_update_start (struct firmware_update_control *control,
	struct cmd_interface_msg *request)
{
	if (request->length != sizeof (struct cerberus_protocol_complete_fw_update)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	request->length = 0;
	return control->start_update (control);
}

/**
 * Process log info request
 *
 * @param pcr_store PCR store instance to utilize
 * @param request Log info request to process
 *
 * @return 0 if request completed successfully or an error code.
 */
int cerberus_protocol_get_log_info (struct pcr_store *pcr_store,
	struct cmd_interface_msg *request)
{
	struct cerberus_protocol_get_log_info_response *rsp =
		(struct cerberus_protocol_get_log_info_response*) request->data;
	int log_length;

	if (request->length != sizeof (struct cerberus_protocol_get_log_info)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	log_length = debug_log_get_size ();
	if (ROT_IS_ERROR (log_length)) {
		log_length = 0;
	}
	rsp->debug_log_length = log_length;

	log_length = pcr_store_get_attestation_log_size (pcr_store);
	if (ROT_IS_ERROR (log_length)) {
		log_length = 0;
	}
	rsp->attestation_log_length = log_length;

	rsp->tamper_log_length = 0;

	request->length = sizeof (struct cerberus_protocol_get_log_info_response);
	return 0;
}

/**
 * Process log read request
 *
 * @param pcr_store PCR store instance to utilize
 * @param hash Hash engine to utilize
 * @param request Log read request to process
 *
 * @return 0 if request completed successfully or an error code.
 */
int cerberus_protocol_log_read (struct pcr_store *pcr_store, struct hash_engine *hash,
	struct cmd_interface_msg *request)
{
	struct cerberus_protocol_get_log *rq = (struct cerberus_protocol_get_log*) request->data;
	struct cerberus_protocol_get_log_response *rsp =
		(struct cerberus_protocol_get_log_response*) request->data;
	int log_length;

	if (request->length != sizeof (struct cerberus_protocol_get_log)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if (rq->log_type == CERBERUS_PROTOCOL_DEBUG_LOG) {
		log_length = debug_log_read_contents (rq->offset, cerberus_protocol_log_data (rsp),
			CERBERUS_PROTOCOL_MAX_LOG_DATA (request));
	}
	else if (rq->log_type == CERBERUS_PROTOCOL_ATTESTATION_LOG) {
		log_length = pcr_store_get_attestation_log (pcr_store, hash, rq->offset,
			cerberus_protocol_log_data (rsp), CERBERUS_PROTOCOL_MAX_LOG_DATA (request));
	}
	else if (rq->log_type == CERBERUS_PROTOCOL_TCG_LOG) {
		log_length = pcr_store_get_tcg_log (pcr_store, cerberus_protocol_log_data (rsp), rq->offset,
			CERBERUS_PROTOCOL_MAX_LOG_DATA (request));
	}
	else {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	if (ROT_IS_ERROR (log_length)) {
		return log_length;
	}

	request->length = cerberus_protocol_get_log_response_length (log_length);
	return 0;
}

/**
 * Process log clear request
 *
 * @param background Command background instance to utilize
 * @param request Log clear request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_log_clear (struct cmd_background *background,
	struct cmd_interface_msg *request)
{
	struct cerberus_protocol_clear_log *rq = (struct cerberus_protocol_clear_log*) request->data;

	if (request->length != sizeof (struct cerberus_protocol_clear_log)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	request->length = 0;

#ifdef CMD_ENABLE_DEBUG_LOG
	if (rq->log_type == CERBERUS_PROTOCOL_DEBUG_LOG) {
		return background->debug_log_clear (background);
	}
	else
#endif
	if (rq->log_type == CERBERUS_PROTOCOL_ATTESTATION_LOG) {
		return 0;
	}

	return CMD_HANDLER_UNSUPPORTED_INDEX;
}

/**
 * Process PFM ID version request
 *
 * @param pfm PFM to query
 * @param request PFM ID request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
static int cerberus_protocol_get_pfm_id_version (struct pfm *pfm,
	struct cmd_interface_msg *request)
{
	return cerberus_protocol_get_manifest_id_version (&pfm->base, request);
}

/**
 * Process PFM ID platform request
 *
 * @param pfm PFM to query
 * @param request PFM ID request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
static int cerberus_protocol_get_pfm_id_platform (struct pfm *pfm,
	struct cmd_interface_msg *request)
{
	return cerberus_protocol_get_manifest_id_platform (&pfm->base, request);
}

/**
 * Process PFM ID request
 *
 * @param pfm_mgr List of PFM managers for all available ports
 * @param num_ports Numbers of available ports
 * @param request PFM ID request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_pfm_id (struct pfm_manager *pfm_mgr[], uint8_t num_ports,
	struct cmd_interface_msg *request)
{
	struct cerberus_protocol_get_pfm_id *rq = (struct cerberus_protocol_get_pfm_id*) request->data;
	struct pfm *curr_pfm = NULL;
	uint8_t port;
	uint8_t id;
	int status = 0;

	if (request->length == (sizeof (struct cerberus_protocol_get_pfm_id) - sizeof (rq->id))) {
		rq->id = 0;
	}
	else if (request->length != sizeof (struct cerberus_protocol_get_pfm_id)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	port = rq->port_id;
	id = rq->id;
	if ((port >= num_ports) || (id > 1)) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	status = cerberus_protocol_get_curr_pfm (pfm_mgr[port], rq->region, &curr_pfm);
	/* When there's no valid PFM manager, return a success
	 * with response indicating no valid manifest */
	if ((status != 0) && (status != CMD_HANDLER_UNSUPPORTED_INDEX)) {
		return status;
	}

	if (id == 0) {
		status = cerberus_protocol_get_pfm_id_version (curr_pfm, request);
	}
	else {
		status = cerberus_protocol_get_pfm_id_platform (curr_pfm, request);
	}

	if (pfm_mgr[port] != NULL) {
		pfm_mgr[port]->free_pfm (pfm_mgr[port], curr_pfm);
	}

	return status;
}

/**
 * Process PFM fw request
 *
 * @param pfm_mgr List of PFM managers for all available ports
 * @param num_ports Numbers of available ports
 * @param request PFM supported FW request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_pfm_fw (struct pfm_manager *pfm_mgr[], uint8_t num_ports,
	struct cmd_interface_msg *request)
{
	struct cerberus_protocol_get_pfm_supported_fw *rq =
		(struct cerberus_protocol_get_pfm_supported_fw*) request->data;
	struct cerberus_protocol_get_pfm_supported_fw_response *rsp =
		(struct cerberus_protocol_get_pfm_supported_fw_response*) request->data;
	struct pfm *curr_pfm = NULL;
	size_t offset;
	uint32_t port;
	char *fw_id = NULL;
	int status;

	if (request->length < sizeof (struct cerberus_protocol_get_pfm_supported_fw)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if ((request->length > sizeof (struct cerberus_protocol_get_pfm_supported_fw)) &&
		(request->length != cerberus_protocol_get_pfm_supported_fw_request_length_with_id (rq))) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if (rq->port_id >= num_ports) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	offset = rq->offset;
	port = rq->port_id;

	status = cerberus_protocol_get_curr_pfm (pfm_mgr[port], rq->region, &curr_pfm);
	if (status != 0) {
		if (status == CMD_HANDLER_UNSUPPORTED_INDEX) {
			status = 0;
			rsp->valid = 0;
			rsp->version = 0;
			request->length = cerberus_protocol_get_pfm_supported_fw_response_length (0);
			goto exit;
		}
		else {
			return status;
		}
	}

	if (curr_pfm != NULL) {
		rsp->valid = 1;

		status = curr_pfm->base.get_id (&curr_pfm->base, &rsp->version);
		if (status != 0) {
			goto exit;
		}

		if ((request->length > sizeof (struct cerberus_protocol_get_pfm_supported_fw)) &&
			(cerberus_protocol_get_pfm_supported_fw_id_length (rq) != 0)) {
			fw_id = cerberus_protocol_get_pfm_supported_fw_id (rq);
		}

		status = curr_pfm->buffer_supported_versions (curr_pfm, fw_id, offset,
			CERBERUS_PROTOCOL_MAX_PFM_VERSIONS (request), cerberus_protocol_pfm_supported_fw (rsp));
		if (ROT_IS_ERROR (status)) {
			goto exit;
		}

		request->length = cerberus_protocol_get_pfm_supported_fw_response_length (status);
		status = 0;
	}
	else {
		rsp->valid = 0;
		rsp->version = 0;
		request->length = cerberus_protocol_get_pfm_supported_fw_response_length (0);
	}

exit:
	if (pfm_mgr[port] != NULL) {
		pfm_mgr[port]->free_pfm (pfm_mgr[port], curr_pfm);
	}
	return status;
}

/**
 * Process PFM update init request
 *
 * @param pfm_cmd List of PFM command interfaces for all available ports
 * @param num_ports Number of available ports
 * @param request PFM update init request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_pfm_update_init (struct manifest_cmd_interface* pfm_cmd[], uint8_t num_ports,
	struct cmd_interface_msg *request)
{
	struct cerberus_protocol_prepare_pfm_update *rq =
		(struct cerberus_protocol_prepare_pfm_update*) request->data;

	if (request->length != sizeof (struct cerberus_protocol_prepare_pfm_update)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if (rq->port_id >= num_ports) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	if (pfm_cmd[rq->port_id] == NULL) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	request->length = 0;
	return pfm_cmd[rq->port_id]->prepare_manifest (pfm_cmd[rq->port_id], rq->size);
}

/**
 * Process PFM update request
 *
 * @param pfm_cmd List of PFM command interface for all available ports.
 * @param num_ports Number of available ports.
 * @param request PFM update request to process.
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_pfm_update (struct manifest_cmd_interface *pfm_cmd[], uint8_t num_ports,
	struct cmd_interface_msg *request)
{
	struct cerberus_protocol_pfm_update *rq = (struct cerberus_protocol_pfm_update*) request->data;
	int status;

	if (request->length < sizeof (struct cerberus_protocol_pfm_update)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if (rq->port_id >= num_ports) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	if (pfm_cmd[rq->port_id] == NULL) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	status = pfm_cmd[rq->port_id]->store_manifest (pfm_cmd[rq->port_id], &rq->payload,
		cerberus_protocol_pfm_update_length (request));

	request->length = 0;
	return status;
}

/**
 * Process PFM update complete request
 *
 * @param pfm_cmd List of PFM command interface for all available ports.
 * @param num_ports Numbers of available ports.
 * @param request PFM update complete request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_pfm_update_complete (struct manifest_cmd_interface *pfm_cmd[],
	uint8_t num_ports, struct cmd_interface_msg *request)
{
	struct cerberus_protocol_complete_pfm_update *rq =
		(struct cerberus_protocol_complete_pfm_update*) request->data;

	if (request->length != sizeof (struct cerberus_protocol_complete_pfm_update)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if (rq->port_id >= num_ports) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	if (pfm_cmd[rq->port_id] == NULL) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	request->length = 0;
	return pfm_cmd[rq->port_id]->finish_manifest (pfm_cmd[rq->port_id], rq->activation);

}

/**
 * Process get host reset status
 *
 * @param host_0_ctrl Port 0 host control instance
 * @param host_1_ctrl Port 1 host control instance
 * @param request Host reset status request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_host_reset_status (struct host_control *host_0_ctrl,
	struct host_control *host_1_ctrl, struct cmd_interface_msg *request)
{
	struct cerberus_protocol_get_host_state *rq =
		(struct cerberus_protocol_get_host_state*) request->data;
	struct cerberus_protocol_get_host_state_response *rsp =
		(struct cerberus_protocol_get_host_state_response*) request->data;
	struct host_control *control;
	int status;

	if (request->length != sizeof (struct cerberus_protocol_get_host_state)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	switch (rq->port_id) {
		case 0:
			control = host_0_ctrl;
			break;

		case 1:
			control = host_1_ctrl;
			break;

		default:
			return CMD_HANDLER_OUT_OF_RANGE;
	}

	if (control == NULL) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	status = control->is_processor_in_reset (control);
	if (status == 0) {
		rsp->reset_status = CERBERUS_PROTOCOL_HOST_RUNNING;
	}
	else if (status == 1) {
		status = control->is_processor_held_in_reset (control);
		if (status == 1) {
			rsp->reset_status = CERBERUS_PROTOCOL_HOST_HELD_IN_RESET;
		}
		else if (status == 0) {
			rsp->reset_status = CERBERUS_PROTOCOL_HOST_IN_RESET;
		}
		else {
			return status;
		}
	}
	else {
		return status;
	}

	request->length = sizeof (struct cerberus_protocol_get_host_state_response);
	return 0;
}

/**
 * Process unseal message request
 *
 * @param background Command background instance to utilize
 * @param request Unseal request to process
 *
 * @return 0 if processing completed successfully or an error code.
 */
int cerberus_protocol_unseal_message (struct cmd_background *background,
	struct cmd_interface_msg *request)
{
#ifdef CMD_ENABLE_UNSEAL
	struct cerberus_protocol_message_unseal *rq =
		(struct cerberus_protocol_message_unseal*) request->data;
	uint8_t *end = request->data + request->length;
	int status;

	request->crypto_timeout = true;

	if (request->length < sizeof (struct cerberus_protocol_message_unseal)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if ((rq->hmac_type != CERBERUS_PROTOCOL_UNSEAL_HMAC_SHA256) ||
		(rq->seed_type > CERBERUS_PROTOCOL_UNSEAL_SEED_ECDH)) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	if ((rq->seed_type == CERBERUS_PROTOCOL_UNSEAL_SEED_RSA) &&
		(rq->seed_params.rsa.padding > CERBERUS_PROTOCOL_UNSEAL_RSA_OAEP_SHA256)) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	if ((rq->seed_length == 0) || (cerberus_protocol_unseal_ciphertext_length_ptr (rq) >= end)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if ((cerberus_protocol_unseal_ciphertext_length (rq) == 0) ||
		(cerberus_protocol_unseal_hmac_length_ptr (rq) >= end)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if ((cerberus_protocol_unseal_hmac_length (rq) != SHA256_HASH_LENGTH) ||
		((uint8_t*) cerberus_protocol_get_unseal_pmr_sealing (rq) >= end)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if (((uint8_t*) cerberus_protocol_get_unseal_pmr_sealing (rq) +
		sizeof (struct cerberus_protocol_unseal_pmrs)) != end) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	status = background->unseal_start (background, request->data, request->length);

	request->length = 0;
	return status;
#else
	return CMD_HANDLER_UNSUPPORTED_COMMAND;
#endif
}

/**
 * Process unseal message result request
 *
 * @param background Command background instance to utilize
 * @param request Unseal result request to process
 *
 * @return 0 if processing completed successfully or an error code.
 */
int cerberus_protocol_unseal_message_result (struct cmd_background *background,
	struct cmd_interface_msg *request)
{
#ifdef CMD_ENABLE_UNSEAL
	struct cerberus_protocol_message_unseal_result_completed_response *rsp =
		(struct cerberus_protocol_message_unseal_result_completed_response*) request->data;
	size_t max_buf_len;
	int status;

	if (request->length != sizeof (struct cerberus_protocol_message_unseal_result)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	max_buf_len = CERBERUS_PROTOCOL_MAX_UNSEAL_KEY_DATA (request);

	if (background != NULL) {
		status = background->unseal_result (background, &rsp->key, &max_buf_len,
			&rsp->unseal_status);
		if (ROT_IS_ERROR (status)) {
			return status;
		}
	}
	else {
		return CMD_HANDLER_UNSUPPORTED_COMMAND;
	}

	if (rsp->unseal_status == ATTESTATION_CMD_STATUS_SUCCESS) {
		rsp->key_length = max_buf_len;
		request->length = cerberus_protocol_get_unseal_response_length (max_buf_len);
	}
	else {
		request->length = sizeof (struct cerberus_protocol_message_unseal_result_response);
	}

	return 0;
#else
	return CMD_HANDLER_UNSUPPORTED_COMMAND;
#endif
}

/**
 * Process a request to reset the device configuration.
 *
 * @param cmd_auth Command authorization instance to utilize
 * @param background Command background instance to utilize
 * @param request Reset configuration request to process
 *
 * @return 0 if processing completed successfully or an error code.
 */
int cerberus_protocol_reset_config (struct cmd_authorization *cmd_auth,
	struct cmd_background *background, struct cmd_interface_msg *request)
{
#if defined CMD_ENABLE_RESET_CONFIG || defined CMD_ENABLE_INTRUSION
	struct cerberus_protocol_reset_config *rq =
		(struct cerberus_protocol_reset_config*) request->data;
	struct cerberus_protocol_reset_config_response *rsp =
		(struct cerberus_protocol_reset_config_response*) request->data;
	uint8_t *nonce = NULL;
	size_t length;
	int status;
	int (*auth) (struct cmd_authorization*, uint8_t**, size_t*);
	int (*action) (struct cmd_background*);

	request->crypto_timeout = true;

	if (request->length < sizeof (struct cerberus_protocol_reset_config)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	switch (rq->type) {
#ifdef CMD_ENABLE_RESET_CONFIG
		case CERBERUS_PROTOCOL_REVERT_BYPASS:
			auth = cmd_auth->authorize_revert_bypass;
			action = background->reset_bypass;
			break;

		case CERBERUS_PROTOCOL_FACTORY_RESET:
			auth = cmd_auth->authorize_reset_defaults;
			action = background->restore_defaults;
			break;

		case CERBERUS_PROTOCOL_CLEAR_PCD:
			auth = cmd_auth->authorize_clear_platform_config;
			action = background->clear_platform_config;
			break;
#endif

#ifdef CMD_ENABLE_INTRUSION
		case CERBERUS_PROTOCOL_RESET_INTRUSION:
			auth = cmd_auth->authorize_reset_intrusion;
			action = background->reset_intrusion;
			break;
#endif

		default:
			return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	length = cerberus_protocol_reset_authorization_length (request);
	if (length != 0) {
		nonce = cerberus_protocol_reset_authorization (rq);
	}

	status = auth (cmd_auth, &nonce, &length);
	if (status == AUTHORIZATION_CHALLENGE) {
		if (length > CERBERUS_PROTOCOL_MAX_AUTHORIZATION_DATA (request)) {
			return CMD_HANDLER_BUF_TOO_SMALL;
		}

		memcpy (cerberus_protocol_reset_authorization (rsp), nonce, length);
		request->length = cerberus_protocol_get_reset_config_response_length (length);
		status = 0;
	}
	else if (status == 0) {
		status = action (background);
		request->length = 0;
	}

	return status;
#else
	return CMD_HANDLER_UNSUPPORTED_COMMAND;
#endif
}

/**
 * Process a prepare recovery image request.
 *
 * @param recovery_0 Recovery image update command interface instance for port 0.
 * @param recovery_1 Recovery image update command interface instance for port 1.
 * @param request Recovery image prepare request to process.
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_prepare_recovery_image (struct recovery_image_cmd_interface *recovery_0,
	struct recovery_image_cmd_interface *recovery_1, struct cmd_interface_msg *request)
{
	struct cerberus_protocol_prepare_recovery_image_update *rq =
		(struct cerberus_protocol_prepare_recovery_image_update*) request->data;
	struct recovery_image_cmd_interface *recovery_interface;

	if (request->length != sizeof (struct cerberus_protocol_prepare_recovery_image_update)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if (rq->port_id > 1) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	recovery_interface = cerberus_protocol_get_recovery_image_cmd_interface (recovery_0, recovery_1,
		rq->port_id);
	if (recovery_interface == NULL) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	request->length = 0;
	return recovery_interface->prepare_recovery_image (recovery_interface, rq->size);
}

/**
 * Process an update recovery image request.
 *
 * @param recovery_0 Recovery image update command interface instance for port 0.
 * @param recovery_1 Recovery image update command interface instance for port 1.
 * @param request Recovery image update request to process.
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_update_recovery_image (struct recovery_image_cmd_interface *recovery_0,
	struct recovery_image_cmd_interface *recovery_1, struct cmd_interface_msg *request)
{
	struct cerberus_protocol_recovery_image_update *rq =
		(struct cerberus_protocol_recovery_image_update*) request->data;
	struct recovery_image_cmd_interface *recovery_interface;
	int status;

	if (request->length < sizeof (struct cerberus_protocol_recovery_image_update)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if (rq->port_id > 1) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	recovery_interface = cerberus_protocol_get_recovery_image_cmd_interface (recovery_0, recovery_1,
		rq->port_id);
	if (recovery_interface == NULL) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	status = recovery_interface->update_recovery_image (recovery_interface, &rq->payload,
		cerberus_protocol_recovery_image_update_length (request));

	request->length = 0;
	return status;
}

/**
 * Process an activate recovery image request.
 *
 * @param recovery_0 Recovery image update command interface instance for port 0.
 * @param recovery_1 Recovery image update command interface instance for port 1.
 * @param request Recovery image activate request to process.
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_activate_recovery_image (struct recovery_image_cmd_interface *recovery_0,
	struct recovery_image_cmd_interface *recovery_1, struct cmd_interface_msg *request)
{
	struct cerberus_protocol_complete_recovery_image_update *rq =
		(struct cerberus_protocol_complete_recovery_image_update*) request->data;
	struct recovery_image_cmd_interface *recovery_interface;

	if (request->length != sizeof (struct cerberus_protocol_complete_recovery_image_update)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if (rq->port_id > 1) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	recovery_interface = cerberus_protocol_get_recovery_image_cmd_interface (recovery_0, recovery_1,
		rq->port_id);
	if (recovery_interface == NULL) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	request->length = 0;
	return recovery_interface->activate_recovery_image (recovery_interface);
}

/**
 * Process get recovery image ID request.
 *
 * @param manager_0 Recovery image manager instance for port 0.
 * @param manager_1 Recovery image manager instance for port 1.
 * @param request Recovery image get request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_recovery_image_id (struct recovery_image_manager *manager_0,
	struct recovery_image_manager *manager_1, struct cmd_interface_msg *request)
{
	struct cerberus_protocol_get_recovery_image_id *rq =
		(struct cerberus_protocol_get_recovery_image_id*) request->data;
	struct cerberus_protocol_get_recovery_image_id_version_response *rsp =
		(struct cerberus_protocol_get_recovery_image_id_version_response*) request->data;
	struct recovery_image *curr_recovery_image;
	struct recovery_image_manager *curr_mgr;
	int status = 0;

	if (request->length ==
		(sizeof (struct cerberus_protocol_get_recovery_image_id) - sizeof (rq->id))) {
		rq->id = 0;
	}
	else if (request->length != sizeof (struct cerberus_protocol_get_recovery_image_id)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if (rq->port_id > 1) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	curr_mgr = cerberus_protocol_get_recovery_image_manager (manager_0, manager_1, rq->port_id);
	if (curr_mgr == NULL) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	memset (rsp->version, 0, sizeof (rsp->version));

	curr_recovery_image = curr_mgr->get_active_recovery_image (curr_mgr);
	if (curr_recovery_image != NULL) {
		status = curr_recovery_image->get_version (curr_recovery_image, rsp->version,
			sizeof (rsp->version));
		if (status != 0) {
			goto exit;
		}
	}

	request->length = sizeof (struct cerberus_protocol_get_recovery_image_id_version_response);

exit:
	if (curr_recovery_image != NULL) {
		curr_mgr->free_recovery_image (curr_mgr, curr_recovery_image);
	}

	return status;
}

/**
 * Process get attestation data request
 *
 * @param pcr_store PCR store instance to utilize
 * @param request Log read request to process
 *
 * @return 0 if request completed successfully or an error code.
 */
int cerberus_protocol_get_attestation_data (struct pcr_store *pcr_store,
	struct cmd_interface_msg *request)
{
	struct cerberus_protocol_get_attestation_data *rq =
		(struct cerberus_protocol_get_attestation_data*) request->data;
	struct cerberus_protocol_get_attestation_data_response *resp =
		(struct cerberus_protocol_get_attestation_data_response*) request->data;
	int status;

	if (request->length != sizeof (struct cerberus_protocol_get_attestation_data)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	status = pcr_store_get_measurement_data (pcr_store, PCR_MEASUREMENT (rq->pmr, rq->entry),
		rq->offset, cerberus_protocol_attestation_data (resp),
		CERBERUS_PROTOCOL_MAX_ATTESTATION_DATA (request));
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	request->length = cerberus_protocol_get_attestation_data_response_length (status);

	return 0;
}

/**
 * Process a key exchange request.
 *
 * @param session Session manager to utilize.
 * @param request Key exchange request to process.
 * @param encrypted Flag indicating if request was received in an encrypted session.
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_key_exchange (struct session_manager *session,
	struct cmd_interface_msg *request, uint8_t encrypted)
{
	struct cerberus_protocol_key_exchange_type_1 *type1_rq =
		(struct cerberus_protocol_key_exchange_type_1*) request->data;
	struct cerberus_protocol_key_exchange_type_2 *type2_rq =
		(struct cerberus_protocol_key_exchange_type_2*) request->data;
	int status;

	request->crypto_timeout = true;

	if (session == NULL) {
		return CMD_HANDLER_UNSUPPORTED_COMMAND;
	}

	if (request->length <= sizeof (struct cerberus_protocol_key_exchange)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	switch (type1_rq->common.key_type) {
		case CERBERUS_PROTOCOL_SESSION_KEY:
			return session->establish_session (session, request);

		case CERBERUS_PROTOCOL_PAIRED_KEY_HMAC:
			if (!encrypted) {
				return CMD_HANDLER_CMD_SHOULD_BE_ENCRYPTED;
			}

			status = session->setup_paired_session (session, request->source_eid,
				type1_rq->pairing_key_len,
				cerberus_protocol_key_exchange_type_1_hmac_data (type1_rq),
				cerberus_protocol_key_exchange_type_1_hmac_len (request));

			break;

		case CERBERUS_PROTOCOL_DELETE_SESSION_KEY:
			if (!encrypted) {
				return CMD_HANDLER_CMD_SHOULD_BE_ENCRYPTED;
			}

			status = session->reset_session (session, request->source_eid,
				cerberus_protocol_key_exchange_type_2_hmac_data (type2_rq),
				cerberus_protocol_key_exchange_type_2_hmac_len (request));
			if (status == 0) {
				type2_rq->common.header.crypt = 0;
			}

			break;

		default:
			return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	if (status == 0) {
		request->length = sizeof (struct cerberus_protocol_key_exchange_response);
	}

	return status;
}

/**
 * Process a session sync request.
 *
 * @param session Session manager to utilize.
 * @param request Session sync request to process.
 * @param encrypted Flag indicating if request was received in an encrypted session.
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_session_sync (struct session_manager *session,
	struct cmd_interface_msg *request, uint8_t encrypted)
{
	struct cerberus_protocol_session_sync *rq =
		(struct cerberus_protocol_session_sync*) request->data;
	int status;

	request->crypto_timeout = true;

	if (session == NULL) {
		return CMD_HANDLER_UNSUPPORTED_COMMAND;
	}

	if (!encrypted) {
		return CMD_HANDLER_CMD_SHOULD_BE_ENCRYPTED;
	}

	if (request->length != sizeof (struct cerberus_protocol_session_sync)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	status = session->session_sync (session, request->source_eid, rq->rn_req,
		cerberus_protocol_session_sync_hmac_data (rq),
		CERBERUS_PROTOCOL_MAX_SESSION_SYNC_HMAC_LEN (request));
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	request->length = cerberus_protocol_session_sync_length (status);

	return 0;
}
