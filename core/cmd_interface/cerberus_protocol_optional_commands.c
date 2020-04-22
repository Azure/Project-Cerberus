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
#include "device_manager.h"
#include "recovery/recovery_image.h"
#include "cerberus_protocol_required_commands.h"
#include "cerberus_protocol_master_commands.h"
#include "cerberus_protocol_optional_commands.h"


/**
 * Get PFM cmd interface for a specified PFM.
 *
 * @param pfm_0 PFM command interface for port 0.
 * @param pfm_1 PFM command interface for port 1.
 * @param port The port to query.
 *
 * @return The PFM cmd interface if a valid PFM was found or null.
 */
struct manifest_cmd_interface* cerberus_protocol_get_pfm_cmd_interface (
	struct manifest_cmd_interface *pfm_0, struct manifest_cmd_interface *pfm_1, uint8_t port)
{
	if (port == 0) {
		return pfm_0;
	}
	else if (port == 1) {
		return pfm_1;
	}

	return NULL;
}

/**
 * Get PFM manager interface for a specified PFM.
 *
 * @param pfm_mgr_0 Port 0 PFM manager.
 * @param pfm_mgr_1 Port 1 PFM manager.
 * @param port The PFM port to query.
 *
 * @return The PFM manager interface if a valid PFM was found or null.
 */
static struct pfm_manager* cerberus_protocol_get_pfm_manager (struct pfm_manager *pfm_mgr_0,
	struct pfm_manager *pfm_mgr_1, uint8_t port)
{
	if (port == 0) {
		return pfm_mgr_0;
	}
	else if (port == 1) {
		return pfm_mgr_1;
	}

	return NULL;
}

/**
 * Get PFM interface for a specified PFM location.
 *
 * @param pfm_mgr_0 Port 0 PFM manager.
 * @param pfm_mgr_1 Port 1 PFM manager.
 * @param port The PFM port to query.
 * @param region The PFM region to query. 0 for active, 1 for pending.
 * @param pfm Output for the PFM.
 *
 * @return 0 if the operation was successful or an error code.
 */
static int cerberus_protocol_get_curr_pfm (struct pfm_manager *pfm_mgr_0,
	struct pfm_manager *pfm_mgr_1, uint8_t port, uint8_t region, struct pfm **pfm)
{
	struct pfm_manager *curr_pfm_mgr = cerberus_protocol_get_pfm_manager (pfm_mgr_0, pfm_mgr_1,
		port);

	if (curr_pfm_mgr == NULL) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	if (region == 0) {
		*pfm = curr_pfm_mgr->get_active_pfm (curr_pfm_mgr);
	}
	else if (region == 1) {
		*pfm = curr_pfm_mgr->get_pending_pfm (curr_pfm_mgr);
	}
	else {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	return 0;
}

/**
 * Release a pfm instance.
 *
 * @param manager PFM manager for port 0.
 * @param manager PFM manager for port 1.
 * @param port The PFM port to query.
 * @param pfm The PFM to release.
 */
static void cerberus_protocol_free_pfm (struct pfm_manager* pfm_mgr_0,
	struct pfm_manager* pfm_mgr_1, uint8_t port, struct pfm *pfm)
{
	struct pfm_manager *curr_pfm_mgr = NULL;

	curr_pfm_mgr = cerberus_protocol_get_pfm_manager (pfm_mgr_0, pfm_mgr_1, port);
	if (curr_pfm_mgr == NULL) {
		return;
	}

	curr_pfm_mgr->free_pfm (curr_pfm_mgr, pfm);
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
 * Process FW update init packet
 *
 * @param control Firmware update control instance to utilize
 * @param request FW update request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_fw_update_init (struct firmware_update_control *control,
	struct cmd_interface_request *request)
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
 * Process FW update packet
 *
 * @param control Firmware update control instance to utilize
 * @param request FW update request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_fw_update (struct firmware_update_control *control,
	struct cmd_interface_request *request)
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
 * Process FW update start packet
 *
 * @param control Firmware update control instance to utilize
 * @param request FW update start request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_fw_update_start (struct firmware_update_control *control,
	struct cmd_interface_request *request)
{
	if (request->length != sizeof (struct cerberus_protocol_complete_fw_update)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	request->length = 0;
	return control->start_update (control);
}

/**
 * Process log info packet
 *
 * @param pcr_store PCR store instance to utilize
 * @param request Log info request to process
 *
 * @return 0 if request completed successfully or an error code.
 */
int cerberus_protocol_get_log_info (struct pcr_store *pcr_store,
	struct cmd_interface_request *request)
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

	log_length = pcr_store_get_tcg_log_size (pcr_store);
	if (ROT_IS_ERROR (log_length)) {
		log_length = 0;
	}
	rsp->attestation_log_length = log_length;

	rsp->tamper_log_length = 0;

	request->length = sizeof (struct cerberus_protocol_get_log_info_response);
	return 0;
}

/**
 * Process log read packet
 *
 * @param pcr_store PCR store instance to utilize
 * @param hash Hash engine to utilize
 * @param request Log read request to process
 *
 * @return 0 if request completed successfully or an error code.
 */
int cerberus_protocol_log_read (struct pcr_store *pcr_store, struct hash_engine *hash,
	struct cmd_interface_request *request)
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
	else if (rq->log_type == CERBERUS_PROTOCOL_TCG_LOG) {
		log_length = pcr_store_get_tcg_log (pcr_store, hash, rq->offset,
			cerberus_protocol_log_data (rsp), CERBERUS_PROTOCOL_MAX_LOG_DATA (request));
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
 * Process log clear packet
 *
 * @param background Command background instance to utilize
 * @param request Log clear request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_log_clear (struct cmd_background *background,
	struct cmd_interface_request *request)
{
	struct cerberus_protocol_clear_log *rq = (struct cerberus_protocol_clear_log*) request->data;

	if (request->length != sizeof (struct cerberus_protocol_clear_log)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	request->length = 0;

	if (rq->log_type == CERBERUS_PROTOCOL_DEBUG_LOG) {
		return background->debug_log_clear (background);
	}
	else if (rq->log_type == CERBERUS_PROTOCOL_TCG_LOG) {
		return 0;
	}

	return CMD_HANDLER_UNSUPPORTED_INDEX;
}

/**
 * Process PFM ID packet
 *
 * @param pfm_mgr_0 PFM manager for port 0
 * @param pfm_mgr_1 PFM manager for port 1
 * @param request PFM ID request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_pfm_id (struct pfm_manager *pfm_mgr_0, struct pfm_manager *pfm_mgr_1,
	struct cmd_interface_request *request)
{
	struct cerberus_protocol_get_pfm_id *rq = (struct cerberus_protocol_get_pfm_id*) request->data;
	struct cerberus_protocol_get_pfm_id_version_response *rsp =
		(struct cerberus_protocol_get_pfm_id_version_response*) request->data;
	struct pfm *curr_pfm = NULL;
	uint8_t port;
	int status = 0;

	if (request->length == (sizeof (struct cerberus_protocol_get_pfm_id) - sizeof (rq->id))) {
		rq->id = 0;
	}
	else if (request->length != sizeof (struct cerberus_protocol_get_pfm_id)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	port = rq->port_id;
	if (port > 1) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	status = cerberus_protocol_get_curr_pfm (pfm_mgr_0, pfm_mgr_1, port, rq->region, &curr_pfm);
	if (status != 0) {
		return status;
	}

	if (curr_pfm != NULL) {
		status = curr_pfm->base.get_id (&curr_pfm->base, &rsp->version);
		if (status != 0) {
			goto exit;
		}

		rsp->valid = 1;
	}
	else {
		rsp->valid = 0;
		rsp->version = 0;
	}

	request->length = sizeof (struct cerberus_protocol_get_pfm_id_version_response);

exit:
	cerberus_protocol_free_pfm (pfm_mgr_0, pfm_mgr_1, port, curr_pfm);
	return status;
}

/**
 * Process PFM fw packet
 *
 * @param pfm_0 PFM command interface for port 0.
 * @param pfm_1 PFM command interface for port 1.
 * @param pfm_mgr_0 PFM manager for port 0.
 * @param pfm_mgr_1 PFM manager for port 1.
 * @param request PFM supported FW request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_pfm_fw (struct manifest_cmd_interface *pfm_0,
	struct manifest_cmd_interface *pfm_1, struct pfm_manager *pfm_mgr_0,
	struct pfm_manager *pfm_mgr_1, struct cmd_interface_request *request)
{
	struct cerberus_protocol_get_pfm_supported_fw *rq =
		(struct cerberus_protocol_get_pfm_supported_fw*) request->data;
	struct cerberus_protocol_get_pfm_supported_fw_response *rsp =
		(struct cerberus_protocol_get_pfm_supported_fw_response*) request->data;
	struct pfm_firmware_versions supported_ids;
	struct pfm *curr_pfm;
	uint32_t fw_length = 0;
	uint32_t offset;
	uint32_t port;
	uint16_t length;
	char *out_buf_ptr;
	char *out_buf_ptr2;
	int status;
	int i;

	if (request->length != sizeof (struct cerberus_protocol_get_pfm_supported_fw)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if (rq->port_id > 1) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	status = cerberus_protocol_get_curr_pfm (pfm_mgr_0, pfm_mgr_1, rq->port_id, rq->region,
		&curr_pfm);
	if (status != 0) {
		return status;
	}

	offset = rq->offset;
	port = rq->port_id;

	if (curr_pfm != NULL) {
		rsp->valid = 1;

		status = curr_pfm->base.get_id (&curr_pfm->base, &rsp->version);
		if (status != 0) {
			goto exit;
		}

		status = curr_pfm->get_supported_versions (curr_pfm, &supported_ids);
		if (status != 0) {
			goto exit;
		}

		/* TODO: Improve the efficiency here.  Loop through the versions once, starting to copy data
		 * directly into the command buffer after 'offset' bytes and stop at the buffer size.  Avoid
		 * the malloc. */

		for (i = 0; i < supported_ids.count; ++i) {
			fw_length += strlen (supported_ids.versions[i].fw_version_id);
			++fw_length;
		}

		if (offset >= fw_length) {
			request->length = cerberus_protocol_get_pfm_supported_fw_response_length (0);
			goto cleanup_fw_versions;
		}

		out_buf_ptr = platform_malloc (fw_length);
		if (out_buf_ptr == NULL) {
			status = CMD_HANDLER_NO_MEMORY;
			goto cleanup_fw_versions;
		}

		out_buf_ptr2 = out_buf_ptr;

		for (i = 0; i < supported_ids.count; ++i, ++out_buf_ptr2) {
			strcpy (out_buf_ptr2, supported_ids.versions[i].fw_version_id);
			out_buf_ptr2 += strlen (supported_ids.versions[i].fw_version_id);
			*out_buf_ptr2 = '\0';
		}

		length = min (CERBERUS_PROTOCOL_MAX_PFM_VERSIONS (request), fw_length - offset);
		memcpy (cerberus_protocol_pfm_supported_fw (rsp), &out_buf_ptr[offset], length);

		request->length = cerberus_protocol_get_pfm_supported_fw_response_length (length);

		platform_free (out_buf_ptr);
	cleanup_fw_versions:
		curr_pfm->free_fw_versions (curr_pfm, &supported_ids);
	}
	else {
		rsp->valid = 0;
		rsp->version = 0;
		request->length = cerberus_protocol_get_pfm_supported_fw_response_length (0);
	}

exit:
	cerberus_protocol_free_pfm (pfm_mgr_0, pfm_mgr_1, port, curr_pfm);
	return status;
}

/**
 * Process PFM update init packet
 *
 * @param pfm_0 PFM command interface for port 0.
 * @param pfm_1 PFM command interface for port 1.
 * @param request PFM update init request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_pfm_update_init (struct manifest_cmd_interface *pfm_0,
	struct manifest_cmd_interface *pfm_1, struct cmd_interface_request *request)
{
	struct cerberus_protocol_prepare_pfm_update *rq =
		(struct cerberus_protocol_prepare_pfm_update*) request->data;
	struct manifest_cmd_interface *curr_pfm_interface;

	if (request->length != sizeof (struct cerberus_protocol_prepare_pfm_update)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if (rq->port_id > 1) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	curr_pfm_interface = cerberus_protocol_get_pfm_cmd_interface (pfm_0, pfm_1, rq->port_id);
	if (curr_pfm_interface == NULL) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	request->length = 0;
	return curr_pfm_interface->prepare_manifest (curr_pfm_interface, rq->size);
}

/**
 * Process PFM update packet
 *
 * @param pfm_0 PFM command interface for port 0.
 * @param pfm_1 PFM command interface for port 1.
 * @param request PFM update request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_pfm_update (struct manifest_cmd_interface *pfm_0,
	struct manifest_cmd_interface *pfm_1, struct cmd_interface_request *request)
{
	struct cerberus_protocol_pfm_update *rq = (struct cerberus_protocol_pfm_update*) request->data;
	struct manifest_cmd_interface *curr_pfm_interface;
	int status;

	if (request->length < sizeof (struct cerberus_protocol_pfm_update)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if (rq->port_id > 1) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	curr_pfm_interface = cerberus_protocol_get_pfm_cmd_interface (pfm_0, pfm_1, rq->port_id);
	if (curr_pfm_interface == NULL) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	status = curr_pfm_interface->store_manifest (curr_pfm_interface, &rq->payload,
		cerberus_protocol_pfm_update_length (request));

	request->length = 0;
	return status;
}

/**
 * Process PFM update complete packet
 *
 * @param pfm_0 PFM command interface for port 0.
 * @param pfm_1 PFM command interface for port 1.
 * @param request PFM update complete request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_pfm_update_complete (struct manifest_cmd_interface *pfm_0,
	struct manifest_cmd_interface *pfm_1, struct cmd_interface_request *request)
{
	struct cerberus_protocol_complete_pfm_update *rq =
		(struct cerberus_protocol_complete_pfm_update*) request->data;
	struct manifest_cmd_interface *curr_pfm_interface;

	if (request->length != sizeof (struct cerberus_protocol_complete_pfm_update)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if (rq->port_id > 1) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	curr_pfm_interface = cerberus_protocol_get_pfm_cmd_interface (pfm_0, pfm_1, rq->port_id);
	if (curr_pfm_interface == NULL) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	request->length = 0;
	return curr_pfm_interface->finish_manifest (curr_pfm_interface, rq->activation);

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
	struct host_control *host_1_ctrl, struct cmd_interface_request *request)
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
	struct cmd_interface_request *request)
{
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
	struct cmd_interface_request *request)
{
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
	struct cmd_background *background, struct cmd_interface_request *request)
{
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
		case 0:
			auth = cmd_auth->authorize_revert_bypass;
			action = background->reset_bypass;
			break;

		case 1:
			auth = cmd_auth->authorize_reset_defaults;
			action = background->restore_defaults;
			break;

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
}

/**
 * Process a prepare recovery image packet.
 *
 * @param recovery_0 Recovery image update command interface instance for port 0.
 * @param recovery_1 Recovery image update command interface instance for port 1.
 * @param request Recovery image prepare request to process.
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_prepare_recovery_image (struct recovery_image_cmd_interface *recovery_0,
	struct recovery_image_cmd_interface *recovery_1, struct cmd_interface_request *request)
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
 * Process an update recovery image packet.
 *
 * @param recovery_0 Recovery image update command interface instance for port 0.
 * @param recovery_1 Recovery image update command interface instance for port 1.
 * @param request Recovery image update request to process.
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_update_recovery_image (struct recovery_image_cmd_interface *recovery_0,
	struct recovery_image_cmd_interface *recovery_1, struct cmd_interface_request *request)
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
 * Process an activate recovery image packet.
 *
 * @param recovery_0 Recovery image update command interface instance for port 0.
 * @param recovery_1 Recovery image update command interface instance for port 1.
 * @param request Recovery image activate request to process.
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_activate_recovery_image (struct recovery_image_cmd_interface *recovery_0,
	struct recovery_image_cmd_interface *recovery_1, struct cmd_interface_request *request)
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
 * Process get recovery image ID packet.
 *
 * @param manager_0 Recovery image manager instance for port 0.
 * @param manager_1 Recovery image manager instance for port 1.
 * @param request Recovery image get request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_recovery_image_id (struct recovery_image_manager *manager_0,
	struct recovery_image_manager *manager_1, struct cmd_interface_request *request)
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
