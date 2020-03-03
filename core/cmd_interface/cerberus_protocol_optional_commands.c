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
static struct manifest_cmd_interface* cerberus_protocol_get_pfm_cmd_interface (
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
	uint32_t image_size;

	if (request->length != (CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (image_size))) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	memcpy (&image_size, &request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN], sizeof (image_size));

	request->length = 0;
	return control->prepare_staging (control, image_size);
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
	int status;

	if (request->length < (CERBERUS_PROTOCOL_MIN_MSG_LEN + 1)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	status = control->write_staging (control, &request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN],
		request->length - CERBERUS_PROTOCOL_MIN_MSG_LEN);

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
	if (request->length != CERBERUS_PROTOCOL_MIN_MSG_LEN) {
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
	uint32_t log_size;

	if (request->length != CERBERUS_PROTOCOL_MIN_MSG_LEN) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	log_size = debug_log_get_size ();
	if (ROT_IS_ERROR (log_size)) {
		log_size = 0;
	}

	memcpy (&request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN], &log_size, sizeof (log_size));

	log_size = pcr_store_get_tcg_log_size (pcr_store);
	if (ROT_IS_ERROR (log_size)) {
		log_size = 0;
	}

	memcpy (&request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (log_size)], &log_size,
		sizeof (log_size));

	/* Tamper log */
	log_size = 0;
	memcpy (&request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 2 * sizeof (log_size)], &log_size,
		sizeof (log_size));

	request->length = CERBERUS_PROTOCOL_MIN_MSG_LEN + (sizeof (log_size) * 3);
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
	uint32_t log_length;
	uint32_t offset;
	uint8_t log_type;

	if (request->length != (CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (log_type) + sizeof (offset))) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	log_type = request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN];
	memcpy (&offset, &request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (log_type)],
		sizeof (offset));

	if (log_type == CERBERUS_PROTOCOL_DEBUG_LOG) {
		log_length = debug_log_read_contents (offset, &request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN],
			MCTP_PROTOCOL_MAX_PAYLOAD_PER_MSG - CERBERUS_PROTOCOL_MIN_MSG_LEN);
	}
	else if (log_type == CERBERUS_PROTOCOL_TCG_LOG) {
		log_length = pcr_store_get_tcg_log (pcr_store, hash, offset,
			&request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN],
			MCTP_PROTOCOL_MAX_PAYLOAD_PER_MSG - CERBERUS_PROTOCOL_MIN_MSG_LEN);
	}
	else {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	if (ROT_IS_ERROR (log_length)) {
		return log_length;
	}

	request->length = CERBERUS_PROTOCOL_MIN_MSG_LEN + log_length;
	return 0;
}

#ifdef ENABLE_DEBUG_COMMANDS
/**
 * Process log fill packet
 *
 * @param background Command background instance to utilize
 * @param request Log fill request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_debug_fill_log (struct cmd_background *background,
	struct cmd_interface_request *request)
{
	if (request->length != CERBERUS_PROTOCOL_MIN_MSG_LEN) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	request->length = 0;

	return background->debug_log_fill (background);
}
#endif

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
	uint8_t log_type;

	if (request->length != (CERBERUS_PROTOCOL_MIN_MSG_LEN + 1)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	log_type = request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN];

	request->length = 0;

	if (log_type == CERBERUS_PROTOCOL_DEBUG_LOG) {
		return background->debug_log_clear (background);
	}
	else if (log_type == CERBERUS_PROTOCOL_TCG_LOG) {
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
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_pfm_id_request_packet*, request);
	CERBERUS_PROTOCOL_CMD (rsp, struct cerberus_protocol_get_pfm_id_response_packet*, request);
	struct pfm *curr_pfm = NULL;
	uint8_t port;
	int status = 0;

	if (request->length != CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_pfm_id_request_packet)) {
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
		status = curr_pfm->base.get_id (&curr_pfm->base, &rsp->id);
		if (status != 0) {
			goto exit;
		}

		rsp->valid = 1;
	}
	else {
		rsp->valid = 0;
		rsp->id = 0;
	}

	request->length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_pfm_id_response_packet);

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
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_pfm_supported_fw_request_packet*,
		request);
	CERBERUS_PROTOCOL_CMD (rsp_header, struct cerberus_protocol_get_pfm_supported_fw_header*,
		request);
	struct pfm_firmware_versions supported_ids;
	struct pfm *curr_pfm = NULL;
	uint32_t fw_length = 0;
	uint32_t offset;
	uint16_t length;
	uint8_t port;
	char *out_buf_ptr;
	char *out_buf_ptr2;
	int status;
	int i;

	if (request->length != CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_pfm_supported_fw_request_packet)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	offset = rq->offset;
	port = rq->port_id;
	if (port > 1) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	status = cerberus_protocol_get_curr_pfm (pfm_mgr_0, pfm_mgr_1, port, rq->region, &curr_pfm);
	if (status != 0) {
		return status;
	}

	if (curr_pfm != NULL) {
		status = curr_pfm->base.get_id (&curr_pfm->base, &rsp_header->id);
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
			if ((offset == fw_length) && (fw_length == 0)) {
				rsp_header->valid = 1;
				request->length = CERBERUS_PROTOCOL_CMD_LEN (
					struct cerberus_protocol_get_pfm_supported_fw_header);
			}
			else {
				rsp_header->valid = 0;
				request->length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
			}
			goto cleanup_fw_versions;
		}

		out_buf_ptr = platform_malloc (fw_length);
		if (out_buf_ptr == NULL) {
			status = CMD_HANDLER_NO_MEMORY;
			goto cleanup_fw_versions;
		}

		rsp_header->valid = 1;
		out_buf_ptr2 = out_buf_ptr;

		for (i = 0; i < supported_ids.count; ++i, ++out_buf_ptr2) {
			strcpy (out_buf_ptr2, supported_ids.versions[i].fw_version_id);
			out_buf_ptr2 += strlen (supported_ids.versions[i].fw_version_id);
			*out_buf_ptr2 = '\0';
		}

		length = min (MCTP_PROTOCOL_MAX_PAYLOAD_PER_MSG - CERBERUS_PROTOCOL_CMD_LEN (
			struct cerberus_protocol_get_pfm_supported_fw_header), fw_length - offset);
		memcpy (request->data + CERBERUS_PROTOCOL_CMD_LEN (
			struct cerberus_protocol_get_pfm_supported_fw_header), &out_buf_ptr[offset],
			length);

		request->length = CERBERUS_PROTOCOL_CMD_LEN (
			struct cerberus_protocol_get_pfm_supported_fw_header) + length;

		platform_free (out_buf_ptr);
	cleanup_fw_versions:
		curr_pfm->free_fw_versions (curr_pfm, &supported_ids);
	}
	else {
		request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0;
		request->length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
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
	struct manifest_cmd_interface *curr_pfm_interface;
	uint8_t port;

	if (request->length != CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_prepare_pfm_update_request_packet)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	port = request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN];
	if (port > 1) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	curr_pfm_interface = cerberus_protocol_get_pfm_cmd_interface (pfm_0, pfm_1, port);

	return cerberus_protocol_manifest_update_init (curr_pfm_interface, request, 1,
		CMD_HANDLER_UNSUPPORTED_INDEX);
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
	struct manifest_cmd_interface *curr_pfm_interface;
	uint8_t port;

	if (request->length <= CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_pfm_update_header_packet)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	port = request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN];
	if (port > 1) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	curr_pfm_interface = cerberus_protocol_get_pfm_cmd_interface (pfm_0, pfm_1, port);

	return cerberus_protocol_manifest_update (curr_pfm_interface, request, 1,
		CMD_HANDLER_UNSUPPORTED_INDEX);
}

/**
 * Process PFM update complete packet
 *
 * @param pfm_0 PFM command interface for port 0.
 * @param pfm_1 PFM command interface for port 1.
 * @param request PFM update complete request to process
 * @param delayed_activation_allowed Can delay activation till after reboot
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_pfm_update_complete (struct manifest_cmd_interface *pfm_0,
	struct manifest_cmd_interface *pfm_1, struct cmd_interface_request *request,
	bool delayed_activation_allowed)
{
	struct manifest_cmd_interface *curr_pfm_interface;
	uint8_t port;

	if (request->length != CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_complete_pfm_update_request_packet)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	port = request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN];
	if (port > 1) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	curr_pfm_interface = cerberus_protocol_get_pfm_cmd_interface (pfm_0, pfm_1, port);

	return cerberus_protocol_manifest_update_complete (curr_pfm_interface, request, 1,
		CMD_HANDLER_UNSUPPORTED_INDEX, delayed_activation_allowed);
}

/**
 * Process PFM update status packet
 *
 * @param pfm_0 PFM command interface for port 0.
 * @param pfm_1 PFM command interface for port 1.
 * @param request PFM update status request to process
 *
 * @return Response length if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_pfm_update_status (struct manifest_cmd_interface *pfm_0,
	struct manifest_cmd_interface *pfm_1, struct cmd_interface_request *request)
{
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_update_status_request_packet*, request);
	struct manifest_cmd_interface *curr_pfm_interface;

	if (request->length != CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_update_status_request_packet)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if (rq->port_id > 1) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	curr_pfm_interface = cerberus_protocol_get_pfm_cmd_interface (pfm_0, pfm_1, rq->port_id);

	return cerberus_protocol_get_manifest_update_status (curr_pfm_interface, request,
		CMD_HANDLER_UNSUPPORTED_INDEX);
}

/**
 * Process a request for host verification actions on reset.
 *
 * @param host_0 Host processor for port 0
 * @param host_1 Host processor for port 1
 * @param request Host verification actions request to process
 *
 * @return Response length if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_host_next_verification_status (struct host_processor *host_0,
	struct host_processor *host_1, struct cmd_interface_request *request)
{
	struct host_processor *host;
	int status;

	switch (request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1]) {
		case 0:
			host = host_0;
			break;

		case 1:
			host = host_1;
			break;

		default:
			return CMD_HANDLER_OUT_OF_RANGE;
	}

	if (host) {
		status = host->get_next_reset_verification_actions (host);
	}
	else {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	memcpy (&request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN], &status, sizeof (status));

	request->length = CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (status);
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
static struct recovery_image_cmd_interface* cerberus_protocol_get_recovery_image_cmd_interface (
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
static struct recovery_image_manager* cerberus_protocol_get_recovery_image_manager (
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
 * Process recovery image extended get update status packet.
 *
 * @param manager_0 The recovery image manager instance for port 0.
 * @param manager_1 The recovery image manager instance for port 1.
 * @param cmd_0 The recovery image command interface instance for port 0.
 * @param cmd_1 The recovery image command interface instance for port 1.
 * @param port The port to query.
 * @param update_status Output buffer to store the update status.
 * @param rem_len Output buffer for the remaining update bytes.
 *
 * @return 0 if request processing completed successfully or an error code.
 */
static int cerberus_protocol_get_extended_recovery_image_update_status (
	struct recovery_image_manager *manager_0, struct recovery_image_manager *manager_1,
	struct recovery_image_cmd_interface *cmd_0, struct recovery_image_cmd_interface *cmd_1,
	uint8_t port, uint32_t *update_status, uint32_t *rem_len)
{
	struct recovery_image_cmd_interface *cmd_interface;
	struct recovery_image_manager *recovery_manager;
	struct flash_updater *updating;

	if (port > 1) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	recovery_manager = cerberus_protocol_get_recovery_image_manager (manager_0, manager_1, port);
	if (recovery_manager == NULL) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	cmd_interface = cerberus_protocol_get_recovery_image_cmd_interface (cmd_0, cmd_1,
		port);

	if (cmd_interface == NULL) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	*update_status = cmd_interface->get_status (cmd_interface);
	updating = recovery_manager->get_flash_update_manager (recovery_manager);
	*rem_len = 	flash_updater_get_remaining_bytes (updating);

	return 0;
}

/**
 * Process recovery image get update status packet
 *
 * @param recovery_0 The recovery image command interface instance for port 0.
 * @param recovery_1 The recovery image command interface instance for port 1.
 * @param request Recovery image update status request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
static int cerberus_protocol_get_recovery_image_update_status (
	struct recovery_image_cmd_interface *recovery_0,
	struct recovery_image_cmd_interface *recovery_1, struct cmd_interface_request *request)
{
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_update_status_request_packet*, request);
	CERBERUS_PROTOCOL_CMD (rsp, struct cerberus_protocol_get_update_status_response_packet*,
		request);
	struct recovery_image_cmd_interface *curr_recovery_interface;

	if (rq->port_id > 1) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	curr_recovery_interface = cerberus_protocol_get_recovery_image_cmd_interface (recovery_0,
		recovery_1, rq->port_id);

	if (curr_recovery_interface == NULL) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	rsp->update_status = curr_recovery_interface->get_status (curr_recovery_interface);

	return 0;
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
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_host_state_request_packet*, request);
	CERBERUS_PROTOCOL_CMD (resp, struct cerberus_protocol_get_host_state_response_packet*, request);
	struct host_control *control;
	int status;

	if (request->length != CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_host_state_request_packet)) {
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
		resp->reset_status = HOST_PROCESSOR_OUT_OF_RESET;
	}
	else if (status == 1) {
		status = control->is_processor_held_in_reset (control);
		if (status == 1) {
			resp->reset_status = HOST_PROCESSOR_HELD_IN_RESET;
		}
		else if (status == 0) {
			resp->reset_status = HOST_PROCESSOR_NOT_HELD_IN_RESET;
		}
		else {
			return status;
		}
	}
	else {
		return status;
	}

	request->length =
		CERBERUS_PROTOCOL_CMD_LEN (struct cerberus_protocol_get_host_state_response_packet);
	return 0;
}

/**
 * Process update status packet
 *
 * @param control Firmware update control instance to utilize
 * @param pfm_0 Port 0 PFM command interface
 * @param pfm_1 Port 1 PFM command interface
 * @param cfm CFM command interface
 * @param pcd PCD command interface
 * @param host_0 Port 0 host processor
 * @param host_1 Port 1 host processor
 * @param recovery_0 The recovery image command interface instance for port 0.
 * @param recovery_1 The recovery image command interface instance for port 1.
 * @param background Command background instance to utilize
 * @param request Update status request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_update_status (struct firmware_update_control *control,
	struct manifest_cmd_interface *pfm_0, struct manifest_cmd_interface *pfm_1,
	struct manifest_cmd_interface *cfm, struct manifest_cmd_interface *pcd,
	struct host_processor *host_0, struct host_processor *host_1,
	struct recovery_image_cmd_interface *recovery_0,
	struct recovery_image_cmd_interface *recovery_1, struct cmd_background *background,
	struct cmd_interface_request *request)
{
	CERBERUS_PROTOCOL_CMD (rsp, struct cerberus_protocol_get_update_status_response_packet*,
		request);
	int status = 0;

	if (request->length != CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_update_status_request_packet)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	switch (request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN]) {
		case CERBERUS_PROTOCOL_FW_UPDATE:
			rsp->update_status = control->get_status (control);
			break;

		case CERBERUS_PROTOCOL_PFM_UPDATE:
			return cerberus_protocol_get_pfm_update_status (pfm_0, pfm_1, request);

		case CERBERUS_PROTOCOL_CFM_UPDATE:
			return cerberus_protocol_get_manifest_update_status (cfm, request,
				CMD_HANDLER_UNSUPPORTED_COMMAND);

		case CERBERUS_PROTOCOL_PCD_UPDATE:
			return cerberus_protocol_get_manifest_update_status (pcd, request,
				CMD_HANDLER_UNSUPPORTED_COMMAND);

		case CERBERUS_PROTOCOL_HOST_FW_NEXT_RESET:
			return cerberus_protocol_get_host_next_verification_status (host_0, host_1, request);

		case CERBERUS_PROTOCOL_CONFIG_RESET_UPDATE:
			rsp->update_status = background->get_config_reset_status (background);
			break;

		case CERBERUS_PROTOCOL_RECOVERY_IMAGE_UPDATE:
			status = cerberus_protocol_get_recovery_image_update_status (recovery_0, recovery_1,
				request);
			break;

		default:
			return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	request->length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_update_status_response_packet);
	return status;
}

/**
 * Process extended update status packet
 *
 * @param control Firmware update control instance to utilize
 * @param recovery_manager_0 The recovery image manager instance for port 0.
 * @param recovery_manager_1 The recovery image manager instance for port 1.
 * @param recovery_cmd_0 The recovery image command interface instance for port 0.
 * @param recovery_cmd_1 The recovery image command interface instance for port 1.
 * @param request Expected update status request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_extended_update_status (struct firmware_update_control *control,
	struct recovery_image_manager *recovery_manager_0,
	struct recovery_image_manager *recovery_manager_1,
	struct recovery_image_cmd_interface *recovery_cmd_0,
	struct recovery_image_cmd_interface *recovery_cmd_1, struct cmd_interface_request *request)
{
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_get_ext_update_status_request_packet*,
		request);
	CERBERUS_PROTOCOL_CMD (rsp, struct cerberus_protocol_get_ext_update_status_response_packet*,
		request);
	int status;

	if (request->length != CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_ext_update_status_request_packet)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	switch (rq->update_type) {
		case CERBERUS_PROTOCOL_FW_UPDATE:
			rsp->update_status = control->get_status (control);
			rsp->remaining_len = control->get_remaining_len (control);
			break;

		case CERBERUS_PROTOCOL_RECOVERY_IMAGE_UPDATE:
			status = cerberus_protocol_get_extended_recovery_image_update_status (
				recovery_manager_0,	recovery_manager_1, recovery_cmd_0, recovery_cmd_1, rq->port_id,
				&rsp->update_status, &rsp->remaining_len);
			if (status != 0) {
				return status;
			}
			break;

		default:
			return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

	request->length = CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_get_ext_update_status_response_packet);
	return 0;
}

/**
 * Process unseal message request
 *
 * @param background Command background instance to utilize
 * @param request Unseal request to process
 * @param direction Direction of caller in reference to Cerberus
 * @param platform_pcr PCR to utilize for platform measurement
 *
 * @return 0 if processing completed successfully or an error code.
 */
int cerberus_protocol_unseal_message (struct cmd_background *background,
	struct cmd_interface_request *request, int direction, uint8_t platform_pcr)
{
	uint16_t seed_len;
	uint16_t cipher_len;
	uint16_t seed_offset;
	uint16_t cipher_offset;
	uint16_t hmac_offset;
	uint16_t sealing_offset;

	request->crypto_timeout = true;

	if (direction != DEVICE_MANAGER_UPSTREAM) {
		return CMD_HANDLER_INVALID_DEVICE_MODE;
	}

	if ((CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len)) > request->length) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	memcpy (&seed_len, &request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN], sizeof (seed_len));
	if (seed_len == 0) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if ((CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len) + seed_len + sizeof (cipher_len)) >
		request->length) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	seed_offset = CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (seed_len);

	memcpy (&cipher_len, &request->data[seed_offset + seed_len], sizeof (cipher_len));
	if (cipher_len == 0) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	cipher_offset = seed_offset + seed_len + sizeof (cipher_len);
	hmac_offset = cipher_offset + cipher_len;
	sealing_offset = hmac_offset + SHA256_HASH_LENGTH;

	if ((sealing_offset + 64) != request->length) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	request->length = 0;
	if (background != NULL) {
		return background->unseal_start (background, &request->data[seed_offset], seed_len,
			&request->data[hmac_offset], &request->data[cipher_offset], cipher_len,
			&request->data[sealing_offset], platform_pcr);
	}
	else {
		return CMD_HANDLER_UNSUPPORTED_COMMAND;
	}
}

/**
 * Process unseal message result request
 *
 * @param background Command background instance to utilize
 * @param request Unseal result request to process
 * @param direction Direction of caller in reference to Cerberus
 *
 * @return 0 if processing completed successfully or an error code.
 */
int cerberus_protocol_unseal_message_result (struct cmd_background *background,
	struct cmd_interface_request *request, int direction)
{
	uint32_t attestation_status;
	size_t max_buf_len = MCTP_PROTOCOL_MAX_PAYLOAD_PER_MSG - (CERBERUS_PROTOCOL_MIN_MSG_LEN + 6);
	int status;

	if (direction != DEVICE_MANAGER_UPSTREAM) {
		return CMD_HANDLER_INVALID_DEVICE_MODE;
	}

	if (request->length != CERBERUS_PROTOCOL_MIN_MSG_LEN) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	if (background != NULL) {
		status = background->unseal_result (background,
			&request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 6], &max_buf_len, &attestation_status);
		if (ROT_IS_ERROR (status)) {
			return status;
		}
	}
	else {
		return CMD_HANDLER_UNSUPPORTED_COMMAND;
	}

	memcpy (&request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN], (uint8_t*) &attestation_status,
		sizeof (attestation_status));

	if (attestation_status == ATTESTATION_CMD_STATUS_SUCCESS) {
		memcpy (&request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (attestation_status)],
			(uint8_t*) &max_buf_len, sizeof (uint16_t));

		request->length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 6 + max_buf_len;
	}
	else {
		request->length = CERBERUS_PROTOCOL_MIN_MSG_LEN + sizeof (attestation_status);
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
	uint8_t *nonce = NULL;
	size_t length = 0;
	int status;
	int (*auth) (struct cmd_authorization*, uint8_t**, size_t*);
	int (*action) (struct cmd_background*);

	request->crypto_timeout = true;

	if (request->length < (CERBERUS_PROTOCOL_MIN_MSG_LEN + 1)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	switch (request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN]) {
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

	if (request->length > (CERBERUS_PROTOCOL_MIN_MSG_LEN + 1)) {
		nonce = &request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN + 1];
		length = request->length - (CERBERUS_PROTOCOL_MIN_MSG_LEN + 1);
	}

	status = auth (cmd_auth, &nonce, &length);
	if (status == AUTHORIZATION_CHALLENGE) {
		if (length > (MCTP_PROTOCOL_MAX_PAYLOAD_PER_MSG - CERBERUS_PROTOCOL_MIN_MSG_LEN)) {
			return CMD_HANDLER_BUF_TOO_SMALL;
		}

		memcpy (&request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN], nonce, length);
		request->length = length + CERBERUS_PROTOCOL_MIN_MSG_LEN;
		status = 0;
	}
	else {
		if (status == 0) {
			status = action (background);
			request->length = 0;
		}
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
int cerberus_protocol_prepare_recovery_image (
	struct recovery_image_cmd_interface *recovery_0,
	struct recovery_image_cmd_interface *recovery_1,
	struct cmd_interface_request *request)
{
	struct recovery_image_cmd_interface *recovery_interface;
	CERBERUS_PROTOCOL_CMD (rq,
		struct cerberus_protocol_prepare_recovery_image_update_request_packet*, request);

	if (rq->port_id > 1) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	if (request->length != CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_prepare_recovery_image_update_request_packet)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	recovery_interface = cerberus_protocol_get_recovery_image_cmd_interface (recovery_0, recovery_1,
		rq->port_id);
	request->length = 0;
	if (recovery_interface != NULL) {
		return recovery_interface->prepare_recovery_image (recovery_interface, rq->size);
	}
	else {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}
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
	struct recovery_image_cmd_interface *recovery_interface;
	int offset = 1;
	int status = CMD_HANDLER_UNSUPPORTED_INDEX;
	CERBERUS_PROTOCOL_CMD (rq, struct cerberus_protocol_recovery_image_update_header_packet*,
		request);

	if (rq->port_id > 1) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	if (request->length <= CERBERUS_PROTOCOL_CMD_LEN (
		struct cerberus_protocol_recovery_image_update_header_packet)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	recovery_interface = cerberus_protocol_get_recovery_image_cmd_interface (recovery_0, recovery_1,
		rq->port_id);
	if (recovery_interface != NULL) {
		status = recovery_interface->update_recovery_image (recovery_interface,
		&request->data[CERBERUS_PROTOCOL_MIN_MSG_LEN + offset],
		request->length - offset - CERBERUS_PROTOCOL_MIN_MSG_LEN);
	}
	else {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}

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
	struct recovery_image_cmd_interface *recovery_interface;
	CERBERUS_PROTOCOL_CMD (rq,
		struct cerberus_protocol_activate_recovery_image_update_request_packet*, request);

	if (rq->port_id > 1) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	if (request->length != (CERBERUS_PROTOCOL_MIN_MSG_LEN + 1)) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	recovery_interface = cerberus_protocol_get_recovery_image_cmd_interface (recovery_0, recovery_1,
		rq->port_id);
	request->length = 0;
	if (recovery_interface != NULL) {
		return recovery_interface->activate_recovery_image (recovery_interface);
	}
	else {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}
}

/**
 * Process get recovery image version packet.
 *
 * @param manager_0 Recovery image manager instance for port 0.
 * @param manager_1 Recovery image manager instance for port 1.
 * @param request Recovery image get request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int cerberus_protocol_get_recovery_image_version (
	struct recovery_image_manager *manager_0,
	struct recovery_image_manager *manager_1, struct cmd_interface_request *request)
{
	CERBERUS_PROTOCOL_CMD (rq,
		struct cerberus_protocol_get_recovery_image_version_update_request_packet*, request);
	CERBERUS_PROTOCOL_CMD (rsp,
		struct cerberus_protocol_get_recovery_image_version_update_response_packet*, request);
	struct recovery_image *curr_recovery_image = NULL;
	struct recovery_image_manager *curr_mgr;
	int status = 0;

	if (rq->port_id > 1) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	if (request->length != CERBERUS_PROTOCOL_MIN_MSG_LEN + 1) {
		return CMD_HANDLER_BAD_LENGTH;
	}

	curr_mgr = cerberus_protocol_get_recovery_image_manager (manager_0, manager_1, rq->port_id);
	if (curr_mgr == NULL) {
		return CMD_HANDLER_UNSUPPORTED_INDEX;
	}
	curr_recovery_image = curr_mgr->get_active_recovery_image (curr_mgr);

	memset (&rsp->version, 0, CERBERUS_PROTOCOL_FW_VERSION_LEN);

	if (curr_recovery_image != NULL) {
		status = curr_recovery_image->get_version (curr_recovery_image, rsp->version,
			CERBERUS_PROTOCOL_FW_VERSION_LEN);
		if (status != 0) {
			goto exit;
		}
	}

	request->length = CERBERUS_PROTOCOL_FW_VERSION_LEN + CERBERUS_PROTOCOL_MIN_MSG_LEN;

exit:
	if (curr_recovery_image != NULL) {
		curr_mgr->free_recovery_image (curr_mgr, curr_recovery_image);
	}

	return status;
}
