// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <string.h>
#include "attestation_discover_mctp.h"
#include "attestation_logging.h"
#include "platform_api.h"
#include "common/type_cast.h"
#include "common/unused.h"
#include "logging/debug_log.h"
#include "mctp/mctp_control_protocol.h"
#include "mctp/mctp_control_protocol_commands.h"
#include "spdm/spdm_commands.h"
#include "spdm/spdm_discovery.h"
#include "spdm/spdm_measurements.h"


#ifdef ATTESTATION_SUPPORT_CERBERUS_CHALLENGE
/**
 * Perform discovery on a provided device using the Cerberus protocol.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param eid EID of device to discover.
 *
 * @return Completion status, 0 if success or an error code otherwise
 */
static int attestation_discover_mctp_identify_device_cerberus_protocol (
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
 * @param discover Attestation discover instance to utilize.
 * @param eid EID of device to discover.
 *
 * @return Completion status, 0 if success or an error code otherwise
 */
static int attestation_discover_mctp_identify_device_spdm_protocol (
	const struct attestation_requester *attestation, const struct attestation_discover *discover,
	uint8_t eid)
{
	const struct attestation_discover_mctp *mctp_discover =
		(const struct attestation_discover_mctp*) discover;
	struct spdm_discovery_device_id_block *block =
		(struct spdm_discovery_device_id_block*) attestation->state->txn.msg_buffer;
	struct spdm_discovery_device_id_descriptor *descriptor;
	uint16_t pci_vid = 0;
	uint16_t pci_device_id = 0;
	uint16_t pci_sub_vid = 0;
	uint16_t pci_sub_id = 0;
	uint16_t id;
	size_t offset = sizeof (struct spdm_discovery_device_id_block);
	uint8_t found = 0;
	int device_addr;
	int device_num;
	int i_descriptor;
	int status;

	if ((attestation == NULL) || (discover == NULL) || (mctp_discover->transport == NULL)) {
		return ATTESTATION_INVALID_ARGUMENT;
	}

	attestation->state->txn.protocol = ATTESTATION_PROTOCOL_DMTF_SPDM;
	attestation->state->txn.spdm_minor_version = ATTESTATION_PROTOCOL_DMTF_SPDM_1_0;
	attestation->state->txn.transcript_hash_type = HASH_TYPE_SHA256;
	attestation->state->txn.measurement_hash_type = HASH_TYPE_SHA256;

	device_addr = device_manager_get_device_addr (attestation->device_mgr,
		DEVICE_MANAGER_MCTP_BRIDGE_DEVICE_NUM);
	if (ROT_IS_ERROR (device_addr)) {
		return device_addr;
	}

	status = attestation_requester_send_and_receive_spdm_get_measurements (attestation,
		mctp_discover->transport, eid, device_addr, SPDM_MEASUREMENT_OPERATION_GET_DEVICE_ID, true);
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

		// PCI descriptors are 2 bytes length, skip if not valid
		if (descriptor->descriptor_len != sizeof (uint16_t)) {
			offset += descriptor->descriptor_len;
			continue;
		}

		id = buffer_unaligned_read16 ((uint16_t*) &attestation->state->txn.msg_buffer[offset]);
		offset += sizeof (uint16_t);

		switch (descriptor->descriptor_type) {
			case SPDM_DISCOVERY_DEVICE_ID_PCI_VID:
				pci_vid = id;
				found |= 1;
				break;

			case SPDM_DISCOVERY_DEVICE_ID_PCI_DEVICE_ID:
				pci_device_id = id;
				found |= (1 << 1);
				break;

			case SPDM_DISCOVERY_DEVICE_ID_PCI_SUBSYSTEM_VID:
				pci_sub_vid = id;
				found |= (1 << 2);
				break;

			case SPDM_DISCOVERY_DEVICE_ID_PCI_SUBSYSTEM_ID:
				pci_sub_id = id;
				found |= (1 << 3);
				break;

			default:
				continue;
		}
	}

	if (found == 0x0F) {
		device_num =
			device_manager_get_unidentified_device_num_by_device_ids (attestation->device_mgr,
			pci_vid, pci_device_id, pci_sub_vid, pci_sub_id);
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
 * Perform discovery on a provided device using MCTP control message transport.
 *
 * @param attestation Attestation requester instance to utilize.
 * @param eid EID of device to discover.
 *
 * @return Completion status, 0 if success or an error code otherwise
 */
static int attestation_discover_mctp_identify_device (
	const struct attestation_requester *attestation, const struct attestation_discover *discover,
	uint8_t eid)
{
	struct mctp_control_get_message_type_response *msg_type_rsp = NULL;
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	uint8_t i_type;
	uint8_t *msg_type;
	int status;

	if (attestation == NULL) {
		return ATTESTATION_INVALID_ARGUMENT;
	}

	memset (&attestation->state->txn, 0, sizeof (struct attestation_requester_transaction_state));
	attestation->state->txn.device_discovery = true;

	status = attestation_requester_get_message_type (attestation, eid, &request, &response);
	if (status != 0) {
		goto done;
	}

	msg_type_rsp = (struct mctp_control_get_message_type_response*) response.payload;
	for (i_type = 0; i_type < msg_type_rsp->message_type_count; ++i_type) {
		msg_type = mctp_control_get_message_type_response_get_entries (msg_type_rsp) + i_type;

		switch (*msg_type) {
#ifdef ATTESTATION_SUPPORT_CERBERUS_CHALLENGE
			case MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF:
				status = attestation_discover_mctp_identify_device_cerberus_protocol (attestation,
					eid);
				goto done;
#endif

#ifdef ATTESTATION_SUPPORT_SPDM
			case MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM:
				status = attestation_discover_mctp_identify_device_spdm_protocol (attestation,
					discover, eid);
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
static int attestation_discover_mctp_get_mctp_routing_table (
	const struct attestation_requester *attestation)
{
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	struct mctp_control_get_routing_table_entries_response *routing_table_rsp;
	struct mctp_control_routing_table_entry *entry;
	uint8_t entry_handle = 0;
	uint8_t i_entry;
	uint8_t i_eid;
	int bridge_eid;
	int request_len;
	int status;

	if ((attestation == NULL) || (attestation->mctp_control == NULL)) {
		return ATTESTATION_INVALID_ARGUMENT;
	}

	device_manager_clear_unidentified_devices (attestation->device_mgr);

	bridge_eid = device_manager_get_device_eid (attestation->device_mgr,
		DEVICE_MANAGER_MCTP_BRIDGE_DEVICE_NUM);
	if (ROT_IS_ERROR (bridge_eid)) {
		status = bridge_eid;
		goto failed;
	}

	while (entry_handle != 0xFF) {
		status = msg_transport_create_empty_request (attestation->mctp_control,
			attestation->state->txn.msg_buffer, sizeof (attestation->state->txn.msg_buffer),
			bridge_eid,	&request);
		if (status != 0) {
			goto failed;
		}

		request_len =
			mctp_control_protocol_generate_get_routing_table_entries_request (entry_handle,
			request.payload, request.payload_length);
		if (ROT_IS_ERROR (request_len)) {
			status = request_len;
			goto failed;
		}

		/* Update the payload length and request length after request message is ready. */
		cmd_interface_msg_set_message_payload_length (&request, request_len);

		status = msg_transport_create_empty_response (attestation->state->txn.msg_buffer,
			sizeof (attestation->state->txn.msg_buffer), &response);
		if (status != 0) {
			goto failed;
		}

		status =
			attestation_requester_send_mctp_control_request_and_get_response (attestation,
			attestation->mctp_control, &request, &response,
			MCTP_CONTROL_PROTOCOL_GET_ROUTING_TABLE_ENTRIES);
		if (status != 0) {
			goto failed;
		}

		status = mctp_control_protocol_process_get_routing_table_entries_response (&response);
		if (status != 0) {
			goto failed;
		}

		routing_table_rsp =
			(struct mctp_control_get_routing_table_entries_response*) response.payload;

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
					goto failed;
				}
			}
		}

		entry_handle = routing_table_rsp->next_entry_handle;
	}

	return 0;

failed:
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
		ATTESTATION_LOGGING_GET_MCTP_ROUTING_TABLE_ERROR, status, 0);

	return status;
}

/**
 * Timer callback to request MCTP routing table from the bridge.
 * Called when the PCD-configured MCTP bridge wait timeout elapses.  This is a fallback mechanism
 * to maintain legacy MCTP bridge behavior where the BMC may not send a Set EID request to signal
 * routing table readiness.  If a Set EID request has already been received (indicating the bridge
 * notified us of a routing table update), the routing table fetch is skipped since discovery was
 * already triggered.  If no Set EID was received before the timeout, this initiates the routing
 * table fetch and starts discovery.
 *
 * TODO: Remove this fallback if all MCTP bridge implementations reliably send Set EID requests.
 *
 * @param context Refresh context containing attestation and MCTP discover instances.
 */
void attestation_discover_mctp_refresh_routing_table (
	struct attestation_discover_mctp_refresh_context *context)
{
	const struct attestation_requester *attestation;
	const struct attestation_discover_mctp *mctp;

	if (context == NULL) {
		return;
	}

	attestation = context->attestation;
	mctp = context->mctp_discover;

	if ((attestation == NULL) || (mctp == NULL)) {
		return;
	}

	/* Only trigger if still in IDLE state (waiting for bridge). If Set EID already moved
	 * the state, discovery is already triggered — skip. */
	if (mctp->state->discovery_state == ATTESTATION_DISCOVERY_IDLE) {
		mctp->state->discovery_state = ATTESTATION_DISCOVERY_REQUIRED_REFRESH;
		mctp->state->routing_table_dirty = true;

		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_BRIDGE_RESET_TRIGGERED_ROUTING_TABLE_SYNC, 0, 0);

		platform_semaphore_post (&attestation->state->next_action);
	}
}

/**
 * Initialize and start the MCTP routing table refresh timer.
 *
 * Sets up the timer context and arms a one-shot timer that will trigger a routing table
 * sync request if no Set EID is received within the specified timeout.
 *
 * @param timer Platform timer to create and arm.
 * @param context Refresh context to initialize with attestation and discover instances.
 * @param attestation Attestation requester instance.
 * @param discover MCTP discover instance.
 * @param timeout_ms Timeout in milliseconds before requesting routing table.
 *
 * @return 0 if success or an error code.
 */
int attestation_discover_mctp_start_timer (platform_timer *timer,
	struct attestation_discover_mctp_refresh_context *context,
	const struct attestation_requester *attestation,
	const struct attestation_discover_mctp *discover, uint32_t timeout_ms)
{
	int status;

	if ((timer == NULL) || (context == NULL) || (attestation == NULL) || (discover == NULL)) {
		return ATTESTATION_INVALID_ARGUMENT;
	}

	context->attestation = attestation;
	context->mctp_discover = discover;

	status = platform_timer_create (timer,
		(timer_callback) attestation_discover_mctp_refresh_routing_table, context);
	if (status != 0) {
		return status;
	}

	status = platform_timer_arm_one_shot (timer, timeout_ms);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
			ATTESTATION_LOGGING_BRIDGE_FAILED_TO_DETECT_MCTP_BRIDGE_RESET, status, 0);

		return status;
	}

	return 0;
}


/**
 * MCTP control protocol set EID request observer function. Incoming set EID requests are monitored
 * since they are used by the MCTP bridge to alert device of routing table updates.
 *
 * @param observer The MCTP control protocol observer instance that received the notification.
 */
void attestation_requester_on_mctp_set_eid_request (
	const struct mctp_control_protocol_observer *observer)
{
	const struct attestation_discover_mctp *mctp =
		TO_DERIVED_TYPE (observer, const struct attestation_discover_mctp, mctp_rsp_observer);

	mctp->state->discovery_state = ATTESTATION_DISCOVERY_RECEIVED_SET_EID_REQUEST;
	mctp->state->routing_table_dirty = true;

	debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_ATTESTATION,
		ATTESTATION_LOGGING_SET_EID_RECEIVED, 0, 0);
}

/**
 * Sync the MCTP routing table and prepare device discovery.
 * Fetches the routing table from the bridge, populates the unidentified device list,
 * and resets discovery state so devices can be identified.
 *
 * @param mctp_discover MCTP discover instance.
 * @param attestation Attestation requester instance.
 * @param attestation_discover Base attestation discover instance.
 *
 * @return 0 if success or an error code.
 */
static int attestation_discover_mctp_sync_routing_table (
	const struct attestation_discover_mctp *mctp_discover,
	const struct attestation_requester *attestation,
	const struct attestation_discover *attestation_discover)
{
	int status;

	if (mctp_discover->state->discovery_state == ATTESTATION_DISCOVERY_IDLE) {
		mctp_discover->state->discovery_state = ATTESTATION_DISCOVERY_RECEIVED_SET_EID_REQUEST;
	}

	status = attestation_discover_mctp_get_mctp_routing_table (attestation);
	if (status != 0) {
		return status;
	}

	status = device_manager_restart_device_discovery_by_handler (attestation->device_mgr,
		attestation_discover);
	if (status != 0) {
		return status;
	}

	mctp_discover->state->routing_table_dirty = false;

	return 0;
}

/**
 * Get the device EID using device entry details.
 *
 * @param attestation_discover Attestation discover instance to utilize.
 * @param attestation Attestation requester instance to utilize.
 * @param device_num The device number to query EID for.
 *
 * @return EID value of the device, ATTESTATION_REFRESH_ROUTING_TABLE if routing table was
 * refreshed, or an error code.
 */
int attestation_discover_mctp_get_device_eid_by_device_num (
	const struct attestation_discover *attestation_discover,
	const struct attestation_requester *attestation, int device_num)
{
	const struct attestation_discover_mctp *mctp_discover =
		(const struct attestation_discover_mctp*) attestation_discover;
	int status;

	if ((attestation_discover == NULL) || (attestation == NULL)) {
		return ATTESTATION_INVALID_ARGUMENT;
	}

	if (mctp_discover->state->routing_table_dirty) {
		status = attestation_discover_mctp_sync_routing_table (mctp_discover, attestation,
			attestation_discover);
		if (status != 0) {
			return status;
		}

		return ATTESTATION_REFRESH_ROUTING_TABLE;
	}

	return device_manager_get_device_eid (attestation->device_mgr, device_num);
}

/**
 * Discover devices using MCTP approach.
 * Fetches the MCTP routing table from the bridge (if triggered by SET EID), populates the
 * unidentified device list, then discovers each device via Cerberus/SPDM protocols.
 *
 * @param attestation_discover Attestation discover instance to utilize.
 * @param attestation Attestation requester instance to utilize.
 *
 * @return Discovery status, 0 if success or an error code.
 */
int attestation_discover_mctp_discover_device (
	const struct attestation_discover *attestation_discover,
	const struct attestation_requester *attestation)
{
	const struct attestation_discover_mctp *mctp_discover =
		(const struct attestation_discover_mctp*) attestation_discover;
	int eid = 0;
	int status = 0;
	uint32_t component_id = 0;
	uint8_t instance_id = 0;

	if ((attestation_discover == NULL) || (attestation == NULL) ||
		(attestation->device_mgr == NULL)) {
		return ATTESTATION_INVALID_ARGUMENT;
	}

	if ((mctp_discover->state->discovery_state == ATTESTATION_DISCOVERY_IDLE) ||
		(mctp_discover->state->discovery_state == ATTESTATION_DISCOVERY_COMPLETE)) {
		return 0;
	}

	while (eid != DEVICE_MGR_NO_DEVICES_AVAILABLE) {
		/* If routing table was invalidated during discovery, refresh and restart. */
		if (mctp_discover->state->routing_table_dirty) {
			status = attestation_discover_mctp_sync_routing_table (mctp_discover, attestation,
				attestation_discover);
			if (status != 0) {
				goto failed;
			}
			eid = 0;
			continue;
		}

		eid = device_manager_get_eid_of_next_device_to_discover (attestation->device_mgr);
		if (!ROT_IS_ERROR (eid)) {
			status = attestation_discover_mctp_identify_device (attestation, attestation_discover,
				eid);
			if (status != 0) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
					ATTESTATION_LOGGING_DEVICE_FAILED_DISCOVERY,
					attestation->state->txn.requested_command, status);
			}
			else {
				status = device_manager_get_component_id_by_eid (attestation->device_mgr, eid,
					&component_id);
				if (status != 0) {
					goto failed;
				}

				status = device_manager_get_instance_id_by_eid (attestation->device_mgr, eid,
					&instance_id);
				if (status != 0) {
					goto failed;
				}

				debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_ATTESTATION,
					ATTESTATION_LOGGING_EID_DISCOVERED,	component_id, eid << 16 | instance_id);
			}
		}
		else if (eid != DEVICE_MGR_NO_DEVICES_AVAILABLE) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
				ATTESTATION_LOGGING_NEXT_DEVICE_DISCOVERY_ERROR, eid, 0);
		}
	}

	mctp_discover->state->discovery_state = ATTESTATION_DISCOVERY_COMPLETE;

	debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_ATTESTATION,
		ATTESTATION_LOGGING_MCTP_DISCOVERY_COMPLETE, 0, 0);

	return 0;
failed:
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ATTESTATION,
		ATTESTATION_LOGGING_DEVICE_FAILED_DISCOVERY, eid, status);

	return status;
}

/**
 * Initialize the attestation discover mctp instance
 *
 * @param discover attestation discover mctp instance to initialize.
 * @param state Variable context for the discover instance. This must be uninitialized.
 * @param transport SPDM message transport for discovery operations.
 *
 * @return Init status, 0 if success or an error code.
 */
int attestation_discover_mctp_init (struct attestation_discover_mctp *discover,
	struct attestation_discover_mctp_state *state, const struct msg_transport *transport)
{
	if ((discover == NULL) || (state == NULL)) {
		return ATTESTATION_INVALID_ARGUMENT;
	}

	memset (discover, 0, sizeof (struct attestation_discover_mctp));
	discover->base.discover_device = attestation_discover_mctp_discover_device;
	discover->base.get_device_eid_by_device_num =
		attestation_discover_mctp_get_device_eid_by_device_num;
	discover->transport = transport;
	discover->state = state;

	discover->mctp_rsp_observer.on_set_eid_request =
		attestation_requester_on_mctp_set_eid_request;

	return attestation_discover_mctp_init_state (discover);
}

/**
 * Initialize only the variable state of an attestation discover mctp instance. The rest of the
 * instance is assumed to have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param discover The attestation discover mctp instance that contains the state to initialize.
 *
 * @return Init status, 0 if success or an error code.
 */
int attestation_discover_mctp_init_state (const struct attestation_discover_mctp *discover)
{
	if ((discover == NULL) || (discover->state == NULL)) {
		return ATTESTATION_INVALID_ARGUMENT;
	}

	memset (discover->state, 0, sizeof (struct attestation_discover_mctp_state));
	discover->state->discovery_state = ATTESTATION_DISCOVERY_IDLE;
	discover->state->routing_table_dirty = false;

	return 0;
}

/**
 * Release the resources used for attestation discover mctp.
 *
 * @param discover The attestation discover to release.
 */
void attestation_discover_mctp_release (const struct attestation_discover_mctp *discover)
{
	UNUSED (discover);
}
