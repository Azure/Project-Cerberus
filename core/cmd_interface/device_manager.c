// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "platform_api.h"
#include "device_manager.h"
#include "common/common_math.h"
#include "mctp/mctp_base_protocol.h"
#include "crypto/hash.h"

/**
 * Determine if device is undergoing or failed attestation and should use the unauthenticated
 * cadence
 *
 * @param state Device state
 */
#define device_manager_is_device_unauthenticated(state)			\
	((state == DEVICE_MANAGER_READY_FOR_ATTESTATION) ||  \
	(state == DEVICE_MANAGER_ATTESTATION_FAILED))

/**
 * Determine if device is ready to be attested
 *
 * @param state Device state
 */
#define device_manager_can_device_be_attested(state)			\
	(device_manager_is_device_unauthenticated(state) || (state == DEVICE_MANAGER_AUTHENTICATED) ||\
	 (state == DEVICE_MANAGER_NEVER_ATTESTED))


/**
 * Update device manager device table entry state
 *
 * @param mgr Device manager instance to utilize.
 * @param device_num Device table entry to update.
 * @param state Device state.
 *
 * @return Completion status, 0 if success or an error code.
 */
int device_manager_update_device_state (struct device_manager *mgr, int device_num,
	enum device_manager_device_state state)
{
	enum device_manager_device_state prev_state;
	uint32_t timeout = 0;

	if ((mgr == NULL) || (state >= NUM_DEVICE_MANAGER_STATES)) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	if (device_num >= mgr->num_devices) {
		return DEVICE_MGR_UNKNOWN_DEVICE;
	}

	prev_state = mgr->entries[device_num].state;
	mgr->entries[device_num].state = state;

	if (state == DEVICE_MANAGER_AUTHENTICATED) {
		timeout = mgr->authenticated_cadence_ms;
	}
	else if ((device_manager_is_device_unauthenticated (state)) &&
		(device_manager_is_device_unauthenticated (prev_state) ||
			(prev_state == DEVICE_MANAGER_NEVER_ATTESTED))) {
		timeout = mgr->unauthenticated_cadence_ms;
	}
	else if (state == DEVICE_MANAGER_NEVER_ATTESTED) {
		timeout = 0;
	}

	return platform_init_timeout (timeout, &mgr->entries[device_num].attestation_timeout);
}

/**
 * Initialize a device manager.
 *
 * The first device entry will be for the local device, and the device capabilities will be
 * initialized based on the device configuration.  These capabilities can be updated as necessary
 * with device_manager_update_device_capabilities().
 *
 * @param mgr Device manager instance to initialize.
 * @param num_requester_devices Number of requester devices to manage. This must be at least 1 to
 * 	support the local device.
 * @param num_responder_devices Number of responder devices to manage.
 * @param hierarchy Role of the local device in the Cerberus hierarchy (PA vs. AC RoT).
 * @param bus_role Role the local device will take on the I2C bus.
 * @param unauthenticated_cadence_ms Period to wait before reauthenticating unauthenticated device.
 * @param authenticated_cadence_ms Period to wait before reauthenticating authenticated device.
 * @param unidentified_timeout_ms Timeout period to wait before reidentifying unidentified device.
 * @param mctp_ctrl_timeout_ms Timeout duration for MCTP control requests.
 * @param mctp_bridge_additional_timeout_ms Timeout adjustment to MCTP bridge communication.
 * @param attestation_rsp_not_ready_max_duration_ms Maximum SPDM ResponseNotReady duration.
 * @param attestation_rsp_not_ready_max_retry Maximum SPDM ResponseNotReady retries.
 *
 * @return Initialization status, 0 if success or an error code.
 */
int device_manager_init (struct device_manager *mgr, int num_requester_devices,
	int num_responder_devices, uint8_t hierarchy, uint8_t bus_role,
	uint32_t unauthenticated_cadence_ms, uint32_t authenticated_cadence_ms,
	uint32_t unidentified_timeout_ms, uint32_t mctp_ctrl_timeout_ms,
	uint32_t mctp_bridge_additional_timeout_ms, uint32_t attestation_rsp_not_ready_max_duration_ms,
	uint8_t attestation_rsp_not_ready_max_retry)
{
	int total_num_devices = num_requester_devices + num_responder_devices;
	int status;

	if ((mgr == NULL) || (num_requester_devices == 0) ||
		(hierarchy >= NUM_BUS_HIERACHY_ROLES) || (bus_role >= NUM_BUS_ROLES)) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	memset (mgr, 0, sizeof (struct device_manager));

	mgr->entries = platform_calloc (total_num_devices, sizeof (struct device_manager_entry));
	if (mgr->entries == NULL) {
		return DEVICE_MGR_NO_MEMORY;
	}

	if (num_responder_devices != 0) {
		mgr->attestation_status = platform_malloc (num_responder_devices);
		if (mgr->attestation_status == NULL) {
			platform_free (mgr->entries);
			return DEVICE_MGR_NO_MEMORY;
		}
	}

	mgr->num_devices = total_num_devices;
	mgr->num_requester_devices = num_requester_devices;
	mgr->num_responder_devices = num_responder_devices;
	mgr->unauthenticated_cadence_ms = unauthenticated_cadence_ms;
	mgr->authenticated_cadence_ms = authenticated_cadence_ms;
	mgr->unidentified_timeout_ms = unidentified_timeout_ms;
	mgr->mctp_ctrl_timeout_ms = mctp_ctrl_timeout_ms;
	mgr->mctp_bridge_additional_timeout_ms = mctp_bridge_additional_timeout_ms;
	mgr->attestation_rsp_not_ready_max_duration_ms = attestation_rsp_not_ready_max_duration_ms;
	mgr->attestation_rsp_not_ready_max_retry = attestation_rsp_not_ready_max_retry;

	/* Initialize the local device capabilities. */
	mgr->entries[DEVICE_MANAGER_SELF_DEVICE_NUM].capabilities.request.max_message_size =
		MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	mgr->entries[DEVICE_MANAGER_SELF_DEVICE_NUM].capabilities.request.max_packet_size =
		MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	mgr->entries[DEVICE_MANAGER_SELF_DEVICE_NUM].capabilities.request.security_mode =
		DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	mgr->entries[DEVICE_MANAGER_SELF_DEVICE_NUM].capabilities.request.bus_role = bus_role;
	mgr->entries[DEVICE_MANAGER_SELF_DEVICE_NUM].capabilities.request.hierarchy_role =
		hierarchy;
	mgr->entries[DEVICE_MANAGER_SELF_DEVICE_NUM].capabilities.max_timeout =
		device_manager_set_timeout_ms (MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS);
	mgr->entries[DEVICE_MANAGER_SELF_DEVICE_NUM].capabilities.max_sig =
		device_manager_set_crypto_timeout_ms (MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS);

	status = device_manager_update_device_state (mgr, DEVICE_MANAGER_SELF_DEVICE_NUM,
		DEVICE_MANAGER_NOT_ATTESTABLE);
	if (status != 0) {
		platform_free (mgr->entries);
		platform_free (mgr->attestation_status);
	}

	return status;
}

/**
 * Initialize a device manager for an AC-RoT Cerberus.  This will set Cerberus hierachy role to
 * DEVICE_MANAGER_AC_ROT_MODE, set the number of responder devices to zero, and set all the
 * component attestation defaults to zero.
 *
 * @param mgr Device manager instance to initialize.
 * @param num_requester_devices Number of requester devices to manage. This must be at least 1 to
 * 	support the local device.
 * @param bus_role Role the local device will take on the I2C bus.
 *
 * @return Initialization status, 0 if success or an error code.
 */
int device_manager_init_ac_rot (struct device_manager *mgr, int num_requester_devices,
	uint8_t bus_role)
{
	return device_manager_init (mgr, num_requester_devices, 0, DEVICE_MANAGER_AC_ROT_MODE,
		bus_role, 0, 0, 0, 0, 0, 0, 0);
}

#ifdef ATTESTATION_SUPPORT_DEVICE_DISCOVERY
/**
 * Free unidentified devices circular list
 *
 * @param mgr Device manager instance to utilize
 */
void device_manager_clear_unidentified_devices (struct device_manager *mgr)
{
	struct device_manager_unidentified_entry *entry;

	if (mgr->unidentified != NULL) {
		while (mgr->unidentified->next != mgr->unidentified) {
			entry = mgr->unidentified->next;
			mgr->unidentified->next = entry->next;
			platform_free (entry);
		}

		platform_free (mgr->unidentified);

		mgr->unidentified = NULL;
	}
}
#endif

/**
 * Release device manager
 *
 * @param mgr Device manager instance to release
 */
void device_manager_release (struct device_manager *mgr)
{
	if (mgr) {
		platform_free (mgr->entries);
		platform_free (mgr->attestation_status);

		mgr->num_devices = 0;

#ifdef ATTESTATION_SUPPORT_DEVICE_DISCOVERY
		device_manager_clear_unidentified_devices (mgr);
#endif
	}
}

/**
 * Find device index in device manager table using SMBUS address and EID.
 *
 * @param mgr The device manager to utilize.
 * @param eid The EID to find.
 *
 * @return The device number if found or an error code.
 */
int device_manager_get_device_num (struct device_manager *mgr, uint8_t eid)
{
	int i_device;

	if (mgr == NULL) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	for (i_device = 0; i_device < mgr->num_devices; ++i_device) {
		if (mgr->entries[i_device].eid == eid) {
			return i_device;
		}
	}

	return DEVICE_MGR_UNKNOWN_DEVICE;
}

/**
 * Find device SMBUS address for a device in device manager table.
 *
 * @param mgr The device manager to utilize.
 * @param device_num The device table entry to utilize.
 *
 * @return The device address if found or an error code.
 */
int device_manager_get_device_addr (struct device_manager *mgr, int device_num)
{
	if (mgr == NULL) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	if (device_num >= mgr->num_devices) {
		return DEVICE_MGR_UNKNOWN_DEVICE;
	}

	return mgr->entries[device_num].smbus_addr;
}

/**
 * Find device SMBUS address for a device in device manager table.
 *
 * @param mgr The device manager to utilize.
 * @param eid EID of device to utilize.
 *
 * @return The device address if found or an error code.
 */
int device_manager_get_device_addr_by_eid (struct device_manager *mgr, uint8_t eid)
{
	if (mgr == NULL) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	return device_manager_get_device_addr (mgr, device_manager_get_device_num (mgr, eid));
}

/**
 * Find device EID for a device in device manager table.
 *
 * @param mgr The device manager to utilize.
 * @param device_num The device table entry to utilize.
 *
 * @return The device EID if found or an error code.
 */
int device_manager_get_device_eid (struct device_manager *mgr, int device_num)
{
	if (mgr == NULL) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	if (device_num >= mgr->num_devices) {
		return DEVICE_MGR_UNKNOWN_DEVICE;
	}

	return mgr->entries[device_num].eid;
}

/**
 * Update device manager device table entry with new eid.
 *
 * @param mgr Device manager instance to utilize.
 * @param device_num Device table entry to update.
 * @param eid Device EID to use.
 *
 * @return Completion status, 0 if success or an error code.
 */
int device_manager_update_device_eid (struct device_manager *mgr, int device_num, uint8_t eid)
{
	if (mgr == NULL) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	if (device_num >= mgr->num_devices) {
		return DEVICE_MGR_UNKNOWN_DEVICE;
	}

	mgr->entries[device_num].eid = eid;

	return 0;
}

/**
 * Update device manager device table entry.  All non-attestable devices need to be in device
 * entries at the beginning.
 *
 * @param mgr Device manager instance to utilize.
 * @param device_num Device table entry to update.
 * @param eid Device EID.
 * @param smbus_addr Device SMBUS Address.
 * @param pcd_component_index Index of component in PCD.  If not a PCD component, use
 * 	DEVICE_MANAGER_NOT_PCD_COMPONENT.
 *
 * @return Completion status, 0 if success or an error code.
 */
int device_manager_update_not_attestable_device_entry (struct device_manager *mgr, int device_num,
	uint8_t eid, uint8_t smbus_addr, uint8_t pcd_component_index)
{
	if (mgr == NULL) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	if (device_num >= mgr->num_devices) {
		return DEVICE_MGR_UNKNOWN_DEVICE;
	}

	mgr->entries[device_num].eid = eid;
	mgr->entries[device_num].smbus_addr = smbus_addr;
	mgr->entries[device_num].pcd_component_index = pcd_component_index;
	mgr->entries[device_num].state = DEVICE_MANAGER_NOT_ATTESTABLE;

	return platform_init_timeout (0, &mgr->entries[device_num].attestation_timeout);
}

/**
 * Update device manager device table MCTP bridge component entry.  All attestable devices need to
 * be in device entries that follow non-attestable devices.  The order in which device entries are
 * added needs to follow order in PCD.
 *
 * @param mgr Device manager instance to utilize.
 * @param device_num Device table entry to update.
 * @param pci_vid PCI Vendor ID.
 * @param pci_device_id PCI Device ID.
 * @param pci_subsystem_vid PCI Subsystem Vendor ID.
 * @param pci_subsystem_id PCI Subsystem ID.
 * @param components_count Number of identical components this element describes.
 * @param component_id Component ID in PCD and CFM.
 * @param pcd_component_index Index of component in PCD.  If not a PCD component, use
 * 	DEVICE_MANAGER_NOT_PCD_COMPONENT.
 *
 * @return Completion status, 0 if success or an error code.
 */
int device_manager_update_mctp_bridge_device_entry (struct device_manager *mgr, int device_num,
	uint16_t pci_vid, uint16_t pci_device_id, uint16_t pci_subsystem_vid, uint16_t pci_subsystem_id,
	uint8_t components_count, uint32_t component_id, uint8_t pcd_component_index)
{
	int i_component;
	int status;

	if ((mgr == NULL) || (components_count == 0)) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	if ((device_num + components_count) > mgr->num_devices) {
		return DEVICE_MGR_UNKNOWN_DEVICE;
	}

	for (i_component = device_num; i_component < (device_num + components_count); ++i_component) {
		mgr->entries[i_component].component_id = component_id;
		mgr->entries[i_component].pci_device_id = pci_device_id;
		mgr->entries[i_component].pci_vid = pci_vid;
		mgr->entries[i_component].pci_subsystem_id = pci_subsystem_id;
		mgr->entries[i_component].pci_subsystem_vid = pci_subsystem_vid;
		mgr->entries[i_component].smbus_addr =
			mgr->entries[DEVICE_MANAGER_MCTP_BRIDGE_DEVICE_NUM].smbus_addr;
		mgr->entries[device_num].pcd_component_index = pcd_component_index;

		status = device_manager_update_device_state (mgr, i_component, DEVICE_MANAGER_UNIDENTIFIED);
		if (status != 0) {
			return status;
		}

		status = platform_init_timeout (0, &mgr->entries[i_component].attestation_timeout);
		if (status != 0) {
			return status;
		}
	}

	return 0;
}

/**
 * Retrieve the device capabilities for a device in the device manager table.
 *
 * @param mgr The device manager to query.
 * @param device_num The device table entry to retrieve capabilites for.
 * @param capabilities Output buffer for the device capabilities.
 *
 * @return Completion status, 0 if success or an error code.
 */
int device_manager_get_device_capabilities (struct device_manager *mgr, int device_num,
	struct device_manager_full_capabilities *capabilities)
{
	if ((mgr == NULL) || (capabilities == NULL)) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	if (device_num >= mgr->num_devices) {
		return DEVICE_MGR_UNKNOWN_DEVICE;
	}

	memcpy (capabilities, &mgr->entries[device_num].capabilities,
		sizeof (struct device_manager_full_capabilities));

	return 0;
}

/**
 * Update the device capabilities for a device in the device manager device table.
 *
 * @param mgr Device manager instance to update.
 * @param device_num Device table entry to update.
 * @param capabilities Capabilities to use for the device entry.
 *
 * @return Completion status, 0 if success or an error code.
 */
int device_manager_update_device_capabilities (struct device_manager *mgr, int device_num,
	struct device_manager_full_capabilities *capabilities)
{
	if ((mgr == NULL) || (capabilities == NULL)) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	if (device_num >= mgr->num_devices) {
		return DEVICE_MGR_UNKNOWN_DEVICE;
	}

	memcpy (&mgr->entries[device_num].capabilities, capabilities,
		sizeof (struct device_manager_full_capabilities));

	return 0;
}

/**
 * Retrieve the device capabilites for a request.  This will only retrieve the local devices's
 * capabilities.
 *
 * @param mgr The devcie manager to query.
 * @param capabilites Output buffer for the device capabilities.
 *
 * @return Completion status, 0 if success or an error code.
 */
int device_manager_get_device_capabilities_request (struct device_manager *mgr,
	struct device_manager_capabilities *capabilites)
{
	if ((mgr == NULL) || (capabilites == NULL)) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	memcpy (capabilites, &mgr->entries[0].capabilities.request,
		sizeof (struct device_manager_capabilities));

	return 0;
}

/**
 * Update only the device capabilities from a request massage for a device in the device manager
 * device table.
 *
 * @param mgr Device manager instance to update.
 * @param device_num Device table entry to update.
 * @param capabilities Capabilities to use for the device entry.
 *
 * @return Completion status, 0 if success or an error code.
 */
int device_manager_update_device_capabilities_request (struct device_manager *mgr, int device_num,
	struct device_manager_capabilities *capabilities)
{
	if ((mgr == NULL) || (capabilities == NULL)) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	if (device_num >= mgr->num_devices) {
		return DEVICE_MGR_UNKNOWN_DEVICE;
	}

	memcpy (&mgr->entries[device_num].capabilities, capabilities,
		sizeof (struct device_manager_capabilities));

	return 0;
}

/**
 * Get the maximum message length supported by a device.  For any remote device, this will be the
 * negotiated maximum based on shared capabilities.  If the requested device is not known or has
 * invalid capabilites, the local device message length is used.
 *
 * @param mgr Device manager to query.
 * @param device_num Entry in the device table to query.
 *
 * @return The maximum message size to use when communicating with the device.
 */
size_t device_manager_get_max_message_len (struct device_manager *mgr, int device_num)
{
	size_t remote_len = 0;

	if (mgr == NULL) {
		return MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	}

	if (device_num < mgr->num_devices) {
		remote_len = mgr->entries[device_num].capabilities.request.max_message_size;
	}
	if (remote_len == 0) {
		remote_len = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	}

	return min (mgr->entries[0].capabilities.request.max_message_size, remote_len);
}

/**
 * Get the maximum message length supported by a device.  For any remote device, this will be the
 * negotiated maximum based on shared capabilities.  If the requested device is not known or has
 * invalid capabilites, the local device message length is used.
 *
 * @param mgr Device manager to query.
 * @param eid EID of the device entry to query.
 *
 * @return The maximum message size to use when communicating with the device.
 */
size_t device_manager_get_max_message_len_by_eid (struct device_manager *mgr, uint8_t eid)
{
	if (mgr == NULL) {
		return MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	}

	return device_manager_get_max_message_len (mgr, device_manager_get_device_num (mgr, eid));
}

/**
 * Get the maximum MCTP transmission unit supported by a device.  For any remote device, this will
 * be the negotiated maximum based on shared capabilities.  If the requested device is not known or
 * has invalid capabilites, the local device packet length is used.
 *
 * @param mgr Device manager to query.
 * @param device_num Entry in the device table to query.
 *
 * @return The maximum packet size to use when communicating with the device.
 */
size_t device_manager_get_max_transmission_unit (struct device_manager *mgr, int device_num)
{
	size_t remote_len = 0;

	if (mgr == NULL) {
		return MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	}

	if (device_num < mgr->num_devices) {
		remote_len = mgr->entries[device_num].capabilities.request.max_packet_size;
	}
	if (remote_len == 0) {
		remote_len = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	}

	return min (mgr->entries[0].capabilities.request.max_packet_size, remote_len);
}

/**
 * Get the maximum MCTP transmission unit supported by a device.  For any remote device, this will
 * be the negotiated maximum based on shared capabilities.  If the requested device is not known or
 * has invalid capabilites, the local device packet length is used.
 *
 * @param mgr Device manager to query.
 * @param eid EID of the device entry to query.
 *
 * @return The maximum packet size to use when communicating with the device.
 */
size_t device_manager_get_max_transmission_unit_by_eid (struct device_manager *mgr, uint8_t eid)
{
	if (mgr == NULL) {
		return MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	}

	return device_manager_get_max_transmission_unit (mgr, device_manager_get_device_num (mgr, eid));
}

/**
 * Get the maximum amount of time to wait for a response from a remote device.  If the device is not
 * known or has invalid capabilities, the local device timeout is assumed.
 *
 * @param mgr Device manager to query.
 * @param device_num Entry in the device table to query.
 *
 * @return The response timeout for the device.
 */
uint32_t device_manager_get_reponse_timeout (struct device_manager *mgr, int device_num)
{
	if (mgr == NULL) {
		return MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS;
	}

	if ((device_num >= mgr->num_devices) ||
		(mgr->entries[device_num].capabilities.max_timeout == 0)) {
		return ((mgr->entries[0].capabilities.max_timeout * 10) +
			mgr->mctp_bridge_additional_timeout_ms);
	}

	return ((mgr->entries[device_num].capabilities.max_timeout * 10) +
		mgr->mctp_bridge_additional_timeout_ms);
}

/**
 * Get the maximum amount of time to wait for a response from a remote device.  If the device is not
 * known or has invalid capabilities, the local device timeout is assumed.
 *
 * @param mgr Device manager to query.
 * @param eid EID of the device entry to query.
 *
 * @return The response timeout for the device.
 */
uint32_t device_manager_get_reponse_timeout_by_eid (struct device_manager *mgr, uint8_t eid)
{
	if (mgr == NULL) {
		return MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS;
	}

	return device_manager_get_reponse_timeout (mgr, device_manager_get_device_num (mgr, eid));
}

/**
 * Get the maximum amount of time to wait for a response from a remote device when executing
 * cryptographic requests.  If the device is not known or has invalid capabilities, the local device
 * timeout is assumed.
 *
 * @param mgr Device manager to query.
 * @param device_num Entry in the device table to query.
 *
 * @return The cryptographic response timeout for the device.
 */
uint32_t device_manager_get_crypto_timeout (struct device_manager *mgr, int device_num)
{
	if (mgr == NULL) {
		return MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS;
	}

	if ((device_num >= mgr->num_devices) ||
		(mgr->entries[device_num].capabilities.max_sig == 0)) {
		return ((mgr->entries[0].capabilities.max_sig * 100) +
			mgr->mctp_bridge_additional_timeout_ms);
	}

	return ((mgr->entries[device_num].capabilities.max_sig * 100) +
		mgr->mctp_bridge_additional_timeout_ms);
}

/**
 * Get the maximum amount of time to wait for a response from a remote device when executing
 * cryptographic requests.  If the device is not known or has invalid capabilities, the local device
 * timeout is assumed.
 *
 * @param mgr Device manager to query.
 * @param eid EID of the device entry to query.
 *
 * @return The cryptographic response timeout for the device.
 */
uint32_t device_manager_get_crypto_timeout_by_eid (struct device_manager *mgr, uint8_t eid)
{
	if (mgr == NULL) {
		return MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS;
	}

	return device_manager_get_crypto_timeout (mgr, device_manager_get_device_num (mgr, eid));
}

/**
 * Get the SPDM ResponseNotReady limits.
 *
 * @param mgr Device manager to query.
 * @param max_timeout_ms Buffer to fill with maximum ResponseNotReady wait duration in milliseconds.
 * @param max_retries Buffer to fill with maximum number of ResponseNotReady retries permitted.
 *
 * @return Completion status, 0 if success or an error code.
 */
int device_manager_get_rsp_not_ready_limits (struct device_manager *mgr, uint32_t *max_timeout_ms,
	uint8_t *max_retries)
{
	if ((mgr == NULL) || (max_timeout_ms == NULL) || (max_retries == NULL)) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	*max_timeout_ms = mgr->attestation_rsp_not_ready_max_duration_ms;
	*max_retries = mgr->attestation_rsp_not_ready_max_retry;

	return 0;
}

/**
 * Get the maximum amount of time to wait for a response from a remote device when executing
 * MCTP control protocol requests.
 *
 * @param mgr Device manager to query.
 *
 * @return The response timeout.
 */
uint32_t device_manager_get_mctp_ctrl_timeout (struct device_manager *mgr)
{
	if (mgr == NULL) {
		return DEVICE_MANAGER_MCTP_CTRL_PROTOCOL_TIMEOUT_MS;
	}

	return (mgr->mctp_ctrl_timeout_ms + mgr->mctp_bridge_additional_timeout_ms);
}

/**
 * Update certificate chain digest buffer in device manager device table entry
 *
 * @param mgr Device manager instance to utilize.
 * @param eid EID of device to update.
 * @param slot_num Slot number of incoming certificate chain.
 * @param digest Digest buffer with a new certificate chain digest.
 * @param digest_len Length of digest.
 *
 * @return Completion status, 0 if success or an error code.
 */
int device_manager_update_cert_chain_digest (struct device_manager *mgr, uint8_t eid,
	uint8_t slot_num, const uint8_t *digest, size_t digest_len)
{
	uint8_t i_device;
	int device_num;

	if ((mgr == NULL) || (digest == NULL) || (digest_len == 0)) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	if (digest_len > HASH_MAX_HASH_LEN) {
		return DEVICE_MGR_INPUT_TOO_LARGE;
	}

	device_num = device_manager_get_device_num (mgr, eid);
	if (ROT_IS_ERROR (device_num)) {
		return device_num;
	}

	/* Before updating entry corresponding to EID, ensure digest received doesn't match another
	 * devices certificate chain digest */

	for (i_device = 0; i_device < mgr->num_devices; ++i_device) {
		if (i_device == device_num) {
			continue;
		}

		if (mgr->entries[i_device].hash_len == digest_len) {
			if (memcmp (mgr->entries[i_device].cert_chain_digest, digest, digest_len) == 0) {
				return DEVICE_MGR_DIGEST_NOT_UNIQUE;
			}
		}
	}

	memcpy (mgr->entries[device_num].cert_chain_digest, digest, digest_len);

	mgr->entries[device_num].hash_len = digest_len;
	mgr->entries[device_num].slot_num = slot_num;

	return 0;
}

/**
 * Clear certificate chain digest buffer in device manager device table entry
 *
 * @param mgr Device manager instance to utilize.
 * @param eid EID of device to update.
 *
 * @return Completion status, 0 if success or an error code.
 */
int device_manager_clear_cert_chain_digest (struct device_manager *mgr, uint8_t eid)
{
	int device_num;

	if (mgr == NULL) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	device_num = device_manager_get_device_num (mgr, eid);
	if (ROT_IS_ERROR (device_num)) {
		return device_num;
	}

	mgr->entries[device_num].hash_len = 0;

	return 0;
}

/**
 * Compare certificate chain digest with cached digest in a device manager device table entry
 *
 * @param mgr Device manager instance to utilize.
 * @param eid EID of device to utilize.
 * @param digest Buffer with digest to test.
 * @param digest_len Length of digest buffer.
 *
 * @return 0 if digests match or an error code.
 */
int device_manager_compare_cert_chain_digest (struct device_manager *mgr, uint8_t eid,
	uint8_t *digest, size_t digest_len)
{
	int device_num;
	int status;

	if ((mgr == NULL) || (digest == NULL) || (digest_len == 0)) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	device_num = device_manager_get_device_num (mgr, eid);
	if (ROT_IS_ERROR (device_num)) {
		return device_num;
	}

	if (digest_len != mgr->entries[device_num].hash_len) {
		return DEVICE_MGR_DIGEST_LEN_MISMATCH;
	}

	status = memcmp (digest, mgr->entries[device_num].cert_chain_digest,
		mgr->entries[device_num].hash_len);
	if (status != 0) {
		return DEVICE_MGR_DIGEST_MISMATCH;
	}

	return 0;
}

/**
 * Update alias certificate public key buffer in device manager device table entry
 *
 * @param mgr Device manager instance to utilize.
 * @param eid EID of device to update.
 * @param key Key buffer with a new alias key.
 * @param key_len Length of key.
 * @param key_type Alias key type.
 *
 * @return Completion status, 0 if success or an error code.
 */
int device_manager_update_alias_key (struct device_manager *mgr, uint8_t eid, const uint8_t *key,
	size_t key_len, int key_type)
{
	int device_num;

	if ((mgr == NULL) || (key == NULL) || (key_len == 0)) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	if (key_len > DEVICE_MANAGER_MAX_KEY_LEN) {
		return DEVICE_MGR_INPUT_TOO_LARGE;
	}

	device_num = device_manager_get_device_num (mgr, eid);
	if (ROT_IS_ERROR (device_num)) {
		return device_num;
	}

	memcpy (mgr->entries[device_num].alias_key.key, key, key_len);
	mgr->entries[device_num].alias_key.key_len = key_len;
	mgr->entries[device_num].alias_key.key_type = key_type;

	return 0;
}

/**
 * Get alias key from a device manager device table entry
 *
 * @param mgr Device manager instance to utilize.
 * @param eid EID of device to utilize.
 *
 * @return Container to update with alias key if found or NULL.
 */
const struct device_manager_key* device_manager_get_alias_key (struct device_manager *mgr,
	uint8_t eid)
{
	int device_num;

	if (mgr == NULL) {
		return NULL;
	}

	device_num = device_manager_get_device_num (mgr, eid);
	if (ROT_IS_ERROR (device_num)) {
		return NULL;
	}

	return &mgr->entries[device_num].alias_key;
}

/**
 * Find device state for a device in device manager table.
 *
 * @param mgr The device manager to utilize.
 * @param device_num The device table entry to utilize.
 *
 * @return The device state if found or an error code.
 */
int device_manager_get_device_state (struct device_manager *mgr, int device_num)
{
	if (mgr == NULL) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	if (device_num >= mgr->num_devices) {
		return DEVICE_MGR_UNKNOWN_DEVICE;
	}

	return mgr->entries[device_num].state;
}

/**
 * Find device state for a device in device manager table.
 *
 * @param mgr The device manager to utilize.
 * @param eid EID of device to utilize.
 *
 * @return The device state if found or an error code.
 */
int device_manager_get_device_state_by_eid (struct device_manager *mgr, uint8_t eid)
{
	if (mgr == NULL) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	return device_manager_get_device_state (mgr, device_manager_get_device_num (mgr, eid));
}

/*
 * Update device manager device table entry state
 *
 * @param mgr Device manager instance to utilize.
 * @param eid EID of device to update.
 * @param state Device state.
 *
 * @return Completion status, 0 if success or an error code.
 */
int device_manager_update_device_state_by_eid (struct device_manager *mgr, uint8_t eid,
	enum device_manager_device_state state)
{
	if (mgr == NULL) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	return device_manager_update_device_state (mgr, device_manager_get_device_num (mgr, eid),
		state);
}

/**
 * Find component ID for a device in device manager table.
 *
 * @param mgr The device manager to utilize.
 * @param eid The EID of the device table entry to utilize.
 * @param component_id Component ID in PCD and CFM.
 *
 * @return Completion status, 0 if success or an error code.
 */
int device_manager_get_component_id (struct device_manager *mgr, uint8_t eid,
	uint32_t *component_id)
{
	int device_num;

	if ((mgr == NULL) || (component_id == NULL)) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	device_num = device_manager_get_device_num (mgr, eid);
	if (ROT_IS_ERROR (device_num)) {
		return device_num;
	}

	*component_id = mgr->entries[device_num].component_id;

	return 0;
}

/**
 * Get EID of first device that is ready for attestation. A device that is starting or has failed
 * attestation has a cadence of unauthenticated_cadence_ms, a device that has previously  passed
 * attestation has a cadence of authenticated_cadence_ms. The device manager keeps track of last
 * device authenticated, so checking starts after that device.
 *
 * @param mgr Device manager instance to utilize.
 *
 * @return EID of device to attest or an error code.
 */
int device_manager_get_eid_of_next_device_to_attest (struct device_manager *mgr)
{
	uint8_t num_checked = 0;
	int starting_device;
	int i_device;
	int status;

	if ((mgr == NULL) || (mgr->num_devices == 0)) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	starting_device = (mgr->last_device_authenticated + 1) % mgr->num_devices;

	for (i_device = starting_device; num_checked < mgr->num_devices;
		i_device = (i_device + 1) % mgr->num_devices, ++num_checked) {
		if (!device_manager_can_device_be_attested ((mgr->entries[i_device].state))) {
			continue;
		}

		status = platform_has_timeout_expired (&mgr->entries[i_device].attestation_timeout);
		if (ROT_IS_ERROR (status)) {
			return status;
		}
		if (status) {
			goto found;
		}
	}

	return DEVICE_MGR_NO_DEVICES_AVAILABLE;

found:
	mgr->last_device_authenticated = i_device;

	return mgr->entries[i_device].eid;
}

/**
 * Reset all authenticated devices back to discovered state.
 *
 * @param mgr Device manager instance to utilize.
 *
 * @return Completion status, 0 if success or an error code.
 */
int device_manager_reset_authenticated_devices (struct device_manager *mgr)
{
	int i_device;
	int status;

	if (mgr == NULL) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	for (i_device = 0; i_device < mgr->num_devices; ++i_device) {
		if (mgr->entries[i_device].state == DEVICE_MANAGER_AUTHENTICATED) {
			status = device_manager_update_device_state (mgr, i_device,
				DEVICE_MANAGER_NEVER_ATTESTED);
			if (status != 0) {
				return status;
			}
		}
	}

	return 0;
}

/**
 * Reset all discovered devices back to unidentified state.
 *
 * @param mgr Device manager instance to utilize.
 *
 * @return Completion status, 0 if success or an error code.
 */
int device_manager_reset_discovered_devices (struct device_manager *mgr)
{
	int i_device;
	int status;

	if (mgr == NULL) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	for (i_device = 0; i_device < mgr->num_devices; ++i_device) {
		if (!device_manager_can_device_be_attested (mgr->entries[i_device].state)) {
			continue;
		}

		status = device_manager_update_device_state (mgr, i_device,
			DEVICE_MANAGER_UNIDENTIFIED);
		if (status != 0) {
			return status;
		}
	}

	return 0;
}

/**
 * Get device manager device table entry number by device IDs
 *
 * @param mgr Device manager instance to utilize.
 * @param pci_vid The PCI vendor ID to utilize.
 * @param pci_device_id The PCI device ID to utilize.
 * @param pci_subsystem_vid The PCI subsystem vendor ID to utilize.
 * @param pci_subsystem_id The PCI subsystem ID to utilize.
 *
 * @return Device number of entry if found or an error code.
 */
int device_manager_get_device_num_by_device_ids (struct device_manager *mgr, uint16_t pci_vid,
	uint16_t pci_device_id, uint16_t pci_subsystem_vid, uint16_t pci_subsystem_id)
{
	int i_device;

	if (mgr == NULL) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	for (i_device = 0; i_device < mgr->num_devices; ++i_device) {
		if (mgr->entries[i_device].state == DEVICE_MANAGER_UNIDENTIFIED) {
			if ((mgr->entries[i_device].pci_vid == pci_vid) &&
				(mgr->entries[i_device].pci_device_id == pci_device_id) &&
				(mgr->entries[i_device].pci_subsystem_vid == pci_subsystem_vid) &&
				(mgr->entries[i_device].pci_subsystem_id == pci_subsystem_id)) {
				return i_device;
			}
		}
	}

	return DEVICE_MGR_UNKNOWN_DEVICE;
}

/**
 * Update device manager device table entry device IDs
 *
 * @param mgr Device manager instance to utilize.
 * @param device_num Device table entry to update.
 * @param pci_vid The PCI vendor ID to utilize.
 * @param pci_device_id The PCI device ID to utilize.
 * @param pci_subsystem_vid The PCI subsystem vendor ID to utilize.
 * @param pci_subsystem_id The PCI subsystem ID to utilize.
 *
 * @return Completion status, 0 if success or an error code.
 */
int device_manager_update_device_ids (struct device_manager *mgr, int device_num, uint16_t pci_vid,
	uint16_t pci_device_id, uint16_t pci_subsystem_vid, uint16_t pci_subsystem_id)
{
	if (mgr == NULL) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	if (device_num >= mgr->num_devices) {
		return DEVICE_MGR_UNKNOWN_DEVICE;
	}

	mgr->entries[device_num].pci_vid = pci_vid;
	mgr->entries[device_num].pci_device_id = pci_device_id;
	mgr->entries[device_num].pci_subsystem_vid = pci_subsystem_vid;
	mgr->entries[device_num].pci_subsystem_id = pci_subsystem_id;

	return 0;
}

#ifdef ATTESTATION_SUPPORT_DEVICE_DISCOVERY
/**
 * Add a node to device manager unidentified device linked list.
 *
 * @param mgr Device manager instance to utilize.
 * @param eid EID of device to add.
 *
 * @return 0 if completed successfully or an error code.
 */
int device_manager_add_unidentified_device (struct device_manager *mgr, uint8_t eid)
{
	struct device_manager_unidentified_entry *new_entry;

	if (mgr == NULL) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	new_entry = platform_calloc (1, sizeof (struct device_manager_unidentified_entry));
	if (new_entry == NULL) {
		return DEVICE_MGR_NO_MEMORY;
	}

	new_entry->eid = eid;

	if (mgr->unidentified == NULL) {
		new_entry->next = new_entry;
		mgr->unidentified = new_entry;
	}
	else {
		new_entry->next = mgr->unidentified->next;
		mgr->unidentified->next = new_entry;
	}

	return platform_init_timeout (0, &new_entry->discovery_timeout);
}

/**
 * Find device entry with requested EID in unidentified device list.
 *
 * @param mgr Device manager instance to utilize.
 * @param eid EID of device to find.
 * @param entry Container to fill with pointer to requested device entry.
 * @param prev Container to fill with pointer to device right before requested device entry. Can be
 * 	set to NULL if not needed.
 *
 * @return 0 if completed successfully or an error code.
 */
static int device_manager_find_unidentified_device (struct device_manager *mgr, uint8_t eid,
	struct device_manager_unidentified_entry **entry,
	struct device_manager_unidentified_entry **prev)
{
	struct device_manager_unidentified_entry *previous;

	previous = mgr->unidentified;

	while (previous->next->eid != eid) {
		previous = previous->next;

		if (previous == mgr->unidentified) {
			return DEVICE_MGR_UNKNOWN_DEVICE;
		}
	}

	*entry = previous->next;

	if (prev != NULL) {
		*prev = previous;
	}

	return 0;
}

/**
 * Remove a node from device manager unidentified device linked list.
 *
 * @param mgr Device manager instance to utilize.
 * @param eid EID of device to remove.
 *
 * @return 0 if completed successfully or an error code.
 */
int device_manager_remove_unidentified_device (struct device_manager *mgr, uint8_t eid)
{
	struct device_manager_unidentified_entry *previous;
	struct device_manager_unidentified_entry *entry;
	int status;

	if (mgr == NULL) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	if (mgr->unidentified == NULL) {
		return 0;
	}

	status = device_manager_find_unidentified_device (mgr, eid, &entry, &previous);
	if (status != 0) {
		return status;
	}

	previous->next = previous->next->next;
	if (previous->next == entry) {
		mgr->unidentified = NULL;
	}

	platform_free (entry);

	return 0;
}

/**
 * Mark a node from device manager unidentified device linked list as timed out.
 *
 * @param mgr Device manager instance to utilize.
 * @param eid EID of device to utilize.
 *
 * @return 0 if completed successfully or an error code.
 */
int device_manager_unidentified_device_timed_out (struct device_manager *mgr, uint8_t eid)
{
	struct device_manager_unidentified_entry *entry;
	int status;

	if (mgr == NULL) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	if (mgr->unidentified == NULL) {
		return DEVICE_MGR_UNKNOWN_DEVICE;
	}

	status = device_manager_find_unidentified_device (mgr, eid, &entry, NULL);
	if (status != 0) {
		return status;
	}

	entry->timeout = true;

	return platform_init_timeout (mgr->unidentified_timeout_ms, &entry->discovery_timeout);
}

/**
 * Get EID of next device to discover from device manager unidentified device linked list.
 *
 * @param mgr Device manager instance to utilize.
 *
 * @return EID if found or an error code.
 */
int device_manager_get_eid_of_next_device_to_discover (struct device_manager *mgr)
{
	struct device_manager_unidentified_entry *runner;
	int status;

	if (mgr == NULL) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	if (mgr->unidentified == NULL) {
		return DEVICE_MGR_NO_DEVICES_AVAILABLE;
	}

	runner = mgr->unidentified;

	status = platform_has_timeout_expired (&runner->discovery_timeout);
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	if (!runner->timeout || status) {
		goto found;
	}

	while (runner->next != mgr->unidentified) {
		status = platform_has_timeout_expired (&runner->discovery_timeout);
		if (ROT_IS_ERROR (status)) {
			return status;
		}

		if (!runner->timeout || status) {
			goto found;
		}
		else {
			runner = runner->next;
		}
	}

	return DEVICE_MGR_NO_DEVICES_AVAILABLE;

found:
	runner->timeout = 0;

	mgr->unidentified = runner->next;

	return runner->eid;
}
#endif

/**
 * Check a timeout to see if it will expire before a specified duration.
 *
 * @param timeout The timeout to check.
 * @param duration_ms The duration to check the timeout against.
 *
 * @return The minimum of the remaining time in the specified timeout or the specified duration.
 */
static uint32_t device_manager_find_min_timeout (const platform_clock *timeout,
	uint32_t duration_ms)
{
	uint32_t check_ms;
	int status;

	status = platform_get_timeout_remaining (timeout, &check_ms);
	if (status != 0) {
		/* If the remaining timeout could not be determined, assume the timeout has expired. */
		check_ms = 0;
	}

	return min (check_ms, duration_ms);
}

/**
 * Get time in milliseconds till next attestation or discovery action.
 *
 * @param mgr Device manager instance to utilize.
 *
 * @return Time in milliseconds till next action.
 */
uint32_t device_manager_get_time_till_next_action (struct device_manager *mgr)
{
	uint32_t duration_ms = DEVICE_MANAGER_MIN_ACTIVITY_CHECK;
	uint8_t i_device;

	if (mgr == NULL) {
		return duration_ms;
	}

	for (i_device = 0; i_device < mgr->num_devices; ++i_device) {
		if (!device_manager_can_device_be_attested (mgr->entries[i_device].state)) {
			continue;
		}

		duration_ms = device_manager_find_min_timeout (&mgr->entries[i_device].attestation_timeout,
			duration_ms);
	}

#ifdef ATTESTATION_SUPPORT_DEVICE_DISCOVERY
	{
		struct device_manager_unidentified_entry *runner = mgr->unidentified;

		if (runner == NULL) {
			return duration_ms;
		}

		duration_ms = device_manager_find_min_timeout (&runner->discovery_timeout, duration_ms);

		while (runner->next != mgr->unidentified) {
			runner = runner->next;

			duration_ms = device_manager_find_min_timeout (&runner->discovery_timeout, duration_ms);
		}
	}
#endif

	return duration_ms;
}

/**
 * Update attestation status buffer with attestation statuses of responder devices, then return
 * pointer to buffer.  Byte position in buffer maps to the index of a component in the PCD.  Byte
 * value maps to device_manager_device_state enum value.
 *
 * @param mgr Device manager instance to utilize.
 * @param attestation_status Buffer to fill with pointer to attestation status buffer.  If the
 * device has no responder devices, the output will be NULL.
 *
 * @return Length of attestation_status if completed successfully or an error code.  If the device
 *  has no responder devices, the length returned shall be 0.
 */
int device_manager_get_attestation_status (struct device_manager *mgr,
	const uint8_t **attestation_status)
{
	size_t attestation_status_len;
	int i_device;
	int i_entry;

	if ((mgr == NULL) || (attestation_status == NULL)) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	attestation_status_len = mgr->num_responder_devices;
	*attestation_status = mgr->attestation_status;

	if (mgr->num_responder_devices != 0) {
		memset (mgr->attestation_status, 0xFF, attestation_status_len);

		if (!mgr->attestable_components_list_invalid) {
			// Skip the requester devices in the beginning of the list
			for (i_device = mgr->num_requester_devices, i_entry = 0; i_device < mgr->num_devices;
				++i_device, ++i_entry) {
				mgr->attestation_status[i_entry] = mgr->entries[i_device].state;
			}
		}
	}

	return attestation_status_len;
}

int device_manager_mark_component_attestation_invalid (struct device_manager *mgr)
{
	if (mgr == NULL) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	mgr->attestable_components_list_invalid = true;

	return 0;
}

bool device_manager_is_device_unattestable (struct device_manager *mgr, uint8_t eid)
{
	int device_num;

	if (mgr == NULL) {
		return false;
	}

	device_num = device_manager_get_device_num (mgr, eid);
	if (ROT_IS_ERROR (device_num)) {
		return false;
	}

	return (mgr->entries[device_num].state == DEVICE_MANAGER_NOT_ATTESTABLE);
}
