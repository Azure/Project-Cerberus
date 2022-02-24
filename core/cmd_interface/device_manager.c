// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "platform.h"
#include "device_manager.h"
#include "common/common_math.h"
#include "mctp/mctp_base_protocol.h"
#include "crypto/hash.h"


/**
 * Initialize a device manager.
 *
 * The first device entry will be for the local device, and the device capabilities will be
 * initialized based on the device configuration.  These capabilities can be updated as necessary
 * with device_manager_update_device_capabilities().
 *
 * @param mgr Device manager instance to initialize.
 * @param num_devices Number of devices to manage.  This must be at least 1 to support the local
 * device.
 * @param hierarchy Role of the local device in the Cerberus hierarchy (PA vs. AC RoT).
 * @param bus_role Role the local device will take on the I2C bus.
 *
 * @return Initialization status, 0 if success or an error code.
 */
int device_manager_init (struct device_manager *mgr, int num_devices, uint8_t hierarchy,
	uint8_t bus_role)
{
	if ((mgr == NULL) || (num_devices == 0) || (hierarchy >= NUM_BUS_HIERACHY_ROLES) ||
		(bus_role >= NUM_BUS_ROLES)) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	mgr->entries = platform_calloc (num_devices, sizeof (struct device_manager_entry));
	if (mgr->entries == NULL) {
		return DEVICE_MGR_NO_MEMORY;
	}

	/* Initialize the local device capabilities. */
	mgr->entries[0].info.capabilities.request.max_message_size =
		MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	mgr->entries[0].info.capabilities.request.max_packet_size =
		MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	mgr->entries[0].info.capabilities.request.security_mode =
		DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	mgr->entries[0].info.capabilities.request.bus_role = bus_role;
	mgr->entries[0].info.capabilities.request.hierarchy_role = hierarchy;
	mgr->entries[0].info.capabilities.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	mgr->entries[0].info.capabilities.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	mgr->num_devices = num_devices;

	return 0;
}

/**
 * Release a single certificate.
 *
 * @param cert Certificate to release
 */
static void device_manager_release_cert (struct der_cert *cert)
{
	if (cert != NULL) {
		platform_free ((void*) cert->cert);
		cert->cert = NULL;
		cert->length = 0;
	}
}

/**
 * Release the complete certificate chain for a single device entry.
 *
 * @param mgr Device manager instance.
 * @param device_num Device table entry to release.
 */
static void device_manager_release_cert_chain (struct device_manager *mgr, int device_num)
{
	int i_cert;

	if (mgr->entries[device_num].cert_chain.cert != NULL) {
		for (i_cert = 0; i_cert < mgr->entries[device_num].cert_chain.num_cert; ++i_cert) {
			device_manager_release_cert (&mgr->entries[device_num].cert_chain.cert[i_cert]);
		}

		platform_free (mgr->entries[device_num].cert_chain.cert);
		mgr->entries[device_num].cert_chain.cert = NULL;
		mgr->entries[device_num].cert_chain.num_cert = 0;
	}
}

/**
 * Release device manager
 *
 * @param mgr Device manager instance to release
 */
void device_manager_release (struct device_manager *mgr)
{
	int i_device;

	if (mgr) {
		for (i_device = 0; i_device < mgr->num_devices; ++i_device) {
			device_manager_release_cert_chain (mgr, i_device);
		}

		platform_free (mgr->entries);

		mgr->num_devices = 0;
	}
}

/**
 * Add new device manager entries
 *
 * @param mgr Device manager instance to update.
 * @param num_devices Number of devices Cerberus can communicate with.
 *
 * @return Completion status, 0 if success or an error code.
 */
int device_manager_resize_entries_table (struct device_manager *mgr, int num_devices)
{
	uint8_t *temp;

	if ((mgr == NULL) || (num_devices == 0)) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	if (num_devices == mgr->num_devices) {
		return 0;
	}

	temp = platform_calloc (num_devices, sizeof (struct device_manager_entry));
	if (mgr->entries == NULL) {
		return DEVICE_MGR_NO_MEMORY;
	}

	if (num_devices < mgr->num_devices) {
		memcpy (temp, mgr->entries, num_devices * sizeof (struct device_manager_entry));
	}
	else {
		memcpy (temp, mgr->entries, mgr->num_devices * sizeof (struct device_manager_entry));
	}

	platform_free (mgr->entries);

	mgr->entries = (struct device_manager_entry*) temp;
	mgr->num_devices = num_devices;

	return 0;
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
		if (mgr->entries[i_device].info.eid == eid) {
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

	return mgr->entries[device_num].info.smbus_addr;
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

	return mgr->entries[device_num].info.eid;
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

	mgr->entries[device_num].info.eid = eid;

	return 0;
}

/**
 * Update device manager device table entry
 *
 * @param mgr Device manager instance to utilize.
 * @param device_num Device table entry to update.
 * @param eid Device EID.
 * @param smbus_addr Device SMBUS Address.
 *
 * @return Completion status, 0 if success or an error code.
 */
int device_manager_update_device_entry (struct device_manager *mgr, int device_num, uint8_t eid,
	uint8_t smbus_addr)
{
	if (mgr == NULL) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	if (device_num >= mgr->num_devices) {
		return DEVICE_MGR_UNKNOWN_DEVICE;
	}

	mgr->entries[device_num].info.eid = eid;
	mgr->entries[device_num].info.smbus_addr = smbus_addr;
	mgr->entries[device_num].component_type[0] = '\0';

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

	memcpy (capabilities, &mgr->entries[device_num].info.capabilities,
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

	memcpy (&mgr->entries[device_num].info.capabilities, capabilities,
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

	memcpy (capabilites, &mgr->entries[0].info.capabilities.request,
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

	memcpy (&mgr->entries[device_num].info.capabilities, capabilities,
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
		remote_len = mgr->entries[device_num].info.capabilities.request.max_message_size;
	}
	if (remote_len == 0) {
		remote_len = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	}

	return min (mgr->entries[0].info.capabilities.request.max_message_size, remote_len);
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
		remote_len = mgr->entries[device_num].info.capabilities.request.max_packet_size;
	}
	if (remote_len == 0) {
		remote_len = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	}

	return min (mgr->entries[0].info.capabilities.request.max_packet_size, remote_len);
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
		(mgr->entries[device_num].info.capabilities.max_timeout == 0)) {
		return mgr->entries[0].info.capabilities.max_timeout * 10;
	}

	return mgr->entries[device_num].info.capabilities.max_timeout * 10;
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
 * cryptographic requsets.  If the device is not known or has invalid capabilities, the local device
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
		(mgr->entries[device_num].info.capabilities.max_sig == 0)) {
		return mgr->entries[0].info.capabilities.max_sig * 100;
	}

	return mgr->entries[device_num].info.capabilities.max_sig * 100;
}

/**
 * Get the maximum amount of time to wait for a response from a remote device when executing
 * cryptographic requsets.  If the device is not known or has invalid capabilities, the local device
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
 * Initialize device manager device table entry certificate chain
 *
 * @param mgr Device manager instance to utilize.
 * @param device_num Device table entry to utilize.
 * @param num_cert Number of certificates to initialize chain to hold.
 *
 * @return Completion status, 0 if success or an error code.
 */
int device_manager_init_cert_chain (struct device_manager *mgr, int device_num, uint8_t num_cert)
{
	if ((mgr == NULL) || (num_cert == 0)) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	if (device_num >= mgr->num_devices) {
		return DEVICE_MGR_UNKNOWN_DEVICE;
	}

	device_manager_release_cert_chain (mgr, device_num);

	mgr->entries[device_num].cert_chain.cert = platform_calloc (num_cert, sizeof (struct der_cert));

	if (mgr->entries[device_num].cert_chain.cert == NULL) {
		return DEVICE_MGR_NO_MEMORY;
	}

	mgr->entries[device_num].cert_chain.num_cert = num_cert;

	return 0;
}

/**
 * Update certificate in device manager device table entry certificate chain
 *
 * @param mgr Device manager instance to utilize.
 * @param device_num Device table entry to update.
 * @param cert_num Certificate to update.
 * @param buf Input buffer of certificate to update.
 * @param buf_len Length of certificate buffer
 *
 * @return Completion status, 0 if success or an error code.
 */
int device_manager_update_cert (struct device_manager *mgr, int device_num, uint8_t cert_num,
	const uint8_t *buf, int buf_len)
{
	if ((mgr == NULL) || (buf == NULL) || (buf_len == 0)) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	if (device_num >= mgr->num_devices) {
		return DEVICE_MGR_UNKNOWN_DEVICE;
	}

	if (cert_num >= mgr->entries[device_num].cert_chain.num_cert) {
		return DEVICE_MGR_INVALID_CERT_NUM;
	}

	device_manager_release_cert (&mgr->entries[device_num].cert_chain.cert[cert_num]);

	mgr->entries[device_num].cert_chain.cert[cert_num].cert = platform_malloc (buf_len);

	if (mgr->entries[device_num].cert_chain.cert[cert_num].cert == NULL) {
		return DEVICE_MGR_NO_MEMORY;
	}

	memcpy ((uint8_t*)mgr->entries[device_num].cert_chain.cert[cert_num].cert, buf, buf_len);

	mgr->entries[device_num].cert_chain.cert[cert_num].length = buf_len;

	return 0;
}

/**
 * Find device certification chain for a device in device manager table.
 *
 * @param mgr The device manager to utilize.
 * @param device_num The device table entry to utilize.
 * @param chain Output buffer for device certificate chain retrieved.
 *
 * @return Completion status, 0 if success or an error code.
 */
int device_manager_get_device_cert_chain (struct device_manager *mgr, int device_num,
	struct device_manager_cert_chain* chain)
{
	if ((mgr == NULL) || (chain == NULL)) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	if (device_num >= mgr->num_devices) {
		return DEVICE_MGR_UNKNOWN_DEVICE;
	}

	memcpy (chain, &mgr->entries[device_num].cert_chain, sizeof (struct device_manager_cert_chain));

	return 0;
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
 * Update device manager device table entry state
 *
 * @param mgr Device manager instance to utilize.
 * @param device_num Device table entry to update.
 * @param state Device state.
 *
 * @return Completion status, 0 if success or an error code.
 */
int device_manager_update_device_state (struct device_manager *mgr, int device_num, int state)
{
	if ((mgr == NULL) || (state >= NUM_DEVICE_MANAGER_STATES)) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	if (device_num >= mgr->num_devices) {
		return DEVICE_MGR_UNKNOWN_DEVICE;
	}

	mgr->entries[device_num].state = state;

	return 0;
}

/**
 * Find component type digest for a device in device manager table.
 *
 * @param mgr The device manager to utilize.
 * @param eid The EID of the device table entry to utilize.
 *
 * @return The component type digest if found or NULL.
 */
const uint8_t* device_manager_get_component_type (struct device_manager *mgr, uint8_t eid)
{
	int device_num;

	if (mgr == NULL) {
		return NULL;
	}

	device_num = device_manager_get_device_num (mgr, eid);
	if (ROT_IS_ERROR (device_num)) {
		return NULL;
	}

	return mgr->entries[device_num].component_type;
}

/**
 * Update device manager device table entry component type
 *
 * @param mgr Device manager instance to utilize.
 * @param hash Hashing engine to utilize.
 * @param eid The EID of the device table entry to utilize.
 * @param component_type Component type to set.
 *
 * @return Completion status, 0 if success or an error code.
 */
int device_manager_update_component_type (struct device_manager *mgr, struct hash_engine *hash,
	uint8_t eid, const char *component_type)
{
	int device_num;

	if ((mgr == NULL) || (hash == NULL) || (component_type == NULL) ||
		(strlen (component_type) >= MANIFEST_MAX_STRING)) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	device_num = device_manager_get_device_num (mgr, eid);
	if (ROT_IS_ERROR (device_num)) {
		return device_num;
	}

	return hash->calculate_sha256 (hash, (uint8_t*) component_type,
		strlen (component_type), mgr->entries[device_num].component_type,
		sizeof (mgr->entries[device_num].component_type));
}
