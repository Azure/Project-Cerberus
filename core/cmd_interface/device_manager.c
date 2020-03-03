// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "platform.h"
#include "device_manager.h"

/**
 * Release certificate
 *
 * @param cert Certificate to release
 */
static void device_manager_release_cert (struct der_cert *cert)
{
	if (cert != NULL) {
		platform_free ((void*)cert->cert);
		cert->cert = NULL;
		cert->length = 0;
	}
}

/**
 * Release device manager device table entry certificate chain
 *
 * @param mgr Device manager instance to utilize.
 * @param device_num Device table entry to utilize.
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
 * Find device direction for a device in device manager table.
 *
 * @param mgr The device manager to utilize.
 * @param device_num The device table entry to utilize.
 *
 * @return The device direction if found or an error code.
 */
int device_manager_get_device_direction (struct device_manager *mgr, int device_num)
{
	if (mgr == NULL) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	if (device_num >= mgr->num_devices) {
		return DEVICE_MGR_UNKNOWN_DEVICE;
	}

	return mgr->entries[device_num].direction;
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
 * @param direction Device direction relative to Cerberus.
 * @param eid Device EID. 
 * @param smbus_addr Device SMBUS Address.
 *
 * @return Completion status, 0 if success or an error code.
 */
int device_manager_update_device_entry (struct device_manager *mgr, int device_num, 
	uint8_t direction, uint8_t eid, uint8_t smbus_addr)
{
	if ((mgr == NULL) || (direction >= NUM_DEVICE_DIRECTIONS)) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	if (device_num >= mgr->num_devices) {
		return DEVICE_MGR_UNKNOWN_DEVICE;
	}

	mgr->entries[device_num].direction = direction;
	mgr->entries[device_num].info.eid = eid;
	mgr->entries[device_num].info.smbus_addr = smbus_addr;

	return 0;
}

/**
 * Find device capabilities for a device in device manager table.
 *
 * @param mgr The device manager to utilize.
 * @param device_num The device table entry to utilize.
 * @param capabilities Output buffer for device capabilities retrieved.
 *
 * @return Completion status, 0 if success or an error code.
 */
int device_manager_get_device_capabilities (struct device_manager *mgr, int device_num, 
	struct device_manager_capabilities* capabilities)
{
	if ((mgr == NULL) || (capabilities == NULL)) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	if (device_num >= mgr->num_devices) {
		return DEVICE_MGR_UNKNOWN_DEVICE;
	}

	memcpy (capabilities, &mgr->entries[device_num].info.capabilities, 
		sizeof (struct device_manager_capabilities));

	return 0;
}

/**
 * Update device manager device table entry capabilities
 *
 * @param mgr Device manager instance to utilize.
 * @param device_num Device table entry to update.
 * @param capabilities Device capabilities.
 *
 * @return Completion status, 0 if success or an error code.
 */
int device_manager_update_device_capabilities (struct device_manager *mgr, int device_num, 
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
 * Initialize device manager instance
 *
 * @param mgr Device manager instance to initialize.
 * @param num_devices Number of devices Cerberus can communicate with. 
 *
 * @return Initialization status, 0 if success or an error code.
 */
int device_manager_init (struct device_manager *mgr, int num_devices)
{
	if ((mgr == NULL) || (num_devices == 0)) {
		return DEVICE_MGR_INVALID_ARGUMENT;
	}

	mgr->entries = platform_calloc (num_devices, sizeof (struct device_manager_entry));
	if (mgr->entries == NULL) {
		return DEVICE_MGR_NO_MEMORY;
	}

	mgr->num_devices = num_devices;

	return 0;
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
