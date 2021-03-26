// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform.h"
#include "pcd_flash.h"
#include "pcd_format.h"
#include "flash/flash_util.h"
#include "cmd_interface/device_manager.h"
#include "manifest/manifest_flash.h"


static int pcd_flash_verify (struct manifest *pcd, struct hash_engine *hash,
	struct signature_verification *verification, uint8_t *hash_out, size_t hash_length)
{
	struct pcd_flash *pcd_flash = (struct pcd_flash*) pcd;

	if (pcd_flash == NULL) {
		return PCD_INVALID_ARGUMENT;
	}

	return manifest_flash_verify (&pcd_flash->base_flash, hash, verification, hash_out,
		hash_length);
}

static int pcd_flash_get_id (struct manifest *pcd, uint32_t *id)
{
	struct pcd_flash *pcd_flash = (struct pcd_flash*) pcd;

	if (pcd_flash == NULL) {
		return PCD_INVALID_ARGUMENT;
	}

	return manifest_flash_get_id (&pcd_flash->base_flash, id);
}

static int pcd_flash_get_platform_id (struct manifest *pcd, char **id, size_t length)
{
	struct pcd_flash *pcd_flash = (struct pcd_flash*) pcd;

	if (pcd_flash == NULL) {
		return PCD_INVALID_ARGUMENT;
	}

	return manifest_flash_get_platform_id (&pcd_flash->base_flash, id, length);
}

static void pcd_flash_free_platform_id (struct manifest *manifest, char *id)
{
	/* Don't need to do anything.  Manifest allocated buffers use the internal static buffer. */
}

static int pcd_flash_get_hash (struct manifest *pcd, struct hash_engine *hash, uint8_t *hash_out,
	size_t hash_length)
{
	struct pcd_flash *pcd_flash = (struct pcd_flash*) pcd;

	if (pcd_flash == NULL) {
		return PCD_INVALID_ARGUMENT;
	}

	return manifest_flash_get_hash (&pcd_flash->base_flash, hash, hash_out, hash_length);
}

static int pcd_flash_get_signature (struct manifest *pcd, uint8_t *signature, size_t length)
{
	struct pcd_flash *pcd_flash = (struct pcd_flash*) pcd;

	if (pcd_flash == NULL) {
		return PCD_INVALID_ARGUMENT;
	}

	return manifest_flash_get_signature (&pcd_flash->base_flash, signature, length);
}

static int pcd_flash_is_empty (struct manifest *pcd)
{
	struct pcd_flash *pcd_flash = (struct pcd_flash*) pcd;

	if (pcd_flash == NULL) {
		return PCD_INVALID_ARGUMENT;
	}

	if (!pcd_flash->base_flash.manifest_valid) {
		return MANIFEST_NO_MANIFEST;
	}

	/* Every PCD must have a platform ID.  If that is all we have, then it is an empty manifest. */
	return (pcd_flash->base_flash.toc_header.entry_count == 1);
}

/**
 * Helper function that grabs RoT element information from PCD.
 *
 * @param pcd The PCD instance to utilize.
 * @param rot_element_ptr Pointer to an pcd_rot_element instance.
 * @param found Optional buffer to contain index of RoT element if found, set to NULL if unused.
 *
 * @return 0 if completed successfully or an error code.
 */
static int pcd_flash_get_rot_element_ptr (struct pcd *pcd, uint8_t *rot_element_ptr, uint8_t *found)
{
	struct pcd_flash *pcd_flash = (struct pcd_flash*) pcd;
	int status;

	status = manifest_flash_read_element_data (&pcd_flash->base_flash, pcd_flash->base_flash.hash,
		PCD_ROT, 0, MANIFEST_NO_PARENT, 0, found, NULL, NULL, &rot_element_ptr,
		sizeof (struct pcd_rot_element));
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	if (status < (int) (sizeof (struct pcd_rot_element))) {
		return PCD_MALFORMED_ROT_ELEMENT;
	}

	return 0;
}

static int pcd_flash_get_rot_info (struct pcd *pcd, struct pcd_rot_info *info)
{
	struct pcd_flash *pcd_flash = (struct pcd_flash*) pcd;
	struct pcd_rot_element rot_element;
	int status;

	if ((pcd_flash == NULL) || (info == NULL)) {
		return PCD_INVALID_ARGUMENT;
	}

	if (!pcd_flash->base_flash.manifest_valid) {
		return MANIFEST_NO_MANIFEST;
	}

	status = pcd_flash_get_rot_element_ptr (pcd, (uint8_t*) &rot_element, NULL);
	if (status != 0) {
		return status;
	}

	info->is_pa_rot = (pcd_get_rot_type (&rot_element) == PCD_ROT_TYPE_PA_ROT);
	info->port_count = rot_element.port_count;
	info->components_count = rot_element.components_count;
	info->i2c_slave_addr = rot_element.rot_address;
	info->eid = rot_element.rot_eid;
	info->bridge_i2c_addr = rot_element.bridge_address;
	info->bridge_eid = rot_element.bridge_eid;

	return 0;
}

static int pcd_flash_get_port_info (struct pcd *pcd, uint8_t port_id, struct pcd_port_info *info)
{
	struct pcd_flash *pcd_flash = (struct pcd_flash*) pcd;
	struct pcd_port_element port_element;
	uint8_t *port_element_ptr = (uint8_t*) &port_element;
	struct pcd_rot_element rot_element;
	uint8_t found;
	int start = 0;
	int i_port;
	int status;

	if ((pcd_flash == NULL) || (info == NULL)) {
		return PCD_INVALID_ARGUMENT;
	}

	if (!pcd_flash->base_flash.manifest_valid) {
		return MANIFEST_NO_MANIFEST;
	}

	status = pcd_flash_get_rot_element_ptr (pcd, (uint8_t*) &rot_element, &found);
	if (status != 0) {
		return status;
	}

	if (rot_element.port_count == 0) {
		return PCD_INVALID_PORT;
	}

	start = found + 1;

	for (i_port = 0; i_port < rot_element.port_count; ++i_port) {
		status = manifest_flash_read_element_data (&pcd_flash->base_flash,
			pcd_flash->base_flash.hash, PCD_SPI_FLASH_PORT, start, PCD_ROT, 0, &found,
			NULL, NULL, &port_element_ptr, sizeof (struct pcd_port_element));
		if (status == MANIFEST_CHILD_NOT_FOUND) {
			return PCD_INVALID_PORT;
		}
		if (ROT_IS_ERROR (status)) {
			return status;
		}
		if (((size_t) status) < (sizeof (struct pcd_port_element))) {
			return PCD_MALFORMED_PORT_ELEMENT;
		}
		if (port_element.port_id != port_id) {
			start = found + 1;
			continue;
		}

		info->spi_freq = port_element.spi_frequency_hz;
		info->flash_mode = pcd_get_port_flash_mode (&port_element);
		info->reset_ctrl = pcd_get_port_reset_control (&port_element);
		info->runtime_verification = pcd_get_port_runtime_verification (&port_element);
		info->watchdog_monitoring = pcd_get_port_watchdog_monitoring (&port_element);
		info->policy = port_element.policy;
		info->pulse_interval = port_element.pulse_interval;

		return 0;
	}

	return PCD_INVALID_PORT;
}

static int pcd_flash_get_power_controller_info (struct pcd *pcd,
	struct pcd_power_controller_info *info)
{
	struct pcd_flash *pcd_flash = (struct pcd_flash*) pcd;
	struct pcd_power_controller_element power_controller_element;
	uint8_t *power_controller_element_ptr = (uint8_t*) &power_controller_element;
	int status;

	if ((pcd_flash == NULL) || (info == NULL)) {
		return PCD_INVALID_ARGUMENT;
	}

	if (!pcd_flash->base_flash.manifest_valid) {
		return MANIFEST_NO_MANIFEST;
	}

	status = manifest_flash_read_element_data (&pcd_flash->base_flash, pcd_flash->base_flash.hash,
		PCD_POWER_CONTROLLER, 0, MANIFEST_NO_PARENT, 0, NULL, NULL, NULL,
		&power_controller_element_ptr, sizeof (struct pcd_power_controller_element));
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	info->mux_count = power_controller_element.i2c.mux_count;
	info->i2c_mode = pcd_get_i2c_interface_i2c_mode (&power_controller_element.i2c);
	info->bus = power_controller_element.i2c.bus;
	info->address = power_controller_element.i2c.address;
	info->eid = power_controller_element.i2c.eid;

	return 0;
}

static int pcd_flash_get_devices_info (struct pcd *pcd, struct device_manager_info **devices,
	size_t *num_devices)
{
	struct pcd_flash *pcd_flash = (struct pcd_flash*) pcd;
	struct device_manager_info *device_ptr;
	struct pcd_i2c_interface *interface;
	struct pcd_mctp_bridge_component_connection *connection;
	union {
		struct pcd_rot_info rot_info;
		struct pcd_direct_i2c_component_element direct_component;
		struct pcd_mctp_bridge_component_element bridge_component;
	} buffer;
	uint8_t *element_ptr;
	uint8_t i_component;
	uint8_t found;
	size_t type_len;
	int start = 0;
	int status;

	if ((pcd_flash == NULL) || (devices == NULL) || (num_devices == NULL)) {
		return PCD_INVALID_ARGUMENT;
	}

	if (!pcd_flash->base_flash.manifest_valid) {
		return MANIFEST_NO_MANIFEST;
	}

	status = pcd_flash_get_rot_info (pcd, &buffer.rot_info);
	if (status != 0) {
		return status;
	}

	if (buffer.rot_info.components_count == 0) {
		*num_devices = 0;
		return 0;
	}

	*num_devices = buffer.rot_info.components_count;

	*devices = platform_calloc (*num_devices, sizeof (struct device_manager_info));
	if (*devices == NULL) {
		return PCD_NO_MEMORY;
	}

	device_ptr = *devices;
	element_ptr = (uint8_t*) &buffer.direct_component;

	for (i_component = 0; i_component < *num_devices; ++i_component) {
		status = manifest_flash_read_element_data (&pcd_flash->base_flash,
			pcd_flash->base_flash.hash, PCD_COMPONENT_DIRECT, start, MANIFEST_NO_PARENT, 0, &found,
			NULL, NULL, &element_ptr, sizeof (struct pcd_direct_i2c_component_element));
		if (status == MANIFEST_ELEMENT_NOT_FOUND) {
			break;
		}
		if (ROT_IS_ERROR (status)) {
			goto fail;
		}
		if (((size_t) status) <
			(sizeof (struct pcd_direct_i2c_component_element) - MANIFEST_MAX_STRING)) {
			status = PCD_MALFORMED_DIRECT_I2C_COMPONENT_ELEMENT;
			goto fail;
		}

		type_len = ((buffer.direct_component.component.type_len + 3) & ~((size_t) 3));
		interface = (struct pcd_i2c_interface*) (element_ptr +
			(sizeof (struct pcd_component_common) - MANIFEST_MAX_STRING + type_len));

		device_ptr->eid = interface->eid;
		device_ptr->smbus_addr = interface->address;

		start = found + 1;
		++device_ptr;
	}

	start = 0;
	element_ptr = (uint8_t*) &buffer.bridge_component;

	for (; i_component < *num_devices; ++i_component) {
		status = manifest_flash_read_element_data (&pcd_flash->base_flash,
			pcd_flash->base_flash.hash, PCD_COMPONENT_MCTP_BRIDGE, start, MANIFEST_NO_PARENT, 0,
			&found, NULL, NULL, &element_ptr, sizeof (struct pcd_mctp_bridge_component_element));
		if (ROT_IS_ERROR (status)) {
			goto fail;
		}
		if ((size_t) status <
			(sizeof (struct pcd_mctp_bridge_component_element) - MANIFEST_MAX_STRING)) {
			status = PCD_MALFORMED_BRIDGE_COMPONENT_ELEMENT;
			goto fail;
		}

		connection = pcd_get_mctp_bridge_component_connection (element_ptr, status);

		device_ptr->eid = connection->eid;

		start = found + 1;
		++device_ptr;
	}

	return 0;

fail:
	platform_free (*devices);

	return status;
}

/**
 * Initialize the interface to a PCD residing in flash memory.
 *
 * @param pcd The PCD instance to initialize.
 * @param flash The flash device that contains the PCD.
 * @param hash A hash engine to use for validating run-time access to PCD information. If it is
 * possible for any PCD information to be requested concurrently by different threads, this hash
 * engine MUST be thread-safe. There is no internal synchronization around the hashing operations.
 * @param base_addr The starting address of the PCD storage location.
 * @param signature_cache Buffer to hold the manifest signature.
 * @param max_signature The maximum supported length for a manifest signature.
 * @param platform_id_cache Buffer to hold the manifest platform ID.
 * @param max_platform_id The maximum platform ID length supported, including the NULL terminator.
 *
 * @return 0 if the PCD instance was initialized successfully or an error code.
 */
int pcd_flash_init (struct pcd_flash *pcd, struct flash *flash, struct hash_engine *hash,
	uint32_t base_addr, uint8_t *signature_cache, size_t max_signature, uint8_t *platform_id_cache,
	size_t max_platform_id)
{
	int status;

	if ((pcd == NULL) || (signature_cache == NULL) || (platform_id_cache == NULL)) {
		return PCD_INVALID_ARGUMENT;
	}

	memset (pcd, 0, sizeof (struct pcd_flash));

	status = manifest_flash_v2_init (&pcd->base_flash, flash, hash, base_addr, PCD_MAGIC_NUM,
		PCD_V2_MAGIC_NUM, signature_cache, max_signature, platform_id_cache, max_platform_id);
	if (status != 0) {
		return status;
	}

	pcd->base.base.verify = pcd_flash_verify;
	pcd->base.base.get_id = pcd_flash_get_id;
	pcd->base.base.get_platform_id = pcd_flash_get_platform_id;
	pcd->base.base.free_platform_id = pcd_flash_free_platform_id;
	pcd->base.base.get_hash = pcd_flash_get_hash;
	pcd->base.base.get_signature = pcd_flash_get_signature;
	pcd->base.base.is_empty = pcd_flash_is_empty;

	pcd->base.get_port_info = pcd_flash_get_port_info;
	pcd->base.get_rot_info = pcd_flash_get_rot_info;
	pcd->base.get_devices_info = pcd_flash_get_devices_info;
	pcd->base.get_power_controller_info = pcd_flash_get_power_controller_info;

	return 0;
}

/**
 * Release the resources used by the PCD interface.
 *
 * @param pcd The PCD instance to release.
 */
void pcd_flash_release (struct pcd_flash *pcd)
{
	if (pcd != NULL) {
		manifest_flash_release (&pcd->base_flash);
	}
}
