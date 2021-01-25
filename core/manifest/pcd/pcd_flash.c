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
	struct flash *flash_device;
	struct pcd_header pcd_header;
	struct pcd_rot_header pcd_rot_header;
	struct pcd_port_header pcd_port_header;
	struct pcd_components_header pcd_components_header;
	struct pcd_component_header pcd_component_header;
	struct pcd_mux_header pcd_mux_header;
	struct pcd_platform_header pcd_platform_header;
	uint32_t pcd_addr;
	uint16_t pcd_len;
	uint16_t pcd_rot_len;
	uint16_t pcd_components_len;
	uint16_t pcd_component_len;
	uint8_t index;
	uint8_t index2;
	int status;

	if ((pcd_flash == NULL) || (hash == NULL) || (verification == NULL)) {
		return PCD_INVALID_ARGUMENT;
	}

	status = manifest_flash_verify (&pcd_flash->base_flash, hash, verification, hash_out,
		hash_length);
	if (status != 0) {
		return status;
	}

	pcd_len = pcd_flash->base_flash.header.length -
		(pcd_flash->base_flash.header.sig_length + sizeof (struct manifest_header));
	pcd_addr = pcd_flash->base_flash.addr + sizeof (struct manifest_header);

	flash_device = pcd_flash->base_flash.flash;
	status = flash_device->read (flash_device, pcd_addr, (uint8_t*) &pcd_header,
		sizeof (struct pcd_header));
	if (status != 0) {
		goto error;
	}

	if (pcd_len != pcd_header.length) {
		status = PCD_INVALID_SEG_LEN;
		goto error;
	}

	pcd_len -= pcd_header.header_len;
	pcd_addr += pcd_header.header_len;

	status = flash_device->read (flash_device, pcd_addr, (uint8_t*) &pcd_rot_header,
		sizeof (struct pcd_rot_header));
	if (status != 0) {
		goto error;
	}

	if (pcd_len < pcd_rot_header.length) {
		status = PCD_INVALID_SEG_LEN;
		goto error;
	}

	pcd_rot_len = pcd_rot_header.length - pcd_rot_header.header_len;
	pcd_addr += pcd_rot_header.header_len;

	for (index = 0; index < pcd_rot_header.num_ports; ++index) {
		status = flash_device->read (flash_device, pcd_addr, (uint8_t*) &pcd_port_header,
			sizeof (struct pcd_port_header));
		if (status != 0) {
			goto error;
		}

		pcd_addr += pcd_port_header.length;
		pcd_rot_len -= pcd_port_header.length;
	}

	if (pcd_rot_len != 0) {
		status = PCD_INVALID_SEG_LEN;
		goto error;
	}

	pcd_len -= pcd_rot_header.length;

	status = flash_device->read (flash_device, pcd_addr, (uint8_t*) &pcd_components_header,
		sizeof (struct pcd_components_header));
	if (status != 0) {
		goto error;
	}

	if (pcd_len < pcd_components_header.length) {
		status = PCD_INVALID_SEG_LEN;
		goto error;
	}

	pcd_addr += pcd_components_header.header_len;
	pcd_components_len = pcd_components_header.length - pcd_components_header.header_len;

	for (index = 0; index < pcd_components_header.num_components; ++index) {
		status = flash_device->read (flash_device, pcd_addr, (uint8_t*) &pcd_component_header,
			sizeof (struct pcd_component_header));
		if (status != 0) {
			goto error;
		}

		pcd_component_len = pcd_component_header.length - pcd_component_header.header_len;
		if (pcd_components_len < pcd_component_len) {
			status = PCD_INVALID_SEG_LEN;
			goto error;
		}

		pcd_addr += pcd_component_header.header_len;

		for (index2 = 0; index2 < pcd_component_header.num_muxes; ++index2) {
			status = flash_device->read (flash_device, pcd_addr, (uint8_t*) &pcd_mux_header,
				sizeof (struct pcd_mux_header));
			if (status != 0) {
				goto error;
			}

			pcd_addr += pcd_mux_header.length;
			pcd_component_len -= pcd_mux_header.length;
		}

		if (pcd_component_len != 0) {
			status = PCD_INVALID_SEG_LEN;
			goto error;
		}

		pcd_components_len -= pcd_component_header.length;
	}

	if (pcd_components_len != 0) {
		status = PCD_INVALID_SEG_LEN;
		goto error;
	}

	pcd_len -= pcd_components_header.length;

	status = flash_device->read (flash_device, pcd_addr, (uint8_t*) &pcd_platform_header,
		sizeof (struct pcd_platform_header));
	if (status != 0) {
		goto error;
	}

	if (pcd_len != pcd_platform_header.length) {
		status = PCD_INVALID_SEG_LEN;
		goto error;
	}

	if (pcd_platform_header.length !=
	   (pcd_platform_header.header_len + pcd_platform_header.id_len)) {
		status = PCD_INVALID_SEG_HDR_LEN;
		goto error;
	}

	if (pcd_platform_header.length >= pcd_flash->base_flash.max_platform_id) {
		status = MANIFEST_PLAT_ID_BUFFER_TOO_SMALL;
		goto error;
	}

	pcd_addr += sizeof (struct pcd_platform_header);
	status = flash_device->read (flash_device, pcd_addr,
		(uint8_t*) pcd_flash->base_flash.platform_id, pcd_platform_header.id_len);
	if (status != 0) {
		goto error;
	}

	pcd_flash->base_flash.platform_id[pcd_platform_header.id_len] = '\0';
	return 0;

error:
	/* Clearing this flag in validation error cases is not tested but is only temporary as v1 PCDs
	 * will be unsupported with the move to v2. */
	pcd_flash->base_flash.manifest_valid = false;
	return status;
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

static int pcd_flash_get_port_info (struct pcd *pcd, uint8_t port_id, struct pcd_port_info *info)
{
	struct pcd_flash *pcd_flash = (struct pcd_flash*) pcd;
	struct pcd_header pcd_header;
	struct pcd_rot_header rot_header;
	struct pcd_port_header port_header;
	struct flash *flash_device;
	uint32_t next_addr;
	size_t i_port;
	int status;

	if ((pcd_flash == NULL) || (info == NULL)) {
		return PCD_INVALID_ARGUMENT;
	}

	if (!pcd_flash->base_flash.manifest_valid) {
		return MANIFEST_NO_MANIFEST;
	}

	flash_device = pcd_flash->base_flash.flash;

	status = flash_device->read (flash_device, pcd_flash->base_flash.addr +
		sizeof (struct manifest_header), (uint8_t*) &pcd_header, sizeof (struct pcd_header));
	if (status != 0) {
		return status;
	}

	next_addr = pcd_flash->base_flash.addr + sizeof (struct manifest_header) +
		pcd_header.header_len;
	status = flash_device->read (flash_device, next_addr, (uint8_t*) &rot_header,
		sizeof (struct pcd_rot_header));
	if (status != 0) {
		return status;
	}

	next_addr += sizeof (struct pcd_rot_header);

	for (i_port = 0; i_port < rot_header.num_ports; ++i_port) {
		status = flash_device->read (flash_device, next_addr, (uint8_t*) &port_header,
			sizeof (struct pcd_port_header));
		if (status != 0) {
			return status;
		}

		if (port_header.id == port_id) {
			info->spi_freq = port_header.frequency;
			return 0;
		}

		next_addr += sizeof (struct pcd_port_header);
	}

	return PCD_INVALID_PORT;
}

static int pcd_flash_get_rot_info (struct pcd *pcd, struct pcd_rot_info *info)
{
	struct pcd_flash *pcd_flash = (struct pcd_flash*) pcd;
	struct pcd_header pcd_header;
	struct pcd_rot_header rot_header;
	struct flash *flash_device;
	uint32_t next_addr;
	int status;

	if ((pcd_flash == NULL) || (info == NULL)) {
		return PCD_INVALID_ARGUMENT;
	}

	if (!pcd_flash->base_flash.manifest_valid) {
		return MANIFEST_NO_MANIFEST;
	}

	flash_device = pcd_flash->base_flash.flash;

	status = flash_device->read (flash_device, pcd_flash->base_flash.addr +
		sizeof (struct manifest_header), (uint8_t*) &pcd_header, sizeof (struct pcd_header));
	if (status != 0) {
		return status;
	}

	next_addr = pcd_flash->base_flash.addr + sizeof (struct manifest_header) +
		pcd_header.header_len;
	status = flash_device->read (flash_device, next_addr, (uint8_t*) &rot_header,
		sizeof (struct pcd_rot_header));
	if (status != 0) {
		return status;
	}

	info->is_pa_rot = (rot_header.flags & PCD_ROT_HDR_IS_PA_ROT_SET_MASK);
	info->i2c_slave_addr = rot_header.addr;
	info->bmc_i2c_addr = rot_header.bmc_i2c_addr;

	return 0;
}

static int pcd_flash_get_devices_info (struct pcd *pcd, struct device_manager_info **devices,
	size_t *num_devices)
{
	struct pcd_flash *pcd_flash = (struct pcd_flash*) pcd;
	struct pcd_header pcd_header;
	struct pcd_rot_header rot_header;
	struct pcd_components_header components_header;
	struct pcd_component_header component_header;
	struct flash *flash_device;
	uint32_t next_addr;
	size_t i_component;
	int status;

	if ((devices == NULL) || (num_devices == NULL)) {
		return PCD_INVALID_ARGUMENT;
	}

	*devices = NULL;
	*num_devices = 0;

	if (pcd_flash == NULL) {
		return PCD_INVALID_ARGUMENT;
	}

	if (!pcd_flash->base_flash.manifest_valid) {
		return MANIFEST_NO_MANIFEST;
	}

	flash_device = pcd_flash->base_flash.flash;

	status = flash_device->read (flash_device, pcd_flash->base_flash.addr +
		sizeof (struct manifest_header), (uint8_t*) &pcd_header, sizeof (struct pcd_header));
	if (status != 0) {
		return status;
	}

	next_addr = pcd_flash->base_flash.addr + sizeof (struct manifest_header) +
		pcd_header.header_len;
	status = flash_device->read (flash_device, next_addr, (uint8_t*) &rot_header,
		sizeof (struct pcd_rot_header));
	if (status != 0) {
		return status;
	}

	next_addr += rot_header.length;
	status = flash_device->read (flash_device, next_addr, (uint8_t*) &components_header,
		sizeof (struct pcd_components_header));
	if (status != 0) {
		return status;
	}

	*devices = platform_calloc (components_header.num_components,
		sizeof (struct device_manager_info));

	if (*devices == NULL) {
		return PCD_NO_MEMORY;
	}

	*num_devices = components_header.num_components;
	next_addr += sizeof (struct pcd_components_header);

	for (i_component = 0; i_component < components_header.num_components; ++i_component) {
		status = flash_device->read (flash_device, next_addr, (uint8_t*) &component_header,
			sizeof (struct pcd_component_header));
		if (status != 0) {
			platform_free ((void*) *devices);
			*num_devices = 0;
			*devices = NULL;

			return status;
		}

		next_addr += sizeof (struct pcd_component_header);

		(*devices)[i_component].smbus_addr = component_header.addr;
		(*devices)[i_component].eid = component_header.eid;
	}

	return 0;
}

/**
 * Initialize the interface to a PCD residing in flash memory.
 *
 * @param pcd The PCD instance to initialize.
 * @param flash The flash device that contains the PCD.
 * @param base_addr The starting address of the PCD storage location.
 * @param signature_cache Buffer to hold the manifest signature.
 * @param max_signature The maximum supported length for a manifest signature.
 * @param platform_id_cache Buffer to hold the manifest platform ID.
 * @param max_platform_id The maximum platform ID length supported, including the NULL terminator.
 *
 * @return 0 if the PCD instance was initialized successfully or an error code.
 */
int pcd_flash_init (struct pcd_flash *pcd, struct flash *flash, uint32_t base_addr,
	uint8_t *signature_cache, size_t max_signature, uint8_t *platform_id_cache,
	size_t max_platform_id)
{
	int status;

	if ((pcd == NULL) || (signature_cache == NULL) || (platform_id_cache == NULL)) {
		return PCD_INVALID_ARGUMENT;
	}

	memset (pcd, 0, sizeof (struct pcd_flash));

	status = manifest_flash_v2_init (&pcd->base_flash, flash, NULL, base_addr, PCD_MAGIC_NUM,
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

	pcd->base.get_port_info = pcd_flash_get_port_info;
	pcd->base.get_rot_info = pcd_flash_get_rot_info;
	pcd->base.get_devices_info = pcd_flash_get_devices_info;

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
