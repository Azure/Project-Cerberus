// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "pcd_flash.h"
#include "pcd_format.h"
#include "platform_api.h"
#include "cmd_interface/device_manager.h"
#include "common/array_size.h"
#include "common/buffer_util.h"
#include "common/type_cast.h"
#include "common/unused.h"
#include "flash/flash_util.h"
#include "manifest/manifest_flash.h"


int pcd_flash_verify (const struct manifest *pcd, const struct hash_engine *hash,
	const struct signature_verification *verification, uint8_t *hash_out, size_t hash_length)
{
	const struct pcd_flash *pcd_flash = (const struct pcd_flash*) pcd;

	if (pcd_flash == NULL) {
		return PCD_INVALID_ARGUMENT;
	}

	return manifest_flash_verify (&pcd_flash->base_flash, hash, verification, hash_out,
		hash_length);
}

int pcd_flash_get_id (const struct manifest *pcd, uint32_t *id)
{
	const struct pcd_flash *pcd_flash = (const struct pcd_flash*) pcd;

	if (pcd_flash == NULL) {
		return PCD_INVALID_ARGUMENT;
	}

	return manifest_flash_get_id (&pcd_flash->base_flash, id);
}

int pcd_flash_get_platform_id (const struct manifest *pcd, char **id, size_t length)
{
	const struct pcd_flash *pcd_flash = (const struct pcd_flash*) pcd;

	if (pcd_flash == NULL) {
		return PCD_INVALID_ARGUMENT;
	}

	return manifest_flash_get_platform_id (&pcd_flash->base_flash, id, length);
}

void pcd_flash_free_platform_id (const struct manifest *manifest, char *id)
{
	UNUSED (manifest);
	UNUSED (id);

	/* Don't need to do anything.  Manifest allocated buffers use the internal static buffer. */
}

int pcd_flash_get_hash (const struct manifest *pcd, const struct hash_engine *hash,
	uint8_t *hash_out, size_t hash_length)
{
	const struct pcd_flash *pcd_flash = (const struct pcd_flash*) pcd;

	if (pcd_flash == NULL) {
		return PCD_INVALID_ARGUMENT;
	}

	return manifest_flash_get_hash (&pcd_flash->base_flash, hash, hash_out, hash_length);
}

int pcd_flash_get_signature (const struct manifest *pcd, uint8_t *signature, size_t length)
{
	const struct pcd_flash *pcd_flash = (const struct pcd_flash*) pcd;

	if (pcd_flash == NULL) {
		return PCD_INVALID_ARGUMENT;
	}

	return manifest_flash_get_signature (&pcd_flash->base_flash, signature, length);
}

int pcd_flash_is_empty (const struct manifest *pcd)
{
	const struct pcd_flash *pcd_flash = (const struct pcd_flash*) pcd;

	if (pcd_flash == NULL) {
		return PCD_INVALID_ARGUMENT;
	}

	if (!pcd_flash->base_flash.state->manifest_valid) {
		return MANIFEST_NO_MANIFEST;
	}

	/* Every PCD must have a platform ID.  If that is all we have, then it is an empty manifest. */
	return (pcd_flash->base_flash.state->entry_count == 1);
}

/**
 * Helper function that grabs RoT element information from PCD.
 *
 * @param pcd The PCD instance to utilize.
 * @param rot_element_ptr Pointer to a pcd_rot_element instance.
 * @param found Optional buffer to contain index of RoT element if found, set to NULL if unused.
 * @param format Output describing the format version of the RoT element.
 *
 * @return 0 if completed successfully or an error code.
 */
static int pcd_flash_get_rot_element_ptr (const struct pcd *pcd, uint8_t *rot_element_ptr,
	int *found, uint8_t *format)
{
	const struct pcd_flash *pcd_flash = (const struct pcd_flash*) pcd;
	int status;

	status = manifest_flash_read_element_data (&pcd_flash->base_flash, pcd_flash->base_flash.hash,
		PCD_ROT, 0, MANIFEST_NO_PARENT, 0, found, format, NULL, &rot_element_ptr,
		sizeof (struct pcd_rot_element_v2));
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	if (((*format == 1) && (status < (int) (sizeof (struct pcd_rot_element_v1)))) ||
		((*format >= 2) && (status < (int) (sizeof (struct pcd_rot_element_v2))))) {
		return PCD_MALFORMED_ROT_ELEMENT;
	}

	return 0;
}

int pcd_flash_get_rot_info (const struct pcd *pcd, struct pcd_rot_info *info)
{
	const struct pcd_flash *pcd_flash = (const struct pcd_flash*) pcd;
	struct pcd_rot_element_v2 rot_element;
	uint8_t format;
	int status;

	if ((pcd_flash == NULL) || (info == NULL)) {
		return PCD_INVALID_ARGUMENT;
	}

	if (!pcd_flash->base_flash.state->manifest_valid) {
		return MANIFEST_NO_MANIFEST;
	}

	status = pcd_flash_get_rot_element_ptr (pcd, (uint8_t*) &rot_element, NULL, &format);
	if (status != 0) {
		return status;
	}

	// Set default fields for unused fields in v1 format
	if (format == 1) {
		rot_element.attestation_success_retry = PCD_FLASH_ATTESTATION_SUCCESS_RETRY_DEFAULT;
		rot_element.attestation_fail_retry = PCD_FLASH_ATTESTATION_FAIL_RETRY_DEFAULT;
		rot_element.discovery_fail_retry = PCD_FLASH_DISCOVERY_FAIL_RETRY_DEFAULT;
		rot_element.mctp_ctrl_timeout = PCD_FLASH_MCTP_CTRL_TIMEOUT_DEFAULT;
		rot_element.mctp_bridge_get_table_wait = PCD_FLASH_MCTP_BRIDGE_GET_TABLE_WAIT_DEFAULT;
		rot_element.mctp_bridge_additional_timeout =
			PCD_FLASH_MCTP_BRIDGE_ADDITIONAL_TIMEOUT_DEFAULT;
		rot_element.attestation_rsp_not_ready_max_duration =
			PCD_FLASH_ATTESTATION_RSP_NOT_READY_MAX_DURATION_DEFAULT;
		rot_element.attestation_rsp_not_ready_max_retry =
			PCD_FLASH_ATTESTATION_RSP_NOT_READY_MAX_RETRY_DEFAULT;
	}

	info->is_pa_rot = (pcd_get_rot_type (&rot_element.v1) == PCD_ROT_TYPE_PA_ROT);
	info->port_count = rot_element.v1.port_count;
	info->components_count = rot_element.v1.components_count;
	info->i2c_slave_addr = rot_element.v1.rot_address;
	info->eid = rot_element.v1.rot_eid;
	info->bridge_i2c_addr = rot_element.v1.bridge_address;
	info->bridge_eid = rot_element.v1.bridge_eid;
	info->attestation_success_retry = rot_element.attestation_success_retry;
	info->attestation_fail_retry = rot_element.attestation_fail_retry;
	info->discovery_fail_retry = rot_element.discovery_fail_retry;
	info->mctp_ctrl_timeout = rot_element.mctp_ctrl_timeout;
	info->mctp_bridge_get_table_wait = rot_element.mctp_bridge_get_table_wait;
	info->mctp_bridge_additional_timeout = rot_element.mctp_bridge_additional_timeout;
	info->attestation_rsp_not_ready_max_duration =
		rot_element.attestation_rsp_not_ready_max_duration;
	info->attestation_rsp_not_ready_max_retry = rot_element.attestation_rsp_not_ready_max_retry;

	return 0;
}

int pcd_flash_get_port_info (const struct pcd *pcd, uint8_t port_id, struct pcd_port_info *info)
{
	const struct pcd_flash *pcd_flash = (const struct pcd_flash*) pcd;
	struct pcd_port_element port_element;
	uint8_t *port_element_ptr = (uint8_t*) &port_element;
	struct pcd_rot_element_v2 rot_element;
	int found;
	uint8_t rot_element_format;
	int start = 0;
	int i_port;
	int status;

	if ((pcd_flash == NULL) || (info == NULL)) {
		return PCD_INVALID_ARGUMENT;
	}

	if (!pcd_flash->base_flash.state->manifest_valid) {
		return MANIFEST_NO_MANIFEST;
	}

	status = pcd_flash_get_rot_element_ptr (pcd, (uint8_t*) &rot_element, &found,
		&rot_element_format);
	if (status != 0) {
		return status;
	}

	if (rot_element.v1.port_count == 0) {
		return PCD_INVALID_PORT;
	}

	start = found + 1;

	for (i_port = 0; i_port < rot_element.v1.port_count; ++i_port) {
		status = manifest_flash_read_element_data (&pcd_flash->base_flash,
			pcd_flash->base_flash.hash, PCD_SPI_FLASH_PORT, start, PCD_ROT, 0, &found, NULL, NULL,
			&port_element_ptr, sizeof (struct pcd_port_element));
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
		info->host_reset_action = pcd_get_port_host_reset_action (&port_element);
		info->policy = port_element.policy;
		info->pulse_interval = port_element.pulse_interval;

		return 0;
	}

	return PCD_INVALID_PORT;
}

int pcd_flash_get_power_controller_info (const struct pcd *pcd,
	struct pcd_power_controller_info *info)
{
	const struct pcd_flash *pcd_flash = (const struct pcd_flash*) pcd;
	struct pcd_power_controller_element power_controller_element;
	uint8_t *power_controller_element_ptr = (uint8_t*) &power_controller_element;
	int status;

	if ((pcd_flash == NULL) || (info == NULL)) {
		return PCD_INVALID_ARGUMENT;
	}

	if (!pcd_flash->base_flash.state->manifest_valid) {
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

/**
 * Component element types available in PCD manifest.
 */
static const uint8_t pcd_flash_component_element_types[] = {
	PCD_COMPONENT_DIRECT,
	PCD_COMPONENT_MCTP_BRIDGE,
	PCD_COMPONENT_TCG_LOG,
};


int pcd_flash_buffer_supported_components (const struct pcd *pcd, size_t offset, size_t length,
	uint8_t *pcd_component_ids)
{
	const struct pcd_flash *pcd_flash = (const struct pcd_flash*) pcd;
	struct pcd_rot_info rot_info;
	struct pcd_supported_component supported_component;

	/* To avoid unnecessary allocations do not read the whole entry for each element, only
	 * portion that is enough to get component ids and instance counts. */
	union {
		struct pcd_component_common_v3 common_v3;				/** Common part for v3 components. */
		struct pcd_component_common_v2 common_v2;				/** Common part for v2 components. */
		struct pcd_mctp_bridge_component_element_v2 mctp_v2;	/** MCTP Bridge component (special case) */
	} component_data;
	uint8_t *element_data_ptr = (uint8_t*) &component_data;

	size_t i_components = 0;
	size_t component_len = 0;
	int status;
	int current_start_entry = 0;
	uint8_t element_type = 0xff;
	uint8_t element_format = 0;

	if ((pcd_flash == NULL) || (pcd_component_ids == NULL) || (length == 0)) {
		return PCD_INVALID_ARGUMENT;
	}

	if (!pcd_flash->base_flash.state->manifest_valid) {
		return MANIFEST_NO_MANIFEST;
	}

	status = pcd_flash_get_rot_info (pcd, &rot_info);
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	while ((i_components < rot_info.components_count) && (length > 0)) {
		status = manifest_flash_read_element_data_multi_type (&pcd_flash->base_flash,
			pcd_flash->base_flash.hash, pcd_flash_component_element_types,
			ARRAY_SIZE (pcd_flash_component_element_types),	current_start_entry, MANIFEST_NO_PARENT,
			0, &current_start_entry, &element_type, &element_format, NULL, &element_data_ptr,
			sizeof (component_data));
		if (ROT_IS_ERROR (status)) {
			return status;
		}

		current_start_entry += 1;

		switch (element_type) {
			case PCD_COMPONENT_DIRECT:
				if ((size_t) status < sizeof (struct pcd_direct_i2c_component_element_v2)) {
					return PCD_MALFORMED_DIRECT_I2C_COMPONENT_ELEMENT;
				}

				[[fallthrough]];

			case PCD_COMPONENT_TCG_LOG:
				if ((size_t) status < sizeof (struct pcd_tcg_log_component_element_v2)) {
					return PCD_MALFORMED_TCG_LOG_COMPONENT_ELEMENT;
				}

				/* These components always have one instance */
				supported_component.component_count = 1;
				supported_component.component_id = component_data.common_v2.component_id;

				break;

			case PCD_COMPONENT_MCTP_BRIDGE:
				if ((size_t) status < sizeof (struct pcd_mctp_bridge_component_element_v2)) {
					return PCD_MALFORMED_BRIDGE_COMPONENT_ELEMENT;
				}

				supported_component.component_id = component_data.mctp_v2.component.component_id;

				if (element_format <= 2) {
					supported_component.component_count =
						component_data.mctp_v2.connection.components_count;
				}
				else {
					supported_component.component_count = component_data.common_v3.instances_count;
				}

				break;

			default:
				/* Should never happen */
				continue;
		}

		component_len += buffer_copy ((uint8_t*) &supported_component, sizeof (supported_component),
			&offset, &length, &pcd_component_ids[component_len]);

		i_components++;
	}

	return component_len;
}

/**
 * Internal context for get_next_component implementation to keep track of iteration state.
 */
struct pcd_flash_component_info_context {
	int start;								/**< Starting entry for next search. */

	/* This is used to keep the buffer for component types across multiple calls.
	 * As some FreeRTOS heaps doesn't implement realloc, we need to keep the buffer around
	 * and reallocate only if bigger buffer is needed to reduce heap fragmentation. */
	size_t allocated_component_types_count;	/**< Number of component types allocated in component_types. */
};


/**
 * Helper function to allocate or reallocate component types buffer in component info context if needed.
 *
 * @param component The component container to allocate buffer for.
 * @param type_count The number of component types to allocate.
 */
static int pcd_flash_allocate_component_types (struct pcd_component_info *component,
	size_t type_count)
{
	struct pcd_flash_component_info_context *context = component->context;

	if (type_count <= context->allocated_component_types_count) {
		/* Current buffer is big enough, no need to reallocate. */
		return 0;
	}

	platform_free (component->component_types);
	context->allocated_component_types_count = 0;

	component->component_types = platform_calloc (type_count,
		sizeof (struct pcd_allowed_component_type_info));

	if (!component->component_types) {
		return PCD_NO_MEMORY;
	}

	context->allocated_component_types_count = type_count;

	return 0;
}

/**
 * Reads the v2 common part of the component element and fills the component info structure with it.
 *
 * @param component The component container to fill.
 * @param common_v2 The common part of the component element in v2 format.
 *
 * @return 0 if the common part was read and parsed successfully or an error code.
 */
static int pcd_flash_read_v2_component_common (struct pcd_component_info *component,
	const struct pcd_component_common_v2 *common_v2)
{
	int status;

	/* V2 are single source - always one type. */
	status = pcd_flash_allocate_component_types (component, 1);
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	component->component_id = common_v2->component_id;
	component->components_count = 1;
	component->component_type_count = 1;
	component->component_types[0].cfm_component_id = component->component_id;
	component->component_types[0].max_usage = 0;
	component->component_types[0].min_usage = 0;

	return 0;
}

/**
 * Reads the v3 common part of the component element and fills the component info structure with it.
 *
 * @param component The component container to fill.
 * @param common_v3 The common part of the component element in v3 format.
 *
 * @return 0 if the common part was read and parsed successfully or an error code.
 */
static int pcd_flash_read_v3_component_common (struct pcd_component_info *component,
	const struct pcd_component_common_v3 *common_v3)
{
	int status;
	size_t i;

	/* V3 are single or multi source - allocate at least one type entry. */
	status = pcd_flash_allocate_component_types (component,
		(common_v3->component_types_count == 0) ? 1 : common_v3->component_types_count);
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	component->component_id = common_v3->component_id;
	component->components_count = common_v3->instances_count;

	if (common_v3->component_types_count == 0) {
		/* Single source component, fill one source. */
		component->component_type_count = 1;
		component->component_types[0].cfm_component_id = component->component_id;
		component->component_types[0].max_usage = 0;
		component->component_types[0].min_usage = 0;
	}
	else {
		/* Multi-source component */
		component->component_type_count = common_v3->component_types_count;

		for (i = 0; i < component->component_type_count; ++i) {
			component->component_types[i].cfm_component_id =
				common_v3->component_types[i].cfm_component_id;
			component->component_types[i].max_usage = common_v3->component_types[i].max_usage;
			component->component_types[i].min_usage = common_v3->component_types[i].min_usage;
		}
	}

	return 0;
}

/**
 * Function to read and parse a direct I2C component element and fill the component info structure with it.
 *
 * @param pcd_flash The PCD flash instance.
 * @param component The component container to fill.
 * @param entry_format The format version of the component element.
 * @param entry_data The raw data of the component element read from flash.
 * @param entry_len The length of the raw component element data.
 *
 * @return 0 if the component was read and parsed successfully or an error code.
 */
static int pcd_flash_read_direct_component (const struct pcd_flash *pcd_flash,
	struct pcd_component_info *component, uint8_t entry_format, uint8_t *entry_data,
	size_t entry_len)
{
	const struct pcd_direct_i2c_component_element_v2 *element_v2 =
		(struct pcd_direct_i2c_component_element_v2*) entry_data;
	const struct pcd_component_common_v3 *hdr_v3 = (struct pcd_component_common_v3*) entry_data;

	const struct pcd_i2c_interface *i2c_interface = NULL;
	int status;

	component->type = PCD_COMPONENT_TYPE_DIRECT;

	switch (entry_format) {
		case 0:
		case 1:
		case 2:
			if (entry_len < sizeof (*element_v2)) {
				return PCD_MALFORMED_DIRECT_I2C_COMPONENT_ELEMENT;
			}

			status = pcd_flash_read_v2_component_common (component, &element_v2->component);
			if (ROT_IS_ERROR (status)) {
				return status;
			}

			i2c_interface = pcd_get_component_v2_details (&element_v2->component);

			break;

		case 3:
		default:
			if (entry_len < sizeof (struct pcd_component_common_v3)) {
				return PCD_MALFORMED_DIRECT_I2C_COMPONENT_ELEMENT;
			}

			if (entry_len < pcd_component_common_v3_length (hdr_v3) + sizeof (*i2c_interface)) {
				return PCD_MALFORMED_DIRECT_I2C_COMPONENT_ELEMENT;
			}

			status = pcd_flash_read_v3_component_common (component, hdr_v3);
			if (ROT_IS_ERROR (status)) {
				return status;
			}

			i2c_interface = pcd_get_component_v3_details (hdr_v3);

			break;
	}

	if (i2c_interface == NULL) {
		return PCD_MALFORMED_DIRECT_I2C_COMPONENT_ELEMENT;
	}

	component->details.direct.address = i2c_interface->address;
	component->details.direct.bus = i2c_interface->bus;
	component->details.direct.eid = i2c_interface->eid;
	component->details.direct.i2c_mode =
		pcd_get_i2c_interface_i2c_mode (i2c_interface);
	component->details.direct.mux_count = i2c_interface->mux_count;

	return 0;
}


/**
 * Function to read and parse an MCTP bridge component element and fill the component info structure with it.
 *
 * @param pcd_flash The PCD flash instance.
 * @param component The component container to fill.
 * @param entry_format The format version of the component element.
 * @param entry_data The raw data of the component element read from flash.
 * @param entry_len The length of the raw component element data.
 *
 * @return 0 if the component was read and parsed successfully or an error code.
 */
static int pcd_flash_read_mctp_bridge_component (const struct pcd_flash *pcd_flash,
	struct pcd_component_info *component, uint8_t entry_format, uint8_t *entry_data,
	size_t entry_len)
{
	const struct pcd_mctp_bridge_component_element_v2 *element_v2 =
		(struct pcd_mctp_bridge_component_element_v2*) entry_data;
	const struct pcd_component_common_v3 *hdr_v3 = (struct pcd_component_common_v3*) entry_data;
	const struct pcd_mctp_bridge_component_connection_v3 *connection_v3 = NULL;
	int status;

	component->type = PCD_COMPONENT_TYPE_MCTP_BRIDGE;

	switch (entry_format) {
		case 0:
		case 1:
		case 2:
			if (entry_len < sizeof (*element_v2)) {
				return PCD_MALFORMED_BRIDGE_COMPONENT_ELEMENT;
			}

			status = pcd_flash_read_v2_component_common (component, &element_v2->component);
			if (ROT_IS_ERROR (status)) {
				return status;
			}

			component->components_count = element_v2->connection.components_count;

			component->details.mctp_bridge.pci_device_id = element_v2->connection.device_id;
			component->details.mctp_bridge.pci_vid = element_v2->connection.vendor_id;
			component->details.mctp_bridge.pci_subsystem_id =
				element_v2->connection.subsystem_device_id;
			component->details.mctp_bridge.pci_subsystem_vid =
				element_v2->connection.subsystem_vendor_id;

			break;

		case 3:
		default:
			if (entry_len < sizeof (struct pcd_component_common_v3)) {
				return PCD_MALFORMED_BRIDGE_COMPONENT_ELEMENT;
			}

			if (entry_len < pcd_component_common_v3_length (hdr_v3) + sizeof (*connection_v3)) {
				return PCD_MALFORMED_BRIDGE_COMPONENT_ELEMENT;
			}

			status = pcd_flash_read_v3_component_common (component, hdr_v3);
			if (ROT_IS_ERROR (status)) {
				return status;
			}

			connection_v3 = pcd_get_component_v3_details (hdr_v3);

			component->details.mctp_bridge.pci_device_id = connection_v3->device_id;
			component->details.mctp_bridge.pci_vid = connection_v3->vendor_id;
			component->details.mctp_bridge.pci_subsystem_id =
				connection_v3->subsystem_device_id;
			component->details.mctp_bridge.pci_subsystem_vid =
				connection_v3->subsystem_vendor_id;

			break;
	}

	return 0;
}

/**
 * Function to read and parse a TCG log component element and fill the component info structure with it.
 *
 * @param pcd_flash The PCD flash instance.
 * @param component The component container to fill.
 * @param entry_format The format version of the component element.
 * @param entry_data The raw data of the component element read from flash.
 * @param entry_len The length of the raw component element data.
 *
 * @return 0 if the component was read and parsed successfully or an error code.
 */
static int pcd_flash_read_tcg_log_component (const struct pcd_flash *pcd_flash,
	struct pcd_component_info *component, uint8_t entry_format, uint8_t *entry_data,
	size_t entry_len)
{
	const struct pcd_tcg_log_component_element_v2 *element_v2 =
		(struct pcd_tcg_log_component_element_v2*) entry_data;
	const struct pcd_component_common_v3 *hdr_v3 = (struct pcd_component_common_v3*) entry_data;

	int status;

	component->type = PCD_COMPONENT_TYPE_TCG_LOG;

	switch (entry_format) {
		case 0:
		case 1:
		case 2:
			/* This part is not going to be used because TCG Log components are only supported in PCD v3 and above.
			 * However, the TCG Log component element format version 2 was defined before the v3 PCD was added,
			 * therefore we support it here to keep consistency with the original definition of the TCG Log component element.
			 */
			if (entry_len < sizeof (*element_v2)) {
				return PCD_MALFORMED_TCG_LOG_COMPONENT_ELEMENT;
			}

			status = pcd_flash_read_v2_component_common (component, &element_v2->component);
			if (ROT_IS_ERROR (status)) {
				return status;
			}
			break;

		case 3:
		default:
			if (entry_len < sizeof (struct pcd_component_common_v3)) {
				return PCD_MALFORMED_TCG_LOG_COMPONENT_ELEMENT;
			}

			if (entry_len < pcd_component_common_v3_length (hdr_v3)) {
				return PCD_MALFORMED_TCG_LOG_COMPONENT_ELEMENT;
			}

			status = pcd_flash_read_v3_component_common (component, hdr_v3);
			if (ROT_IS_ERROR (status)) {
				return status;
			}

			break;
	}

	return 0;
}

void pcd_flash_free_component (const struct pcd *pcd, struct pcd_component_info *component)
{
	if ((pcd == NULL) || (component == NULL)) {
		return;
	}

	if (component->component_types != NULL) {
		platform_free (component->component_types);
		component->component_types = NULL;
	}

	component->component_type_count = 0;

	platform_free (component->context);
	component->context = NULL;
}

int pcd_flash_get_next_component (const struct pcd *pcd, struct pcd_component_info *component,
	bool first)
{
	const struct pcd_flash *pcd_flash = TO_DERIVED_TYPE (pcd, const struct pcd_flash, base);
	int status;
	struct pcd_flash_component_info_context *context;

	uint8_t *element_data = NULL;
	uint8_t element_format;
	size_t element_total_len;
	uint8_t element_type;

	/* For free_component to be safely called even in case of PCD_INVALID_ARGUMENT. */
	if ((component != NULL) && first) {
		memset (component, 0, sizeof (struct pcd_component_info));
	}

	if ((pcd_flash == NULL) || (component == NULL)) {
		return PCD_INVALID_ARGUMENT;
	}

	if (!pcd_flash->base_flash.state->manifest_valid) {
		return MANIFEST_NO_MANIFEST;
	}

	if (first) {
		context = platform_calloc (1, sizeof (struct pcd_flash_component_info_context));
		if (context == NULL) {
			return PCD_NO_MEMORY;
		}

		component->context = context;
	}

	context = (struct pcd_flash_component_info_context*) component->context;

	component->components_count = 0;
	/* Keep the buffer allocated until free is explicitly called. */
	component->component_type_count = 0;

	/* Read to dynamically allocated buffer to be interpreted as target type. */
	status = manifest_flash_read_element_data_multi_type (&pcd_flash->base_flash,
		pcd_flash->base_flash.hash, pcd_flash_component_element_types,
		ARRAY_SIZE (pcd_flash_component_element_types), context->start,	MANIFEST_NO_PARENT, 0,
		&context->start, &element_type, &element_format, &element_total_len, &element_data, 0);
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	switch (element_type) {
		case PCD_COMPONENT_DIRECT:
			status = pcd_flash_read_direct_component (pcd_flash, component, element_format,
				element_data, element_total_len);

			break;

		case PCD_COMPONENT_MCTP_BRIDGE:
			status = pcd_flash_read_mctp_bridge_component (pcd_flash, component, element_format,
				element_data, element_total_len);

			break;

		case PCD_COMPONENT_TCG_LOG:
			status = pcd_flash_read_tcg_log_component (pcd_flash, component, element_format,
				element_data, element_total_len);

			break;

		default:
			/* Should never happen */
			break;
	}

	platform_free (element_data);

	if (!ROT_IS_ERROR (status)) {
		context->start = context->start + 1;
	}
	else if (first) {
		/* Free the component container if this is the first element and an error occurred. */
		pcd_flash_free_component (pcd, component);
	}

	return status;
}

/**
 * Initialize the interface to a PCD residing in flash memory.  PCDs support manifest versions
 * 2 and 3.
 *
 * @param pcd The PCD instance to initialize.
 * @param state Variable context for the PCD instance.  This must be uninitialized.
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
int pcd_flash_init (struct pcd_flash *pcd, struct pcd_flash_state *state, const struct flash *flash,
	const struct hash_engine *hash, uint32_t base_addr, uint8_t *signature_cache,
	size_t max_signature, uint8_t *platform_id_cache, size_t max_platform_id)
{
	int status;

	if ((pcd == NULL) || (state == NULL)) {
		return PCD_INVALID_ARGUMENT;
	}

	memset (pcd, 0, sizeof (struct pcd_flash));

	status = manifest_flash_v3_init (&pcd->base_flash, &state->base, flash, hash, base_addr,
		MANIFEST_NOT_SUPPORTED, PCD_V2_MAGIC_NUM, PCD_V3_MAGIC_NUM, signature_cache, max_signature,
		platform_id_cache, max_platform_id);
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

	pcd->base.buffer_supported_components = pcd_flash_buffer_supported_components;
	pcd->base.get_port_info = pcd_flash_get_port_info;
	pcd->base.get_rot_info = pcd_flash_get_rot_info;
	pcd->base.get_power_controller_info = pcd_flash_get_power_controller_info;
	pcd->base.get_next_component = pcd_flash_get_next_component;
	pcd->base.free_component = pcd_flash_free_component;

	return 0;
}

/**
 * Initialize only the variable state for a PCD on flash.  The rest of the handler is assumed to
 * have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param pcd The PCD that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int pcd_flash_init_state (const struct pcd_flash *pcd)
{
	if (pcd == NULL) {
		return PCD_INVALID_ARGUMENT;
	}

	return manifest_flash_init_state (&pcd->base_flash);
}

/**
 * Release the resources used by the PCD interface.
 *
 * @param pcd The PCD instance to release.
 */
void pcd_flash_release (const struct pcd_flash *pcd)
{
	if (pcd != NULL) {
		manifest_flash_release (&pcd->base_flash);
	}
}
