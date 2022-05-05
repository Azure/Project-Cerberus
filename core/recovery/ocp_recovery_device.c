// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "ocp_recovery_device.h"
#include "common/buffer_util.h"
#include "common/common_math.h"
#include "common/unused.h"


/**
 * Placeholder for the active command code when no command has been started.
 */
#define	OCP_RECOVERY_DEVICE_NO_COMMAND			0

/**
 * The maximum number of bytes that can be read from an indirect memory region while maintaining
 * 4-byte alignment.
 */
#define	OCP_RECOVERY_DEVICE_MAX_INDIRECT_READ	252


/**
 * Initialize a device handler for the OCP Recovery protocol.
 *
 * @param device The handler to initialize.
 * @param state The recovery state to initialize.  This must not already be initialized.
 * @param hw The HW interface for executing device actions in response to recovery commands.
 * @param cms_list A list of memory regions that are accessible through the recovery handler.  This
 * can be null if there are no supported regions.
 * @param cms_count The number of memory regions in the list.
 *
 * @return 0 if the handler was successfully initialized or an error code.
 */
int ocp_recovery_device_init (struct ocp_recovery_device *device,
	struct ocp_recovery_device_state *state, const struct ocp_recovery_device_hw *hw,
	const struct ocp_recovery_device_cms *cms_list, size_t cms_count)
{
	if ((device == NULL) || (state == NULL) || (hw == NULL) ||
		((cms_list == NULL) && (cms_count != 0))) {
		return OCP_RECOVERY_DEVICE_INVALID_ARGUMENT;
	}

	memset (device, 0, sizeof (struct ocp_recovery_device));

	device->state = state;
	device->hw = hw;
	device->cms = cms_list;
	device->cms_count = cms_count;

	return ocp_recovery_device_init_state (device);
}

/**
 * Initialize only the variable state of an OCP Recovery handler.  The rest of a device handler
 * structure is assumed to have already been initialized.
 *
 * This would generally be used with a statically initialized handler instance.
 *
 * @param device The recovery handler containing the state to initialize.
 *
 * @return 0 if the handler state was successfully initialized or an error code.
 */
int ocp_recovery_device_init_state (const struct ocp_recovery_device *device)
{
	size_t i;

	if ((device == NULL) || (device->state == NULL)) {
		return OCP_RECOVERY_DEVICE_INVALID_ARGUMENT;
	}

	memset (device->state, 0, sizeof (struct ocp_recovery_device_state));

	if (!device->hw->activate_recovery || !device->cms) {
		device->state->recovery_status = OCP_RECOVERY_RECOVERY_STATUS_NOT_RECOVERY_MODE;
	}
	else {
		device->state->recovery_status = OCP_RECOVERY_RECOVERY_STATUS_WAITING_FOR_IMAGE;
	}

	for (i = 0; i < device->cms_count; i++) {
		switch (device->cms[i].type & ~OCP_RECOVERY_INDIRECT_STATUS_REGION_POLLING_FLAG) {
			case OCP_RECOVERY_INDIRECT_STATUS_REGION_RECOVERY_CODE:
			case OCP_RECOVERY_INDIRECT_STATUS_REGION_VENDOR_RW:
				if (device->cms[i].length & 0x3) {
					/* Writable regions must by 4-byte aligned. */
					return OCP_RECOVERY_DEVICE_RW_CMS_NOT_ALIGNED;
				}

				if (device->cms[i].length == OCP_RECOVERY_DEVICE_CMS_LENGTH_VARIABLE) {
					/* Writable regions can't use logging interfaces. */
					return OCP_RECOVERY_DEVICE_RW_LOG;
				}
				break;

			default:
				/* Other region types can handle mis-alignment, though it is not ideal. */
				break;
		}
	}

	return 0;
}

/**
 * Release the resources for an OCP Recovery device handler.  This will release both the handler
 * instance and the associated state.
 *
 * @param device The handler to release.
 */
void ocp_recovery_device_release (const struct ocp_recovery_device *device)
{
	UNUSED (device);
}

/**
 * Notify the device handler that a new recovery command has been received.  This must be called as
 * soon as the command code is known.  The final direction of the command is not known at this
 * point.
 *
 * If the command is invalid, the request must be NACKed.
 *
 * @param device The recovery handler to update.
 * @param command_code The received command code.
 *
 * @return 0 if the command has been accepted by the handler or an error code.  If the command is
 * invalid, OCP_RECOVERY_DEVICE_NACK is returned to indicate the transaction must be NACKed.
 */
int ocp_recovery_device_start_new_command (const struct ocp_recovery_device *device,
	uint8_t command_code)
{
	if (device == NULL) {
		return OCP_RECOVERY_DEVICE_INVALID_ARGUMENT;
	}

	if ((command_code < OCP_RECOVERY_CMD_MIN_VALID) ||
		(command_code > OCP_RECOVERY_CMD_MAX_VALID)) {
		device->state->protocol_status |= OCP_RECOVERY_DEVICE_STATUS_PROTO_UNSUPPORTED_CMD;
		return OCP_RECOVERY_DEVICE_NACK;
	}

	device->state->active_cmd = command_code;

	return 0;
}

/**
 * Process a received RESET recovery command.
 *
 * @param device The recovery handler that will process the command.
 * @param reset Buffer containing the request.
 *
 * @return 0 if the a device reset was triggered or OCP_RECOVERY_DEVICE_UNSUPPORTED if reset is not
 * supported.  In most cases, 0 will never be returned because the device would have been reset.
 */
static int ocp_recovery_device_write_reset (const struct ocp_recovery_device *device,
	const struct ocp_recovery_reset *reset)
{
	int status = 0;

	if (reset->intf_control != OCP_RECOVERY_RESET_INTF_DISABLE_MASTERING) {
		return OCP_RECOVERY_DEVICE_UNSUPPORTED_PARAM;
	}

	if ((!device->hw->supports_forced_recovery) &&
		(reset->forced_recovery == OCP_RECOVERY_RESET_FORCED_RECOVERY)) {
		return OCP_RECOVERY_DEVICE_UNSUPPORTED_PARAM;
	}

	switch (reset->reset_ctrl) {
		case OCP_RECOVERY_RESET_DEVICE_RESET:
			if (device->hw->reset_device) {
				device->hw->reset_device (device->hw,
					(reset->forced_recovery == OCP_RECOVERY_RESET_FORCED_RECOVERY));
			}
			else {
				status = OCP_RECOVERY_DEVICE_UNSUPPORTED_PARAM;
			}
			break;

		case OCP_RECOVERY_RESET_MGMT_RESET:
			if (device->hw->reset_management) {
				device->hw->reset_management (device->hw,
					(reset->forced_recovery == OCP_RECOVERY_RESET_FORCED_RECOVERY));
			}
			else {
				status = OCP_RECOVERY_DEVICE_UNSUPPORTED_PARAM;
			}
			break;
	}

	/* If the device resets, this won't get called, but if the device is not reset, store the
	 * value that was written. */
	if (status == 0) {
		memcpy (&device->state->reset, reset, sizeof (struct ocp_recovery_reset));
		device->state->reset.reset_ctrl = OCP_RECOVERY_RESET_NO_RESET;
	}

	return status;
}

/**
 * Process a received RECOVERY_CTRL recovery command.
 *
 * @param device The recovery handler that will process the command.
 * @param recovery_ctrl Buffer containing the request.
 *
 * @return 0 if the request completed successfully or an error code.
 */
static int ocp_recovery_device_write_recovery_ctrl (const struct ocp_recovery_device *device,
	const struct ocp_recovery_recovery_ctrl *recovery_ctrl)
{
	bool auth_error;
	int status = 0;

	if (recovery_ctrl->cms >= device->cms_count) {
		return OCP_RECOVERY_DEVICE_UNSUPPORTED_CMS;
	}

	if (recovery_ctrl->recovery_image == OCP_RECOVERY_RECOVERY_CTRL_IMAGE_IN_DEVICE) {
		return OCP_RECOVERY_DEVICE_UNSUPPORTED_PARAM;
	}

	if ((!device->hw->activate_recovery) &&
		((recovery_ctrl->recovery_image == OCP_RECOVERY_RECOVERY_CTRL_IMAGE_FROM_CMS) ||
			(recovery_ctrl->activate == OCP_RECOVERY_RECOVERY_CTRL_ACTIVATE_IMAGE))) {
		return OCP_RECOVERY_DEVICE_UNSUPPORTED_PARAM;
	}

	if (recovery_ctrl->recovery_image == OCP_RECOVERY_RECOVERY_CTRL_IMAGE_FROM_CMS) {
		if (device->cms[recovery_ctrl->cms].type !=
			OCP_RECOVERY_INDIRECT_STATUS_REGION_RECOVERY_CODE) {
			device->state->recovery_status = OCP_RECOVERY_RECOVERY_STATUS_INVALID_CMS;
			status = OCP_RECOVERY_DEVICE_CMS_NOT_CODE_REGION;
		}

		if ((status == 0) &&
			(recovery_ctrl->activate == OCP_RECOVERY_RECOVERY_CTRL_ACTIVATE_IMAGE)) {
			status = device->hw->activate_recovery (device->hw, &device->cms[recovery_ctrl->cms],
				&auth_error);
			if (status == 0) {
				device->state->recovery_status = OCP_RECOVERY_RECOVERY_STATUS_SUCCESSFUL;
			}
			else {
				if (auth_error) {
					device->state->recovery_status = OCP_RECOVERY_RECOVERY_STATUS_AUTH_FAILURE;
				}
				else {
					device->state->recovery_status = OCP_RECOVERY_RECOVERY_STATUS_FAILED;
				}
			}
		}
	}

	memcpy (&device->state->recovery_ctrl, recovery_ctrl,
		sizeof (struct ocp_recovery_recovery_ctrl));
	device->state->recovery_ctrl.activate = OCP_RECOVERY_RECOVERY_CTRL_ACTIVATE_NONE;

	return status;
}

/**
 * Process a received INDIRECT_CTRL recovery command.
 *
 * @param device The recovery handler that will process the command.
 * @param indirect_ctrl Buffer containing the request.
 *
 * @return 0 if the request completed successfully or an error code.
 */
static int ocp_recovery_device_write_indirect_ctrl (const struct ocp_recovery_device *device,
	const struct ocp_recovery_indirect_ctrl *indirect_ctrl)
{
	if (!device->cms) {
		return OCP_RECOVERY_DEVICE_UNSUPPORTED;
	}

	/* There doesn't need to be any validation done on the values at this point.  If the CMS is not
	 * supported, it will be reported as such by INDIRECT_STATUS and INDIRECT_DATA will not allow
	 * any access.  If the offset is too large for the region, it will get corrected prior to any
	 * INDIRECT_DATA access. */

	memcpy (&device->state->indirect_ctrl, indirect_ctrl,
		sizeof (struct ocp_recovery_indirect_ctrl));

	/* Address offset must be 4-byte aligned.  Move to the next aligned address. */
	device->state->indirect_ctrl.offset = (device->state->indirect_ctrl.offset + 3) & ~0x3ull;

	return 0;
}

/**
 * Process a received INDIRECT_DATA recovery command.
 *
 * @param device The recovery handler that will process the command.
 * @param indirect_data Buffer containing the request.
 * @param length The amount of data being written.
 *
 * @return 0 if the request completed successfully or an error code.
 */
static int ocp_recovery_device_write_indirect_data (const struct ocp_recovery_device *device,
	const struct ocp_recovery_indirect_data *indirect_data, size_t length)
{
	const struct ocp_recovery_device_cms *cms;
	size_t write_len;
	const uint8_t *pos;

	if (!device->cms) {
		return OCP_RECOVERY_DEVICE_UNSUPPORTED;
	}

	/* Find the CMS that is currently being accessed. */
	if (device->state->indirect_ctrl.cms >= device->cms_count) {
		return OCP_RECOVERY_DEVICE_UNSUPPORTED_CMS;
	}

	cms = &device->cms[device->state->indirect_ctrl.cms];
	if ((cms->type != OCP_RECOVERY_INDIRECT_STATUS_REGION_RECOVERY_CODE) &&
		(cms->type != OCP_RECOVERY_INDIRECT_STATUS_REGION_VENDOR_RW)) {
		device->state->indirect_status |= OCP_RECOVERY_INDIRECT_STATUS_READ_ONLY;
		return OCP_RECOVERY_DEVICE_RO_CMS;
	}

	/* Copy the data to the memory region. */
	pos = indirect_data->data;
	do {
		/* Check the offset to see if the read should wrap to the beginning. */
		if (device->state->indirect_ctrl.offset >= cms->length) {
			device->state->indirect_ctrl.offset = 0;
			device->state->indirect_status |= OCP_RECOVERY_INDIRECT_STATUS_OVERLFLOW;
		}

		write_len = min (length, cms->length - device->state->indirect_ctrl.offset);
		memcpy (&cms->base_addr[device->state->indirect_ctrl.offset], pos, write_len);

		/* Make sure we only ever increment the offset in 4-byte chunks. */
		device->state->indirect_ctrl.offset += (write_len + 3) & ~0x3ull;

		length -= write_len;
		pos += write_len;
	} while (length > 0);

	return 0;
}

/**
 * The recovery command is writing data to the device.  This call is only valid after first calling
 * ocp_recovery_device_start_new_command.
 *
 * Once this function returns, the current command context is closed and the handler begins waiting
 * for a new command.
 *
 * @param device The recovery handler that will process the command.
 * @param data The command data received from the requestor.  This must only be the recovery command
 * data.  Any bus protocol data must not be included.
 * @param length The number of data bytes received.
 *
 * @return 0 if the command was processed successfully or an error code.
 */
int ocp_recovery_device_write_request (const struct ocp_recovery_device *device,
	const union ocp_recovery_device_cmd_buffer *data, size_t length)
{
	int status = OCP_RECOVERY_DEVICE_RO_COMMAND;

	if ((device == NULL) || (data == NULL)) {
		return OCP_RECOVERY_DEVICE_INVALID_ARGUMENT;
	}

	switch (device->state->active_cmd) {
		case OCP_RECOVERY_DEVICE_NO_COMMAND:
			status = OCP_RECOVERY_DEVICE_NO_ACTIVE_COMMAND;
			break;

		case OCP_RECOVERY_CMD_RESET:
			if (length == sizeof (struct ocp_recovery_reset)) {
				status = ocp_recovery_device_write_reset (device, &data->reset);
			}
			else if (length > sizeof (struct ocp_recovery_reset)) {
				status = OCP_RECOVERY_DEVICE_EXTRA_CMD_BYTES;
			}
			else {
				status = OCP_RECOVERY_DEVICE_CMD_INCOMPLETE;
			}
			break;

		case OCP_RECOVERY_CMD_RECOVERY_CTRL:
			if (length == sizeof (struct ocp_recovery_recovery_ctrl)) {
				status = ocp_recovery_device_write_recovery_ctrl (device, &data->recovery_ctrl);
			}
			else if (length > sizeof (struct ocp_recovery_recovery_ctrl)) {
				status = OCP_RECOVERY_DEVICE_EXTRA_CMD_BYTES;
			}
			else {
				status = OCP_RECOVERY_DEVICE_CMD_INCOMPLETE;
			}
			break;

		case OCP_RECOVERY_CMD_INDIRECT_CTRL:
			if (length == sizeof (struct ocp_recovery_indirect_ctrl)) {
				status = ocp_recovery_device_write_indirect_ctrl (device, &data->indirect_ctrl);
			}
			else if (length > sizeof (struct ocp_recovery_indirect_ctrl)) {
				status = OCP_RECOVERY_DEVICE_EXTRA_CMD_BYTES;
			}
			else {
				status = OCP_RECOVERY_DEVICE_CMD_INCOMPLETE;
			}
			break;

		case OCP_RECOVERY_CMD_INDIRECT_DATA:
			status = ocp_recovery_device_write_indirect_data (device, &data->indirect_data, length);
			break;

		case OCP_RECOVERY_CMD_VENDOR:
			status = OCP_RECOVERY_DEVICE_UNSUPPORTED;
			break;
	}

	/* Update the protocol status in the case of an error. */
	switch (status) {
		case 0:
			/* Successful command. */
			break;

		case OCP_RECOVERY_DEVICE_UNSUPPORTED:
		case OCP_RECOVERY_DEVICE_RO_COMMAND:
			device->state->protocol_status = OCP_RECOVERY_DEVICE_STATUS_PROTO_UNSUPPORTED_CMD;
			break;

		case OCP_RECOVERY_DEVICE_UNSUPPORTED_PARAM:
		case OCP_RECOVERY_DEVICE_UNSUPPORTED_CMS:
			device->state->protocol_status = OCP_RECOVERY_DEVICE_STATUS_PROTO_UNSUPPORTED_PARAM;
			break;

		case OCP_RECOVERY_DEVICE_CMD_INCOMPLETE:
		case OCP_RECOVERY_DEVICE_EXTRA_CMD_BYTES:
			device->state->protocol_status = OCP_RECOVERY_DEVICE_STATUS_PROTO_LENGTH_ERROR;
			break;
	}

	device->state->active_cmd = OCP_RECOVERY_DEVICE_NO_COMMAND;
	return status;
}

/**
 * Read the data to respond to a PROT_CAP recovery command.
 *
 * @param device The recovery handler that will process the command.
 * @param prot_cap Output buffer for the command data.
 *
 * @return The number of bytes in the command response or an error code.
 */
static int ocp_recovery_device_read_prot_cap (const struct ocp_recovery_device *device,
	struct ocp_recovery_prot_cap *prot_cap)
{
	memcpy (prot_cap->magic_string, OCP_RECOVERY_PROT_CAP_MAGIC_STRING,
		sizeof (prot_cap->magic_string));
	prot_cap->major_version = OCP_RECOVERY_PROT_CAP_MAJOR_VERSION;
	prot_cap->minor_version = OCP_RECOVERY_PROT_CAP_MINOR_VERSION;
	prot_cap->capabilities = OCP_RECOVERY_PROT_CAP_SUPPORTS_IDENTIFICATION |
		OCP_RECOVERY_PROT_CAP_SUPPORTS_DEVICE_STATUS;
	prot_cap->cms_regions = 0;
	prot_cap->max_response_time = 0x10;		// This translates to a 65ms response time.
	prot_cap->heartbeat_period = 0;			// Heartbeat is not supported.

	if (device->hw->reset_device) {
		prot_cap->capabilities |= OCP_RECOVERY_PROT_CAP_SUPPORTS_DEVICE_RESET;
	}

	if (device->hw->reset_management) {
		prot_cap->capabilities |= OCP_RECOVERY_PROT_CAP_SUPPORTS_MGMT_RESET;
	}

	if (device->hw->supports_forced_recovery) {
		prot_cap->capabilities |= OCP_RECOVERY_PROT_CAP_SUPPORTS_FORCED_RECOVERY;
	}

	if (device->cms) {
		prot_cap->capabilities |= OCP_RECOVERY_PROT_CAP_SUPPORTS_MEMORY_ACCESS;
		prot_cap->cms_regions = device->cms_count;

		if (device->hw->activate_recovery) {
			prot_cap->capabilities |= OCP_RECOVERY_PROT_CAP_SUPPORTS_PUSH_IMAGE;
		}
	}

	return sizeof (struct ocp_recovery_prot_cap);
}

/**
 * Read the data to respond to a DEVICE_STATUS recovery command.
 *
 * @param device The recovery handler that will process the command.
 * @param device_status Output buffer for the command data.
 *
 * @return The number of bytes in the command response or an error code.
 */
static int ocp_recovery_device_read_device_status (const struct ocp_recovery_device *device,
	struct ocp_recovery_device_status *device_status)
{
	enum ocp_recovery_device_status_code status_code;
	enum ocp_recovery_recovery_reason_code reason_code;

	device->hw->get_device_status (device->hw, &status_code, &reason_code,
		(struct ocp_recovery_device_status_vendor*) device_status->vendor_status);

	device_status->base.status = status_code;
	device_status->base.protocol_status = device->state->protocol_status;
	device_status->base.recovery_reason = reason_code;
	device_status->base.heartbeat = 0;
	device_status->base.vendor_length = sizeof (struct ocp_recovery_device_status_vendor);

	/* Clear the protocol status on read. */
	device->state->protocol_status = 0;

	return sizeof (device_status->base) + device_status->base.vendor_length;
}

/**
 * Read the data to respond to an INDIRECT_STATUS recovery command.
 *
 * @param device The recovery handler that will process the command.
 * @param indirect_status Output buffer for the command data.
 *
 * @return The number of bytes in the command response or an error code.
 */
static int ocp_recovery_device_read_indirect_status (const struct ocp_recovery_device *device,
	struct ocp_recovery_indirect_status *indirect_status)
{
	const struct ocp_recovery_device_cms *cms;
	int status;

	if (!device->cms) {
		return OCP_RECOVERY_DEVICE_UNSUPPORTED;
	}

	indirect_status->status = device->state->indirect_status;
	if (device->state->indirect_ctrl.cms < device->cms_count) {
		cms = &device->cms[device->state->indirect_ctrl.cms];

		indirect_status->type = cms->type;
		if (cms->length != OCP_RECOVERY_DEVICE_CMS_LENGTH_VARIABLE) {
			indirect_status->size = cms->length;
		}
		else {
			status = cms->variable->get_size (cms->variable);
			if (ROT_IS_ERROR (status)) {
				return status;
			}

			indirect_status->size = status;
		}

		/* Make sure the size gets rounded up to the next 4-byte unit. */
		indirect_status->size = (indirect_status->size + 3) / 4;
	}
	else {
		indirect_status->type = OCP_RECOVERY_INDIRECT_STATUS_REGION_UNSUPPORTED;
		indirect_status->size = 0;
	}

	/* Clear the indirect status on read. */
	device->state->indirect_status = 0;

	return sizeof (struct ocp_recovery_indirect_status);
}

/**
 * Read the data to respond to an INDIRECT_DATA recovery command.
 *
 * @param device The recovery handler that will process the command.
 * @param indirect_status Output buffer for the command data.
 *
 * @return The number of bytes in the command response or an error code.
 */
static int ocp_recovery_device_read_indirect_data (const struct ocp_recovery_device *device,
	struct ocp_recovery_indirect_data *indirect_data)
{
	const struct ocp_recovery_device_cms *cms;
	size_t read_len;

	if (!device->cms) {
		return OCP_RECOVERY_DEVICE_UNSUPPORTED;
	}

	/* Find the CMS that is currently being accessed. */
	if (device->state->indirect_ctrl.cms >= device->cms_count) {
		return OCP_RECOVERY_DEVICE_UNSUPPORTED_CMS;
	}

	cms = &device->cms[device->state->indirect_ctrl.cms];

	/* Check the offset to see if the read should wrap to the beginning. */
	if (cms->length == OCP_RECOVERY_DEVICE_CMS_LENGTH_VARIABLE) {
		read_len = cms->variable->get_size (cms->variable);
		if (ROT_IS_ERROR ((int) read_len)) {
			return read_len;
		}
	}
	else {
		read_len = cms->length;
	}

	if (device->state->indirect_ctrl.offset >= read_len) {
		device->state->indirect_ctrl.offset = 0;
		device->state->indirect_status |= OCP_RECOVERY_INDIRECT_STATUS_OVERLFLOW;
	}

	/* Read the data from the memory region. */
	memset (indirect_data->data, 0, sizeof (indirect_data->data));

	if (cms->length == OCP_RECOVERY_DEVICE_CMS_LENGTH_VARIABLE) {
		read_len = cms->variable->get_data (cms->variable, device->state->indirect_ctrl.offset,
			indirect_data->data, OCP_RECOVERY_DEVICE_MAX_INDIRECT_READ);
		if (ROT_IS_ERROR ((int) read_len)) {
			return read_len;
		}
	}
	else {
		size_t max_length = OCP_RECOVERY_DEVICE_MAX_INDIRECT_READ;
		size_t offset = device->state->indirect_ctrl.offset;

		read_len = buffer_copy (cms->base_addr, cms->length, &offset, &max_length,
			indirect_data->data);
	}

	/* Make sure we only ever increment the offset in 4-byte chunks. */
	read_len = (read_len + 3) & ~0x3ull;
	device->state->indirect_ctrl.offset += read_len;

	return read_len;
}

/**
 * The recovery command is requesting data from device.  This call is only valid after first calling
 * ocp_recovery_device_start_new_command.
 *
 * Once this function returns, the current command context is closed and the handler begins waiting
 * for a new command.
 *
 * @param device The recovery handler that will process the command.
 * @param data Output buffer for the requested data.  This will only contain the recovery command
 * data.  Any bus protocol data must not be included.
 *
 * @return The number of bytes written to the data buffer or an error code.  Use ROT_IS_ERROR to
 * check the return value.
 */
int ocp_recovery_device_read_request (const struct ocp_recovery_device *device,
	union ocp_recovery_device_cmd_buffer *data)
{
	int status;

	if ((device == NULL) || (data == NULL)) {
		return OCP_RECOVERY_DEVICE_INVALID_ARGUMENT;
	}

	switch (device->state->active_cmd) {
		case OCP_RECOVERY_DEVICE_NO_COMMAND:
			return OCP_RECOVERY_DEVICE_NO_ACTIVE_COMMAND;

		case OCP_RECOVERY_CMD_PROT_CAP:
			status = ocp_recovery_device_read_prot_cap (device, &data->prot_cap);
			break;

		case OCP_RECOVERY_CMD_DEVICE_ID:
			status = device->hw->get_device_id (device->hw, &data->device_id);
			break;

		case OCP_RECOVERY_CMD_DEVICE_STATUS:
			status = ocp_recovery_device_read_device_status (device, &data->device_status);
			break;

		case OCP_RECOVERY_CMD_RESET:
			status = sizeof (struct ocp_recovery_reset);
			memcpy (&data->reset, &device->state->reset, status);
			break;

		case OCP_RECOVERY_CMD_RECOVERY_CTRL:
			status = sizeof (struct ocp_recovery_recovery_ctrl);
			memcpy (&data->recovery_ctrl, &device->state->recovery_ctrl, status);
			break;

		case OCP_RECOVERY_CMD_RECOVERY_STATUS:
			data->recovery_status.status = device->state->recovery_status;
			data->recovery_status.vendor_status = 0;
			status = sizeof (struct ocp_recovery_recovery_status);
			break;

		case OCP_RECOVERY_CMD_INDIRECT_CTRL:
			if (device->cms) {
				status = sizeof (struct ocp_recovery_indirect_ctrl);
				memcpy (&data->indirect_ctrl, &device->state->indirect_ctrl, status);
			}
			else {
				status = OCP_RECOVERY_DEVICE_UNSUPPORTED;
			}
			break;

		case OCP_RECOVERY_CMD_INDIRECT_STATUS:
			status = ocp_recovery_device_read_indirect_status (device, &data->indirect_status);
			break;

		case OCP_RECOVERY_CMD_INDIRECT_DATA:
			status = ocp_recovery_device_read_indirect_data (device, &data->indirect_data);
			break;

		default:
			status = OCP_RECOVERY_DEVICE_UNSUPPORTED;
			break;
	}

	/* Update the protocol status in the case of an error. */
	switch (status) {
		case 0:
			/* Successful command. */
			break;

		case OCP_RECOVERY_DEVICE_UNSUPPORTED:
			device->state->protocol_status = OCP_RECOVERY_DEVICE_STATUS_PROTO_UNSUPPORTED_CMD;
			break;

		case OCP_RECOVERY_DEVICE_UNSUPPORTED_CMS:
			device->state->protocol_status = OCP_RECOVERY_DEVICE_STATUS_PROTO_UNSUPPORTED_PARAM;
			break;
	}

	device->state->active_cmd = OCP_RECOVERY_DEVICE_NO_COMMAND;
	return status;
}

/**
 * Notify the recovery handler of a checksum failure at the physical layer.  Any current command
 * context must be closed, since that command was corrupted during transmission.
 *
 * @param device The recovery handler to update.
 */
void ocp_recovery_device_checksum_failure (const struct ocp_recovery_device *device)
{
	if (device) {
		device->state->active_cmd = OCP_RECOVERY_DEVICE_NO_COMMAND;
		device->state->protocol_status = OCP_RECOVERY_DEVICE_STATUS_PROTO_CRC_ERROR;
	}
}

/**
 * Notify the recovery handler that the physical layer has received more data than allowed by the
 * protocol, overflowing the command buffer.  The received command has been discarded and any
 * current command context should be closed.
 *
 * @param device The recovery handler to update.
 */
void ocp_recovery_device_write_overflow (const struct ocp_recovery_device *device)
{
	if (device) {
		device->state->active_cmd = OCP_RECOVERY_DEVICE_NO_COMMAND;
		device->state->protocol_status = OCP_RECOVERY_DEVICE_STATUS_PROTO_LENGTH_ERROR;
	}
}

/**
 * Notify the recovery handler that the physical layer has received less data then specified by the
 * command.  The received command has been discarded and any current command context should be
 * closed.
 *
 * @param device The recovery handler to update.
 */
void ocp_recovery_device_write_incomplete (const struct ocp_recovery_device *device)
{
	/* This has the same behavior as the overflow case. */
	ocp_recovery_device_write_overflow (device);
}
