// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "ocp_recovery_smbus.h"
#include "recovery_logging.h"
#include "common/unused.h"
#include "crypto/checksum.h"


/**
 * Initial value to use for the count of received bytes.
 */
#define	OCP_RECOVERY_SMBUS_NEW_COMMAND				-1

/**
 * Indicator that an invalid command code was received by the device.
 */
#define	OCP_RECOVERY_SMBUS_COMMAND_CODE_INVALID		-2

/**
 * Indicator that too much data has been received by the device.
 */
#define	OCP_RECOVERY_SMBUS_COMMAND_OVERFLOW			-3


/**
 * Initialize a OCP Recovery handler for the SMBus protocol layer.
 *
 * @param smbus The SMBus handler to initialize.
 * @param state Variable context for the SMBus handler.  This must not already be initialized.
 * @param device The device handler for the recovery protocol.
 *
 * @return 0 if the handler was successfully initialized or an error code.
 */
int ocp_recovery_smbus_init (struct ocp_recovery_smbus *smbus,
	struct ocp_recovery_smbus_state *state, const struct ocp_recovery_device *device)
{
	if ((smbus == NULL) || (state == NULL) || (device == NULL)) {
		return OCP_RECOVERY_SMBUS_INVALID_ARGUMENT;
	}

	memset (smbus, 0, sizeof (struct ocp_recovery_smbus));

	smbus->state = state;
	smbus->device = device;

	return ocp_recovery_smbus_init_state (smbus);
}

/**
 * Initialize only the variable state of an OCP Recovery SMBus handler.  The rest of the SMBus
 * handler structure is assumed to have already been initialized.
 *
 * This would generally be used with a statically initialized handler instance.
 *
 * @param smbus The SMBus handler containing the state to initialize.
 *
 * @return 0 if the handler state was successfully initialized or an error code.
 */
int ocp_recovery_smbus_init_state (const struct ocp_recovery_smbus *smbus)
{
	if ((smbus == NULL) || (smbus->state == NULL)) {
		return OCP_RECOVERY_SMBUS_INVALID_ARGUMENT;
	}

	memset (smbus->state, 0, sizeof (struct ocp_recovery_smbus_state));

	return 0;
}

/**
 * Release the resources used by an OCP Recovery SMBus protocol handler.
 *
 * @param smbus The SMBus handler to release.
 */
void ocp_recovery_smbus_release (const struct ocp_recovery_smbus *smbus)
{
	UNUSED (smbus);
}

/**
 * Notify the SMBus layer that a new transaction is starting.  This should only be called when
 * it is known that the transaction is targeting this device.
 *
 * @param smbus The SMBus handler to notify.
 * @param smbus_addr The SMBus address for this device.  This should be the 7-bit address with no
 * read/write bit.
 */
void ocp_recovery_smbus_start (const struct ocp_recovery_smbus *smbus, uint8_t smbus_addr)
{
	if (smbus == NULL) {
		return;
	}

	memset (smbus->state->cmd.bytes, 0, sizeof (smbus->state->cmd.bytes));
	smbus->state->rx_bytes = OCP_RECOVERY_SMBUS_NEW_COMMAND;
	smbus->state->crc = checksum_init_smbus_crc8 (smbus_addr << 1);
}

/**
 * Notify the SMBus layer that the current transaction has completed.  This should only be called
 * for transactions that were targeting this device.
 *
 * @param smbus The SMBus handler to notify.
 */
void ocp_recovery_smbus_stop (const struct ocp_recovery_smbus *smbus)
{
	bool pec_valid = true;
	int status;

	if (smbus == NULL) {
		return;
	}

	/* If no data was received, this was a block read command and there is nothing to do here. */
	if (smbus->state->rx_bytes > 0) {

		/* In order to have received a valid command, there needs to be at least the specified
		 * number of bytes plus an extra byte for the byte count value. */
		if (smbus->state->rx_bytes > smbus->state->cmd.block_cmd.byte_count) {

			/* If there is at least one extra byte, the command has a PEC byte. */
			if (smbus->state->rx_bytes >= (smbus->state->cmd.block_cmd.byte_count + 2)) {
				smbus->state->crc = checksum_update_smbus_crc8 (smbus->state->crc,
					smbus->state->cmd.bytes, smbus->state->cmd.block_cmd.byte_count + 1);

				/* The PEC byte will be the one immediately following the block command data. */
				if (smbus->state->crc !=
					smbus->state->cmd.bytes[smbus->state->cmd.block_cmd.byte_count + 1]) {
					pec_valid = false;
				}
			}

			if (pec_valid) {
				status = ocp_recovery_device_write_request (smbus->device,
					&smbus->state->cmd.block_cmd.payload, smbus->state->cmd.block_cmd.byte_count);
				if (status != 0) {
					debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_RECOVERY,
						RECOVERY_LOGGING_OCP_WRITE_ERROR, status, 0);
				}
			}
			else {
				ocp_recovery_device_checksum_failure (smbus->device);

				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_RECOVERY,
					RECOVERY_LOGGING_OCP_PEC_ERROR, smbus->state->crc,
					smbus->state->cmd.bytes[smbus->state->cmd.block_cmd.byte_count + 1]);
			}
		}
		else {
			ocp_recovery_device_write_incomplete (smbus->device);

			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_RECOVERY,
				RECOVERY_LOGGING_OCP_WRITE_INCOMPLETE, smbus->state->rx_bytes,
				smbus->state->cmd.block_cmd.byte_count);
		}
	}

	/* The message has been consumed, so reset the state for received data. */
	smbus->state->rx_bytes = OCP_RECOVERY_SMBUS_NEW_COMMAND;
}

/**
 * Notify the SMBus layer of a single byte of data received from the physical layer.
 *
 * @param smbus The SMBus handler to notify.
 * @param data The data that was received.
 *
 * @return 0 if the data was received successfully or an error code.  It is possible that this data
 * represents a command code that is invalid and the physical layer should NACK the data.  In that
 * case, OCP_RECOVERY_SMBUS_NACK will be returned.
 */
int ocp_recovery_smbus_receive_byte (const struct ocp_recovery_smbus *smbus, uint8_t data)
{
	int status;

	if (smbus == NULL) {
		return OCP_RECOVERY_DEVICE_INVALID_ARGUMENT;
	}

	if (smbus->state->rx_bytes <= OCP_RECOVERY_SMBUS_COMMAND_CODE_INVALID) {
		/* If the physical interface is not able to prevent additional data from being received for
		 * an invalid command, continue to inform the lower layer that the command is invalid and
		 * ignore it. */
		return OCP_RECOVERY_SMBUS_NACK;
	}
	else if (smbus->state->rx_bytes == OCP_RECOVERY_SMBUS_NEW_COMMAND) {
		/* The command code has not been received and processed yet. */
		smbus->state->crc = checksum_update_smbus_crc8 (smbus->state->crc, &data, 1);

		status = ocp_recovery_device_start_new_command (smbus->device, data);
		if (status != 0) {
			/* Mark the current command as invalid. */
			smbus->state->rx_bytes = OCP_RECOVERY_SMBUS_COMMAND_CODE_INVALID;
			return (status == OCP_RECOVERY_DEVICE_NACK) ? OCP_RECOVERY_SMBUS_NACK : 0;
		}
	}
	else if (smbus->state->rx_bytes < (int) sizeof (smbus->state->cmd.bytes)) {
		smbus->state->cmd.bytes[smbus->state->rx_bytes] = data;
	}
	else {
		/* Ignore the extra byte and notify the protocol handler that the command is not valid. */
		smbus->state->rx_bytes = OCP_RECOVERY_SMBUS_COMMAND_OVERFLOW;
		ocp_recovery_device_write_overflow (smbus->device);

		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_RECOVERY,
			RECOVERY_LOGGING_OCP_WRITE_OVERFLOW, 0, 0);

		return OCP_RECOVERY_SMBUS_OVERFLOW;
	}

	smbus->state->rx_bytes++;

	return 0;
}

/**
 * Notify the SMBus layer of a request to read data from the physical layer.
 *
 * @param smbus The SMBus handler to notify.
 * @param smbus_addr SMBus address for the device that will respond with data.  This should be the
 * 7-bit address with no Read/Write bit.
 * @param data Output for the buffer descriptor that will contain the data to send.  This buffer
 * should not be modified or released by the caller.
 *
 * @return 0 if the data to send was successfully generated or OCP_RECOVERY_SMBUS_INVALID_ARGUMENT
 * if either parameter is null.
 */
int ocp_recovery_smbus_transmit_bytes (const struct ocp_recovery_smbus *smbus, uint8_t smbus_addr,
	const union ocp_recovery_smbus_cmd_buffer **data)
{
	int bytes;

	if ((smbus == NULL) || (data == NULL)) {
		return OCP_RECOVERY_DEVICE_INVALID_ARGUMENT;
	}

	smbus_addr = (smbus_addr << 1) | 1;	// This is a read request, so set the read bit.
	smbus->state->crc = checksum_update_smbus_crc8 (smbus->state->crc, &smbus_addr, 1);

	bytes = ocp_recovery_device_read_request (smbus->device, &smbus->state->cmd.block_cmd.payload);
	if (!ROT_IS_ERROR (bytes)) {
		smbus->state->cmd.block_cmd.byte_count = bytes;
	}
	else {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_RECOVERY,
			RECOVERY_LOGGING_OCP_READ_ERROR, bytes, 0);

		/* On a failure, generate an empty response. */
		smbus->state->cmd.block_cmd.byte_count = 0;
		bytes = 0;
	}

	/* Calculate the final PEC.  The PEC will immediately following the last byte of payload. */
	smbus->state->cmd.bytes[bytes + 1] = checksum_update_smbus_crc8 (smbus->state->crc,
		smbus->state->cmd.bytes, bytes + 1);

	*data = &smbus->state->cmd;

	return 0;
}
