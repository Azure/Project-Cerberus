// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <string.h>
#include "authorized_execution_prepare_firmware_update.h"
#include "platform_api.h"
#include "cmd_interface/config_reset.h"
#include "common/buffer_util.h"
#include "common/unused.h"
#include "firmware/firmware_logging.h"


#pragma pack(push, 1)

/**
 * Data payload necessary for executing authorized preparation for firmware update.
 */
struct authorized_execution_prepare_firmware_update_payload {
	uint32_t marker;		/**< Magic number on the payload. */
	uint32_t img_length;	/**< Total length of the image data that will be sent. */
	uint8_t hash_type;		/**< Hash algorithm used for image digest generation. */
	uint8_t digest;			/**< First byte of the variable length image digest. */
};

/**
 * Magic number expected on valid payloads.
 */
#define	AUTHORIZED_EXECUTION_PREPARE_FIRMWARE_UPDATE_MARKER		0x46575550

/**
 * Get the length of the digest in the authorized payload.
 *
 * @param len Total length of the data payload.
 *
 * @return Length of the digest field.
 */
#define	authorized_execution_prepare_firmware_update_digest_length(len)     \
	((len) - (sizeof (struct authorized_execution_prepare_firmware_update_payload) - 1))

/**
 * Hash algorithms that can be used to generate the image digest.
 */
enum {
	AUTHORIZED_EXECUTION_PREPARE_FIRMWARE_UPDATE_SHA256 = 0,	/**< Digest uses SHA-256. */
	AUTHORIZED_EXECUTION_PREPARE_FIRMWARE_UPDATE_SHA384 = 1,	/**< Digest uses SHA-384. */
	AUTHORIZED_EXECUTION_PREPARE_FIRMWARE_UPDATE_SHA512 = 2,	/**< Digest uses SHA-512. */
};

#pragma pack(pop)


/**
 * Validate and parse the authorized payload to prepare firmware update.
 *
 * @param execution The execution context being used to parse the data.
 * @param payload The payload data to validate and parse.
 * @param length Length of the payload data.
 * @param hash_type Output for the hash algorithm used for the image digest.
 * @param digest_length Output for the image digest length.
 *
 * @return 0 if the payload is valid or an error code.
 */
static int authorized_execution_prepare_firmware_update_parse_payload (
	const struct authorized_execution *execution,
	const struct authorized_execution_prepare_firmware_update_payload *payload, size_t length,
	enum hash_type *hash_type, size_t *digest_length)
{
	if ((execution == NULL) || (payload == NULL)) {
		return AUTHORIZED_EXECUTION_INVALID_ARGUMENT;
	}

	if (length < sizeof (*payload)) {
		return AUTHORIZED_EXECUTION_DATA_NOT_VALID;
	}

	if (buffer_unaligned_read32 (&payload->marker) !=
		AUTHORIZED_EXECUTION_PREPARE_FIRMWARE_UPDATE_MARKER) {
		return AUTHORIZED_EXECUTION_DATA_NOT_VALID;
	}

	switch (payload->hash_type) {
		case AUTHORIZED_EXECUTION_PREPARE_FIRMWARE_UPDATE_SHA256:
			*hash_type = HASH_TYPE_SHA256;
			break;

		case AUTHORIZED_EXECUTION_PREPARE_FIRMWARE_UPDATE_SHA384:
			*hash_type = HASH_TYPE_SHA384;
			break;

		case AUTHORIZED_EXECUTION_PREPARE_FIRMWARE_UPDATE_SHA512:
			*hash_type = HASH_TYPE_SHA512;
			break;

		default:
			return AUTHORIZED_EXECUTION_DATA_NOT_VALID;
	}

	*digest_length = authorized_execution_prepare_firmware_update_digest_length (length);
	if ((int) *digest_length != hash_get_hash_length (*hash_type)) {
		return AUTHORIZED_EXECUTION_DATA_NOT_VALID;
	}

	return 0;
}

int authorized_execution_prepare_firmware_update_execute (
	const struct authorized_execution *execution, const uint8_t *data, size_t length,
	bool *reset_req)
{
	const struct authorized_execution_prepare_firmware_update *prep =
		(const struct authorized_execution_prepare_firmware_update*) execution;
	const struct authorized_execution_prepare_firmware_update_payload *payload =
		(const struct authorized_execution_prepare_firmware_update_payload*) data;
	enum hash_type hash_type;
	size_t digest_length;
	platform_clock wait_timeout;
	int status;

	UNUSED (reset_req);

	status = authorized_execution_prepare_firmware_update_parse_payload (execution, payload, length,
		&hash_type, &digest_length);
	if (status != 0) {
		return status;
	}

	if (prep->timeout_ms != 0) {
		status = platform_init_timeout (prep->timeout_ms, &wait_timeout);
		if (status != 0) {
			return status;
		}
	}

	/* Start update prepare handling. */
	status = prep->fw_update->prepare_staging (prep->fw_update,
		buffer_unaligned_read32 (&payload->img_length));
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CERBERUS_FW,
			FIRMWARE_LOGGING_AUTHORIZED_PREPARE_FAIL, status, 0);

		return status;
	}

	/* Wait for update prepare to complete. */
	do {
		/* Wait for some time before checking the status. */
		platform_msleep (25);

		status = prep->fw_update->get_status (prep->fw_update);
	} while (((status == UPDATE_STATUS_STARTING) || (status == UPDATE_STATUS_STAGING_PREP)) &&
		((prep->timeout_ms == 0) || (platform_has_timeout_expired (&wait_timeout) == 0)));

	if (status != UPDATE_STATUS_SUCCESS) {
		if ((status == UPDATE_STATUS_STARTING) || (status == UPDATE_STATUS_STAGING_PREP)) {
			/* The prepare handling has not completed, but the timeout expired.  Log the failure. */
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CERBERUS_FW,
				FIRMWARE_LOGGING_AUTHORIZED_PREPARE_FAIL, AUTHORIZED_EXECUTION_EXECUTE_FAILED, 0);

			/* TODO:  This doesn't actually solve any problem that may be causing the firmware
			 * handler to be stuck.  It just prevents this task from also being stuck.  It would be
			 * good to have some way to clean up from this case.  Perhaps this could just be handled
			 * with some generic task watchdog at a system level. */
		}
		else {
			/* The prepare handling completed unsuccessfully.  No need to log any message here since
			 * that would be done be the update handler. */
		}

		return AUTHORIZED_EXECUTION_EXECUTE_FAILED;
	}

	/* Set the expected digest of the update data. */
	status = prep->fw_update->set_image_digest (prep->fw_update, hash_type, &payload->digest,
		digest_length);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CERBERUS_FW,
			FIRMWARE_LOGGING_AUTHORIZED_PREPARE_FAIL, status, 0);
	}

	return status;
}

int authorized_execution_prepare_firmware_update_validate_data (
	const struct authorized_execution *execution, const uint8_t *data, size_t length)
{
	const struct authorized_execution_prepare_firmware_update_payload *payload =
		(const struct authorized_execution_prepare_firmware_update_payload*) data;
	enum hash_type hash_type;
	size_t digest_length;

	return authorized_execution_prepare_firmware_update_parse_payload (execution, payload, length,
		&hash_type, &digest_length);
}

void authorized_execution_prepare_firmware_update_get_status_identifiers (
	const struct authorized_execution *execution, uint8_t *start, uint8_t *error)
{
	UNUSED (execution);

	if (start) {
		*start = CONFIG_RESET_STATUS_AUTHORIZED_OPERATION;
	}

	if (error) {
		*error = CONFIG_RESET_STATUS_AUTHORIZED_OP_FAILED;
	}
}

/**
 * Initialize an authorized execution context to prepare the device to receive a firmware update.
 *
 * @param execution The firmware update execution context to initialize.
 * @param fw_update Control interface for managing the firmware update.
 * @param prepare_timeout_ms The amount of time to wait for update preparation to complete, in
 * milliseconds.  If this is 0, there is no timeout for the operation.
 *
 * @return 0 if the execution context was initialized successfully or an error code.
 */
int authorized_execution_prepare_firmware_update_init (
	struct authorized_execution_prepare_firmware_update *execution,
	const struct firmware_update_control *fw_update, uint32_t prepare_timeout_ms)
{
	if ((execution == NULL) || (fw_update == NULL)) {
		return AUTHORIZED_EXECUTION_INVALID_ARGUMENT;
	}

	memset (execution, 0, sizeof (*execution));

	execution->base.execute = authorized_execution_prepare_firmware_update_execute;
	execution->base.validate_data = authorized_execution_prepare_firmware_update_validate_data;
	execution->base.get_status_identifiers =
		authorized_execution_prepare_firmware_update_get_status_identifiers;

	execution->fw_update = fw_update;
	execution->timeout_ms = prepare_timeout_ms;

	return 0;
}

/**
 * Release the resourced used for authorized prepare firmware update execution.
 *
 * @param execution The firmware update execution context to release.
 */
void authorized_execution_prepare_firmware_update_release (
	const struct authorized_execution_prepare_firmware_update *execution)
{
	UNUSED (execution);
}
