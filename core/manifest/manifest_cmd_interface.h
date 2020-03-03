// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MANIFEST_CMD_INTERFACE_H_
#define MANIFEST_CMD_INTERFACE_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>


/**
 * Status codes for manifest operations. MAKE SURE IN SYNC WITH tools\cerberus_utility\cerberus_utility_commands.h!!
 */
enum manifest_cmd_status {
	MANIFEST_CMD_STATUS_SUCCESS = 0,				/**< Successful operation. */
	MANIFEST_CMD_STATUS_STARTING,					/**< The manifest operation is starting. */
	MANIFEST_CMD_STATUS_REQUEST_BLOCKED,			/**< A request has been made before the previous one finished. */
	MANIFEST_CMD_STATUS_PREPARE,					/**< The manifest is being prepared for updating. */
	MANIFEST_CMD_STATUS_PREPARE_FAIL,				/**< There was an error preparing the manifest for updating. */
	MANIFEST_CMD_STATUS_STORE_DATA,					/**< New manifest data is being stored. */
	MANIFEST_CMD_STATUS_STORE_FAIL,					/**< There was an error storing manifest data. */
	MANIFEST_CMD_STATUS_VALIDATION,					/**< The new manifest is being validated. */
	MANIFEST_CMD_STATUS_VALIDATE_FAIL,				/**< There was an error validating the new manifest. */
	MANIFEST_CMD_STATUS_INTERNAL_ERROR,				/**< An unspecified, internal error occurred. */
	MANIFEST_CMD_STATUS_NONE_STARTED,				/**< No manifest operation has been started. */
	MANIFEST_CMD_STATUS_TASK_NOT_RUNNING,			/**< The task servicing manifest operations is not running. */
	MANIFEST_CMD_STATUS_UNKNOWN,					/**< The manifest status could not be determined. */
	MANIFEST_CMD_STATUS_ACTIVATING,					/**< Activation is being attempted for a new manifest. */
	MANIFEST_CMD_STATUS_ACTIVATION_FAIL,			/**< There was an error activating the new manifest. */
	MANIFEST_CMD_STATUS_ACTIVATION_PENDING,			/**< Validation was successful, but activation requires a host reboot. */
	MANIFEST_CMD_STATUS_ACTIVATION_FLASH_ERROR,		/**< An error occurred during activation that prevents host access to flash. */
};

/**
 * Make a status value suitable to be returned by get_status.
 *
 * @param status The status per manifest_cmd_status.
 * @param error The error code for the operation.
 */
#define	MANIFEST_CMD_STATUS(status, error)	(((error & 0xffffff) << 8) | status)


/**
 * Defines the API to handle commands for a single manifest.
 */
struct manifest_cmd_interface {
	/**
	 * Trigger the system to prepare for receiving new manifest data. This will return immediately,
	 * with the status of the operation being reported separately.
	 *
	 * @param cmd The command interface for the manifest instance to prepare for update.
	 * @param manifest_size Size of incoming manifest
	 *
	 * @return 0 if the action was successfully triggered or an error code.
	 */
	int (*prepare_manifest) (struct manifest_cmd_interface *cmd, uint32_t manifest_size);

	/**
	 * Indicate that new manifest data should be stored. This will return immediately, with the
	 * status of the operation being reported separately.
	 *
	 * @param cmd The command interface for the manifest to store.
	 * @param data The manifest data to store.
	 * @param length The number manifest data bytes to store.
	 *
	 * @return 0 if the action was successfully triggered or an error code.
	 */
	int (*store_manifest) (struct manifest_cmd_interface *cmd, const uint8_t *data, size_t length);

	/**
	 * Indicate that a complete manifest has been received and should be validated. This will return
	 * immediately, with the status of the operation being reported separately.
	 *
	 * @param cmd The command interface for the manifest instance to verify.
	 * @param activate Flag indicating if validation with the new manifest should be immediately
	 * performed.
	 *
	 * @return 0 if the action was successfully triggered or an error code.
	 */
	int (*finish_manifest) (struct manifest_cmd_interface *cmd, bool activate);

	/**
	 * Get the status of the last manifest operation requested.
	 *
	 * @param cmd The command interface for the manifest to query.
	 *
	 * @return The manifest operation status. The lower 8 bits will be the operation status as per
	 * enum manifest_cmd_status. The remaining bits will be the return code from the manifest
	 * operation.
	 */
	int (*get_status) (struct manifest_cmd_interface *cmd);
};


#endif /* MANIFEST_CMD_INTERFACE_H_ */
