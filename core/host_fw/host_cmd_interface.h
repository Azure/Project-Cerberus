// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_CMD_INTERFACE_H_
#define HOST_CMD_INTERFACE_H_

#include <stdint.h>
#include "host_processor.h"
#include "host_state_manager.h"
#include "spi_filter/spi_filter_interface.h"


/**
 * Status codes for host processor operations.
 */
enum host_cmd_status {
	HOST_CMD_STATUS_SUCCESS = 0,			/**< Successful operation. */
	HOST_CMD_STATUS_STARTING,				/**< The host operation is starting. */
	HOST_CMD_STATUS_REQUEST_BLOCKED,		/**< A request has been made before the previous one finished. */
	HOST_CMD_STATUS_NONE_STARTED,			/**< No host operation has been started. */
	HOST_CMD_STATUS_TASK_NOT_RUNNING,		/**< The task servicing host operations is not running. */
	HOST_CMD_STATUS_UNKNOWN,				/**< The host operation status could not be determined. */
	HOST_CMD_STATUS_INTERNAL_ERROR,			/**< An unspecified, internal error occurred. */
	HOST_CMD_STATUS_START_FLASH_CONFIG,		/**< The host flash configuration is being updated. */
	HOST_CMD_STATUS_FLASH_CONFIG_FAILED,	/**< There was an error updating the host flash configuration. */
};

/**
 * Make a status value suitable to be returned by get_status.
 *
 * @param status The status per host_cmd_status.
 * @param error The error code for the operation.
 */
#define	HOST_CMD_STATUS(status, error)	(((error & 0xffffff) << 8) | status)


/**
 * Defines the API for handling commands for host processor management.
 */
struct host_cmd_interface {
	/**
	 * Get the next verification actions that will be taken for a host during the next reset event.
	 *
	 * This request will be handled synchronously.
	 *
	 * @param cmd The host handler to query.
	 * @param action Output for the pending host verification actions.
	 *
	 * @return 0 if the actions were successfully determined or an error code.
	 */
	int (*get_next_host_verification) (const struct host_cmd_interface *cmd,
		enum host_processor_reset_actions *action);

	/**
	 * Get the current configuration used for protecting and managing the host flash.
	 *
	 * This request will be handled synchronously.
	 *
	 * @param cmd The host handler to query.
	 * @param mode Output for the current flash management mode.
	 * @param current_ro Output for the flash that is currently designated as the read-only flash
	 * for the host.
	 * @param next_ro Output for the flash that will be designated as the read-only flash during the
	 * next host verification event.
	 * @param apply_next_ro Output for the host events that will trigger the next read-only flash to
	 * be get used.
	 */
	int (*get_flash_configuration) (const struct host_cmd_interface *cmd,
		spi_filter_flash_mode *mode, spi_filter_cs *current_ro, spi_filter_cs *next_ro,
		enum host_read_only_activation *apply_next_ro);

	/**
	 * Request a change to the current or future configuration used for protecting and managing the
	 * host flash.
	 *
	 * This call will return immediately, with the request will being handled asynchronously.
	 * Results are reporting through the host_cmd_interface.get_status() call.
	 *
	 * @param cmd The handler for the host whose flash configuration should be changed.
	 * @param current_ro The flash device that should immediately be used as the read-only flash.
	 * If this is negative, the flash device will not be changed.  If non-negative, this must map to
	 * valid spi_filter_cs values, but will not be validated by the handler.
	 * @param next_ro The flash device that should be made the read-only flash during the next host
	 * verification operation.  If this is negative, the next flash will not be changed.  If
	 * non-negative, this must map to valid spi_filter_cs values, but will not be validated by the
	 * handler.
	 * @param apply_next_ro The host verification events that should trigger a switch of the
	 * read-only flash.  If this is negative, the setting will not be changed.  If non-negative,
	 * this must map to valid enum host_read_only_activation values, but will not be validated by
	 * the handler.
	 *
	 * @return 0 if the request was submitted successfully or an error code.
	 */
	int (*set_flash_configuration) (const struct host_cmd_interface *cmd, int8_t current_ro,
		int8_t next_ro, int8_t apply_next_ro);

	/**
	 * Get the status of the last asynchronous host operation that was requested.
	 *
	 * @param cmd the host handler to query.
	 *
	 * @return The host operation status. The lower 8 bits will be the operation status as per
	 * enum host_cmd_status. The remaining bits will be the return code from the host operation.
	 */
	int (*get_status) (const struct host_cmd_interface *cmd);
};


#endif	/* HOST_CMD_INTERFACE_H_ */
