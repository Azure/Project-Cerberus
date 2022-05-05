// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef OCP_RECOVERY_DEVICE_H_
#define OCP_RECOVERY_DEVICE_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "status/rot_status.h"
#include "ocp_recovery.h"


/**
 * Length marker to use indicating a variable CMS that using an API instance to get the data.
 */
#define	OCP_RECOVERY_DEVICE_CMS_LENGTH_VARIABLE		0

/**
 * Interface to read data from a CMS that is variable is some why.  It may be a variable-length
 * region, such as a log.  It may be a region whose data is not directly accessible in memory, in
 * which case this would act as an adapter to get this information.
 *
 * This interface only supports read-only regions of data.
 */
struct ocp_recovery_device_variable_cms {
	/**
	 * Get the size of the data contained in the CMS.
	 *
	 * @param cms The CMS to query.
	 *
	 * @return Length of the data in the CMS or an error code.  Use ROT_IS_ERROR to check the return
	 * value.
	 */
	int (*get_size) (const struct ocp_recovery_device_variable_cms *cms);

	/**
	 * Get the data contained within the CMS.
	 *
	 * @param cms The CMS to query.
	 * @param offset The offset within the CMS to start reading.
	 * @param data Output buffer that will hold the contents of the CMS.
	 * @param length The maximum length of the data that should be read.
	 *
	 * @return The number of bytes read from the CMS or an error code.  Use ROT_IS_ERROR to check
	 * the return value.
	 */
	int (*get_data) (const struct ocp_recovery_device_variable_cms *cms, size_t offset,
		uint8_t *data, size_t length);
};

/**
 * Defines a region of memory that is accessible through the recovery interface.  The OCP Recovery
 * spec refers to these regions as Component Memory Spaces (CMS).
 *
 * NOTE:  Polling regions are not supported by this implementation.
 */
struct ocp_recovery_device_cms {
	union {
		uint8_t *base_addr;											/**< The base address for a fixed-length region of memory. */
		const struct ocp_recovery_device_variable_cms *variable;	/**< Log interface for the memory region.  Must be a RO region. */
	};
	/**
	 * Size of the memory that is accessible, in bytes.
	 *
	 * This must be 4-byte aligned if the region is writable.  It should be 4-byte aligned in all
	 * cases. A length of 0 indicates a variable length region using the variable interface.  When
	 * using a variable interface, it is best if the data will always be 4-byte aligned.
	 */
	size_t length;
	enum ocp_recovery_region_type type;								/**< The type of memory region that is exposed. */
};

#pragma pack(push, 1)
/**
 * Define a vender-specific status format that will be reported in DEVICE_STATUS messages.
 */
struct ocp_recovery_device_status_vendor {
	uint8_t failure_id;						/**< Identifier indicating the overall failure condition. */
	uint32_t error_code;					/**< Specific error code of the failure. */
};

/**
 * The buffer for sending and receiving OCP Recovery commands.
 */
union ocp_recovery_device_cmd_buffer {
	struct ocp_recovery_prot_cap prot_cap;					/**< The PROT_CAP command structure. */
	struct ocp_recovery_device_id device_id;				/**< The DEVICE_ID command structure. */
	struct ocp_recovery_device_status device_status;		/**< The DEVICE_STATUS command structure. */
	struct ocp_recovery_reset reset;						/**< The RESET command structure. */
	struct ocp_recovery_recovery_ctrl recovery_ctrl;		/**< The RECOVERY_CTRL command structure. */
	struct ocp_recovery_recovery_status recovery_status;	/**< The RECOVERY_STATUS command structure. */
	struct ocp_recovery_indirect_ctrl indirect_ctrl;		/**< The INDIRECT_CTRL command structure. */
	struct ocp_recovery_indirect_status indirect_status;	/**< The INDIRECT_STATUS command structure. */
	struct ocp_recovery_indirect_data indirect_data;		/**< The INDIRECT_DATA command structure. */
	uint8_t bytes[255];										/**< Raw byte access to the command bytes. */
};
#pragma pack(pop)

/**
 * Interface to the device hardware to execute certain recovery operations.
 */
struct ocp_recovery_device_hw {
	/**
	 * Get the device identifier to provide through the recovery interface.
	 *
	 * This is a required command per the OCP Recovery spec and cannot be null.
	 *
	 * @param recovery_hw The HW interface to query.
	 * @param id Output buffer for the device ID information.
	 *
	 * @return The number of bytes written to the device ID buffer or an error code.
	 */
	int (*get_device_id) (const struct ocp_recovery_device_hw *recovery_hw,
		struct ocp_recovery_device_id *id);

	/**
	 * Get the current device status.
	 *
	 * This is a required command per the OCP Recovery spec and cannot be null.
	 *
	 * @param recovery_hw The HW interface to query.
	 * @param status_code The current overall device status.
	 * @param reason_code The reason why the device is currently in recovery mode.  If it is not in
	 * recovery mode, this should be set to OCP_RECOVERY_DEVICE_STATUS_REC_NO_FAILURE.
	 * @param vendor Detailed error status using RoT error codes.
	 */
	void (*get_device_status) (const struct ocp_recovery_device_hw *recovery_hw,
		enum ocp_recovery_device_status_code *status_code,
		enum ocp_recovery_recovery_reason_code *reason_code,
		struct ocp_recovery_device_status_vendor *vendor);

	/**
	 * Execute a full device reset.  This is likely to be disruptive to any bus activities.  This
	 * call will not return.
	 *
	 * This call will be null if this operation is not supported.
	 *
	 * @param recovery_hw The HW interface that will execute the reset.
	 * @param forced_recovery Flag indicating if the device should be forced into recovery mode upon
	 * reset.  If forced recovery is not supported, this parameter will be ignored.
	 */
	void (*reset_device) (const struct ocp_recovery_device_hw *recovery_hw, bool forced_recovery);

	/**
	 * Execute a reset of the device management entity only.  This must not disrupt any bus
	 * operations, such as PCIe.  This call will not return if the handler is running in the same
	 * processor as the management entity.
	 *
	 * This call will be null if this operation is not supported.
	 *
	 * @param recovery_hw The HW interface that will execute the reset.
	 * @param forced_recovery Flag indicating if the device should be forced into recovery mode upon
	 * reset.  If forced recovery is not supported, this parameter will be ignored.
	 */
	void (*reset_management) (const struct ocp_recovery_device_hw *recovery_hw,
		bool forced_recovery);

	/**
	 * Validate and prepare a recovery image for execution.  The recovery image will written to a
	 * memory region exposed through the recovery interface.
	 *
	 * This call will be null if this operation is not supported.
	 *
	 * @param recovery_hw The HW interface that will activate the recovery image.
	 * @param recovery The memory region that contains the recovery image to activate.
	 * @param is_auth_error Optional output flag for the error case indicating there was an
	 * authentication error of the recovery image.  On success, this output is not specified.
	 *
	 * @return 0 if recovery image was successfully activated or an error code.
	 */
	int (*activate_recovery) (const struct ocp_recovery_device_hw *recovery_hw,
		const struct ocp_recovery_device_cms *recovery, bool *is_auth_error);

	/**
	 * Flag indicating if forced recovery is supported.
	 */
	bool supports_forced_recovery;
};

/**
 * Variable context for the OCP Recovery device handler.
 */
struct ocp_recovery_device_state {
	uint8_t active_cmd;									/**< The current command being received. */
	uint8_t protocol_status;							/**< The current device protocol status. */
	uint8_t recovery_status;							/**< The current device recovery status. */
	uint8_t indirect_status;							/**< The current device indirect status. */
	struct ocp_recovery_reset reset;					/**< Current state of reset control data. */
	struct ocp_recovery_recovery_ctrl recovery_ctrl;	/**< Current state of recovery control data. */
	struct ocp_recovery_indirect_ctrl indirect_ctrl;	/**< Current state of the indirect control data. */
};

/**
 * Device-side handler for the OCP Recovery protocol.
 */
struct ocp_recovery_device {
	struct ocp_recovery_device_state *state;			/**< The variable context for the handler. */
	const struct ocp_recovery_device_hw *hw;			/**< HW interface to the device. */
	const struct ocp_recovery_device_cms *cms;			/**< Memory regions available for recovery commands. */
	size_t cms_count;									/**< Number of memory regions supported. */
};


/**
 * Initialize a static instance of an OCP Recovery handler.  This does not initialize the handler
 * state.  That will need to be initialized separately with ocp_recovery_device_init_state.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr The recovery state to initialize.  This must not already be initialized.
 * @param hw_ptr The HW interface for executing device actions in response to recovery commands.
 * This can be a constant instance.
 * @param cms_list A list of memory regions that are accessible through the recovery handler.  This
 * can be null if there are no supported regions.
 * @param count The number of memory regions in the list.
 */
#define	ocp_recovery_device_static_init(state_ptr, hw_ptr, cms_list, count)	{ \
		.state = state_ptr, \
		.hw = hw_ptr, \
		.cms = cms_list, \
		.cms_count = count \
	}

int ocp_recovery_device_init (struct ocp_recovery_device *device,
	struct ocp_recovery_device_state *state, const struct ocp_recovery_device_hw *hw,
	const struct ocp_recovery_device_cms *cms_list, size_t cms_count);
int ocp_recovery_device_init_state (const struct ocp_recovery_device *device);
void ocp_recovery_device_release (const struct ocp_recovery_device *device);

int ocp_recovery_device_start_new_command (const struct ocp_recovery_device *device,
	uint8_t command_code);

int ocp_recovery_device_write_request (const struct ocp_recovery_device *device,
	const union ocp_recovery_device_cmd_buffer *data, size_t length);
int ocp_recovery_device_read_request (const struct ocp_recovery_device *device,
	union ocp_recovery_device_cmd_buffer *data);

void ocp_recovery_device_checksum_failure (const struct ocp_recovery_device *device);
void ocp_recovery_device_write_overflow (const struct ocp_recovery_device *device);
void ocp_recovery_device_write_incomplete (const struct ocp_recovery_device *device);


#define	OCP_RECOVERY_DEVICE_ERROR(code)		ROT_ERROR (ROT_MODULE_OCP_RECOVERY_DEVICE, code)

/**
 * Error codes that can be generated by an OCP recovery device handler.
 */
enum {
	OCP_RECOVERY_DEVICE_INVALID_ARGUMENT = OCP_RECOVERY_DEVICE_ERROR (0x00),	/**< Input parameter is null or not valid. */
	OCP_RECOVERY_DEVICE_NO_MEMORY = OCP_RECOVERY_DEVICE_ERROR (0x01),			/**< Memory allocation failed. */
	OCP_RECOVERY_DEVICE_GET_DEV_ID_FAILED = OCP_RECOVERY_DEVICE_ERROR (0x02),	/**< Failed to get the current device's identifier. */
	OCP_RECOVERY_DEVICE_ACTIVATE_REC_FAILED = OCP_RECOVERY_DEVICE_ERROR (0x03),	/**< Failure activating a recovery image. */
	OCP_RECOVERY_DEVICE_NACK = OCP_RECOVERY_DEVICE_ERROR (0x04),				/**< A NACK must be generated on the physical bus. */
	OCP_RECOVERY_DEVICE_NO_ACTIVE_COMMAND = OCP_RECOVERY_DEVICE_ERROR (0x05),	/**< No recovery command has been started. */
	OCP_RECOVERY_DEVICE_RO_COMMAND = OCP_RECOVERY_DEVICE_ERROR (0x06),			/**< A write was accepted for a RO command. */
	OCP_RECOVERY_DEVICE_UNSUPPORTED = OCP_RECOVERY_DEVICE_ERROR (0x07),			/**< The requested operation is unsupported by the device. */
	OCP_RECOVERY_DEVICE_CMD_INCOMPLETE = OCP_RECOVERY_DEVICE_ERROR (0x08),		/**< Not enough data was sent for the command. */
	OCP_RECOVERY_DEVICE_CMS_NOT_CODE_REGION = OCP_RECOVERY_DEVICE_ERROR (0x09),	/**< A memory region used for recovery is not a code region. */
	OCP_RECOVERY_DEVICE_UNSUPPORTED_CMS = OCP_RECOVERY_DEVICE_ERROR (0x0a),		/**< An unsupported CMS was requested. */
	OCP_RECOVERY_DEVICE_RO_CMS = OCP_RECOVERY_DEVICE_ERROR (0x0b),				/**< Received a write request for a RO CMS. */
	OCP_RECOVERY_DEVICE_RW_CMS_NOT_ALIGNED = OCP_RECOVERY_DEVICE_ERROR (0x0c),	/**< A RW CMS is not 4-byte aligned. */
	OCP_RECOVERY_DEVICE_RW_LOG = OCP_RECOVERY_DEVICE_ERROR (0x0d),				/**< A CMS with a logging interface was set as RW. */
	OCP_RECOVERY_DEVICE_UNSUPPORTED_PARAM = OCP_RECOVERY_DEVICE_ERROR (0x0e),	/**< Received a valid operation with an unsupported parameter. */
	OCP_RECOVERY_DEVICE_EXTRA_CMD_BYTES = OCP_RECOVERY_DEVICE_ERROR (0x0f),		/**< Too much data was sent for the command. */
	OCP_RECOVERY_DEVICE_CMS_SIZE_FAILED = OCP_RECOVERY_DEVICE_ERROR (0x10),		/**< Could not determine the size of a variable CMS. */
	OCP_RECOVERY_DEVICE_CMS_DATA_FAILED = OCP_RECOVERY_DEVICE_ERROR (0x11),		/**< Failed to read data from a variable CMS. */
};


#endif /* OCP_RECOVERY_DEVICE_H_ */
