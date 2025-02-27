// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef TDISP_DRIVER_H_
#define TDISP_DRIVER_H_

#include "tdisp_protocol.h"
#include "cmd_interface/cmd_interface.h"
#include "status/rot_status.h"


/**
 * TDISP driver interface.
 */
struct tdisp_driver {
	/**
	 * Get the TDISP device capabilities.
	 *
	 * @param tdisp_driver The TDISP driver interface to query.
	 * @param req_caps The received requester capabilities.
	 * @param rsp_caps The responder capabilities to fill.
	 *
	 * @return 0 if the information was successfully filled or an error code.
	 */
	int (*get_tdisp_capabilities) (const struct tdisp_driver *tdisp_driver,
		const struct tdisp_requester_capabilities *req_caps,
		struct tdisp_responder_capabilities *rsp_caps);

	/**
	 * Lock the device interface.
	 *
	 * @param tdisp_driver The TDISP driver interface to query.
	 * @param function_id The device interface function Id.
	 * @param lock_interface_param Parameters from lock interface request.
	 *
	 * @return 0 if the interface was locked successfully or an error code.
	 */
	int (*lock_interface_request) (const struct tdisp_driver *tdisp_driver, uint32_t function_id,
		const struct tdisp_lock_interface_param *lock_interface_param);

	/**
	 * Get the device interface report.
	 *
	 * @param tdisp_driver The TDISP driver interface to query.
	 * @param function_id The device interface function Id.
	 * @param request_offset The requested offset of the report.
	 * @param request_length The requested length of the report.
	 * @param report_length On input, length of the interface_report buffer.
	 * On output, the length of the returned report.
	 * @param interface_report The device interface report buffer.
	 * @param remainder_length The length of the remainder of the report.
	 *
	 * @return 0 if device interface report was returned successfully or an error code.
	 */
	int (*get_device_interface_report) (const struct tdisp_driver *tdisp_driver,
		uint32_t function_id, uint16_t request_offset, uint16_t request_length,
		uint16_t *report_length, uint8_t *interface_report, uint16_t *remainder_length);

	/**
	 * Get the device interface state.
	 *
	 * @param tdisp_driver The TDISP driver interface to query.
	 * @param function_id The device interface function Id.
	 * @param tdi_state Device interface state.
	 *
	 * @return 0 if the state was returned successfully or an error code.
	 */
	int (*get_device_interface_state) (const struct tdisp_driver *tdisp_driver,
		uint32_t function_id, uint8_t *tdi_state);

	/**
	 * Start the requested device interface.
	 *
	 * @param tdisp_driver The TDISP driver interface to query.
	 * @param function_id The function Id of the device interface to start.
	 *
	 * @return 0 if the device interface was started successfully or an error code.
	 */
	int (*start_interface_request) (const struct tdisp_driver *tdisp_driver, uint32_t function_id);

	/**
	 * Stop the requested device interface.
	 *
	 * @param tdisp_driver The TDISP driver interface to query.
	 * @param function_id The function Id of the device interface to stop.
	 *
	 * @return 0 if the device interface was stopped successfully or an error code.
	 */
	int (*stop_interface_request) (const struct tdisp_driver *tdisp_driver, uint32_t function_id);

	/**
	 * Get the MMIO ranges for the device interface.
	 *
	 * @param tdisp_driver The TDISP driver interface to query.
	 * @param function_id The device interface function Id.
	 * @param mmio_range_count The count of mmio ranges to return.
	 * @param mmio_ranges Returned mmio ranges.
	 *
	 * @return 0 if the mmio ranges were returned successfully or an error code.
	 */
	int (*get_mmio_ranges) (const struct tdisp_driver *tdisp_driver, uint32_t function_id,
		uint32_t mmio_range_count, struct tdisp_mmio_range *mmio_ranges);
};


#define	TDISP_DRIVER_ERROR(code)	ROT_ERROR (ROT_MODULE_TDISP_DRIVER, code)

/**
 * Error codes that can be generated by the TDISP driver interface.
 */
enum {
	TDISP_DRIVER_INVALID_ARGUMENT = TDISP_DRIVER_ERROR (0x00),						/**< Input parameter is null or not valid. */
	TDISP_DRIVER_NO_MEMORY = TDISP_DRIVER_ERROR (0x01),								/**< Memory allocation failed. */
	TDISP_DRIVER_GET_TDISP_CAPABILITIES_FAILED = TDISP_DRIVER_ERROR (0x02),			/**< The driver failed to get the TDISP capabilities. */
	TDISP_DRIVER_GET_DEVICE_INTERFACE_STATE_FAILED = TDISP_DRIVER_ERROR (0x03),		/**< The driver failed to get the device interface state. */
	TDISP_DRIVER_LOCK_INTERFACE_REQUEST_FAILED = TDISP_DRIVER_ERROR (0x04),			/**< The driver failed to lock the device interface. */
	TDISP_DRIVER_START_INTERFACE_REQUEST_FAILED = TDISP_DRIVER_ERROR (0x05),		/**< The driver failed to start the device interface. */
	TDISP_DRIVER_STOP_INTERFACE_REQUEST_FAILED = TDISP_DRIVER_ERROR (0x06),			/**< The driver failed to stop the device interface. */
	TDISP_DRIVER_GET_DEVICE_INTERFACE_REPORT_FAILED = TDISP_DRIVER_ERROR (0x07),	/**< The driver failed to get the device interface report. */
	TDISP_DRIVER_GET_MMIO_RANGES_FAILED = TDISP_DRIVER_ERROR (0x08),				/**< The driver failed to get the mmio ranges. */
	TDISP_DRIVER_NOT_IMPLEMENTED = TDISP_DRIVER_ERROR (0x09),						/**< The driver function is not implemented. */
};


#endif	/* TDISP_DRIVER_H_ */
