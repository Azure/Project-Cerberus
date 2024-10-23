// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef TDISP_TDI_CONTEXT_MANAGER_H_
#define TDISP_TDI_CONTEXT_MANAGER_H_

#include <stddef.h>
#include <stdint.h>
#include "tdisp_protocol.h"
#include "status/rot_status.h"

/**
 * TDISP TDI context bit mask for each supported field
 */
enum {
	TDISP_TDI_CONTEXT_MASK_NONCE = 0x0001,					/**< TDI start nonce field */
	TDISP_TDI_CONTEXT_MASK_LOCK_FLAGS = 0x0002,				/**< TDI lock flags field */
	TDISP_TDI_CONTEXT_MASK_DEFAULT_IDE_STREAM_ID = 0x0004,	/**< TDI default IDE stream ID field */
	TDISP_TDI_CONTEXT_MASK_MMIO_REPORTING_OFFSET = 0x0008,	/**< TDI MMIO reporting offset field */
	TDISP_TDI_CONTEXT_MASK_BIND_P2P_ADDRESS_MASK = 0x0010,	/**< TDI bind P2P address mask field */
	TDISP_TDI_CONTEXT_MASK_RESERVED_0 = 0x0020,				/**< TDI reserved[0] field */
	TDISP_TDI_CONTEXT_MASK_RESERVED_1 = 0x0040,				/**< TDI reserved[1] field */
	TDISP_TDI_CONTEXT_MASK_RESERVED_2 = 0x0080,				/**< TDI reserved[2] field */
	TDISP_TDI_CONTEXT_MASK_RESERVED_3 = 0x0100,				/**< TDI reserved[3] field */
};

/**
 * TDI interface context
 */
struct tdisp_tdi_context {
	uint32_t tdi_context_mask;											/**< TDI context mask indicating validity of each field */
	uint8_t start_interface_nonce[TDISP_START_INTERFACE_NONCE_SIZE];	/**< Start interface nonce. */
	uint16_t lock_flags;												/**< interface lock flags */
	uint8_t default_ide_stream_id;										/**< default IDE stream ID */
	uint64_t mmio_reporting_offset;										/**< MMIO reporting offset */
	uint64_t bind_p2p_address_mask;										/**< P2P binding address mask */
	uint32_t reserved[4];												/**< Reserved */
};

/**
 * Abstract interface for managing TDI contexts. This interface will be shared between
 * TDISP responder and TDISP driver and any other entities which would require access
 * to TDI context. Implementation is supposed to hide any details where and how this
 * information will be stored.
 */
struct tdisp_tdi_context_manager {
	/**
	 * Clears context for specific TDI
	 *
	 * @param mgr TDI context manager
	 * @param tdi_id TDI interface id
	 *
	 * @return 0 on success, error code otherwise
	 */
	int (*clear_tdi_context) (const struct tdisp_tdi_context_manager *mgr, uint32_t tdi_id);

	/**
	 * Clears all TDI contexts
	 *
	 * @param mgr - TDI context manager
	 *
	 * @return 0 on success, error code otherwise
	 */
	int (*clear_all_tdi_context) (const struct tdisp_tdi_context_manager *mgr);

	/**
	 * Gets context for specific TDI
	 *
	 * @param mgr TDI context manager
	 * @param tdi_id TDI interface id
	 * @param context_mask - Specifies context mask which indicates which fields should be
	 * populated in the context struct
	 * @param context - Output struct to receive context information
	 *
	 * @return 0 on success, error code otherwise
	 */
	int (*get_tdi_context) (const struct tdisp_tdi_context_manager *mgr, uint32_t tdi_id,
		uint32_t context_mask, struct tdisp_tdi_context *context);

	/**
	 * Sets TDI start nonce
	 *
	 * @param mgr TDI context manager
	 * @param tdi_id TDI interface id
	 * @param nonce - array representing TDI start nonce
	 * @param nonce_size - nonce size
	 *
	 * @return 0 on success, error code otherwise
	 */
	int (*set_start_nonce) (const struct tdisp_tdi_context_manager *mgr, uint32_t tdi_id,
		const uint8_t *nonce, size_t nonce_size);

	/**
	 * Sets TDI lock flags
	 *
	 * @param mgr TDI context manager
	 * @param tdi_id TDI interface id
	 * @param lock_flags - TDI lock flags
	 *
	 * @return 0 on success, error code otherwise
	 */
	int (*set_lock_flags) (const struct tdisp_tdi_context_manager *mgr, uint32_t tdi_id,
		uint16_t lock_flags);

	/**
	 * Sets TDI default IDE stream ID
	 *
	 * @param mgr TDI context manager
	 * @param tdi_id TDI interface id
	 * @param ide_stream_id Default IDE stream ID
	 *
	 * @return 0 on success, error code otherwise
	 */
	int (*set_default_ide_stream) (const struct tdisp_tdi_context_manager *mgr, uint32_t tdi_id,
		uint8_t ide_stream_id);

	/**
	 * Sets TDI MMIO reporting offset
	 *
	 * @param mgr TDI context manager
	 * @param tdi_id TDI interface id
	 * @param mmio_reporting_offset - MMIO reporting offset for this TDI
	 *
	 * @return 0 on success, error code otherwise
	 */
	int (*set_mmio_reporting_offset) (const struct tdisp_tdi_context_manager *mgr, uint32_t tdi_id,
		uint64_t mmio_reporting_offset);

	/**
	 * Sets TDI bind P2P address mask
	 *
	 * @param mgr TDI context manager
	 * @param tdi_id TDI interface id
	 * @param bind_p2p_address_mask - Bind P2P address mask
	 *
	 * @return 0 on success, error code otherwise
	 */
	int (*set_bind_p2p_address_mask) (const struct tdisp_tdi_context_manager *mgr, uint32_t tdi_id,
		uint64_t bind_p2p_address_mask);

	/**
	 * Sets reserved field
	 *
	 * @param mgr TDI context manager
	 * @param tdi_id TDI interface id
	 * @param index - reserved value index
	 * @param value - reserved value
	 *
	 * @return 0 on success, error code otherwise
	 */
	int (*set_reserved) (const struct tdisp_tdi_context_manager *mgr, uint32_t tdi_id,
		uint8_t index, uint32_t value);
};


int tdisp_tdi_context_clear (struct tdisp_tdi_context *context);
int tdisp_tdi_context_set_start_nonce (struct tdisp_tdi_context *context, const uint8_t *nonce,
	size_t nonce_size);
int tdisp_tdi_context_set_lock_flags (struct tdisp_tdi_context *context, uint32_t lock_flags);
int tdisp_tdi_context_set_default_ide_stream (struct tdisp_tdi_context *context,
	uint8_t ide_stream_id);
int tdisp_tdi_context_set_mmio_reporting_offset (struct tdisp_tdi_context *context,
	uint64_t mmio_reporting_offset);
int tdisp_tdi_context_set_bind_p2p_address_mask (struct tdisp_tdi_context *context,
	uint64_t bind_p2p_address_mask);
int tdisp_tdi_context_set_reserved (struct tdisp_tdi_context *context, uint32_t index,
	uint32_t value);

#define TDISP_TDI_CONTEXT_MANAGER_ERROR(code) \
	ROT_ERROR (ROT_MODULE_TDISP_TDI_CONTEXT_MANAGER, code)

/**
 * Error codes that can be generated by the TDISP TDI context manager interface.
 */
enum {
	TDISP_TDI_CONTEXT_MANAGER_INVALID_ARGUMENT = TDISP_TDI_CONTEXT_MANAGER_ERROR (0x00),				/**< Input parameter is null or not valid. */
	TDISP_TDI_CONTEXT_MANAGER_NO_MEMORY = TDISP_TDI_CONTEXT_MANAGER_ERROR (0x01),						/**< Memory allocation failed. */
	TDISP_TDI_CONTEXT_MANAGER_CLEAR_TDI_CONTEXT_FAILED = TDISP_TDI_CONTEXT_MANAGER_ERROR (0x02),		/**< Failure to clear TDI context */
	TDISP_TDI_CONTEXT_MANAGER_CLEAR_ALL_TDI_CONTEXT_FAILED = TDISP_TDI_CONTEXT_MANAGER_ERROR (0x03),	/**< Failure to clear all TDI contexts */
	TDISP_TDI_CONTEXT_MANAGER_GET_TDI_CONTEXT_FAILED = TDISP_TDI_CONTEXT_MANAGER_ERROR (0x04),			/**< Failure to get TDI contexts */
	TDISP_TDI_CONTEXT_MANAGER_SET_START_NONCE_FAILED = TDISP_TDI_CONTEXT_MANAGER_ERROR (0x05),			/**< Failure to set TDI start nonce */
	TDISP_TDI_CONTEXT_MANAGER_SET_LOCK_FLAGS_FAILED = TDISP_TDI_CONTEXT_MANAGER_ERROR (0x06),			/**< Failure to set TDI lock flags */
	TDISP_TDI_CONTEXT_MANAGER_SET_DEFAULT_IDE_STREAM_ID_FAILED =
		TDISP_TDI_CONTEXT_MANAGER_ERROR (0x07),															/**< Failure to set default IDE stream ID */
	TDISP_TDI_CONTEXT_MANAGER_SET_MMIO_REPORTING_OFFSET_FAILED =
		TDISP_TDI_CONTEXT_MANAGER_ERROR (0x08),															/**< Failure to set TDI MMIO reporting offset */
	TDISP_TDI_CONTEXT_MANAGER_SET_BIND_P2P_ADDRESS_MAKS_FAILED =
		TDISP_TDI_CONTEXT_MANAGER_ERROR (0x09),															/**< Failure to set TDI bind P2P address mask */
};


#endif	// TDISP_TDI_CONTEXT_MANAGER_H_
