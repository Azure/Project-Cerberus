// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "tdisp_tdi_context_manager.h"
#include "common/array_size.h"


/**
 * Clears TDI context struct
 *
 * @param context TDI context
 *
 * @return 0 on success, error code otherwise
 */
int tdisp_tdi_context_clear (struct tdisp_tdi_context *context)
{
	if (context == NULL) {
		return TDISP_TDI_CONTEXT_MANAGER_INVALID_ARGUMENT;
	}

	memset (context, 0, sizeof (*context));

	return 0;
}

/**
 * Sets TDI nonce for start interface validation
 *
 * @param context TDI context
 * @param nonce Array containing nonce data
 * @param nonce_size Nonce array size
 *
 * @return 0 on success, error code otherwise
 */
int tdisp_tdi_context_set_start_nonce (struct tdisp_tdi_context *context, const uint8_t *nonce,
	size_t nonce_size)
{
	if ((context == NULL) || (nonce == NULL) ||
		(nonce_size != sizeof (context->start_interface_nonce))) {
		return TDISP_TDI_CONTEXT_MANAGER_INVALID_ARGUMENT;
	}

	memcpy (context->start_interface_nonce, nonce, nonce_size);
	context->tdi_context_mask |= TDISP_TDI_CONTEXT_MASK_NONCE;

	return 0;
}

/**
 * Sets TDI lock flags
 *
 * @param context TDI context
 * @param lock_flags TDI lock flags
 *
 * @return 0 on success, error code otherwise
 */
int tdisp_tdi_context_set_lock_flags (struct tdisp_tdi_context *context, uint32_t lock_flags)
{
	if (context == NULL) {
		return TDISP_TDI_CONTEXT_MANAGER_INVALID_ARGUMENT;
	}

	context->lock_flags = lock_flags;
	context->tdi_context_mask |= TDISP_TDI_CONTEXT_MASK_LOCK_FLAGS;

	return 0;
}

/**
 * Sets TDI default IDE stream
 *
 * @param context TDI context
 * @param ide_stream_id Default IDE stream ID
 *
 * @return 0 on success, error code otherwise
 */
int tdisp_tdi_context_set_default_ide_stream (struct tdisp_tdi_context *context,
	uint8_t ide_stream_id)
{
	if (context == NULL) {
		return TDISP_TDI_CONTEXT_MANAGER_INVALID_ARGUMENT;
	}

	context->default_ide_stream_id = ide_stream_id;
	context->tdi_context_mask |= TDISP_TDI_CONTEXT_MASK_DEFAULT_IDE_STREAM_ID;

	return 0;
}

/**
 * Sets TDI MMIO reporting offset
 *
 * @param context TDI context
 * @param mmio_reporting_offset TDI MMIO reporting offset
 *
 * @return 0 on success, error code otherwise
 */
int tdisp_tdi_context_set_mmio_reporting_offset (struct tdisp_tdi_context *context,
	uint64_t mmio_reporting_offset)
{
	if (context == NULL) {
		return TDISP_TDI_CONTEXT_MANAGER_INVALID_ARGUMENT;
	}

	context->mmio_reporting_offset = mmio_reporting_offset;
	context->tdi_context_mask |= TDISP_TDI_CONTEXT_MASK_MMIO_REPORTING_OFFSET;

	return 0;
}

/**
 * Sets TDI bind P2P address mask
 *
 * @param context TDI context
 * @param bind_p2p_address_mask TDI bind P2P address mask
 *
 * @return 0 on success, error code otherwise
 */
int tdisp_tdi_context_set_bind_p2p_address_mask (struct tdisp_tdi_context *context,
	uint64_t bind_p2p_address_mask)
{
	if (context == NULL) {
		return TDISP_TDI_CONTEXT_MANAGER_INVALID_ARGUMENT;
	}

	context->bind_p2p_address_mask = bind_p2p_address_mask;
	context->tdi_context_mask |= TDISP_TDI_CONTEXT_MASK_BIND_P2P_ADDRESS_MASK;

	return 0;
}

/**
 * Sets TDI reserved field
 *
 * @param context TDI context
 * @param index Reserved field index
 * @param value Reserved field value
 *
 * @return 0 on success, error code otherwise
 */
int tdisp_tdi_context_set_reserved (struct tdisp_tdi_context *context, uint32_t index,
	uint32_t value)
{
	if ((context == NULL) || (index >= ARRAY_SIZE (context->reserved))) {
		return TDISP_TDI_CONTEXT_MANAGER_INVALID_ARGUMENT;
	}

	context->reserved[index] = value;
	context->tdi_context_mask |= (TDISP_TDI_CONTEXT_MASK_RESERVED_0 << index);

	return 0;
}
