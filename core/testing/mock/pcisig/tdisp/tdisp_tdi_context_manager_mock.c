// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <memory.h>
#include "tdisp_tdi_context_manager_mock.h"
#include "common/array_size.h"
#include "common/type_cast.h"


int tdisp_tdi_context_manager_mock_clear_tdi_context (const struct tdisp_tdi_context_manager *mgr,
	uint32_t tdi_id)
{
	struct tdisp_tdi_context_manager_mock *mock = TO_DERIVED_TYPE (mgr,
		struct tdisp_tdi_context_manager_mock, base);

	if (mgr == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, tdisp_tdi_context_manager_mock_clear_tdi_context, mgr,
		MOCK_ARG_CALL (tdi_id));
}

int tdisp_tdi_context_manager_mock_clear_all_tdi_context (
	const struct tdisp_tdi_context_manager *mgr)
{
	struct tdisp_tdi_context_manager_mock *mock = TO_DERIVED_TYPE (mgr,
		struct tdisp_tdi_context_manager_mock, base);

	if (mgr == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, tdisp_tdi_context_manager_mock_clear_all_tdi_context, mgr);
}

int tdisp_tdi_context_manager_mock_get_tdi_context (const struct tdisp_tdi_context_manager *mgr,
	uint32_t tdi_id, uint32_t context_mask, struct tdisp_tdi_context *context)
{
	struct tdisp_tdi_context_manager_mock *mock = TO_DERIVED_TYPE (mgr,
		struct tdisp_tdi_context_manager_mock, base);

	if (mgr == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, tdisp_tdi_context_manager_mock_get_tdi_context, mgr,
		MOCK_ARG_CALL (tdi_id), MOCK_ARG_CALL (context_mask), MOCK_ARG_PTR_CALL (context));
}

int tdisp_tdi_context_manager_mock_set_start_nonce (const struct tdisp_tdi_context_manager *mgr,
	uint32_t tdi_id, const uint8_t *nonce, size_t nonce_size)
{
	struct tdisp_tdi_context_manager_mock *mock = TO_DERIVED_TYPE (mgr,
		struct tdisp_tdi_context_manager_mock, base);

	if (mgr == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, tdisp_tdi_context_manager_mock_set_start_nonce, mgr,
		MOCK_ARG_CALL (tdi_id), MOCK_ARG_PTR_CALL (nonce), MOCK_ARG_CALL (nonce_size));
}

int tdisp_tdi_context_manager_mock_set_lock_flags (const struct tdisp_tdi_context_manager *mgr,
	uint32_t tdi_id, uint16_t lock_flags)
{
	struct tdisp_tdi_context_manager_mock *mock = TO_DERIVED_TYPE (mgr,
		struct tdisp_tdi_context_manager_mock, base);

	if (mgr == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, tdisp_tdi_context_manager_mock_set_lock_flags, mgr,
		MOCK_ARG_CALL (tdi_id), MOCK_ARG_CALL (lock_flags));
}

int tdisp_tdi_context_manager_mock_set_default_ide_stream (
	const struct tdisp_tdi_context_manager *mgr, uint32_t tdi_id, uint8_t ide_stream_id)
{
	struct tdisp_tdi_context_manager_mock *mock = TO_DERIVED_TYPE (mgr,
		struct tdisp_tdi_context_manager_mock, base);

	if (mgr == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, tdisp_tdi_context_manager_mock_set_default_ide_stream, mgr,
		MOCK_ARG_CALL (tdi_id), MOCK_ARG_CALL (ide_stream_id));
}

int tdisp_tdi_context_manager_mock_set_mmio_reporting_offset (
	const struct tdisp_tdi_context_manager *mgr, uint32_t tdi_id, uint64_t mmio_reporting_offset)
{
	struct tdisp_tdi_context_manager_mock *mock = TO_DERIVED_TYPE (mgr,
		struct tdisp_tdi_context_manager_mock, base);

	if (mgr == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, tdisp_tdi_context_manager_mock_set_mmio_reporting_offset, mgr,
		MOCK_ARG_CALL (tdi_id), MOCK_ARG_CALL (mmio_reporting_offset));
}

int tdisp_tdi_context_manager_mock_set_bind_p2p_address_mask (
	const struct tdisp_tdi_context_manager *mgr, uint32_t tdi_id, uint64_t bind_p2p_address_mask)
{
	struct tdisp_tdi_context_manager_mock *mock = TO_DERIVED_TYPE (mgr,
		struct tdisp_tdi_context_manager_mock, base);

	if (mgr == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, tdisp_tdi_context_manager_mock_set_bind_p2p_address_mask, mgr,
		MOCK_ARG_CALL (tdi_id), MOCK_ARG_CALL (bind_p2p_address_mask));
}

int tdisp_tdi_context_manager_mock_set_reserved (const struct tdisp_tdi_context_manager *mgr,
	uint32_t tdi_id, uint8_t index, uint32_t value)
{
	struct tdisp_tdi_context_manager_mock *mock = TO_DERIVED_TYPE (mgr,
		struct tdisp_tdi_context_manager_mock, base);

	if (mgr == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, tdisp_tdi_context_manager_mock_set_reserved, mgr,
		MOCK_ARG_CALL (tdi_id), MOCK_ARG_CALL (index), MOCK_ARG_CALL (value));
}

// *INDENT-OFF*
MOCK_FUNCTION_TABLE_BEGIN (tdisp_tdi_context_manager, 3)
	MOCK_FUNCTION (
		tdisp_tdi_context_manager,
		clear_tdi_context,
		1,
		MOCK_FUNCTION_ARGS ("tdi_id"))
	MOCK_FUNCTION (
		tdisp_tdi_context_manager,
		clear_all_tdi_context,
		0,
		MOCK_FUNCTION_ARGS ())
	MOCK_FUNCTION (
		tdisp_tdi_context_manager,
		get_tdi_context,
		3,
		MOCK_FUNCTION_ARGS ("tdi_id", "context_mask", "context"))
	MOCK_FUNCTION (
		tdisp_tdi_context_manager,
		set_start_nonce,
		3,
		MOCK_FUNCTION_ARGS ("tdi_id", "nonce", "nonce_size"))
	MOCK_FUNCTION (
		tdisp_tdi_context_manager,
		set_lock_flags,
		2,
		MOCK_FUNCTION_ARGS ("tdi_id", "lock_flags"))
	MOCK_FUNCTION (
		tdisp_tdi_context_manager,
		set_default_ide_stream,
		2,
		MOCK_FUNCTION_ARGS ("tdi_id", "ide_stream_id"))
	MOCK_FUNCTION (
		tdisp_tdi_context_manager,
		set_mmio_reporting_offset,
		2,
		MOCK_FUNCTION_ARGS ("tdi_id", "mmio_reporting_offset"))
	MOCK_FUNCTION (
		tdisp_tdi_context_manager,
		set_bind_p2p_address_mask,
		2,
		MOCK_FUNCTION_ARGS ("tdi_id", "bind_p2p_address_mask"))
	MOCK_FUNCTION (
		tdisp_tdi_context_manager,
		set_reserved,
		3,
		MOCK_FUNCTION_ARGS ("tdi_id", "index", "value"))
MOCK_FUNCTION_TABLE_END (tdisp_tdi_context_manager)
// *INDENT-ON*

/**
 * Initialize a TDISP TDI context manager mock instance.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int tdisp_tdi_context_manager_mock_init (struct tdisp_tdi_context_manager_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (*mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "tdisp_tdi_context_manager");

	mock->base.clear_tdi_context = tdisp_tdi_context_manager_mock_clear_tdi_context;
	mock->base.clear_all_tdi_context = tdisp_tdi_context_manager_mock_clear_all_tdi_context;
	mock->base.get_tdi_context = tdisp_tdi_context_manager_mock_get_tdi_context;
	mock->base.set_start_nonce = tdisp_tdi_context_manager_mock_set_start_nonce;
	mock->base.set_lock_flags = tdisp_tdi_context_manager_mock_set_lock_flags;
	mock->base.set_default_ide_stream = tdisp_tdi_context_manager_mock_set_default_ide_stream;
	mock->base.set_mmio_reporting_offset = tdisp_tdi_context_manager_mock_set_mmio_reporting_offset;
	mock->base.set_bind_p2p_address_mask = tdisp_tdi_context_manager_mock_set_bind_p2p_address_mask;
	mock->base.set_reserved = tdisp_tdi_context_manager_mock_set_reserved;

	MOCK_INTERFACE_INIT (mock->mock, tdisp_tdi_context_manager);

	return 0;
}

/**
 * Validate the expectations on the mock and release the instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if all expectations were met or 1 if not.
 */
int tdisp_tdi_context_manager_mock_validate_and_release (
	struct tdisp_tdi_context_manager_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		mock_release (&mock->mock);
	}

	return status;
}
