// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "spdm_measurements_mock.h"


static int spdm_measurements_mock_get_measurement_count (const struct spdm_measurements *handler)
{
	struct spdm_measurements_mock *mock = (struct spdm_measurements_mock*) handler;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, spdm_measurements_mock_get_measurement_count, handler);
}

static int spdm_measurements_mock_get_measurement_block (const struct spdm_measurements *handler,
	uint8_t block_id, bool raw_bit_stream, const struct hash_engine *hash, enum hash_type hash_type,
	uint8_t *buffer, size_t length)
{
	struct spdm_measurements_mock *mock = (struct spdm_measurements_mock*) handler;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, spdm_measurements_mock_get_measurement_block, handler,
		MOCK_ARG_CALL (block_id), MOCK_ARG_CALL (raw_bit_stream), MOCK_ARG_PTR_CALL (hash),
		MOCK_ARG_CALL (hash_type), MOCK_ARG_PTR_CALL (buffer), MOCK_ARG_CALL (length));
}

static int spdm_measurements_mock_get_measurement_block_length (
	const struct spdm_measurements *handler, uint8_t block_id)
{
	struct spdm_measurements_mock *mock = (struct spdm_measurements_mock*) handler;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, spdm_measurements_mock_get_measurement_block_length, handler,
		MOCK_ARG_CALL (block_id));
}

static int spdm_measurements_mock_get_all_measurement_blocks (
	const struct spdm_measurements *handler, bool raw_bit_stream, const struct hash_engine *hash,
	enum hash_type hash_type, uint8_t *buffer, size_t length)
{
	struct spdm_measurements_mock *mock = (struct spdm_measurements_mock*) handler;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, spdm_measurements_mock_get_all_measurement_blocks, handler,
		MOCK_ARG_CALL (raw_bit_stream), MOCK_ARG_PTR_CALL (hash), MOCK_ARG_CALL (hash_type),
		MOCK_ARG_PTR_CALL (buffer), MOCK_ARG_CALL (length));
}

static int spdm_measurements_mock_get_all_measurement_blocks_length (
	const struct spdm_measurements *handler, bool raw_bit_stream, enum hash_type hash_type)
{
	struct spdm_measurements_mock *mock = (struct spdm_measurements_mock*) handler;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, spdm_measurements_mock_get_all_measurement_blocks_length, handler,
		MOCK_ARG_CALL (raw_bit_stream), MOCK_ARG_CALL (hash_type));
}

static int spdm_measurements_mock_get_measurement_summary_hash (
	const struct spdm_measurements *handler, const struct hash_engine *summary_hash,
	enum hash_type summary_hash_type, const struct hash_engine *measurement_hash,
	enum hash_type measurement_hash_type, bool only_tcb, uint8_t *buffer, size_t length)
{
	struct spdm_measurements_mock *mock = (struct spdm_measurements_mock*) handler;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, spdm_measurements_mock_get_measurement_summary_hash, handler,
		MOCK_ARG_PTR_CALL (summary_hash), MOCK_ARG_CALL (summary_hash_type),
		MOCK_ARG_PTR_CALL (measurement_hash), MOCK_ARG_CALL (measurement_hash_type),
		MOCK_ARG_CALL (only_tcb), MOCK_ARG_PTR_CALL (buffer), MOCK_ARG_CALL (length));
}

static int spdm_measurements_mock_func_arg_count (void *func)
{
	if (func == spdm_measurements_mock_get_measurement_summary_hash) {
		return 7;
	}
	else if (func == spdm_measurements_mock_get_measurement_block) {
		return 6;
	}
	else if (func == spdm_measurements_mock_get_all_measurement_blocks) {
		return 5;
	}
	else if (func == spdm_measurements_mock_get_all_measurement_blocks_length) {
		return 2;
	}
	else if (func == spdm_measurements_mock_get_measurement_block_length) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* spdm_measurements_mock_func_name_map (void *func)
{
	if (func == spdm_measurements_mock_get_measurement_count) {
		return "get_measurement_count";
	}
	else if (func == spdm_measurements_mock_get_measurement_block) {
		return "get_measurement_block";
	}
	else if (func == spdm_measurements_mock_get_measurement_block_length) {
		return "get_measurement_block_length";
	}
	else if (func == spdm_measurements_mock_get_all_measurement_blocks) {
		return "get_all_measurement_blocks";
	}
	else if (func == spdm_measurements_mock_get_all_measurement_blocks_length) {
		return "get_all_measurement_blocks_length";
	}
	else if (func == spdm_measurements_mock_get_measurement_summary_hash) {
		return "get_measurement_summary_hash";
	}
	else {
		return "unknown";
	}
}

static const char* spdm_measurements_mock_arg_name_map (void *func, int arg)
{
	if (func == spdm_measurements_mock_get_measurement_block) {
		switch (arg) {
			case 0:
				return "block_id";

			case 1:
				return "raw_bit_stream";

			case 2:
				return "hash";

			case 3:
				return "hash_type";

			case 4:
				return "buffer";

			case 5:
				return "length";
		}
	}
	else if (func == spdm_measurements_mock_get_measurement_block_length) {
		switch (arg) {
			case 0:
				return "block_id";
		}
	}
	else if (func == spdm_measurements_mock_get_all_measurement_blocks) {
		switch (arg) {
			case 0:
				return "raw_bit_stream";

			case 1:
				return "hash";

			case 2:
				return "hash_type";

			case 3:
				return "buffer";

			case 4:
				return "length";
		}
	}
	else if (func == spdm_measurements_mock_get_all_measurement_blocks_length) {
		switch (arg) {
			case 0:
				return "raw_bit_stream";

			case 1:
				return "hash_type";
		}
	}
	else if (func == spdm_measurements_mock_get_measurement_summary_hash) {
		switch (arg) {
			case 0:
				return "summary_hash";

			case 1:
				return "summary_hash_type";

			case 2:
				return "measurement_hash";

			case 3:
				return "measurement_hash_type";

			case 4:
				return "only_tcb";

			case 5:
				return "buffer";

			case 6:
				return "length";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for handling SPDM measurements.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int spdm_measurements_mock_init (struct spdm_measurements_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct spdm_measurements_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "spdm_measurements");

	mock->base.get_measurement_count = spdm_measurements_mock_get_measurement_count;
	mock->base.get_measurement_block = spdm_measurements_mock_get_measurement_block;
	mock->base.get_measurement_block_length = spdm_measurements_mock_get_measurement_block_length;
	mock->base.get_all_measurement_blocks = spdm_measurements_mock_get_all_measurement_blocks;
	mock->base.get_all_measurement_blocks_length =
		spdm_measurements_mock_get_all_measurement_blocks_length;
	mock->base.get_measurement_summary_hash = spdm_measurements_mock_get_measurement_summary_hash;

	mock->mock.func_arg_count = spdm_measurements_mock_func_arg_count;
	mock->mock.func_name_map = spdm_measurements_mock_func_name_map;
	mock->mock.arg_name_map = spdm_measurements_mock_arg_name_map;

	return 0;
}

/**
 * Release a mock SPDM measurement handler.
 *
 * @param mock The mock to release.
 */
void spdm_measurements_mock_release (struct spdm_measurements_mock *mock)
{
	if (mock) {
		mock_release (&mock->mock);
	}
}

/**
 * Verify the mock was called as expected and release the instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if all expectations were met or 1 if not.
 */
int spdm_measurements_mock_validate_and_release (struct spdm_measurements_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		spdm_measurements_mock_release (mock);
	}

	return status;
}
