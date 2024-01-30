// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "platform_io.h"
#include "spdm_transcript_manager_mock.h"


static int spdm_transcript_manager_mock_set_hash_algo (
	const struct spdm_transcript_manager *transcript_manager, enum hash_type hash_algo)
{
	struct spdm_transcript_manager_mock *mock =
		(struct spdm_transcript_manager_mock*) transcript_manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, spdm_transcript_manager_mock_set_hash_algo, transcript_manager,
		MOCK_ARG_CALL (hash_algo));
}

static void spdm_transcript_manager_mock_set_spdm_version (
	const struct spdm_transcript_manager *transcript_manager, uint8_t spdm_version)
{
	struct spdm_transcript_manager_mock *mock =
		(struct spdm_transcript_manager_mock*) transcript_manager;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, spdm_transcript_manager_mock_set_spdm_version,
		transcript_manager, MOCK_ARG_CALL (spdm_version));
}

static int spdm_transcript_manager_mock_update (
	const struct spdm_transcript_manager *transcript_manager, 
	enum spdm_transcript_manager_context_type context_type, const uint8_t *message,
	size_t message_size, bool use_session_context, uint8_t session_idx)
{
	struct spdm_transcript_manager_mock *mock =
		(struct spdm_transcript_manager_mock*) transcript_manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, spdm_transcript_manager_mock_update, transcript_manager,
		MOCK_ARG_CALL (context_type), MOCK_ARG_PTR_CALL (message), MOCK_ARG_CALL (message_size),
		MOCK_ARG_CALL (use_session_context), MOCK_ARG_CALL (session_idx));
}

static int spdm_transcript_manager_mock_get_hash (
	const struct spdm_transcript_manager *transcript_manager,
	enum spdm_transcript_manager_context_type context_type, bool use_session_context,
	uint8_t session_idx, uint8_t *hash, size_t hash_size)
{
	struct spdm_transcript_manager_mock *mock =
		(struct spdm_transcript_manager_mock*) transcript_manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, spdm_transcript_manager_mock_get_hash, transcript_manager,
		MOCK_ARG_CALL (context_type), MOCK_ARG_CALL (use_session_context),
		MOCK_ARG_CALL (session_idx), MOCK_ARG_PTR_CALL (hash), MOCK_ARG_CALL (hash_size));
}

static void spdm_transcript_manager_mock_reset_context (
	const struct spdm_transcript_manager *transcript_manager,
	enum spdm_transcript_manager_context_type context_type, bool use_session_context,
	uint8_t session_idx)
{
	struct spdm_transcript_manager_mock *mock =
		(struct spdm_transcript_manager_mock*) transcript_manager;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, spdm_transcript_manager_mock_reset_context,
		transcript_manager, MOCK_ARG_CALL (context_type), MOCK_ARG_CALL (use_session_context),
		MOCK_ARG_CALL (session_idx));
}

static void spdm_transcript_manager_mock_reset (
	const struct spdm_transcript_manager *transcript_manager)
{
	struct spdm_transcript_manager_mock *mock =
		(struct spdm_transcript_manager_mock*) transcript_manager;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN_NO_ARGS (&mock->mock, spdm_transcript_manager_mock_reset, transcript_manager);
}

static void spdm_transcript_manager_mock_reset_session_transcript (
	const struct spdm_transcript_manager *transcript_manager, uint8_t session_idx)
{
	struct spdm_transcript_manager_mock *mock =
		(struct spdm_transcript_manager_mock*) transcript_manager;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, spdm_transcript_manager_mock_reset_session_transcript,
		transcript_manager, MOCK_ARG_CALL (session_idx));
}

static int spdm_transcript_manager_mock_func_arg_count (void *func)
{
	if (func == spdm_transcript_manager_mock_set_hash_algo) {
		return 1;
	}
	else if (func == spdm_transcript_manager_mock_set_spdm_version) {
		return 1;
	}
	else if (func == spdm_transcript_manager_mock_update) {
		return 5;
	}
	else if (func == spdm_transcript_manager_mock_get_hash) {
		return 5;
	}
	else if (func == spdm_transcript_manager_mock_reset_context) {
		return 3;
	}
	else if (func == spdm_transcript_manager_mock_reset) {
		return 0;
	}
	else if (func == spdm_transcript_manager_mock_reset_session_transcript) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* spdm_transcript_manager_mock_arg_name_map (void *func, int arg)
{
	if (func == spdm_transcript_manager_mock_set_hash_algo) {
		switch (arg) {
			case 0:
				return "hash_algo";
		}
	}
	else if (func == spdm_transcript_manager_mock_set_spdm_version) {
		switch (arg) {
			case 0:
				return "spdm_version";
		}
	}
	else if (func == spdm_transcript_manager_mock_update) {
		switch (arg) {
			case 0:
				return "context_type";

			case 1:
				return "message";

			case 2:
				return "message_size";

			case 3:
				return "use_session_context";

			case 4:
				return "session_idx";
		}
	}
	else if (func == spdm_transcript_manager_mock_get_hash) {
		switch (arg) {
			case 0:
				return "context_type";

			case 1:
				return "use_session_context";

			case 2:
				return "session_idx";

			case 3:
				return "hash";

			case 4:
				return "hash_size";
		}
	}
	else if (func == spdm_transcript_manager_mock_reset_context) {
		switch (arg) {
			case 0:
				return "context_type";

			case 1:
				return "use_session_context";

			case 2:
				return "session_idx";
		}
	}
	else if (func == spdm_transcript_manager_mock_reset) {
		switch (arg) {
			case 0:
				return "transcript_manager";
		}
	}
	else if (func == spdm_transcript_manager_mock_reset_session_transcript) {
		switch (arg) {
			case 0:
				return "session_idx";
		}
	}

	return "unknown";
}

static const char* spdm_transcript_manager_mock_func_name_map (void *func)
{
	if (func == spdm_transcript_manager_mock_set_hash_algo) {
		return "set_hash_algo";
	}
	else if (func == spdm_transcript_manager_mock_set_spdm_version) {
		return "set_spdm_version";
	}
	else if (func == spdm_transcript_manager_mock_update) {
		return "update";
	}
	else if (func == spdm_transcript_manager_mock_get_hash) {
		return "get_hash";
	}
	else if (func == spdm_transcript_manager_mock_reset_context) {
		return "reset_transcript";
	}
	else if (func == spdm_transcript_manager_mock_reset) {
		return "reset";
	}
	else if (func == spdm_transcript_manager_mock_reset_session_transcript) {
		return "reset_session_transcript";
	}
	else {
		return "unknown";
	}
}

/**
 * Initialize a mock for receiving SPDM protocol notifications.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int spdm_transcript_manager_mock_init (struct spdm_transcript_manager_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct spdm_transcript_manager_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "spdm_transcript_manager");

	mock->base.set_hash_algo = spdm_transcript_manager_mock_set_hash_algo;
	mock->base.set_spdm_version = spdm_transcript_manager_mock_set_spdm_version;
	mock->base.update = spdm_transcript_manager_mock_update;
	mock->base.get_hash = spdm_transcript_manager_mock_get_hash;
	mock->base.reset_transcript = spdm_transcript_manager_mock_reset_context;
	mock->base.reset = spdm_transcript_manager_mock_reset;
	mock->base.reset_session_transcript = spdm_transcript_manager_mock_reset_session_transcript;	

	mock->mock.func_arg_count = spdm_transcript_manager_mock_func_arg_count;
	mock->mock.func_name_map = spdm_transcript_manager_mock_func_name_map;
	mock->mock.arg_name_map = spdm_transcript_manager_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a transcript manager mock.
 *
 * @param mock The mock to release.
 */
void spdm_transcript_manager_mock_release (struct spdm_transcript_manager_mock *mock)
{
	if (mock) {
		mock_release (&mock->mock);
	}
}

/**
 * Validate the expectations on the mock and release the instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if all expectations were met or 1 if not.
 */
int spdm_transcript_manager_mock_validate_and_release (struct spdm_transcript_manager_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		spdm_transcript_manager_mock_release (mock);
	}

	return status;
}