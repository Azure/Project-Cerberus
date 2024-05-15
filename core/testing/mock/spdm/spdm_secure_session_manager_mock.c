// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "spdm_secure_session_manager_mock.h"


static struct spdm_secure_session* spdm_secure_session_manager_mock_create_session (
	const struct spdm_secure_session_manager *session_manager, uint32_t session_id,
	bool is_requester, const struct spdm_connection_info *connection_info)
{
	struct spdm_secure_session_manager_mock *mock =
		(struct spdm_secure_session_manager_mock*) session_manager;

	if (mock == NULL) {
		return NULL;
	}

	MOCK_RETURN_CAST_PTR (&mock->mock, struct spdm_secure_session*,
		spdm_secure_session_manager_mock_create_session, session_manager,
		MOCK_ARG_CALL (session_id), MOCK_ARG_CALL (is_requester), MOCK_ARG_PTR_CALL (connection_info));
}

static void spdm_secure_session_manager_mock_release_session (
		const struct spdm_secure_session_manager *session_manager, uint32_t session_id)
{
	struct spdm_secure_session_manager_mock *mock =
		(struct spdm_secure_session_manager_mock*) session_manager;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, spdm_secure_session_manager_mock_release_session,
		session_manager, MOCK_ARG_CALL (session_id));
}

static void spdm_secure_session_set_session_state (
		const struct spdm_secure_session_manager *session_manager, uint32_t session_id,
		enum spdm_secure_session_state session_state)
{
	struct spdm_secure_session_manager_mock *mock =
		(struct spdm_secure_session_manager_mock*) session_manager;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, spdm_secure_session_set_session_state,
		session_manager, MOCK_ARG_CALL (session_id), MOCK_ARG_CALL (session_state));
}

static void spdm_secure_session_manager_mock_reset (
	const struct spdm_secure_session_manager *session_manager)
{
	struct spdm_secure_session_manager_mock *mock =
		(struct spdm_secure_session_manager_mock*) session_manager;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN_NO_ARGS (&mock->mock, spdm_secure_session_manager_mock_reset, session_manager);
}

static struct spdm_secure_session* spdm_secure_session_manager_mock_get_session (
		const struct spdm_secure_session_manager *session_manager, 
		uint32_t session_id)
{
	struct spdm_secure_session_manager_mock *mock =
		(struct spdm_secure_session_manager_mock*) session_manager;

	if (mock == NULL) {
		return NULL;
	}

	MOCK_RETURN_CAST_PTR (&mock->mock, struct spdm_secure_session*,
		spdm_secure_session_manager_mock_get_session, session_manager,
		MOCK_ARG_CALL (session_id));
}

static int spdm_secure_session_manager_mock_generate_shared_secret (
		const struct spdm_secure_session_manager *session_manager,
		struct spdm_secure_session* session,
		const struct ecc_point_public_key *peer_pub_key_point, uint8_t *local_pub_key_point)
{
	struct spdm_secure_session_manager_mock *mock =
		(struct spdm_secure_session_manager_mock*) session_manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, spdm_secure_session_manager_mock_generate_shared_secret,
		session_manager, MOCK_ARG_PTR_CALL (session), MOCK_ARG_PTR_CALL (peer_pub_key_point),
		MOCK_ARG_PTR_CALL (local_pub_key_point));
}

static int spdm_secure_session_manager_mock_generate_session_handshake_keys (
	const struct spdm_secure_session_manager *session_manager,
	struct spdm_secure_session *session)
{
	struct spdm_secure_session_manager_mock *mock =
		(struct spdm_secure_session_manager_mock*) session_manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, spdm_secure_session_manager_mock_generate_session_handshake_keys,
		session_manager, MOCK_ARG_PTR_CALL (session));
}

static int spdm_secure_session_manager_mock_generate_session_data_keys (
	const struct spdm_secure_session_manager *session_manager,
	struct spdm_secure_session *session)
{
	struct spdm_secure_session_manager_mock *mock =
		(struct spdm_secure_session_manager_mock*) session_manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, spdm_secure_session_manager_mock_generate_session_data_keys,
		session_manager, MOCK_ARG_PTR_CALL (session));
}

static bool spdm_secure_session_manager_is_last_session_id_valid (
	const struct spdm_secure_session_manager *session_manager)
{
	struct spdm_secure_session_manager_mock *mock =
		(struct spdm_secure_session_manager_mock*) session_manager;

	if (mock == NULL) {
		return false;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, spdm_secure_session_manager_is_last_session_id_valid,
		session_manager);
}

static uint32_t spdm_secure_session_manager_get_last_session_id (
	const struct spdm_secure_session_manager *session_manager)
{
	struct spdm_secure_session_manager_mock *mock =
		(struct spdm_secure_session_manager_mock*) session_manager;

	if (mock == NULL) {
		return 0;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, spdm_secure_session_manager_get_last_session_id,
		session_manager);
}

static void spdm_secure_session_manager_mock_reset_last_session_id_validity (
	const struct spdm_secure_session_manager *session_manager)
{
	struct spdm_secure_session_manager_mock *mock =
		(struct spdm_secure_session_manager_mock*) session_manager;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN_NO_ARGS (&mock->mock, 
		spdm_secure_session_manager_mock_reset_last_session_id_validity, session_manager);
}

static int spdm_secure_session_manager_mock_func_arg_count (void *func)
{
	if (func == spdm_secure_session_manager_mock_create_session) {
		return 3;
	}else if (func == spdm_secure_session_manager_mock_release_session) {
		return 1;
	}
	else if (func == spdm_secure_session_manager_mock_get_session) {
		return 1;
	}
	else if (func == spdm_secure_session_set_session_state) {
		return 2;
	}
	else if (func == spdm_secure_session_manager_mock_reset) {
		return 0;
	}
	else if (func == spdm_secure_session_manager_mock_generate_shared_secret) {
		return 3;
	}
	else if (func == spdm_secure_session_manager_mock_generate_session_handshake_keys) {
		return 1;
	}
	else if (func == spdm_secure_session_manager_mock_generate_session_data_keys) {
		return 1;
	}
	else if (func == spdm_secure_session_manager_is_last_session_id_valid) {
		return 0;
	}
	else if (func == spdm_secure_session_manager_get_last_session_id) {
		return 0;
	}
	else if (func == spdm_secure_session_manager_mock_reset_last_session_id_validity) {
		return 0;
	}
	else
		return 0;
}

static const char* spdm_secure_session_manager_mock_func_name_map (void *func)
{
	if (func == spdm_secure_session_manager_mock_create_session) {
		return "create_session";
	}
	else if (func == spdm_secure_session_manager_mock_release_session) {
		return "release_session";
	}
	else if (func == spdm_secure_session_manager_mock_get_session) {
		return "get_session";
	}
	else if (func == spdm_secure_session_set_session_state) {
		return "set_session_state";
	}
	else if (func == spdm_secure_session_manager_mock_reset) {
		return "reset";
	}
	else if (func == spdm_secure_session_manager_mock_generate_shared_secret) {
		return "generate_shared_secret";
	}
	else if (func == spdm_secure_session_manager_mock_generate_session_handshake_keys) {
		return "generate_session_handshake_keys";
	}
	else if (func == spdm_secure_session_manager_mock_generate_session_data_keys) {
		return "generate_session_data_keys";
	}
	else if (func == spdm_secure_session_manager_is_last_session_id_valid) {
		return "is_last_session_id_valid";
	}
	else if (func == spdm_secure_session_manager_get_last_session_id) {
		return "get_last_session_id";
	}
	else if (func == spdm_secure_session_manager_mock_reset_last_session_id_validity) {
		return "reset_last_session_id_validity";
	}
	else
		return "unknown";
}

static const char* spdm_secure_session_manager_mock_arg_name_map (void *func, int arg)
{
	if (func == spdm_secure_session_manager_mock_create_session) {
		switch (arg) {
			case 0:
				return "session_id";
			case 1:
				return "is_requester";
			case 2:
				return "connection_info";
		}
	}
	else if (func == spdm_secure_session_manager_mock_release_session) {
		switch (arg) {
			case 0:
				return "session_id";
		}
	}
	else if (func == spdm_secure_session_manager_mock_get_session) {
		switch (arg) {
			case 0:
				return "session_id";
		}
	}
	else if (func == spdm_secure_session_set_session_state) {
		switch (arg) {
			case 0:
				return "session_id";
			case 1:
				return "session_state";
		}
	}
	else if (func == spdm_secure_session_manager_mock_reset) {
		switch (arg) {
			case 0:
				return "session_manager";
		}
	}
	else if (func == spdm_secure_session_manager_mock_generate_shared_secret) {
		switch (arg) {
			case 0:
				return "session";
			case 1:
				return "peer_pub_key_point";
			case 2:
				return "local_pub_key_point";
		}
	}
	else if (func == spdm_secure_session_manager_mock_generate_session_handshake_keys) {
		switch (arg) {
			case 0:
				return "session";
		}
	}
	else if (func == spdm_secure_session_manager_mock_generate_session_data_keys) {
		switch (arg) {
			case 0:
				return "session";
		}
	}
	else if (func == spdm_secure_session_manager_is_last_session_id_valid) {
		switch (arg) {
			case 0:
				return "session_manager";
		}
	}
	else if (func == spdm_secure_session_manager_get_last_session_id) {
		switch (arg) {
			case 0:
				return "session_manager";
		}
	}
	return "unknown";
}

/**
 * Initialize a mock for secure session management.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int spdm_secure_session_manager_mock_init (struct spdm_secure_session_manager_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct spdm_secure_session_manager_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "spdm_secure_session_manager");

	mock->base.create_session = spdm_secure_session_manager_mock_create_session;
	mock->base.release_session = spdm_secure_session_manager_mock_release_session;
	mock->base.get_session = spdm_secure_session_manager_mock_get_session;
	mock->base.set_session_state = spdm_secure_session_set_session_state;
	mock->base.reset = spdm_secure_session_manager_mock_reset;
	mock->base.generate_shared_secret = spdm_secure_session_manager_mock_generate_shared_secret;
	mock->base.generate_session_handshake_keys =
		spdm_secure_session_manager_mock_generate_session_handshake_keys;
	mock->base.generate_session_data_keys =
		spdm_secure_session_manager_mock_generate_session_data_keys;
	mock->base.is_last_session_id_valid = spdm_secure_session_manager_is_last_session_id_valid;
	mock->base.get_last_session_id = spdm_secure_session_manager_get_last_session_id;
	mock->base.reset_last_session_id_validity =
		spdm_secure_session_manager_mock_reset_last_session_id_validity;

	mock->mock.func_arg_count = spdm_secure_session_manager_mock_func_arg_count;
	mock->mock.func_name_map = spdm_secure_session_manager_mock_func_name_map;
	mock->mock.arg_name_map = spdm_secure_session_manager_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by the secure session manager mock.
 *
 * @param mock The mock to release.
 */
void spdm_secure_session_manager_mock_release (struct spdm_secure_session_manager_mock *mock)
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
int spdm_secure_session_manager_mock_validate_and_release (struct spdm_secure_session_manager_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		spdm_secure_session_manager_mock_release (mock);
	}

	return status;
}