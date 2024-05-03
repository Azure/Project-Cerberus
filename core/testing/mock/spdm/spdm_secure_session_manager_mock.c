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
		MOCK_ARG_CALL (session_id), MOCK_ARG_CALL (is_requester), MOCK_ARG_CALL (connection_info));
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
		session_manager, MOCK_ARG_CALL (session), MOCK_ARG_CALL (peer_pub_key_point),
		MOCK_ARG_CALL (local_pub_key_point));
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
		session_manager, MOCK_ARG_CALL (session));
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