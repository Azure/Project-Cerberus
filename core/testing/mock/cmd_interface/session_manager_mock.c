// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "session_manager_mock.h"


static int session_manager_mock_add_session (struct session_manager *session, uint8_t eid, 
	const uint8_t *device_nonce, const uint8_t *cerberus_nonce)
{
	struct session_manager_mock *mock = (struct session_manager_mock*) session;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, session_manager_mock_add_session, session, MOCK_ARG_CALL (eid),
		MOCK_ARG_CALL (device_nonce), MOCK_ARG_CALL (cerberus_nonce));
}

static int session_manager_mock_establish_session (struct session_manager *session, 
	struct cmd_interface_msg *request)
{
	struct session_manager_mock *mock = (struct session_manager_mock*) session;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, session_manager_mock_establish_session, session, 
		MOCK_ARG_CALL (request));
}

static int session_manager_mock_decrypt_message (struct session_manager *session, 
	struct cmd_interface_msg *request)
{
	struct session_manager_mock *mock = (struct session_manager_mock*) session;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, session_manager_mock_decrypt_message, session, 
		MOCK_ARG_CALL (request));
}

static int session_manager_mock_encrypt_message (struct session_manager *session, 
	struct cmd_interface_msg *request)
{
	struct session_manager_mock *mock = (struct session_manager_mock*) session;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, session_manager_mock_encrypt_message, session, 
		MOCK_ARG_CALL (request));
}

static int session_manager_mock_is_session_established (struct session_manager *session, 
	uint8_t eid)
{
	struct session_manager_mock *mock = (struct session_manager_mock*) session;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, session_manager_mock_is_session_established, session, 
		MOCK_ARG_CALL (eid));
}

static int session_manager_mock_get_pairing_state (struct session_manager *session, uint8_t eid)
{
	struct session_manager_mock *mock = (struct session_manager_mock*) session;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, session_manager_mock_get_pairing_state, session, MOCK_ARG_CALL (eid));
}

static int session_manager_mock_reset_session (struct session_manager *session, uint8_t eid, 
	uint8_t *hmac, size_t hmac_len)
{
	struct session_manager_mock *mock = (struct session_manager_mock*) session;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, session_manager_mock_reset_session, session, MOCK_ARG_CALL (eid), 
		MOCK_ARG_CALL (hmac), MOCK_ARG_CALL (hmac_len));
}

static int session_manager_mock_setup_paired_session (struct session_manager *session, uint8_t eid, 
	size_t pairing_key_len, uint8_t *pairing_key_hmac, size_t pairing_key_hmac_len)
{
	struct session_manager_mock *mock = (struct session_manager_mock*) session;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, session_manager_mock_setup_paired_session, session, 
		MOCK_ARG_CALL (eid), MOCK_ARG_CALL (pairing_key_len), MOCK_ARG_CALL (pairing_key_hmac), 
		MOCK_ARG_CALL (pairing_key_hmac_len));
}

static int session_manager_mock_session_sync (struct session_manager *session, uint8_t eid, 
	uint32_t rn_req, uint8_t *hmac, size_t hmac_len)
{
	struct session_manager_mock *mock = (struct session_manager_mock*) session;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, session_manager_mock_session_sync, session, MOCK_ARG_CALL (eid), 
		MOCK_ARG_CALL (rn_req), MOCK_ARG_CALL (hmac), MOCK_ARG_CALL (hmac_len));
}

static int session_manager_mock_func_arg_count (void *func)
{
	if ((func == session_manager_mock_is_session_established) || 
		(func == session_manager_mock_get_pairing_state) || 
		(func == session_manager_mock_decrypt_message) || 
		(func == session_manager_mock_encrypt_message) || 
		(func == session_manager_mock_establish_session)) {
		return 1;
	}
	else if ((func == session_manager_mock_add_session) || 
		(func == session_manager_mock_reset_session)) {
		return 3;
	}
	else if ((func == session_manager_mock_setup_paired_session) || 
		(func == session_manager_mock_session_sync)) {
		return 4;
	}
	else {
		return 0;
	}
}

static const char* session_manager_mock_func_name_map (void *func)
{
	if (func == session_manager_mock_add_session) {
		return "add_session";
	}
	else if (func == session_manager_mock_decrypt_message) {
		return "decrypt_message";
	}
	else if (func == session_manager_mock_encrypt_message) {
		return "encrypt_message";
	}
	else if (func == session_manager_mock_is_session_established) {
		return "is_session_established";
	}
	else if (func == session_manager_mock_get_pairing_state) {
		return "get_pairing_state";
	}
	else if (func == session_manager_mock_establish_session) {
		return "establish_session";
	}
	else if (func == session_manager_mock_reset_session) {
		return "reset_session";
	}
	else if (func == session_manager_mock_setup_paired_session) {
		return "setup_paired_session";
	}
	else if (func == session_manager_mock_session_sync) {
		return "session_sync";
	}
	else {
		return "unknown";
	}
}

static const char* session_manager_mock_arg_name_map (void *func, int arg)
{
	if (func == session_manager_mock_add_session) {
		switch (arg) {
			case 0:
				return "eid";

			case 1:
				return "device_nonce";

			case 2:
				return "cerberus_nonce";
		}
	}
	else if ((func == session_manager_mock_decrypt_message) ||
			(func == session_manager_mock_encrypt_message) ||
			(func == session_manager_mock_establish_session))  {
		switch (arg) {
			case 0:
				return "request";
		}
	}
	else if ((func == session_manager_mock_is_session_established) || 
			 (func == session_manager_mock_get_pairing_state)) {
		switch (arg) {
			case 0:
				return "eid";
		}
	}
	else if (func == session_manager_mock_reset_session) {
		switch (arg) {
			case 0:
				return "eid";
			case 1:
				return "hmac";
			case 2:
				return "hmac_len";
		}
	}
	else if (func == session_manager_mock_setup_paired_session) {
		switch (arg) {
			case 0:
				return "eid";
			case 1:
				return "pairing_key_len";
			case 2:
				return "pairing_key_hmac";
			case 3:
				return "pairing_key_hmac_len";
		}
	}
	else if (func == session_manager_mock_session_sync) {
		switch (arg) {
			case 0:
				return "eid";
			case 1:
				return "rn_req";
			case 2:
				return "hmac";
			case 3:
				return "hmac_len";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock instance for a session_manager.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was initialized successfully or an error code.
 */
int session_manager_mock_init (struct session_manager_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct session_manager_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "session_manager");

	mock->base.add_session = session_manager_mock_add_session;
	mock->base.establish_session = session_manager_mock_establish_session;
	mock->base.decrypt_message = session_manager_mock_decrypt_message;
	mock->base.encrypt_message = session_manager_mock_encrypt_message;
	mock->base.is_session_established = session_manager_mock_is_session_established;
	mock->base.get_pairing_state = session_manager_mock_get_pairing_state;
	mock->base.reset_session = session_manager_mock_reset_session;
	mock->base.setup_paired_session = session_manager_mock_setup_paired_session;
	mock->base.session_sync = session_manager_mock_session_sync;

	mock->mock.func_arg_count = session_manager_mock_func_arg_count;
	mock->mock.func_name_map = session_manager_mock_func_name_map;
	mock->mock.arg_name_map = session_manager_mock_arg_name_map;

	return 0;
}

/**
 * Free the resources used by a session_manager mock instance.
 *
 * @param mock The mock to release.
 */
void session_manager_mock_release (struct session_manager_mock *mock)
{
	if (mock != NULL) {
		mock_release (&mock->mock);
	}
}

/**
 * Validate that the session_manager mock instance was called as expected and release it.
 *
 * @param mock The mock instance to validate.
 *
 * @return 0 if the mock was called as expected or 1 if not.
 */
int session_manager_mock_validate_and_release (struct session_manager_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		session_manager_mock_release (mock);
	}

	return status;
}
