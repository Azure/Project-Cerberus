// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "session_manager.h"
#include "session_manager_null.h"
#include "common/unused.h"


int session_manager_null_add_session (struct session_manager *session, uint8_t eid,
	const uint8_t *device_nonce, const uint8_t *cerberus_nonce)
{
	UNUSED (eid);
	UNUSED (device_nonce);
	UNUSED (cerberus_nonce);

	if (session == NULL) {
		return SESSION_MANAGER_INVALID_ARGUMENT;
	}

	return SESSION_MANAGER_OPERATION_UNSUPPORTED;
}

int session_manager_null_establish_session (struct session_manager *session,
	struct cmd_interface_msg *request)
{
	UNUSED (request);

	if (session == NULL) {
		return SESSION_MANAGER_INVALID_ARGUMENT;
	}

	return SESSION_MANAGER_OPERATION_UNSUPPORTED;
}

int session_manager_null_is_session_established (struct session_manager *session, uint8_t eid)
{
	UNUSED (eid);

	if (session == NULL) {
		return SESSION_MANAGER_INVALID_ARGUMENT;
	}

	return false;
}

int session_manager_null_get_pairing_state (struct session_manager *session, uint8_t eid)
{
	UNUSED (eid);

	if (session == NULL) {
		return SESSION_MANAGER_INVALID_ARGUMENT;
	}

	return SESSION_PAIRING_STATE_NOT_SUPPORTED;
}

int session_manager_null_decrypt_message (struct session_manager *session,
	struct cmd_interface_msg *request)
{
	UNUSED (request);

	if (session == NULL) {
		return SESSION_MANAGER_INVALID_ARGUMENT;
	}

	return SESSION_MANAGER_OPERATION_UNSUPPORTED;
}

int session_manager_null_encrypt_message (struct session_manager *session,
	struct cmd_interface_msg *request)
{
	UNUSED (request);

	if (session == NULL) {
		return SESSION_MANAGER_INVALID_ARGUMENT;
	}

	return 0;
}

int session_manager_null_reset_session (struct session_manager *session, uint8_t eid, uint8_t *hmac,
	size_t hmac_len)
{
	UNUSED (eid);
	UNUSED (hmac);
	UNUSED (hmac_len);

	if (session == NULL) {
		return SESSION_MANAGER_INVALID_ARGUMENT;
	}

	return SESSION_MANAGER_OPERATION_UNSUPPORTED;
}

int session_manager_null_setup_paired_session (struct session_manager *session, uint8_t eid,
	size_t pairing_key_len, uint8_t *pairing_key_hmac, size_t pairing_key_hmac_len)
{
	UNUSED (eid);
	UNUSED (pairing_key_len);
	UNUSED (pairing_key_hmac);
	UNUSED (pairing_key_hmac_len);

	if (session == NULL) {
		return SESSION_MANAGER_INVALID_ARGUMENT;
	}

	return SESSION_MANAGER_OPERATION_UNSUPPORTED;
}

int session_manager_null_session_sync (struct session_manager *session, uint8_t eid,
	uint32_t rn_req, uint8_t *hmac, size_t hmac_len)
{
	UNUSED (eid);
	UNUSED (rn_req);
	UNUSED (hmac);
	UNUSED (hmac_len);

	if (session == NULL) {
		return SESSION_MANAGER_INVALID_ARGUMENT;
	}

	return SESSION_MANAGER_OPERATION_UNSUPPORTED;
}

/**
 * Initialize null session manager instance
 *
 * @param session Session manager instance to initialize.
 *
 * @return Initialization status, 0 if success or an error code.
 */
int session_manager_null_init (struct session_manager_null *session)
{
	if (session == NULL) {
		return SESSION_MANAGER_INVALID_ARGUMENT;
	}

	memset (session, 0, sizeof (struct session_manager));

	session->base.add_session = session_manager_null_add_session;
	session->base.establish_session = session_manager_null_establish_session;
	session->base.is_session_established = session_manager_null_is_session_established;
	session->base.get_pairing_state = session_manager_null_get_pairing_state;
	session->base.decrypt_message = session_manager_null_decrypt_message;
	session->base.encrypt_message = session_manager_null_encrypt_message;
	session->base.reset_session = session_manager_null_reset_session;
	session->base.setup_paired_session = session_manager_null_setup_paired_session;
	session->base.session_sync = session_manager_null_session_sync;

	return 0;
}

/**
 * Release session manager
 *
 * @param session Session manager instance to release
 */
void session_manager_null_release (struct session_manager_null *session)
{
	UNUSED (session);
}
