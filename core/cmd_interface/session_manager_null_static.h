// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SESSION_MANAGER_NULL_STATIC_H_
#define SESSION_MANAGER_NULL_STATIC_H_

#include "session_manager_null.h"


int session_manager_null_add_session (struct session_manager *session, uint8_t eid,
	const uint8_t *device_nonce, const uint8_t *cerberus_nonce);
int session_manager_null_establish_session (struct session_manager *session,
	struct cmd_interface_msg *request);
int session_manager_null_is_session_established (struct session_manager *session, uint8_t eid);
int session_manager_null_get_pairing_state (struct session_manager *session, uint8_t eid);
int session_manager_null_decrypt_message (struct session_manager *session,
	struct cmd_interface_msg *request);
int session_manager_null_encrypt_message (struct session_manager *session,
	struct cmd_interface_msg *request);
int session_manager_null_reset_session (struct session_manager *session, uint8_t eid, uint8_t *hmac,
	size_t hmac_len);
int session_manager_null_setup_paired_session (struct session_manager *session, uint8_t eid,
	size_t pairing_key_len, uint8_t *pairing_key_hmac, size_t pairing_key_hmac_len);
int session_manager_null_session_sync (struct session_manager *session, uint8_t eid,
	uint32_t rn_req, uint8_t *hmac, size_t hmac_len);

/**
 * Constant initializer for the null session manager API.
 */
#define SESSION_MANAGEMENT_NULL_API_INIT  { \
		.add_session = session_manager_null_add_session, \
		.establish_session = session_manager_null_establish_session, \
		.is_session_established = session_manager_null_is_session_established, \
		.get_pairing_state = session_manager_null_get_pairing_state, \
		.decrypt_message = session_manager_null_decrypt_message, \
		.encrypt_message = session_manager_null_encrypt_message, \
		.reset_session = session_manager_null_reset_session, \
		.setup_paired_session = session_manager_null_setup_paired_session, \
		.session_sync = session_manager_null_session_sync, \
		.aes = NULL, \
		.hash = NULL, \
		.rng = NULL, \
		.riot = NULL, \
		.sessions_table = NULL, \
		.pairing_eids = NULL, \
		.store = NULL \
	}


/**
 * Initialize a static instance of null session manager.
 *
 * There is no validation done on the arguments.
 */
#define session_manager_null_static_init	{ \
		.base = SESSION_MANAGEMENT_NULL_API_INIT \
	}


#endif	// SESSION_MANAGER_NULL_STATIC_H_
