// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SESSION_MANAGER_H_
#define SESSION_MANAGER_H_


#include <stdbool.h>
#include <stdint.h>
#include "cerberus_protocol.h"
#include "crypto/aes_gcm.h"
#include "crypto/hash.h"
#include "crypto/rng.h"
#include "keystore/keystore.h"
#include "riot/riot_key_manager.h"
#include "status/rot_status.h"


#define SESSION_MANAGER_ENTRY_MAGIC						0xAA92D810

#define SESSION_MANAGER_NONCE_LEN						32
#define SESSION_MANAGER_HMAC_KEY_LEN					32
#define SESSION_MANAGER_TRAILER_LEN                     \
		(CERBERUS_PROTOCOL_AES_GCM_TAG_LEN + CERBERUS_PROTOCOL_AES_IV_LEN)
#define SESSION_MANAGER_PAIRING_KEY_LEN					32


enum {
	SESSION_STATE_UNUSED = 0,	/**< Session slot not used currently */
	SESSION_STATE_SETUP,		/**< Session currently being established */
	SESSION_STATE_ESTABLISHED,	/**< Session successfully established */
	SESSION_STATE_PAIRED,		/**< Pairing flow completed in established session */
};

enum {
	SESSION_PAIRING_STATE_NOT_SUPPORTED = 0,	/**< Pairing with device not supported */
	SESSION_PAIRING_STATE_NOT_INITIALIZED,		/**< Device supports pairing but has not been paired yet */
	SESSION_PAIRING_STATE_NOT_PAIRED,			/**< Device paired but current session not setup with pairing yet */
	SESSION_PAIRING_STATE_PAIRED,				/**< Pairing completed with device successfully */
};

/* Forward declare the message structure needed for session manager API. */
struct cmd_interface_msg;

/**
 * Entry in table holding session information and cached keys.
 */
struct session_manager_entry {
	uint8_t session_key[AES_GCM_256_KEY_LENGTH];			/**< AES session key */
	uint8_t hmac_key[SESSION_MANAGER_HMAC_KEY_LEN];			/**< HMAC key */
	uint8_t device_nonce[SESSION_MANAGER_NONCE_LEN];		/**< Nonce generated by device to use during session establishment */
	uint8_t cerberus_nonce[SESSION_MANAGER_NONCE_LEN];		/**< Nonce generated by Cerberus to use during session establishment */
	uint8_t eid;											/**< EID of other device participating in session */
	uint8_t session_state;									/**< Current session state */
	enum hmac_hash hmac_hash_type;							/**< HMAC hash type to utilize */
	uint8_t aes_init_vector[CERBERUS_PROTOCOL_AES_IV_LEN];	/**< AES Initialization vector used in encryption */
};

/**
 * Module which holds engines needed for session manager operation and caches session keys. Each
 * instance is intended to be dedicated to a single command interface.
 */
struct session_manager {
	/**
	 * Use provided nonces to either create or restart session with device specified using EID.
	 *
	 * @param session Session manager instance to utilize.
	 * @param eid Device EID.
	 * @param device_nonce 32 byte random nonce generated by device used for AES key generation.
	 * @param cerberus_nonce 32 byte random nonce generated by Cerberus used for AES key generation.
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*add_session) (struct session_manager *session, uint8_t eid, const uint8_t *device_nonce,
		const uint8_t *cerberus_nonce);

	/**
	 * Establish session for a device and generate AES session key.
	 *
	 * @param session Session manager instance to utilize.
	 * @param request Request to utilize for setting up the session, expected to hold a key exchange
	 * 	type 0 request.
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*establish_session) (struct session_manager *session, struct cmd_interface_msg *request);

	/**
	 * Check if device EID is on an established session.
	 *
	 * @param session Session manager instance to utilize.
	 * @param eid Device EID.
	 *
	 * @return 1 if established, 0 if not or an error code.
	 */
	int (*is_session_established) (struct session_manager *session, uint8_t eid);

	/**
	 * Check pairing state of session with device.
	 *
	 * @param session Session manager instance to utilize.
	 * @param eid Device EID.
	 *
	 * @return Pairing state or an error code.
	 */
	int (*get_pairing_state) (struct session_manager *session, uint8_t eid);

	/**
	 * Decrypt message using AES session key generated for session with device with requested EID.
	 *
	 * @param session Session manager instance to utilize.
	 * @param request Request to decrypt.
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*decrypt_message) (struct session_manager *session, struct cmd_interface_msg *request);

	/**
	 * Encrypt message using AES session key generated for session with device with requested EID.
	 * Output will contain encrypted message followed by the AES GCM tag and AES initialization
	 * vector generated and used.
	 *
	 * @param session Session manager instance to utilize.
	 * @param request Request to encrypt.
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*encrypt_message) (struct session_manager *session, struct cmd_interface_msg *request);

	/**
	 * Terminate and reset session.
	 *
	 * @param session Session manager instance to utilize.
	 * @param eid Device EID.
	 * @param hmac Optional HMAC provided by device. Set to NULL if not used.
	 * @param hmac_len HMAC length.
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*reset_session) (struct session_manager *session, uint8_t eid, uint8_t *hmac,
		size_t hmac_len);

	/**
	 * Setup device binding in an established encrypted session.
	 *
	 * @param session Session manager instance to utilize.
	 * @param eid Device EID.
	 * @param pairing_key_len Length of the pairing key.
	 * @param pairing_key_hmac Buffer containing HMAC generated by device for pairing key.
	 * @param pairing_key_hmac_len Length of the pairing key HMAC.
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*setup_paired_session) (struct session_manager *session, uint8_t eid,
		size_t pairing_key_len, uint8_t *pairing_key_hmac, size_t pairing_key_hmac_len);

	/**
	 * Get session sync HMAC.
	 *
	 * @param session Session manager instance to utilize.
	 * @param eid Device EID.
	 * @param rn_req Random number provided by device.
	 * @param hmac Buffer to hold generated HMAC.
	 * @param hmac_len Size of provided HMAC buffer.
	 *
	 * @return Size of generated HMAC or an error code.
	 */
	int (*session_sync) (struct session_manager *session, uint8_t eid, uint32_t rn_req,
		uint8_t *hmac, size_t hmac_len);

	const struct aes_gcm_engine *aes;				/**< AES engine used to encrypt/decrypt session data */
	const struct hash_engine *hash;					/**< Hashing engine used to generate AES shared key */
	const struct rng_engine *rng;					/**< RNG engine used to generate IV buffers */
	const struct riot_key_manager *riot;			/**< RIoT key manager containing alias key */
	size_t num_sessions;							/**< Total number of supported sessions */
	struct session_manager_entry *sessions_table;	/**< Table of supported device sessions */
	size_t num_pairing_eids;						/**< Total number of supported devices for pairing mode */
	const uint8_t *pairing_eids;					/**< List of supported devices for pairing mode */
	bool sessions_table_preallocated;				/**< Flag indicating if session tables were provided by caller */
	const struct keystore *store;					/**< Keystore used to persist pairing keys */
};


/* Internal functions for use by derived types. */
int session_manager_init (struct session_manager *session, const struct aes_gcm_engine *aes,
	const struct hash_engine *hash, const struct riot_key_manager *riot,
	struct session_manager_entry *sessions_table, size_t num_sessions, const uint8_t *pairing_eids,
	size_t num_pairing_eids, const struct keystore *store);
void session_manager_release (struct session_manager *session);

int session_manager_add_session (struct session_manager *session, uint8_t eid,
	const uint8_t *device_nonce, const uint8_t *cerberus_nonce);
int session_manager_decrypt_message (struct session_manager *session,
	struct cmd_interface_msg *request);
int session_manager_encrypt_message (struct session_manager *session,
	struct cmd_interface_msg *request);
int session_manager_is_session_established (struct session_manager *session, uint8_t eid);
int session_manager_get_pairing_state (struct session_manager *session, uint8_t eid);
int session_manager_reset_session (struct session_manager *session, uint8_t eid, uint8_t *hmac,
	size_t hmac_len);
int session_manager_setup_paired_session (struct session_manager *session, uint8_t eid,
	size_t pairing_key_len, uint8_t *pairing_key_hmac, size_t pairing_key_hmac_len);
int session_manager_generate_keys_digest (struct session_manager *session,
	const uint8_t *device_key, size_t device_key_len, const uint8_t *session_pub_key,
	size_t session_pub_key_len);
int session_manager_session_sync (struct session_manager *session, uint8_t eid, uint32_t rn_req,
	uint8_t *hmac, size_t hmac_len);

struct session_manager_entry* session_manager_get_session (struct session_manager *session,
	uint8_t eid);


#define	SESSION_MANAGER_ERROR(code)				ROT_ERROR (ROT_MODULE_SESSION_MANAGER, code)

/**
 * Error codes that can be generated by the session manager.
 */
enum {
	SESSION_MANAGER_INVALID_ARGUMENT = SESSION_MANAGER_ERROR (0x00),					/**< Input parameter is null or not valid. */
	SESSION_MANAGER_NO_MEMORY = SESSION_MANAGER_ERROR (0x01),							/**< Memory allocation failed. */
	SESSION_MANAGER_UNEXPECTED_EID = SESSION_MANAGER_ERROR (0x02),						/**< Device EID unexpected. */
	SESSION_MANAGER_SESSION_NOT_ESTABLISHED = SESSION_MANAGER_ERROR (0x03),				/**< Operation can't be completed without establishing session. */
	SESSION_MANAGER_INVALID_ORDER = SESSION_MANAGER_ERROR (0x04),						/**< Invalid order attempted for session establishment. */
	SESSION_MANAGER_FULL = SESSION_MANAGER_ERROR (0x05),								/**< Session manager at capacity and cannot support more sessions. */
	SESSION_MANAGER_MALFORMED_MSG = SESSION_MANAGER_ERROR (0x06),						/**< Provided message to decrypt invalid. */
	SESSION_MANAGER_BUF_TOO_SMALL = SESSION_MANAGER_ERROR (0x07),						/**< Provided output buffer too small for operation. */
	SESSION_MANAGER_INVALID_REQUEST = SESSION_MANAGER_ERROR (0x08),						/**< Provided session request invalid. */
	SESSION_MANAGER_OPERATION_UNSUPPORTED = SESSION_MANAGER_ERROR (0x09),				/**< Requested operation not supported. */
	SESSION_MANAGER_OPERATION_NOT_PERMITTED = SESSION_MANAGER_ERROR (0x0A),				/**< Requested operation not permitted. */
	SESSION_MANAGER_PAIRING_NOT_SUPPORTED_WITH_DEVICE = SESSION_MANAGER_ERROR (0x0B),	/**< Pairing not supported with device. */
	SESSION_MANAGER_ADD_SESSION_FAILED = SESSION_MANAGER_ERROR (0x0C),					/**< Failed to add a new session. */
	SESSION_MANAGER_ESTABLISH_SESSION_FAILED = SESSION_MANAGER_ERROR (0x0D),			/**< Failed to establish the encrypted connection. */
	SESSION_MANAGER_SESSION_CHECK_FAILED = SESSION_MANAGER_ERROR (0x0E),				/**< Failed to check the session state. */
	SESSION_MANAGER_PAIRING_STATE_FAILED = SESSION_MANAGER_ERROR (0x0F),				/**< Failed to check the pairing state. */
	SESSION_MANAGER_DECRYPT_MSG_FAILED = SESSION_MANAGER_ERROR (0x10),					/**< Failed to decrypt a message. */
	SESSION_MANAGER_ENCRYPT_MSG_FAILED = SESSION_MANAGER_ERROR (0x11),					/**< Failed to encrypt a message. */
	SESSION_MANAGER_RESET_SESSION_FAILED = SESSION_MANAGER_ERROR (0x12),				/**< Failed to terminate a session. */
	SESSION_MANAGER_PAIR_SESSION_FAILED = SESSION_MANAGER_ERROR (0x13),					/**< Failed to pair with a device. */
	SESSION_MANAGER_SESSION_SYNC_FAILED = SESSION_MANAGER_ERROR (0x14),					/**< Failed to sync the current session. */
};


#endif	/* SESSION_MANAGER_H_ */
