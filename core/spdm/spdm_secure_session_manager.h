// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPDM_SECURE_SESSION_MANAGER_H_
#define SPDM_SECURE_SESSION_MANAGER_H_

#include "platform_config.h"
#include "spdm_commands.h"
#include "spdm_protocol_session_observer.h"
#include "common/observable.h"
#include "crypto/hkdf.h"
#include "fips/error_state_entry_interface.h"

/* TODO:  This fila has many dependencies but is missing headers for them. */


/* Configurable parameters. Defaults can be overridden in platform_config.h. */

/**
 * Maximum number of SPDM sessions supported.
 */
#ifndef SPDM_MAX_SESSION_COUNT
#define SPDM_MAX_SESSION_COUNT		1
#endif

/**
 * Maximum number of SPDM session sequence numbers.
 */
#ifndef SPDM_MAX_SECURE_SESSION_SEQUENCE_NUMBER
#define SPDM_MAX_SECURE_SESSION_SEQUENCE_NUMBER		UINT64_MAX
#endif

/**
 * Max. DHE key size for supported hash algorithms.
 */
#define SPDM_MAX_DHE_SHARED_SECRET_SIZE		ECC_MAX_KEY_LENGTH

/**
 * Invalid session id.
 */
#define SPDM_INVALID_SESSION_ID		0

/**
 * Session Id concatenation (Request Session Id (16-LSb), Response Session Id (16-MSb))
 */
#define GET_REQUEST_SESSION_ID(session_id) (session_id & 0xFFFF)
#define GET_RESPONSE_SESSION_ID(session_id) ((session_id & 0xFFFF0000) >> 16)
#define MAKE_SESSION_ID(req_session_id, rsp_session_id) \
	((((uint32_t) rsp_session_id) << 16) | req_session_id)

/**
 * SPDM Key Schedule related strings.
 */
#define SPDM_BIN_CONCAT_LABEL				"spdmx.x "
#define SPDM_VERSION_1_1_BIN_CONCAT_LABEL	"spdm1.1 "
#define SPDM_VERSION_1_2_BIN_CONCAT_LABEL	"spdm1.2 "
#define SPDM_BIN_STR_0_LABEL				"derived"
#define SPDM_BIN_STR_1_LABEL				"req hs data"
#define SPDM_BIN_STR_2_LABEL				"rsp hs data"
#define SPDM_BIN_STR_3_LABEL				"req app data"
#define SPDM_BIN_STR_4_LABEL				"rsp app data"
#define SPDM_BIN_STR_5_LABEL				"key"
#define SPDM_BIN_STR_6_LABEL				"iv"
#define SPDM_BIN_STR_7_LABEL				"finished"
#define SPDM_BIN_STR_8_LABEL				"exp master"
#define SPDM_BIN_STR_9_LABEL				"traffic upd"

/**
 * Max. AEAD crypto sizes.
 */
#define SPDM_MAX_AEAD_KEY_SIZE		32
#define SPDM_MAX_AEAD_IV_SIZE		12
#define SPDM_MAX_AEAD_TAG_SIZE		16

/**
 * SPDM secure session type.
 */
enum spdm_secure_session_type {
	SPDM_SESSION_TYPE_NONE,		/**< Open session. */
	SPDM_SESSION_TYPE_MAC_ONLY,	/**< MAC only session. */
	SPDM_SESSION_TYPE_ENC_MAC,	/**< Encrypted and MAC session. */
	SPDM_SESSION_TYPE_MAX,		/**< MAX */
};

/**
 * SPDM session states.
 */
enum spdm_secure_session_state {
	SPDM_SESSION_STATE_NOT_STARTED,	/**< Before send KEY_EXCHANGE/PSK_EXCHANGE or after END_SESSION */
	SPDM_SESSION_STATE_HANDSHAKING,	/**< After send KEY_EXCHANGE, before send FINISH */
	SPDM_SESSION_STATE_ESTABLISHED,	/**< After send FINISH, before END_SESSION */
	SPDM_SESSION_STATE_MAX,			/**< MAX */
};

#pragma pack(1)

/**
 *  Secured Messages opaque specification Id.
 */
#define SPDM_SECURED_MESSAGE_OPAQUE_DATA_SPEC_ID	0x444D5446

/**
 *  Secured Messages opaque data version.
 */
#define SPDM_SECURED_MESSAGE_OPAQUE_VERSION				0x1

/**
 *  Secured Messages opaque data element version.
 */
#define SPDM_SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION				0x1

#define SPDM_SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_VERSION_SELECTION		0x0

#define SPDM_SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_SUPPORTED_VERSION		0x1

/**
 *  Secured Message general opaque data table per SPDM secure session spec section 8.
 */
struct spdm_secured_message_general_opaque_data_table_header {
	uint32_t spec_id;		/**< This will be SPDM_SECURED_MESSAGE_OPAQUE_DATA_SPEC_ID per SPDM secure session spec section 8. */
	uint8_t opaque_version;	/**< Identifies the format of the remaining bytes. Shall be 1 per SPDM secure session spec section 8. */
	uint8_t total_elements;	/**< Total number of elements in OpaqueList. */
	uint16_t reserved;		/**< Reserved. */
};

/**
 * Opaque element table per SPDM secure session spec section 8.
 */
struct spdm_secured_message_opaque_element_table_header {
	uint8_t id;							/**< SPDM_REGISTRY_ID_DMTF*/
	uint8_t vendor_len;					/**< VendorID length. */
	uint16_t opaque_element_data_len;	/**< Opaque element data length. */
};

/**
 * Opaque element table per SPDM secure session spec section 8.
 */
struct spdm_secured_message_opaque_element_header {
	uint8_t sm_data_version;	/**< SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION */
	uint8_t sm_data_id;			/**< SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_VERSION_SELECTION */
};

/**
 * Secured Message version selection data format per SPDM secure session spec section 8.1.1
 */
struct spdm_secured_message_opaque_element_version_selection {
	uint8_t sm_data_version;	/**< SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION */
	uint8_t sm_data_id;			/**< SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_VERSION_SELECTION */
	struct spdm_version_number selected_version;
};

/**
 * Opaque_element_supported_version data format per SPDM secure session spec section 8.1.2
 */
struct spdm_secured_message_opaque_element_supported_version {
	uint8_t sm_data_version;	/**< SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION */
	uint8_t sm_data_id;			/**< SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_SUPPORTED_VERSION */
	uint8_t version_count;		/**< Number of supported versions. */
};

/**
 * SPDM secure message first part of the header.
 */
struct spdm_secured_message_data_header_1 {
	uint32_t session_id;	/**< Session Id of the session. */
};

/**
 * SPDM secure message last part of the header.
 */
struct spdm_secured_message_data_header_2 {
	uint16_t length;	/**< The length of the remaining data, including application_data_length(O), payload, Random(O) and MAC.*/
};

/**
 * SPDM secure message cipher header.
 */
struct spdm_secured_message_cipher_header {
	uint16_t application_data_length;	/**< The length of the application payload. */
};

#pragma pack()

/**
 * SPDM secure session master secrets.
 */
struct spdm_secure_session_master_secrets {
	uint8_t dhe_secret[SPDM_MAX_DHE_SHARED_SECRET_SIZE];	/**< DHE secret. */
	uint8_t master_secret_salt1[HASH_MAX_HASH_LEN];			/**< Salt for generating master secret */
};

/**
 * SPDM secure session handshake secrets.
 */
struct spdm_secure_session_handshake_secrets {
	uint8_t request_finished_key[HASH_MAX_HASH_LEN];					/**< Requester finished key. */
	uint8_t response_finished_key[HASH_MAX_HASH_LEN];					/**< Responder finished key. */
	uint8_t request_handshake_encryption_key[SPDM_MAX_AEAD_KEY_SIZE];	/**< Requester handshake encryption key. */
	uint8_t request_handshake_salt[SPDM_MAX_AEAD_IV_SIZE];				/**< Requester handshake salt. */
	uint64_t request_handshake_sequence_number;							/**< Requester handshake sequence number. */
	uint8_t response_handshake_encryption_key[SPDM_MAX_AEAD_KEY_SIZE];	/**< Responder handshake encryption key. */
	uint8_t response_handshake_salt[SPDM_MAX_AEAD_IV_SIZE];				/**< Responder handshake salt. */
	uint64_t response_handshake_sequence_number;						/**< Responder handshake sequence number. */
};

/**
 * SPDM session data secrets.
 */
struct spdm_secure_session_data_secrets {
	uint8_t request_data_encryption_key[SPDM_MAX_AEAD_KEY_SIZE];	/**< Requester data encryption key. */
	uint8_t request_data_salt[SPDM_MAX_AEAD_IV_SIZE];				/**< Requester data salt. */
	uint64_t request_data_sequence_number;							/**< Requester data sequence number. */
	uint8_t response_data_encryption_key[SPDM_MAX_AEAD_KEY_SIZE];	/**< Responder data encryption key. */
	uint8_t response_data_salt[SPDM_MAX_AEAD_IV_SIZE];				/**< Responder data salt. */
	uint64_t response_data_sequence_number;							/**< Responder data sequence number. */
};

/**
 * SPDM secure session object.
 */
struct spdm_secure_session {
	uint32_t session_id;												/**< SPDM Session Id. */
	uint32_t session_index;												/**< Index of session in sessions array. */
	struct spdm_end_session_request_attributes end_session_attributes;	/**< End session attributes. */
	uint8_t session_policy;												/**< Session termination policy. */
	struct spdm_key_update_request last_key_update_request;				/**< Last key update request. */
	enum spdm_secure_session_type session_type;							/**< Session type. */
	struct spdm_version_number version;									/**< Negotiated version. */
	struct spdm_version_number secure_message_version;					/**< Negotiated secured message version. */
	uint32_t base_hash_algo;											/**< Negotiated base hash algorithm. */
	uint16_t dhe_named_group;											/**< Negotiated DHE algorithm. */
	uint16_t aead_cipher_suite;											/**< Negotiated AEAD algorithm. */
	uint16_t key_schedule;												/**< Negotiated key schedule. */
	size_t hash_size;													/**< Negotiated hash size. */
	size_t dhe_key_size;												/**< Negotiated DHE key size. */
	size_t aead_key_size;												/**< Negotiated AEAD key size. */
	size_t aead_iv_size;												/**< Negotiated AEAD IV size. */
	size_t aead_tag_size;												/**< Negotiated AEAD tag size. */
	enum spdm_secure_session_state session_state;						/**< State in which the SPDM session is. */
	struct spdm_secure_session_master_secrets master_secret;			/**< Master secret. */
	struct spdm_secure_session_handshake_secrets handshake_secret;		/**< Handshake secret. */
	struct spdm_secure_session_data_secrets data_secret;				/**< Data secret. */
	struct spdm_secure_session_data_secrets data_secret_backup;			/**< Data secret backup. */
	bool requester_backup_valid;										/**< Requester backup is valid. */
	bool responder_backup_valid;										/**< Responder backup is valid. */
	bool is_requester;													/**< Requester or responder role. */
	struct spdm_device_capability peer_capabilities;					/**< Peer capabilities. */
};

/**
 * Structure to describe algorithms which are used by SPDM session manager. When user creates
 * session manager instance, multiple pointers to different algorithms implementations are
 * provided as initialization parameters. This struct classifies some of them, for example
 * SW vs HW, so this information could be logged in case of critical errors.
 */
struct spdm_secure_session_manager_algo_info {
	uint32_t ecdh_instance_id;	/**< ECDH algorithm classification */
};

/**
 * SPDM session manager state.
 */
struct spdm_secure_session_manager_state {
	struct spdm_secure_session sessions[SPDM_MAX_SESSION_COUNT];	/**< Secure Sessions. */
	uint32_t current_session_count;									/**< Current number of active sessions. */
	uint32_t last_spdm_request_secure_session_id;					/**< Secure session Id of last secure message. */
	bool last_spdm_request_secure_session_id_valid;					/**< Secure session Id validity. */
	struct observable observable;									/**< Observer manager for the SPDM session manager. */
};

struct spdm_secure_session_manager {
	/**
	 * Create a new SPDM secure session.
	 *
	 * @param session_manager SPDM session manager.
	 * @param session_id Session Id for the session.
	 * @param is_requester true if the session is for the requester, false otherwise.
	 * @param connection_info SPDM connection info.
	 *
	 * @return A pointer to the created SPDM secure session or NULL if the session could not be created.
	 */
	struct spdm_secure_session* (*create_session) (
		const struct spdm_secure_session_manager *session_manager, uint32_t session_id,
		bool is_requester, const struct spdm_connection_info *connection_info);

	/**
	 * Release an SPDM secure session.
	 *
	 * @param session_manager SPDM session manager.
	 * @param session_id Session Id for the session.
	 */
	void (*release_session) (const struct spdm_secure_session_manager *session_manager,
		uint32_t session_id);

	/**
	 * Get an SPDM secure session.
	 *
	 * @param session_manager SPDM session manager.
	 * @param session_id Session Id for the session.
	 *
	 * @return A pointer to the SPDM secure session or NULL if the session does not exist.
	 */
	struct spdm_secure_session* (*get_session) (
		const struct spdm_secure_session_manager *session_manager, uint32_t session_id);

	/**
	 * Set the session state for an SPDM secure session.
	 *
	 * @param session_manager SPDM session manager.
	 * @param session_id Session Id for the session.
	 * @param session_state Session state to set.
	 */
	void (*set_session_state) (const struct spdm_secure_session_manager *session_manager,
		uint32_t session_id, enum spdm_secure_session_state session_state);

	/**
	 * Reset the Session Manager.
	 *
	 * @param session_manager SPDM session manager.
	 */
	void (*reset) (const struct spdm_secure_session_manager *session_manager);

	/**
	 * Generate the shared secret from peer and local publick keys.
	 *
	 * @param session_manager SPDM session manager.
	 * @param session SPDM session info.
	 * @param peer_pub_key_point Peer public key in point format.
	 * @param local_pub_key_point Pointer to store the generated local public key in point format.
	 *
	 * @return 0 if shared secret is generated successfully. error code otherwise.
	 */
	int (*generate_shared_secret) (const struct spdm_secure_session_manager *session_manager,
		struct spdm_secure_session *session, const struct ecc_point_public_key *peer_pub_key_point,
		uint8_t *local_pub_key_point);

	/**
	 * Generate handshake keys for an SPDM secure session.
	 *
	 * @param session_manager Session Manager.
	 * @param session Secure Session.
	 *
	 * @return 0 if the handshake keys are generated successfully, error code otherwise.
	 */
	int (*generate_session_handshake_keys) (
		const struct spdm_secure_session_manager *session_manager,
		struct spdm_secure_session *session);

	/**
	 * Generate data keys for an SPDM secure session.
	 *
	 * @param session_manager SPDM Session Manager.
	 * @param session SPDM Secure Session.
	 *
	 * @return 0 if the data keys are generated successfully, error code otherwise.
	 */
	int (*generate_session_data_keys) (const struct spdm_secure_session_manager *session_manager,
		struct spdm_secure_session *session);

	/**
	 * Query if the last session is active.
	 *
	 * @param session_manager SPDM session manager.
	 *
	 * @return true if the last session is active, false otherwise.
	 */
	bool (*is_last_session_id_valid) (const struct spdm_secure_session_manager *session_manager);

	/**
	 * Get the last session id.
	 *
	 * @param session_manager SPDM session manager.
	 *
	 * @return Last session id.
	 */
	uint32_t (*get_last_session_id) (const struct spdm_secure_session_manager *session_manager);

	/**
	 * Reset the last session id validity.
	 *
	 * @param session_manager SPDM session manager.
	 */
	void (*reset_last_session_id_validity) (
		const struct spdm_secure_session_manager *session_manager);

	/**
	 * Decode a secure message. This includes MAC verification and optionally decryption.
	 *
	 * @param session_manager SPDM session manager.
	 * @param request SPDM request message.
	 *
	 * @return 0 if the secure message is decoded successfully, error code otherwise.
	 */
	int (*decode_secure_message) (const struct spdm_secure_session_manager *session_manager,
		struct cmd_interface_msg *request);

	/**
	 * Encode a secure message. This includes MAC generation and optionally encryption.
	 *
	 * @param session_manager SPDM session manager.
	 * @param request SPDM request message.
	 *
	 * @return 0 if the secure message is encoded successfully, error code otherwise.
	 */
	int (*encode_secure_message) (const struct spdm_secure_session_manager *session_manager,
		struct cmd_interface_msg *request);

	const struct spdm_device_capability *local_capabilities;	/**< Local capabilities. */
	const struct spdm_device_algorithms *local_algorithms;		/**< Local algorithms. */
	const struct aes_gcm_engine *aes_engine;					/**< AES engine. */
	const struct hash_engine *hash_engine;						/**< Hashing engine. */
	const struct rng_engine *rng_engine;						/**< RNG engine. */
	const struct ecc_engine *ecc_engine;						/**< ECC engine. */
	const struct spdm_transcript_manager *transcript_manager;	/**< Transcript Manager. */
	struct spdm_secure_session_manager_state *state;			/**< Session Manager State. */
	uint64_t max_spdm_session_sequence_number;					/**< Max SPDM session sequence number. */
	const struct hkdf_interface *hkdf;							/**< HKDF implementation */
	const struct error_state_entry_interface *error;			/**< Error state management interface */
	struct spdm_secure_session_manager_algo_info algo_info;		/**< Metadata for used algorithms */
};


int spdm_secure_session_manager_init (struct spdm_secure_session_manager *session_manager,
	struct spdm_secure_session_manager_state *state,
	const struct spdm_device_capability *local_capabilities,
	const struct spdm_device_algorithms *local_algorithms, const struct aes_gcm_engine *aes_engine,
	const struct hash_engine *hash_engine, const struct rng_engine *rng_engine,
	const struct ecc_engine *ecc_engine, const struct spdm_transcript_manager *transcript_manager,
	const struct hkdf_interface *hkdf, const struct error_state_entry_interface *error,
	struct spdm_secure_session_manager_algo_info algo_info);

void spdm_secure_session_manager_release (
	const struct spdm_secure_session_manager *session_manager);

int spdm_secure_session_manager_init_state (
	const struct spdm_secure_session_manager *session_manager);

int spdm_secure_session_manager_add_spdm_protocol_session_observer (
	const struct spdm_secure_session_manager *session_manager,
	const struct spdm_protocol_session_observer *observer);
int spdm_secure_session_manager_remove_spdm_protocol_session_observer (
	const struct spdm_secure_session_manager *session_manager,
	const struct spdm_protocol_session_observer *observer);


#define	SPDM_SECURE_SESSION_MANAGER_ERROR(\
	code) ROT_ERROR (ROT_MODULE_SPDM_SECURE_SESSION_MANAGER, code)

/**
 * Error codes that can be generated by the Secure Session Manager.
 */
enum {
	SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT = SPDM_SECURE_SESSION_MANAGER_ERROR (0x00),			/**< Input parameter is null or not valid. */
	SPDM_SECURE_SESSION_MANAGER_NO_MEMORY = SPDM_SECURE_SESSION_MANAGER_ERROR (0x01),					/**< Memory allocation failed. */
	SPDM_SECURE_SESSION_MANAGER_GENERATE_SHARED_SECRET_FAILED =
		SPDM_SECURE_SESSION_MANAGER_ERROR (0x02),														/**< Generate shared secret failed. */
	SPDM_SECURE_SESSION_MANAGER_GENERATE_HANDSHAKE_KEYS_FAILED =
		SPDM_SECURE_SESSION_MANAGER_ERROR (0x03),														/**< Generate handshake keys failed. */
	SPDM_SECURE_SESSION_MANAGER_SEQUENCE_NUMBER_OVERFLOW = SPDM_SECURE_SESSION_MANAGER_ERROR (0x04),	/**< Sequence number overflow. */
	SPDM_SECURE_SESSION_MANAGER_INVALID_MESSAGE_SIZE = SPDM_SECURE_SESSION_MANAGER_ERROR (0x05),		/**< Invalid message size. */
	SPDM_SECURE_SESSION_MANAGER_BUFFER_TOO_SMALL = SPDM_SECURE_SESSION_MANAGER_ERROR (0x06),			/**< Buffer too small. */
	SPDM_SECURE_SESSION_MANAGER_SESSION_TRY_DISCARD_KEY_UPDATE =
		SPDM_SECURE_SESSION_MANAGER_ERROR (0x07),														/**< Message decryption failed, try update keys. */
	SPDM_SECURE_SESSION_MANAGER_UNSUPPORTED_CAPABILITY = SPDM_SECURE_SESSION_MANAGER_ERROR (0x08),		/**< Unsupported capability. */
	SPDM_SECURE_SESSION_MANAGER_INTERNAL_ERROR = SPDM_SECURE_SESSION_MANAGER_ERROR (0x09),				/**< Internal error. */
	SPDM_SECURE_SESSION_MANAGER_GENERATE_DATA_KEYS_FAILED =
		SPDM_SECURE_SESSION_MANAGER_ERROR (0x0A),														/**< Generate data keys failed. */
};


#endif	/* SPDM_SECURE_SESSION_MANAGER_H_ */
