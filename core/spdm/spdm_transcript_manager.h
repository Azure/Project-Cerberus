// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPDM_TRANSCRIPT_MANAGER_H_
#define SPDM_TRANSCRIPT_MANAGER_H_

#include "platform_config.h"
#include "cmd_interface/cmd_interface.h"
#include "crypto/hash.h"


/* Configurable parameters. Defaults can be overridden in platform_config.h. */

/**
 * Buffer size for storing Version, Capabilities, Algorithms SPDM messages.
 */
#ifndef SPDM_TRANSCRIPT_MANAGER_VCA_BUFFER_MAX_SIZE
#define SPDM_TRANSCRIPT_MANAGER_VCA_BUFFER_MAX_SIZE				0x100
#endif

/**
 * Maximum number of SPDM sessions supported.
 * [TODO] Move this to spdm_commands.h in the connection object change.
 * [TODO] Ideally this would go away entirely, along with statically-sized arrays, and rely entirely
 * on input parameters provided during initialization.
 */
#ifndef SPDM_MAX_SESSION_COUNT
#define SPDM_MAX_SESSION_COUNT	1
#endif

/**
 * Count of hash engines required for an SPDM requester/responder.
 */
#define SPDM_TRANSCRIPT_MANAGER_HASH_ENGINE_REQUIRED_COUNT		2

/**
 * Transcript hash context indices.
 */
#define SPDM_TRANSCRIPT_MANAGER_HASH_ENGINE_INDEX_M1M2			0
#define SPDM_TRANSCRIPT_MANAGER_HASH_ENGINE_INDEX_L1L2			1

/**
 * Count of hash engines required for an SPDM session.
 */
#define SPDM_TRANSCRIPT_MANAGER_SESSION_HASH_ENGINE_REQUIRED_COUNT	2


/**
 * Buffer for storing Version, Capabilities and Algorithms SPDM messages.
 */
struct spdm_transcript_manager_vca_managed_buffer {
	size_t buffer_size;												/**< Current size of buffer. */
	uint8_t buffer[SPDM_TRANSCRIPT_MANAGER_VCA_BUFFER_MAX_SIZE];	/**< Buffer to hold the VCA messages. */
};

/**
 * Context for an SPDM transcript digest.
 */
struct spdm_transcript_manager_hash_context {
	uint8_t hash_engine_idx;	/**< Index into the hash_engine array. */
	bool hash_started;			/**< Hash engine state. */
};

/**
 * Transcript hash context for an SPDM session.
 */
struct spdm_transcript_manager_session_context {
	/**
	 * TH for KEY_EXCHANGE response signature: Concatenate (A, D, Ct, K)
	 * D = DIGEST, if MULTI_KEY_CONN_RSP
	 * Ct = certificate chain
	 * K = Concatenate (KEY_EXCHANGE request, KEY_EXCHANGE response\signature+verify_data)
	 *
	 * TH for KEY_EXCHANGE response HMAC: Concatenate (A, D, Ct, K)
	 * D = DIGEST, if MULTI_KEY_CONN_RSP
	 * Ct = certificate chain
	 * K = Concatenate (KEY_EXCHANGE request, KEY_EXCHANGE response\verify_data)
	 *
	 * TH for FINISH request signature: Concatenate (A, D, Ct, K, EncapD, CM, F)
	 * D = DIGEST, if MULTI_KEY_CONN_RSP
	 * Ct = certificate chain
	 * K = Concatenate (KEY_EXCHANGE request, KEY_EXCHANGE response)
	 * EncapD = Encap DIGEST, if MULTI_KEY_CONN_REQ
	 * CM = mutual certificate chain
	 * F = Concatenate (FINISH request\signature+verify_data)
	 *
	 * TH for FINISH response HMAC: Concatenate (A, D, Ct, K, EncapD, CM, F)
	 * D = DIGEST, if MULTI_KEY_CONN_RSP
	 * Ct = certificate chain
	 * K = Concatenate (KEY_EXCHANGE request, KEY_EXCHANGE response)
	 * EncapD = Encap DIGEST, if MULTI_KEY_CONN_REQ
	 * CM = mutual certificate chain, if MutAuth
	 * F = Concatenate (FINISH request\verify_data)
	 */
	struct spdm_transcript_manager_hash_context th;

	/**
	 * L1/L2 = Concatenate (M)
	 * M = Concatenate (GET_MEASUREMENT, MEASUREMENT\signature)
	 */
	struct spdm_transcript_manager_hash_context l1l2;
};

/**
 * Variable context for SPDM Transcript manager.
 */
struct spdm_transcript_manager_state {
	enum hash_type hash_algo;	/**< Hash algorithm used for hashing. */

	/**
	 * Buffer for Version, Capabilities and Algorithms SPDM messages.
	 */
	struct spdm_transcript_manager_vca_managed_buffer message_vca;

	/**
	 * M1/M2 = Concatenate (A, B, C)
	 * A = Concatenate (GET_VERSION, VERSION, GET_CAPABILITIES, CAPABILITIES, NEGOTIATE_ALGORITHMS, ALGORITHMS)
	 * B = Concatenate (GET_DIGEST, DIGEST, GET_CERTIFICATE, CERTIFICATE)
	 * C = Concatenate (CHALLENGE, CHALLENGE_AUTH\signature)
	 */
	struct spdm_transcript_manager_hash_context m1m2;

	/**
	 * L1/L2 = Concatenate (M)
	 * M = Concatenate (GET_MEASUREMENT, MEASUREMENT\signature)
	 */
	struct spdm_transcript_manager_hash_context l1l2;

	/**
	 * Transcript context(s) for SPDM session(s).
	 */
	struct spdm_transcript_manager_session_context session_transcript[SPDM_MAX_SESSION_COUNT];

	uint8_t session_transcript_count;	/**< Current count of session transcript context(s). */
	uint8_t spdm_version;				/**< SPDM version. */
};

/**
 * SPDM Transcript manager context types.
 */
enum spdm_transcript_manager_context_type {
	TRANSCRIPT_CONTEXT_TYPE_VCA,	/**< VCA buffer context identifier. */
	TRANSCRIPT_CONTEXT_TYPE_M1M2,	/**< M1/M2 hash context identifier. */
	TRANSCRIPT_CONTEXT_TYPE_L1L2,	/**< L1/L2 hash context indentifier. */
	TRANSCRIPT_CONTEXT_TYPE_TH,		/**< TH hash context identifier. */
	TRANSCRIPT_CONTEXT_TYPE_MAX,	/**< Invalid context identifier. */
};

/**
 * SPDM Transcript manager to manage transcript hashing.
 */
struct spdm_transcript_manager {
	/**
	 * Set the hash algorithm. The algorithm can be set only once.
	 *
	 * @param transcript_manager	Transcript manager instance.
	 * @param hash_algo				Hash algorithm to set.
	 *
	 * @return 0 if the hash algorithm was set or an error code.
	 */
	int (*set_hash_algo) (const struct spdm_transcript_manager *transcript_manager,
		enum hash_type hash_algo);

	/**
	 * Set the SPDM negotiated version to be used for communication.
	 *
	 * @param transcript_manager	Transcript manager instance.
	 * @param spdm_version			SPDM negotiated version.
	 */
	void (*set_spdm_version) (const struct spdm_transcript_manager *transcript_manager,
		uint8_t spdm_version);

	/**
	 * Update the transcript with a message.
	 *
	 * @param transcript_manager	Transcript manager instance.
	 * @param context_type			Transcript context to update.
	 * @param message				Message to add to the transcript.
	 * @param message_size			Size of message.
	 * @param use_session_context	Use session context to update an SPDM session transcript.
	 * @param session_idx			SPDM session index.
	 *
	 * @return 0 if the message was added to the transcript successfully or an error code.
	 */
	int (*update) (const struct spdm_transcript_manager *transcript_manager,
		enum spdm_transcript_manager_context_type context_type, const uint8_t *message,
		size_t message_size, bool use_session_context, uint8_t session_idx);

	/**
	 * Get the hash based on the hash type. The hashing operation is finished if finish_hash is set
	 * to true. In that case, an additional call to update will start a new hashing operation.
	 * If finish_hash is set to false, the hash is not finalized and can be updated with additional
	 * calls to update.
	 *
	 * @param transcript_manager	Transcript manager instance.
	 * @param context_type			Transcript context type to get the hash from.
	 * @param finish_hash			Flag to indicate to finish the hash.
	 * @param use_session_context	Use session context to update an SPDM session transcript.
	 * @param session_idx			SPDM session index.
	 * @param hash					Buffer to copy the hash to.
	 * @param hash_size				Size of hash.
	 *
	 * @return 0 if the hash was returned successfully or an error code.
	 */
	int (*get_hash) (const struct spdm_transcript_manager *transcript_manager,
		enum spdm_transcript_manager_context_type context_type, bool finish_hash,
		bool use_session_context, uint8_t session_idx, uint8_t *hash, size_t hash_size);

	/**
	 * Reset a transcript context.
	 *
	 * @param transcript_manager	Transcript manager instance.
	 * @param context_type			Transcript context to reset.
	 * @param use_session_context	Use session context to update an SPDM session transcript.
	 * @param session_idx			SPDM session index.
	 */
	void (*reset_transcript) (const struct spdm_transcript_manager *transcript_manager,
		enum spdm_transcript_manager_context_type context_type, bool use_session_context,
		uint8_t session_idx);

	/**
	 * Reset the transcript manager, including transcript context for all SPDM session(s).
	 *
	 * @param transcript_manager	Transcript manager to reset.
	 */
	void (*reset) (const struct spdm_transcript_manager *transcript_manager);

	/**
	 * Reset a session transcript.
	 *
	 * @param transcript_manager	Transcript manager instance.
	 * @param session_idx			Session index.
	 */
	void (*reset_session_transcript) (const struct spdm_transcript_manager *transcript_manager,
		uint8_t session_idx);

	const struct hash_engine *const *hash_engine;	/**< Hash engine instance(s). */
	uint8_t hash_engine_count;						/**< Number of hash engine instances. */
	struct spdm_transcript_manager_state *state;	/**< Variable context for SPDM Transcript manager. */
};


int spdm_transcript_manager_init (struct spdm_transcript_manager *transcript_manager,
	struct spdm_transcript_manager_state *state, const struct hash_engine *const *hash_engine,
	uint8_t hash_engine_count);

int spdm_transcript_manager_init_state (const struct spdm_transcript_manager *transcript_manager);

void spdm_transcript_manager_release (const struct spdm_transcript_manager *transcript_manager);


#define	SPDM_TRANSCRIPT_MANAGER_ERROR(code)	ROT_ERROR (ROT_MODULE_SPDM_TRANSCRIPT_MANAGER, code)

/**
 * Error codes that can be generated by the SPDM Transcript Manager.
 */
enum {
	SPDM_TRANSCRIPT_MANAGER_INVALID_ARGUMENT = SPDM_TRANSCRIPT_MANAGER_ERROR (0x00),			/**< Input parameter is null or not valid. */
	SPDM_TRANSCRIPT_MANAGER_NO_MEMORY = SPDM_TRANSCRIPT_MANAGER_ERROR (0x01),					/**< Memory allocation failed. */
	SPDM_TRANSCRIPT_MANAGER_BUFFER_FULL = SPDM_TRANSCRIPT_MANAGER_ERROR (0x02),					/**< VCA buffer is full. */
	SPDM_TRANSCRIPT_MANAGER_HASH_NOT_STARTED = SPDM_TRANSCRIPT_MANAGER_ERROR (0x03),			/**< Hash not started. */
	SPDM_TRANSCRIPT_MANAGER_INVALID_STATE = SPDM_TRANSCRIPT_MANAGER_ERROR (0x04),				/**< Invalid state. */
	SPDM_TRANSCRIPT_MANAGER_HASH_ALGO_ALREADY_SET = SPDM_TRANSCRIPT_MANAGER_ERROR (0x05),		/**< Hash algorithm is already set. */
	SPDM_TRANSCRIPT_MANAGER_INVALID_SESSION_IDX = SPDM_TRANSCRIPT_MANAGER_ERROR (0x06),			/**< Invalid session index. */
	SPDM_TRANSCRIPT_MANAGER_BUFFER_TOO_SMALL = SPDM_TRANSCRIPT_MANAGER_ERROR (0x07),			/**< Buffer is too small. */
	SPDM_TRANSCRIPT_MANAGER_UNSUPPORTED_CONTEXT_TYPE = SPDM_TRANSCRIPT_MANAGER_ERROR (0x08),	/**< Unsupported context type. */
	SPDM_TRANSCRIPT_MANAGER_SET_HASH_ALGO_FAILED = SPDM_TRANSCRIPT_MANAGER_ERROR (0x09),		/**< Setting the hash algorithm failed. */
	SPDM_TRANSCRIPT_MANAGER_UPDATE_FAILED = SPDM_TRANSCRIPT_MANAGER_ERROR (0x0a),				/**< Updating the transcript failed. */
	SPDM_TRANSCRIPT_MANAGER_GET_HASH_FAILED = SPDM_TRANSCRIPT_MANAGER_ERROR (0x0b),				/**< Getting the hash failed. */
	SPDM_TRANSCRIPT_MANAGER_RESET_FAILED = SPDM_TRANSCRIPT_MANAGER_ERROR (0x0c),				/**< Resetting the transcript manager failed. */
	SPDM_TRANSCRIPT_MANAGER_RESET_SESSION_FAILED = SPDM_TRANSCRIPT_MANAGER_ERROR (0x0d),		/**< Resetting the session transcript failed. */
};


#endif	/* SPDM_TRANSCRIPT_MANAGER_H_ */
