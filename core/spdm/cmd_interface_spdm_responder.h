// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_SPDM_RESPONDER_H_
#define CMD_INTERFACE_SPDM_RESPONDER_H_

#include <stdint.h>
#include "crypto/hash.h"
#include "spdm_protocol.h"
#include "cmd_interface/cmd_interface.h"
#include "spdm_transcript_manager.h"


/**
 * Command interface for processing SPDM protocol requests.
 */
struct cmd_interface_spdm_responder {
	struct cmd_interface base;							/**< Base command interface. */
	struct spdm_state *state;							/**< SPDM state. */
	struct hash_engine *hash_engine;					/**< Hash engine for hashing operations. */
	struct spdm_transcript_manager *transcript_manager;	/**< Transcript manager for SPDM. */
	const struct spdm_version_num_entry *version_num;	/**< Supported version number(s). */
	uint8_t version_num_count;							/**< Number of supported version number(s). */
};


int cmd_interface_spdm_responder_init (struct cmd_interface_spdm_responder *spdm_responder,
	struct spdm_state *state, struct spdm_transcript_manager *transcript_manager,
	struct hash_engine *hash_engine, const struct spdm_version_num_entry *version_num,
	uint8_t version_num_count);

int cmd_interface_spdm_responder_init_state (
	const struct cmd_interface_spdm_responder *spdm_responder);

void cmd_interface_spdm_responder_deinit (const struct cmd_interface_spdm_responder *spdm_responder);


#define	CMD_HANDLER_SPDM_RESPONDER_ERROR(code)		ROT_ERROR (ROT_MODULE_CMD_HANDLER_SPDM_RESPONDER, code)

/**
 * Error codes that can be generated by the SPDM responder.
 */
enum {
	CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT = CMD_HANDLER_SPDM_RESPONDER_ERROR (0x00),			/**< Input parameter is null or not valid. */
	CMD_HANDLER_SPDM_RESPONDER_NO_MEMORY = CMD_HANDLER_SPDM_RESPONDER_ERROR (0x01),					/**< Memory allocation failed. */
	CMD_HANDLER_SPDM_RESPONDER_UNKNOWN_COMMAND = CMD_HANDLER_SPDM_RESPONDER_ERROR (0x02),			/**< A command does not represent a known request. */
	CMD_HANDLER_SPDM_RESPONDER_SPDM_BAD_LENGTH = CMD_HANDLER_SPDM_RESPONDER_ERROR (0x03),			/**< The payload length is wrong for the request. */
	CMD_HANDLER_SPDM_RESPONDER_DEVICE_CERT_NOT_AVAILABLE = CMD_HANDLER_SPDM_RESPONDER_ERROR (0x04),	/**< The device cert is not available. */
	CMD_HANDLER_SPDM_RESPONDER_ALIAS_CERT_NOT_AVAILABLE = CMD_HANDLER_SPDM_RESPONDER_ERROR (0x05),	/**< The alias cert is not available. */
	CMD_HANDLER_SPDM_RESPONDER_UNSUPPORTED_OPERATION = CMD_HANDLER_SPDM_RESPONDER_ERROR (0x06),		/**< The request is not supported. */
	CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST = CMD_HANDLER_SPDM_RESPONDER_ERROR (0x07),			/**< The request is invalid. */
	CMD_HANDLER_SPDM_RESPONDER_VERSION_MISMATCH = CMD_HANDLER_SPDM_RESPONDER_ERROR (0x08),			/**< The request version is not supported. */
};


#endif /* CMD_INTERFACE_SPDM_RESPONDER_H_ */