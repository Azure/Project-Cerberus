// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_TDISP_RESPONDER_H
#define CMD_INTERFACE_TDISP_RESPONDER_H

#include "tdisp_driver.h"


/**
 * PCI TDISP Vendor Protocol Interface.
 */
struct cmd_interface_tdisp_responder {
	struct cmd_interface base;					/**< Base command interface. */
	struct tdisp_state *state;					/**< TDISP state. */
	const struct tdisp_driver *tdisp_driver;	/**< TDISP driver interface. */
	const uint8_t *version_num;					/**< Supported TDISP versions. */
	uint8_t version_num_count;					/**< Number of supported TDISP versions. */
	struct rng_engine *rng_engine;				/**< Engine for random number generation. */
};


int cmd_interface_tdisp_responder_init (struct cmd_interface_tdisp_responder *tdisp_responder,
	struct tdisp_state *state, struct tdisp_driver *tdisp_driver, const uint8_t *version_num,
	uint8_t version_num_count, struct rng_engine *rng_engine);

int cmd_interface_tdisp_responder_init_state (
	const struct cmd_interface_tdisp_responder *tdisp_responder);

void cmd_interface_tdisp_responder_release (
	const struct cmd_interface_tdisp_responder *tdisp_responder);


#define	CMD_INTERFACE_TDISP_RESPONDER_ERROR(\
	code)		ROT_ERROR (ROT_MODULE_CMD_INTERFACE_TDISP_RESPONDER, code)

/**
 * Error codes that can be generated by the TDISP responder.
 */
enum {
	CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT = CMD_INTERFACE_TDISP_RESPONDER_ERROR (0x00),	/**< Input parameter is null or not valid. */
	CMD_INTERFACE_TDISP_RESPONDER_NO_MEMORY = CMD_INTERFACE_TDISP_RESPONDER_ERROR (0x01),			/**< Memory allocation failed. */
	CMD_INTERFACE_TDISP_RESPONDER_INVALID_REQUEST = CMD_INTERFACE_TDISP_RESPONDER_ERROR (0x02),		/**< The request is invalid. */
	CMD_INTERFACE_TDISP_RESPONDER_UNSUPPORTED_REQUEST = CMD_INTERFACE_TDISP_RESPONDER_ERROR (0x03),	/**< The request is unsupported. */
	CMD_INTERFACE_TDISP_RESPONDER_PROCESS_REQUEST_FAILED =
		CMD_INTERFACE_TDISP_RESPONDER_ERROR (0x04),													/**< The request processing failed. */
	CMD_INTERFACE_TDISP_RESPONDER_INVALID_MSG_SIZE = CMD_INTERFACE_TDISP_RESPONDER_ERROR (0x05),	/**< The request message size is invalid. */
	CMD_INTERFACE_TDISP_RESPONDER_UNKNOWN_COMMAND = CMD_INTERFACE_TDISP_RESPONDER_ERROR (0x06),		/**< The request command is unknown. */
	CMD_INTERFACE_TDISP_RESPONDER_UNSUPPORTED_OPERATION =
		CMD_INTERFACE_TDISP_RESPONDER_ERROR (0x07),													/**< The operation is not supported. */
};


#endif	/* CMD_INTERFACE_TDISP_RESPONDER_H */
