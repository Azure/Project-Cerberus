// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_BACKGROUND_HANDLER_H_
#define CMD_BACKGROUND_HANDLER_H_

#include <stdbool.h>
#include "attestation/attestation_responder.h"
#include "cmd_interface/cmd_background.h"
#include "cmd_interface/config_reset.h"
#include "crypto/hash.h"
#include "riot/riot_key_manager.h"
#include "system/event_task.h"


/**
 * Action identifiers for the background command handler.
 */
enum {
	CMD_BACKGROUND_HANDLER_ACTION_RUN_UNSEAL = 1,		/**< Start unsealing with received data. */
	CMD_BACKGROUND_HANDLER_ACTION_RUN_BYPASS,			/**< Revert the device to bypass mode. */
	CMD_BACKGROUND_HANDLER_ACTION_RUN_DEFAULTS,			/**< Restore factory defaults. */
	CMD_BACKGROUND_HANDLER_ACTION_DEBUG_LOG_CLEAR,		/**< Clear the debug log. */
	CMD_BACKGROUND_HANDLER_ACTION_DEBUG_LOG_FILL,		/**< Fill the debug log with data. */
	CMD_BACKGROUND_HANDLER_ACTION_AUTH_RIOT,			/**< Authenticate device certificates. */
	CMD_BACKGROUND_HANDLER_ACTION_AUX_KEY_GEN,			/**< Generate the aux attestation key. */
	CMD_BACKGROUND_HANDLER_ACTION_PLATFORM_CFG,			/**< Clear the platform configuration. */
	CMD_BACKGROUND_HANDLER_ACTION_RESET_INTRUSION,		/**< Reset the intrusion state. */
	CMD_BACKGROUND_HANDLER_ACTION_CLEAR_CFM				/**< Clear define CFMs. */
};


/**
 * Variable context for background command processing.
 */
struct cmd_background_handler_state {
	int cert_state;									/**< Certificate authentication state. */
#ifdef CMD_ENABLE_UNSEAL
	int attestation_status;							/**< The attestation operation status. */
	uint8_t *unseal_request;						/**< The current unseal request. */
	uint8_t key[AUX_ATTESTATION_KEY_256BIT];		/**< Buffer for the unsealed key. */
#endif
#if defined CMD_ENABLE_RESET_CONFIG || defined CMD_ENABLE_INTRUSION
	int config_status;								/**< Status for configuration operations. */
#endif
};

/**
 * Handler for executing background operations from the command processor.
 */
struct cmd_background_handler {
	struct cmd_background base_cmd;					/**< The base interface for command handling. */
	struct event_task_handler base_event;			/**< THe base interface for task integration. */
	struct cmd_background_handler_state *state;		/**< Variable context for the handler. */
	struct riot_key_manager *keys;					/**< Manager for the RIoT keys and certificates. */
	const struct event_task *task;					/**< The task context executing the handler. */
#ifdef CMD_ENABLE_UNSEAL
	struct attestation_responder *attestation;		/**< Attestation responder to utilize for attestation operations. */
	struct hash_engine *hash;						/**< Hash engine to be used in attestation operations. */
#endif
#if defined CMD_ENABLE_RESET_CONFIG || defined CMD_ENABLE_INTRUSION
	struct config_reset *reset;						/**< Configuration reset manager. */
#endif
};


int cmd_background_handler_init (struct cmd_background_handler *handler,
	struct cmd_background_handler_state *state, struct attestation_responder *attestation,
	struct hash_engine *hash, struct config_reset *reset, struct riot_key_manager *riot,
	const struct event_task *task);
int cmd_background_handler_init_state (const struct cmd_background_handler *handler);
void cmd_background_handler_release (const struct cmd_background_handler *handler);

int cmd_background_handler_generate_aux_key (const struct cmd_background_handler *handler,
	struct aux_attestation *aux);


#endif /* CMD_BACKGROUND_HANDLER_H_ */
